from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
V2 = ROOT / "research/provider-live-roadmap/p3-api/v2"
RUNNER = V2 / "live_runner.py"
CONTRACT = V2 / "contract.json"
RESULT = V2 / "result.json"


def load_runner():
    spec = importlib.util.spec_from_file_location("p3_anthropic_api_v2_test", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("v2 runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P3AnthropicAPIV2Tests(unittest.TestCase):
    def assert_minimized_manual_billing(self, value: object) -> None:
        self.assertEqual(
            value,
            {
                "authority": "provider_reported_daily_aggregate",
                "daily_total_display": {"amount": "1.03", "currency": "USD"},
                "known_v2_runs_on_date": 2,
                "model": "Claude Sonnet 5",
                "per_run_attribution": False,
                "raw_export_included": False,
                "rounded_csv_cost_rows": [
                    {
                        "cost_usd": "0.69",
                        "list_price_usd": "0.69",
                        "token_type": "input_no_cache",
                    },
                    {
                        "cost_usd": "0.33",
                        "list_price_usd": "0.33",
                        "token_type": "output",
                    },
                ],
                "source": "anthropic_console_csv_manual_observation",
                "usage_date_utc": "2026-08-17",
            },
        )

    def test_v2_runner_and_contract_exist(self) -> None:
        self.assertTrue(RUNNER.is_file(), "v2 runner missing")
        self.assertTrue(CONTRACT.is_file(), "v2 contract missing")

    @classmethod
    def setUpClass(cls) -> None:
        if not RUNNER.is_file() or not CONTRACT.is_file():
            return
        cls.runner = load_runner()
        cls.contract_raw = CONTRACT.read_bytes()
        cls.contract = json.loads(cls.contract_raw)

    def setUp(self) -> None:
        if self._testMethodName != "test_v2_runner_and_contract_exist":
            if not RUNNER.is_file() or not CONTRACT.is_file():
                self.skipTest("v2 implementation not present")

    def test_candidate_closes_public_two_hop_dependency_before_scorer(self) -> None:
        self.runner.validate_contract(self.contract, repo_root=ROOT)
        candidate = self.runner.prepare_candidate(
            contract=self.contract,
            repo_root=ROOT,
        )
        self.assertEqual(candidate.capture.scorer_load_count, 0)
        self.assertEqual(
            candidate.tasks["evaluation_graph"]["prompt"],
            "Validate the indigo release token through the JavaScript dependency graph. "
            "Invoke verifyIndigo(800, 17) and return only its result.",
        )
        self.assertNotIn(
            "app/routing/constants.py",
            candidate.baseline_packs[("train_graph", "combined")]["selected_paths"],
        )
        self.assertIn(
            "app/routing/constants.py",
            candidate.packs[("train_graph", "combined")]["selected_paths"],
        )
        self.assertEqual(
            candidate.packs[("train_graph", "ordinary")]["rendered_pack"],
            candidate.baseline_packs[("train_graph", "ordinary")]["rendered_pack"],
        )
        self.assertEqual(
            candidate.metrics,
            {
                "baseline_complete_tasks": 2,
                "candidate_complete_tasks": 3,
                "denominator": 3,
                "missing_dependency_edges": 0,
            },
        )

    def test_request_plan_and_approval_bind_exact_candidate(self) -> None:
        candidate = self.runner.prepare_candidate(
            contract=self.contract,
            repo_root=ROOT,
        )
        schedule = self.runner.load_schedule(candidate.v1, repo_root=ROOT)
        plan = candidate.v1.base.build_request_plan(
            contract=candidate.v1.contract,
            schedule=schedule,
            tasks=candidate.tasks,
            packs=candidate.packs,
        )
        self.assertEqual(len(plan), 240)
        runner_digest = hashlib.sha256(RUNNER.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as name:
            scope = self.runner.build_approval_scope(
                candidate=candidate,
                contract=self.contract,
                output_root=Path(name).resolve(),
                plan=plan,
                runner_sha256=runner_digest,
            )
        self.assertEqual(scope["runtime"]["executable_sha256"], runner_digest)
        self.assertEqual(scope["runtime"]["identity"], "python-http.client-p3-v2-runner")
        self.assertEqual(scope["operation"]["version"], "v2")
        self.assertEqual(scope["limits"]["call_cap"], 240)

    def test_authorized_v2_run_is_one_use_and_keeps_private_surfaces_out(self) -> None:
        candidate = self.runner.prepare_candidate(
            contract=self.contract,
            repo_root=ROOT,
        )
        boundary = candidate.v1.base.load_approval_boundary(
            candidate.v1.base.CAPTURED_CONTRACT,
            repo_root=ROOT,
        )
        signing_key = bytes(range(32))
        registry_key = bytes(reversed(range(32)))
        api_key = b"sk-ant-api03-v2-test-secret-never-publish"
        now = int(time.time())
        approval_box: dict[str, object] = {}
        calls: list[str] = []

        def approval_factory(scope: dict[str, object]) -> dict[str, object]:
            if "approval" not in approval_box:
                approval_box["approval"] = boundary.create_approval(
                    scope=scope,
                    issued_at=now - 1,
                    expires_at=now + 3600,
                    nonce="c" * 64,
                    revocation_handle="d" * 64,
                    signing_key=signing_key,
                )
            return approval_box["approval"]

        def invoke(item: dict[str, object]) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return json.dumps(
                {
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg_" + item["scheduled_unit_id"],
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "type": "message",
                    "usage": {"input_tokens": 10, "output_tokens": 2},
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()

        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            os.chmod(root, 0o700)
            output = root / "output"
            state = root / "state"
            output.mkdir(mode=0o700)
            state.mkdir(mode=0o700)
            result = self.runner.run_live_authorized(
                contract_path=CONTRACT,
                repo_root=ROOT,
                output_root=output,
                state_root=state,
                approval=approval_factory,
                verification_key=signing_key,
                registry_key=registry_key,
                api_key=api_key,
                invoke=invoke,
            )
            self.assertEqual(result["status"], "p3_api_v2_measurement_recorded")
            self.assertEqual(len(calls), 240)
            evidence_raw = (output / "p3-api-v2-evidence.json").read_bytes()
            evidence = json.loads(evidence_raw)
            self.runner.validate_evidence(
                evidence,
                contract_raw=self.contract_raw,
                candidate=self.runner.prepare_candidate(
                    contract=self.contract,
                    repo_root=ROOT,
                ),
                repo_root=ROOT,
            )
            forged_runner = copy.deepcopy(evidence)
            forged_runner["v1_evidence"]["runner_sha256"] = "0" * 64
            with self.assertRaises(Exception):
                self.runner.validate_evidence(
                    forged_runner,
                    contract_raw=self.contract_raw,
                    candidate=self.runner.prepare_candidate(
                        contract=self.contract,
                        repo_root=ROOT,
                    ),
                    repo_root=ROOT,
                )
            self.assertNotIn(api_key, evidence_raw)
            self.assertNotIn(b"Authenticated read-only context pack", evidence_raw)
            self.assertEqual(evidence["candidate_metrics"]["missing_dependency_edges"], 0)

            with self.assertRaises(Exception):
                self.runner.run_live_authorized(
                    contract_path=CONTRACT,
                    repo_root=ROOT,
                    output_root=output,
                    state_root=state,
                    approval=approval_factory,
                    verification_key=signing_key,
                    registry_key=registry_key,
                    api_key=api_key,
                    invoke=invoke,
                )
            self.assertEqual(len(calls), 240)

    def test_contract_mutation_and_direct_execution_refuse(self) -> None:
        self.runner.validate_contract(self.contract, repo_root=ROOT)
        changed = copy.deepcopy(self.contract)
        changed["candidate"]["graph_closure_depth"] = 1
        with self.assertRaises(Exception):
            self.runner.validate_contract(changed, repo_root=ROOT)
        self.assertEqual(self.runner.main([]), 2)

    def test_published_result_binds_v2_evidence_and_reports_the_remaining_invalid_task(self) -> None:
        self.assertTrue(RESULT.is_file(), "v2 result missing")
        if not RESULT.is_file():
            return
        result = json.loads(RESULT.read_bytes())
        self.assertEqual(
            result["schema_version"],
            "contextguard.p3-anthropic-api-live-result/v2",
        )
        self.assertEqual(
            result["source"]["contract_sha256"],
            hashlib.sha256(self.contract_raw).hexdigest(),
        )
        self.assertEqual(
            result["source"]["runner_sha256"],
            hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
        )
        self.assertEqual(result["call_accounting"]["completed_calls"], 240)
        self.assertEqual(result["token_usage"]["provider_total_tokens"], 190434)
        self.assertEqual(
            result["analysis"]["realistic_fallback"]["combined_minus_ordinary"]
            ["total_token_delta"],
            -6495,
        )
        self.assertEqual(
            result["analysis"]["realistic_fallback"]["arms"]["combined"]["correct"],
            20,
        )
        self.assertEqual(
            result["analysis"]["realistic_task_correctness"]["evaluation_graph"]
            ["combined"],
            {"correct": 0, "denominator": 10},
        )
        self.assertIn("evaluation_public_oracle_mismatch", result["p3_gate"]["blockers"])
        self.assertFalse(result["p3_gate"]["eligible"])
        self.assertTrue(all(value is False for value in result["claims"].values()))
        self.assertNotIn(b"/private/tmp", RESULT.read_bytes())

    def test_published_manual_billing_is_minimized_daily_provenance_not_per_run_cost(self) -> None:
        result = json.loads(RESULT.read_bytes())
        billing = result["pricing"]["provider_reported_daily_billing"]
        self.assert_minimized_manual_billing(billing)
        self.assertFalse(result["claims"]["authoritative_provider_cost"])
        self.assertFalse(result["claims"]["provider_cost_savings"])

        for mutation in (
            lambda value: value.pop("source"),
            lambda value: value.update(authority="authoritative_provider_receipt"),
            lambda value: value.update(per_run_attribution=True),
            lambda value: value.update(raw_export_included=True),
        ):
            overstated = copy.deepcopy(billing)
            mutation(overstated)
            with self.subTest(overstated=overstated):
                with self.assertRaises(AssertionError):
                    self.assert_minimized_manual_billing(overstated)


if __name__ == "__main__":
    unittest.main()
