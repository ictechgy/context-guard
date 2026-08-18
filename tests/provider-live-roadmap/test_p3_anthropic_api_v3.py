from __future__ import annotations

import importlib.util
import inspect
import copy
import json
import os
from pathlib import Path
import types
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
RUNNER = V3 / "live_runner.py"
CONTRACT = V3 / "live-contract.json"
LAUNCHER = V3 / "live_launcher.py"
PROTOCOL_AMENDMENT = V3 / "protocol-amendment.json"
RESPONSE_AMENDMENT = V3 / "response-amendment.json"


def load_runner():
    spec = importlib.util.spec_from_file_location("p3_anthropic_api_v3_test", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("v3 runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class P3AnthropicAPIV3Tests(unittest.TestCase):
    def test_contract_binds_the_exact_committed_g4_artifacts(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())

        runner.validate_contract(contract, repo_root=ROOT)
        self.assertEqual(contract["artifacts"], runner.EXPECTED_ARTIFACTS)

    def test_contract_freezes_two_approval_batches_and_exact_messages_request(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())

        runner.validate_contract(contract, repo_root=ROOT)
        self.assertEqual(contract["limits"]["scheduled_units"], 288)
        self.assertEqual(contract["limits"]["batch_units"], 144)
        self.assertEqual(contract["limits"]["batch_count"], 2)
        self.assertEqual(contract["limits"]["per_batch_spend_cap_usd"], "20.00")
        self.assertEqual(contract["limits"]["cumulative_spend_cap_usd"], "40.00")
        self.assertEqual(contract["limits"]["prior_protocol_validation_calls"], 1)
        self.assertEqual(contract["limits"]["total_external_call_cap"], 289)
        self.assertIn("whole_batch_worst_case", contract["reservation"])
        self.assertEqual(contract["reservation"]["whole_batch_worst_case"]["output_tokens_per_unit"], 4096)
        self.assertEqual(contract["safety"]["retention"], "unavailable_manual_owner_cleanup")
        self.assertEqual(contract["provider"]["model_id"], "claude-sonnet-5")
        self.assertEqual(
            contract["request"],
            {
                "anthropic_version": "2023-06-01",
                "endpoint": "/v1/messages",
                "max_tokens": 4096,
                "sampling_parameters": "provider_default_unset",
                "thinking": "provider_default_private_ignored_for_scoring",
            },
        )
        self.assertEqual(contract["destination_allowlist"], [{
            "host": "api.anthropic.com", "port": 443, "scheme": "https"
        }])
        self.assertFalse(contract["safety"]["raw_content_publication"])

    def test_request_body_omits_tools_cache_and_sampling_drift(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        raw = runner.build_request_body(
            {"prompt": "Task and authenticated context"}, contract=contract
        )
        self.assertEqual(
            json.loads(raw),
            {
                "max_tokens": 4096,
                "messages": [{
                    "content": "Task and authenticated context", "role": "user"
                }],
                "model": "claude-sonnet-5",
            },
        )
        self.assertNotIn("temperature", json.loads(raw))
        self.assertNotIn("cache", raw.decode("ascii").lower())
        self.assertNotIn("tools", json.loads(raw))

    def test_protocol_amendment_excludes_failed_preflight_and_reserves_unknown_spend(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        amendment = json.loads(PROTOCOL_AMENDMENT.read_bytes())

        runner.validate_contract(contract, repo_root=ROOT)
        self.assertEqual(
            contract["artifacts"]["protocol_amendment"]["sha256"],
            runner.sha256(PROTOCOL_AMENDMENT.read_bytes()),
        )
        self.assertEqual(amendment["failed_preflight"]["attempted_calls"], 1)
        self.assertEqual(amendment["failed_preflight"]["http_status"], 400)
        self.assertEqual(amendment["failed_preflight"]["provider_usage"], "unavailable")
        self.assertEqual(amendment["failed_preflight"]["spend_status"], "unknown")
        self.assertFalse(amendment["failed_preflight"]["included_in_analysis"])
        self.assertFalse(amendment["failed_preflight"]["retried"])
        self.assertEqual(amendment["correction"]["removed_request_fields"], ["temperature"])
        self.assertEqual(amendment["correction"]["measurement_calls"], 288)
        self.assertEqual(amendment["authorization"]["total_external_call_cap"], 289)
        self.assertEqual(
            contract["resume"]["previous_ledger_contract_sha256"],
            "a6c4965c5d938bb6da667bbfde2efb32e539c397c23ad864eb707c6e5e491b5d",
        )
        self.assertNotEqual(
            contract["resume"]["previous_ledger_contract_sha256"],
            amendment["previous_core"]["contract_sha256"],
        )
        self.assertTrue(amendment["authorization"]["fresh_approval_required"])
        prior = contract["reservation"]["prior_protocol_validation"]
        self.assertEqual(prior["attempted_calls"], 1)
        self.assertEqual(prior["spend_status"], "unknown")
        self.assertEqual(prior["worst_case_list_price_micro_usd"], 249344)
        self.assertTrue(prior["included_in_cumulative_cap"])

        plan = []
        for index in range(288):
            prompt = "bounded-protocol-amendment-prompt"
            item = {
                "scheduled_unit_id": f"amended-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        reservation = runner.calculate_worst_case_reservation(
            contract=contract,
            batches=runner.build_batch_plans(plan),
        )
        batch_total = sum(
            batch["worst_case_list_price_micro_usd"]
            for batch in reservation["batches"]
        )
        self.assertEqual(
            reservation["cumulative_worst_case_list_price_micro_usd"],
            batch_total + prior["worst_case_list_price_micro_usd"],
        )

    def test_usage_parser_accepts_bounded_current_optional_fields(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        raw = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-optional-usage",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {
                "cache_creation": {
                    "ephemeral_5m_input_tokens": 0,
                    "ephemeral_1h_input_tokens": 0,
                },
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "inference_geo": "global",
                "input_tokens": 10,
                "output_tokens": 2,
                "output_tokens_details": {"text_tokens": 2},
                "service_tier": "standard",
            },
        }, separators=(",", ":"), sort_keys=True).encode()
        parsed = runner.parse_anthropic_response(raw, contract=contract)
        self.assertEqual(parsed["usage"]["provider_total_tokens"], 12)

    def test_response_amendment_accepts_private_thinking_and_scores_only_text(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        amendment = json.loads(RESPONSE_AMENDMENT.read_bytes())
        raw = json.dumps({
            "content": [
                {"signature": "private-signature", "thinking": "private-reasoning", "type": "thinking"},
                {"text": "PUBLIC-DIFF", "type": "text"},
            ],
            "id": "msg-thinking",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_details": None,
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 11, "output_tokens": 3},
        }, separators=(",", ":"), sort_keys=True).encode()

        runner.validate_contract(contract, repo_root=ROOT)
        parsed = runner.parse_anthropic_response(raw, contract=contract)
        self.assertEqual(parsed["answer"], "PUBLIC-DIFF")
        self.assertNotIn("thinking", parsed)
        self.assertNotIn("private-reasoning", json.dumps(parsed))
        self.assertEqual(
            contract["artifacts"]["response_amendment"]["sha256"],
            runner.sha256(RESPONSE_AMENDMENT.read_bytes()),
        )
        self.assertEqual(amendment["correction"]["remaining_measurement_calls"], 287)
        self.assertFalse(amendment["correction"]["redispatch_sealed_unit"])
        self.assertEqual(amendment["authorization"]["total_external_call_cap"], 289)

        malformed = json.loads(raw)
        malformed["content"][0]["debug"] = "not-allowed"
        with self.assertRaises(Exception):
            runner.parse_anthropic_response(
                json.dumps(malformed, separators=(",", ":"), sort_keys=True).encode(),
                contract=contract,
            )

    def test_verified_capsule_migration_resumes_without_redispatch(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        prompt = "migration-prompt"
        plan = []
        for index in range(288):
            item = {
                "scheduled_unit_id": f"migration-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a010",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        response = json.dumps({
            "content": [
                {"signature": "private-signature", "thinking": "private-reasoning", "type": "thinking"},
                {"text": "READY", "type": "text"},
            ],
            "id": "msg-migration",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_details": None,
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        registry_key = bytes(range(32, 64))
        derived_key = runner._derive_ledger_key(registry_key)
        batches = runner.build_batch_plans(plan)
        reservation = runner.calculate_worst_case_reservation(
            contract=contract, batches=batches
        )
        plan_sha = runner._plan_digest(batches)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            previous_state = root / "previous-state"
            previous_output = root / "previous-output"
            state = root / "state"
            output = root / "output"
            for path in (previous_state, previous_output, state, output):
                path.mkdir(mode=0o700)
            previous_private = previous_output / "private"
            runner._private_dir(previous_private)

            def initialize_previous(value, _key):
                runner._initialize_ledger(
                    value, contract=contract, batches=batches,
                    plan_sha256=plan_sha, reservation=reservation,
                )
                value["contract_sha256"] = runner.EXPECTED_RESUME[
                    "previous_ledger_contract_sha256"
                ]
                first = value["units"][plan[0]["scheduled_unit_id"]]
                first["reserved"] = True
                first["status"] = "reserved"
                runner._mark_not_dispatched(value)
                record = runner._terminal_record(
                    item=plan[0],
                    capsule={"body": response, "http_status": 200, "provider_request_id": "private"},
                    status="failed", error="provider_receipt_missing", parsed=None,
                    started=1, ended=2,
                )
                runner._apply_terminal(
                    value, unit_id=plan[0]["scheduled_unit_id"], record=record
                )
                runner._mark_terminal_batches(value, batches)

            runner._with_ledger(previous_state, derived_key, initialize_previous)
            runner._write_transport_capsule(
                previous_private,
                plan[0]["scheduled_unit_id"],
                {"body": response, "http_status": 200, "provider_request_id": "private"},
                derived_key,
                plan[0],
            )
            expected_resume = {
                "policy": "hmac_verify_single_capsule_without_redispatch",
                "previous_ledger_contract_sha256": runner.EXPECTED_RESUME[
                    "previous_ledger_contract_sha256"
                ],
                "previous_plan_sha256": plan_sha,
                "previous_response_sha256": runner.sha256(response),
                "sealed_unit_id": plan[0]["scheduled_unit_id"],
            }
            runner._migrate_single_verified_capsule_core(
                contract=contract,
                plan=plan,
                previous_state_root=previous_state,
                previous_output_root=previous_output,
                state_root=state,
                output_root=output,
                registry_key=registry_key,
                expected_resume=expected_resume,
            )
            calls = []
            result = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: {"approved": scope["batch_id"]},
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or {
                    "body": response, "http_status": 200, "provider_request_id": "private"
                }),
                scorer_loader=lambda: (lambda capsules, prepared: {
                    "failed_units": 0,
                    "passed_units": len(prepared),
                    "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                    "status": "complete",
                    "total_units": len(prepared),
                }),
                ledger_key=registry_key,
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(calls), 287)
            self.assertNotIn(plan[0]["scheduled_unit_id"], calls)

    def test_transport_captures_actual_request_id_header_privately(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        response_raw = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-header",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()

        class HeaderResponse:
            status = 200

            def read(self, amount: int) -> bytes:
                return response_raw

            def getheader(self, name: str):
                return "req-actual-header" if name == "request-id" else None

        class HeaderConnection:
            def __init__(self, host, *, port, timeout, context):
                pass

            def request(self, method, path, *, body, headers):
                pass

            def getresponse(self):
                return HeaderResponse()

            def close(self):
                pass

        capsule = runner.invoke_anthropic(
            {"prompt": "Task"}, contract=contract,
            api_key=b"sk-ant-api03-test-secret-never-publish",
            connection_factory=HeaderConnection,
        )
        self.assertEqual(capsule["provider_request_id"], "req-actual-header")

    def test_https_invocation_is_exact_destination_and_no_retry(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        response_raw = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg_0123456789",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        calls: list[dict[str, object]] = []

        class FakeResponse:
            status = 200

            def read(self, amount: int) -> bytes:
                self.amount = amount
                return response_raw

        class FakeConnection:
            def __init__(self, host, *, port, timeout, context):
                calls.append({"host": host, "port": port, "timeout": timeout})

            def request(self, method, path, *, body, headers):
                calls[-1].update({"method": method, "path": path, "body": body, "headers": headers})

            def getresponse(self):
                return FakeResponse()

            def close(self):
                calls[-1]["closed"] = True

        key = b"sk-ant-api03-test-secret-never-publish"
        capsule = runner.invoke_anthropic(
                {"prompt": "Task"}, contract=contract, api_key=key,
                connection_factory=FakeConnection,
            )
        self.assertEqual(capsule["body"], response_raw)
        self.assertEqual(capsule["http_status"], 200)
        self.assertEqual(
            (calls[0]["host"], calls[0]["port"], calls[0]["method"], calls[0]["path"]),
            ("api.anthropic.com", 443, "POST", "/v1/messages"),
        )
        self.assertEqual(calls[0]["timeout"], 120)
        self.assertTrue(calls[0]["closed"])

    def test_execution_reserves_before_dispatch_and_loads_scorer_after_all_terminal(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = [
            {
                "scheduled_unit_id": f"unit-{index:03d}",
                "prompt": f"private-prompt-{index}",
                "payload_sha256": runner.sha256(f"private-prompt-{index}".encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0 if index == 0 else 1,
            }
            for index in range(288)
        ]
        response = lambda item: json.dumps({
            "content": [{"text": "private-answer", "type": "text"}],
            "id": "msg_" + item["scheduled_unit_id"],
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        calls: list[str] = []
        approvals: list[dict[str, object]] = []
        scorer_loads: list[int] = []

        def approve(scope: dict[str, object]) -> object:
            approvals.append(scope)
            return {"approved": True, "batch_id": scope["batch_id"]}

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state = root / "state"
            output = root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            result = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=approve,
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or response(item)),
                scorer_loader=lambda: scorer_loads.append(1) or (
                    lambda capsules, prepared: {
                        "failed_units": 0,
                        "passed_units": len(prepared),
                        "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                        "total_units": len(prepared),
                        "status": "complete",
                    }
                ),
            )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(calls), 288)
            self.assertEqual(len(approvals), 2)
            self.assertEqual(scorer_loads, [1])
            self.assertEqual(result["token_usage"]["provider_total_tokens"], 3456)
            public = (output / "p3-api-evidence.json").read_bytes()
            self.assertNotIn(b"private-prompt", public)
            self.assertNotIn(b"private-answer", public)
            self.assertEqual(json.loads(public)["accounting"]["reserved_units"], 288)
            runner.validate_public_evidence(
                json.loads(public), contract_raw=runner.canonical(contract)
            )
            evidence_value = json.loads(public)
            for mutation in (
                lambda value: value["scoring"].__setitem__("passed_units", 287),
                lambda value: value["accounting"].__setitem__("terminal_units", 287),
                lambda value: value["scoring"].__setitem__("scorer_artifact_sha256", "0" * 64),
            ):
                changed = copy.deepcopy(evidence_value)
                mutation(changed)
                with self.assertRaises(Exception):
                    runner.validate_public_evidence(
                        changed, contract_raw=runner.canonical(contract)
                    )
            self.assertEqual(
                json.loads(public)["runner_sha256"], runner.sha256(RUNNER.read_bytes())
            )
            self.assertEqual(os.stat(state).st_mode & 0o777, 0o700)
            self.assertFalse((state / "hmac.key").exists())
            for path in state.iterdir():
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

            resumed = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: (_ for _ in ()).throw(AssertionError("reapproval")),
                invoke=lambda item: (_ for _ in ()).throw(AssertionError("duplicate dispatch")),
                scorer_loader=lambda: {"unexpected": True},
            )
            self.assertEqual(resumed["status"], "completed")
            self.assertEqual(len(calls), 288)

    def test_direct_mutable_execution_refuses(self) -> None:
        runner = load_runner()
        self.assertEqual(runner.main([]), 2)

    def test_production_launcher_requires_explicit_execute(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_launcher_test", LAUNCHER)
        if spec is None or spec.loader is None:
            raise AssertionError("launcher unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        self.assertEqual(launcher.main([]), 2)

    def test_launcher_activation_binds_ledger_hash_fix_and_exact_blobs(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_launcher_activation_test", LAUNCHER)
        if spec is None or spec.loader is None:
            raise AssertionError("launcher unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)

        launcher._verify_core_commit(ROOT)
        self.assertEqual(
            launcher.EXPECTED_CORE_COMMIT,
            "b850c06901b6f5e643173d6331b05b1b47c5c1c0",
        )
        with mock.patch.object(launcher, "EXPECTED_CORE_COMMIT", "0" * 40):
            with self.assertRaises(Exception):
                launcher._verify_core_commit(ROOT)
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(Exception):
                launcher._verify_core_commit(Path(name))

    def test_launcher_blob_identity_and_private_read_fail_closed(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_launcher_blob_test", LAUNCHER)
        if spec is None or spec.loader is None:
            raise AssertionError("launcher unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        expected = b"committed-core"
        digest = __import__("hashlib").sha256(expected).hexdigest()
        launcher._verify_blob_triple(expected, expected, expected, digest)
        for changed in (
            (b"changed-core", expected, expected),
            (expected, b"changed-head", expected),
            (expected, expected, b"changed-worktree"),
        ):
            with self.assertRaises(Exception):
                launcher._verify_blob_triple(*changed, digest)

        with tempfile.TemporaryDirectory() as name:
            private = Path(name) / "oversized.bin"
            private.write_bytes(b"x" * (launcher.MAX_PRIVATE_INPUT_BYTES + 1))
            private.chmod(0o600)
            with self.assertRaises(Exception):
                launcher._read_owner_file(private)

    def test_launcher_keychain_read_is_fixed_service_bounded_and_never_printed(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_launcher_keychain_test", LAUNCHER)
        if spec is None or spec.loader is None:
            raise AssertionError("launcher unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        completed = types.SimpleNamespace(
            returncode=0,
            stdout=b"sk-ant-api03-test-key\n",
        )
        with mock.patch.object(launcher.subprocess, "run", return_value=completed) as run:
            value = launcher._read_keychain_secret()
        self.assertEqual(value, b"sk-ant-api03-test-key")
        self.assertEqual(run.call_args.args[0][:4], ["/usr/bin/security", "find-generic-password", "-s", "contextguard-anthropic-p3"])
        self.assertNotIn(value.decode(), str(run.call_args))

    def test_launcher_keychain_refusal_is_value_free_and_bounded(self) -> None:
        spec = importlib.util.spec_from_file_location("p3_v3_launcher_keychain_refusal_test", LAUNCHER)
        if spec is None or spec.loader is None:
            raise AssertionError("launcher unavailable")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        completed = types.SimpleNamespace(returncode=1, stdout=b"private-error")
        with mock.patch.object(launcher.subprocess, "run", return_value=completed):
            with self.assertRaises(Exception) as raised:
                launcher._read_keychain_secret()
        self.assertNotIn("private-error", str(raised.exception))

    def test_authorized_surface_has_no_injectable_network_or_scorer_overrides(self) -> None:
        runner = load_runner()
        parameters = inspect.signature(runner.run_live_authorized).parameters
        self.assertNotIn("invoke", parameters)
        self.assertNotIn("scorer_loader", parameters)
        self.assertFalse(hasattr(runner, "execute_schedule"))
        self.assertIn("approvals", parameters)
        self.assertIn("verification_key", parameters)
        self.assertIn("registry_key", parameters)

    def test_external_approval_artifacts_are_pinned_and_scopes_are_schema_ready(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        runner.validate_contract(contract, repo_root=ROOT)
        self.assertEqual(
            contract["artifacts"]["approval_schema"],
            {
                "path": "packages/context-guard-receipt/schemas/external-approval.schema.json",
                "sha256": "c535d464311d9f7dd5b326face7596e6b930da4fb3e0350a5d3e0942e735eb69",
            },
        )

    def test_transitive_capture_artifact_mutations_refuse_before_preparation(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        for artifact_name in ("canonical_packer", "canonical_sanitizer", "corpus", "approval_schema"):
            changed = copy.deepcopy(contract)
            changed["artifacts"][artifact_name]["sha256"] = "0" * 64
            with self.assertRaises(Exception):
                runner.validate_contract(changed, repo_root=ROOT)

    def test_bound_scorer_scores_provider_answer_diff_not_json_envelope(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        patch_bytes = (
            b"diff --git a/src/file.py b/src/file.py\n"
            b"--- a/src/file.py\n+++ b/src/file.py\n"
            b"@@ -1 +1 @@\n-old\n+new\n"
        )
        response = json.dumps({
            "content": [{"text": patch_bytes.decode(), "type": "text"}],
            "id": "msg-score",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        seen: list[bytes] = []
        task = {
            "id": "task",
            "allowed_patch_paths": ["src/file.py"],
            "historical_commit": "historical",
            "parent_commit": "parent",
        }
        checker = {"assertions": []}

        class FakeEvaluator:
            def parse_object(self, raw, label):
                return {}

            def validate_report(self, report, *, capture, repo_root):
                return None

            def load_scorer_contract(self, capture, *, repo_root):
                return ({"task": checker}, {"sha256": "a" * 64})

            def preflight_sources(self, corpus_root):
                return ({"task": {"repo": Path("/tmp"), "task": task, "inventory": []}}, {})

            def validate_patch_envelope(self, raw, allowed_paths):
                seen.append(raw)
                if raw != patch_bytes:
                    raise AssertionError("JSON envelope was scored instead of answer diff")
                return ["src/file.py"]

            def selected_patch(self, repo, task_value):
                return patch_bytes

            def export_snapshot(self, repo, commit, inventory, workspace):
                workspace.mkdir(parents=True)
                target = workspace / "src" / "file.py"
                target.parent.mkdir(parents=True)
                target.write_bytes(b"new\n")

            def run_git(self, repo, arguments, *, input_bytes=None):
                return b""

            def assertions_pass(self, workspace, checker_value):
                return True

            def git_blob(self, repo, commit, path):
                return b"new\n"

            def safe_path(self, path):
                return types.SimpleNamespace(parts=tuple(path.split("/")))

        fake = FakeEvaluator()
        plan = [{
            "scheduled_unit_id": "unit-score",
            "task_id": "task",
            "arm_id": "a000",
            "repetition": 0,
        }]
        capsules = {"unit-score": {
            "body": response,
            "http_status": 200,
            "provider_request_id": None,
        }}
        with mock.patch.object(runner, "_load_bound_evaluator", return_value=fake), \
            mock.patch.object(runner, "_load_pinned_capture", return_value={}):
            score = runner._bound_scorer_loader(
                contract=contract, repo_root=ROOT, corpus_root=ROOT
            )()
        result = score(capsules, plan)
        self.assertEqual(seen, [patch_bytes])
        self.assertEqual(result["passed_units"], 1)

    def test_pending_scoring_restart_replaces_evidence_without_redispatch(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = f"retry-prompt-{index}"
            item = {
                "scheduled_unit_id": f"retry-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-retry",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            calls: list[str] = []
            first = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: {"approved": True},
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or {
                    "body": response, "http_status": 200, "provider_request_id": None
                }),
                scorer_loader=lambda: (_ for _ in ()).throw(RuntimeError("transient scorer")),
            )
            self.assertEqual(first["status"], "provider_receipts_sealed_pending_scoring")
            self.assertEqual(len(calls), 288)
            second = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: (_ for _ in ()).throw(AssertionError("reapproval")),
                invoke=lambda item: (_ for _ in ()).throw(AssertionError("redispatch")),
                scorer_loader=lambda: (lambda capsules, prepared: {
                    "failed_units": 0, "passed_units": len(prepared),
                    "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                    "total_units": len(prepared), "status": "complete"
                }),
            )
            self.assertEqual(second["status"], "completed")
            evidence = json.loads((output / "p3-api-evidence.json").read_bytes())
            self.assertEqual(evidence["status"], "completed")
            original_evidence_raw = (output / "p3-api-evidence.json").read_bytes()
            altered = copy.deepcopy(evidence)
            altered["scoring"]["failed_units"] = 1
            altered["scoring"]["passed_units"] = 287
            altered["analysis"] = copy.deepcopy(altered["scoring"])
            (output / "p3-api-evidence.json").write_bytes(runner.canonical(altered))
            ledger_key = __import__("hashlib").sha256(
                b"contextguard/p3-v3-test-ledger/v1\0"
                + runner.canonical({
                    "contract": contract,
                    "plan_sha256": runner.request_plan_sha256(plan),
                })
            ).digest()
            runner._with_ledger(
                state,
                ledger_key,
                lambda value, key: value.update({
                    "evidence_sha256": None,
                    "pending_evidence_sha256": runner.sha256(original_evidence_raw),
                    "status": "provider_receipts_sealed_pending_scoring",
                }),
            )
            with self.assertRaises(Exception):
                runner._execute_schedule_test_core(
                    contract=contract,
                    plan=plan,
                    state_root=state,
                    output_root=output,
                    approval_consume=lambda scope: (_ for _ in ()).throw(AssertionError("reapproval")),
                    invoke=lambda item: (_ for _ in ()).throw(AssertionError("redispatch")),
                    scorer_loader=lambda: (_ for _ in ()).throw(AssertionError("substituted evidence")),
                )

    def test_external_approval_replay_wrong_scope_and_expiry_fail_closed(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = "x"
            item = {
                "scheduled_unit_id": f"approval-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        batch = runner.build_batch_plans(plan)[0]
        scope = runner.build_external_approval_scope(
            contract=contract,
            batch=batch,
            plan_sha256="a" * 64,
            runner_sha256="b" * 64,
            output_root=Path(tempfile.mkdtemp()),
        )
        approval_module = runner._load_bound_approval_module(
            contract=contract, repo_root=ROOT
        )
        verification_key = bytes(range(32))
        registry_key = bytes(range(32, 64))
        now = int(__import__("time").time())
        approval = approval_module.create_approval(
            scope=scope,
            issued_at=now - 1,
            expires_at=now + 300,
            nonce="1" * 64,
            revocation_handle="2" * 64,
            signing_key=verification_key,
        )
        with tempfile.TemporaryDirectory() as name:
            state = Path(name)
            os.chmod(state, 0o700)
            consume = lambda requested, packet=approval: approval_module.authorize_and_consume(
                approval=packet,
                requested_scope=requested,
                verification_key=verification_key,
                registry_key=registry_key,
                state_root=state,
                materialize=lambda value: value,
            )
            consume(scope)
            with self.assertRaises(Exception):
                consume(scope)
            changed = json.loads(json.dumps(scope))
            changed["limits"]["call_cap"] = 143
            with self.assertRaises(Exception):
                approval_module.authorize_and_consume(
                    approval=approval,
                    requested_scope=changed,
                    verification_key=verification_key,
                    registry_key=registry_key,
                    state_root=state,
                    materialize=lambda value: value,
                )
        expired = approval_module.create_approval(
            scope=scope,
            issued_at=now - 10,
            expires_at=now - 1,
            nonce="3" * 64,
            revocation_handle="4" * 64,
            signing_key=verification_key,
        )
        with tempfile.TemporaryDirectory() as name:
            state = Path(name)
            os.chmod(state, 0o700)
            with self.assertRaises(Exception):
                approval_module.authorize_and_consume(
                    approval=expired,
                    requested_scope=scope,
                    verification_key=verification_key,
                    registry_key=registry_key,
                    state_root=state,
                    materialize=lambda value: value,
                )

    def test_external_consume_crash_journal_reconciles_without_replay(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = "journal-prompt"
            item = {
                "scheduled_unit_id": f"journal-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        batches = runner.build_batch_plans(plan)
        plan_sha = runner._plan_digest(batches)
        verification_key = bytes(range(32))
        registry_key = bytes(range(32, 64))
        ledger_key = runner._derive_ledger_key(registry_key)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, approval_state, output = root / "state", root / "approval", root / "output"
            state.mkdir(mode=0o700)
            approval_state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            runner._private_dir(output / "private")
            reservation = runner.calculate_worst_case_reservation(
                contract=contract, batches=batches
            )
            runner._with_ledger(
                state, ledger_key,
                lambda value, key: runner._initialize_ledger(
                    value, contract=contract, batches=batches,
                    plan_sha256=plan_sha, reservation=reservation,
                ),
            )
            scope = runner.build_external_approval_scope(
                contract=contract,
                batch=batches[0],
                plan_sha256=plan_sha,
                runner_sha256=runner._runner_identity(),
                output_root=output,
            )
            module = runner._load_bound_approval_module(contract=contract, repo_root=ROOT)
            now = int(__import__("time").time())
            approval = module.create_approval(
                scope=scope,
                issued_at=now - 1,
                expires_at=now + 300,
                nonce="9" * 64,
                revocation_handle="a" * 64,
                signing_key=verification_key,
            )
            metadata = {
                "authentication_hmac_sha256": approval["authentication_hmac_sha256"],
                "batch_id": "batch-1",
                "nonce_sha256": runner.sha256(approval["nonce"].encode()),
                "revocation_handle_sha256": runner.sha256(approval["revocation_handle"].encode()),
                "scope_sha256": runner.sha256(runner.canonical(scope)),
                "status": "pending_external_consumption",
            }
            runner._prepare_authorization_journal(
                state, ledger_key, batch_id="batch-1", journal=metadata
            )

            def crash(_scope):
                raise SystemExit("crash after registry commit")

            with self.assertRaises(SystemExit):
                module.authorize_and_consume(
                    approval=approval,
                    requested_scope=scope,
                    verification_key=verification_key,
                    registry_key=registry_key,
                    state_root=approval_state,
                    materialize=crash,
                )
            self.assertTrue(
                runner._external_registry_contains_nonce(
                    approval_state, registry_key, metadata["nonce_sha256"]
                )
            )
            runner._authorize_batch(state, ledger_key, batches[0], {
                "batch_id": "batch-1",
                "nonce_sha256": metadata["nonce_sha256"],
                "scope_sha256": metadata["scope_sha256"],
            })
            ledger = runner._ledger_snapshot(state, ledger_key)
            self.assertEqual(ledger["batches"]["batch-1"]["status"], "authorized")
            self.assertEqual(
                ledger["batches"]["batch-1"]["authorization"]["nonce_sha256"],
                metadata["nonce_sha256"],
            )
            scope2 = runner.build_external_approval_scope(
                contract=contract,
                batch=batches[1],
                plan_sha256=plan_sha,
                runner_sha256=runner._runner_identity(),
                output_root=output,
            )
            registry_status = runner._external_registry_status(
                approval_state, registry_key, metadata["nonce_sha256"],
                metadata["revocation_handle_sha256"],
            )
            journal2 = {
                **metadata,
                "batch_id": "batch-2",
                "scope_sha256": runner.sha256(runner.canonical(scope2)),
                "registry_nonce_present_before": True,
                "registry_state_sha256_before": registry_status["state_sha256"],
            }
            with self.assertRaises(Exception):
                runner._reconcile_external_journal(
                    approval_module=module,
                    approval=approval,
                    requested_scope=scope2,
                    verification_key=verification_key,
                    registry_status=registry_status,
                    journal=journal2,
                    state_root=state,
                    ledger_key=ledger_key,
                    batch=batches[1],
                    authorization_metadata={
                        "batch_id": "batch-2",
                        "nonce_sha256": metadata["nonce_sha256"],
                        "scope_sha256": journal2["scope_sha256"],
                    },
                )

    def test_authorized_same_envelope_cannot_authorize_second_batch(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = f"same-envelope-{index}"
            item = {
                "scheduled_unit_id": f"same-envelope-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        batches = runner.build_batch_plans(plan)
        verification_key = bytes(range(32))
        registry_key = bytes(range(32, 64))
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-same-envelope",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            scope = runner.build_external_approval_scope(
                contract=contract,
                batch=batches[0],
                plan_sha256=runner._plan_digest(batches),
                runner_sha256=runner._runner_identity(),
                output_root=output,
            )
            module = runner._load_bound_approval_module(contract=contract, repo_root=ROOT)
            now = int(__import__("time").time())
            approval = module.create_approval(
                scope=scope,
                issued_at=now - 1,
                expires_at=now + 300,
                nonce="b" * 64,
                revocation_handle="c" * 64,
                signing_key=verification_key,
            )
            calls: list[str] = []
            def fake_invoke(item, **kwargs):
                calls.append(item["scheduled_unit_id"])
                return {
                    "body": response, "http_status": 200, "provider_request_id": None
                }
            with mock.patch.object(runner, "prepare_live_plan", return_value=plan), \
                mock.patch.object(runner, "_migrate_single_verified_capsule"), \
                mock.patch.object(runner, "invoke_anthropic", side_effect=fake_invoke), \
                mock.patch.object(runner, "_bound_scorer_loader", return_value=lambda: {
                    "unreachable": True
                }):
                with self.assertRaises(Exception):
                    runner.run_live_authorized(
                        contract_path=CONTRACT,
                        repo_root=ROOT,
                        corpus_root=root,
                        output_root=output,
                        state_root=state,
                        previous_output_root=root,
                        previous_state_root=root,
                        approvals=[approval, approval],
                        verification_key=verification_key,
                        registry_key=registry_key,
                        api_key=b"sk-ant-api03-test-secret-never-publish",
                    )
            # The first batch may dispatch; the reused envelope must not
            # authorize the second batch or produce any second-batch calls.
            self.assertEqual(len(calls), 144)
            self.assertFalse((output / "p3-api-evidence.json").exists())

    def test_authorized_registry_commit_crash_restarts_same_envelopes_without_redispatch(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = f"crash-authorized-{index}"
            item = {
                "scheduled_unit_id": f"crash-authorized-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        batches = runner.build_batch_plans(plan)
        verification_key = bytes(range(32))
        registry_key = bytes(range(32, 64))
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg-crash-authorized",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            runner_sha = runner._runner_identity()
            module = runner._load_bound_approval_module(contract=contract, repo_root=ROOT)
            now = int(__import__("time").time())
            approvals = []
            plan_sha = runner._plan_digest(batches)
            for index, batch in enumerate(batches):
                scope = runner.build_external_approval_scope(
                    contract=contract, batch=batch, plan_sha256=plan_sha,
                    runner_sha256=runner_sha, output_root=output,
                )
                approvals.append(module.create_approval(
                    scope=scope, issued_at=now - 1, expires_at=now + 300,
                    nonce=f"{index + 20:064x}",
                    revocation_handle=f"{index + 30:064x}",
                    signing_key=verification_key,
                ))
            original_authorize = module.authorize_and_consume
            crashed = False
            def crash_once(**kwargs):
                nonlocal crashed
                if not crashed:
                    crashed = True
                    kwargs = {key: value for key, value in kwargs.items() if key != "materialize"}
                    return original_authorize(
                        **kwargs,
                        materialize=lambda scope: (_ for _ in ()).throw(SystemExit(7)),
                    )
                return original_authorize(**kwargs)
            score_calls: list[int] = []
            def fake_scorer():
                def score(capsules, prepared):
                    score_calls.append(len(prepared))
                    return {
                        "failed_units": 0, "passed_units": len(prepared),
                        "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                        "total_units": len(prepared), "status": "complete",
                    }
                return score
            with mock.patch.object(runner, "prepare_live_plan", return_value=plan), \
                mock.patch.object(runner, "_migrate_single_verified_capsule"), \
                mock.patch.object(runner, "_load_bound_approval_module", return_value=module), \
                mock.patch.object(module, "authorize_and_consume", side_effect=crash_once), \
                mock.patch.object(runner, "_bound_scorer_loader", side_effect=lambda **kwargs: fake_scorer):
                with self.assertRaises(SystemExit):
                    runner.run_live_authorized(
                        contract_path=CONTRACT, repo_root=ROOT, corpus_root=root,
                        output_root=output, state_root=state, approvals=approvals,
                        previous_output_root=root, previous_state_root=root,
                        verification_key=verification_key, registry_key=registry_key,
                        api_key=b"sk-ant-api03-test-secret-never-publish",
                    )
            calls: list[str] = []
            def fake_invoke(item, **kwargs):
                calls.append(item["scheduled_unit_id"])
                return {"body": response, "http_status": 200, "provider_request_id": None}
            with mock.patch.object(runner, "prepare_live_plan", return_value=plan), \
                mock.patch.object(runner, "_migrate_single_verified_capsule"), \
                mock.patch.object(runner, "invoke_anthropic", side_effect=fake_invoke), \
                mock.patch.object(runner, "_bound_scorer_loader", side_effect=lambda **kwargs: fake_scorer):
                result = runner.run_live_authorized(
                    contract_path=CONTRACT, repo_root=ROOT, corpus_root=root,
                    output_root=output, state_root=state, approvals=approvals,
                    previous_output_root=root, previous_state_root=root,
                    verification_key=verification_key, registry_key=registry_key,
                    api_key=b"sk-ant-api03-test-secret-never-publish",
                )
            self.assertEqual(result["status"], "completed")
            self.assertEqual(len(calls), 288)
            self.assertEqual(score_calls, [288])
            ledger = json.loads((state / "ledger.json").read_bytes())
            self.assertTrue(all(
                batch["authorization_journal"]["status"] == "committed"
                for batch in ledger["batches"].values()
            ))
    def test_unknown_provider_receipt_stops_dispatch_and_marks_spend_unknown(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = [
            {
                "scheduled_unit_id": f"unit-{index:03d}",
                "prompt": f"private-prompt-{index}",
                "payload_sha256": runner.sha256(f"private-prompt-{index}".encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            for index in range(288)
        ]
        calls: list[str] = []
        scorer_calls: list[int] = []
        capsule = {"body": b"{}", "http_status": 500, "provider_request_id": "req-1"}
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            result = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: {"approved": True},
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or capsule),
                scorer_loader=lambda: scorer_calls.append(1),
            )
            self.assertEqual(result["status"], "provider_receipts_sealed_pending_scoring")
            self.assertEqual(calls, ["unit-000"])
            self.assertEqual(scorer_calls, [])
            evidence = json.loads((output / "p3-api-evidence.json").read_bytes())
            self.assertEqual(evidence["accounting"]["reserved_units"], 1)
            self.assertEqual(evidence["accounting"]["spend_status"], "unknown")
            self.assertEqual(evidence["accounting"]["provider_receipt_units"], 1)
            self.assertEqual(evidence["accounting"]["usage_complete_units"], 0)
            self.assertNotIn("request_id", evidence)
            self.assertNotIn('"request_id"', (output / "p3-api-evidence.json").read_text())

    def test_malformed_and_timeout_transport_have_zero_retry(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = [
            {
                "scheduled_unit_id": f"unit-{index:03d}",
                "prompt": f"private-prompt-{index}",
                "payload_sha256": runner.sha256(f"private-prompt-{index}".encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            for index in range(288)
        ]
        cases = [
            lambda item: {"body": b"{}", "http_status": 200, "provider_request_id": None},
            lambda item: (_ for _ in ()).throw(TimeoutError("timeout")),
            lambda item: {
                "body": json.dumps({
                    "content": [{"text": "READY", "type": "text"}],
                    "id": "msg-cap",
                    "model": "claude-sonnet-5",
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "type": "message",
                    "usage": {"input_tokens": 30000000, "output_tokens": 0},
                }).encode(),
                "http_status": 200,
                "provider_request_id": None,
            },
        ]
        for invoke_case in cases:
            with tempfile.TemporaryDirectory() as name:
                root = Path(name)
                state, output = root / "state", root / "output"
                state.mkdir(mode=0o700)
                output.mkdir(mode=0o700)
                calls: list[str] = []
                runner._execute_schedule_test_core(
                    contract=contract,
                    plan=plan,
                    state_root=state,
                    output_root=output,
                    approval_consume=lambda scope: {"approved": True},
                    invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or invoke_case(item)),
                    scorer_loader=lambda: (_ for _ in ()).throw(AssertionError("scorer before receipt")),
                )
                self.assertEqual(calls, ["unit-000"])

    def test_ledger_tamper_mode_and_symlink_fail_closed_without_key_file(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state = root / "state"
            state.mkdir(mode=0o700)
            key = b"k" * 32
            runner._with_ledger(
                state,
                key,
                lambda value, ignored: value.update({"schema_version": "test"}),
            )
            ledger = state / "ledger.json"
            tampered = json.loads(ledger.read_bytes())
            tampered["schema_version"] = "tampered"
            ledger.write_bytes(runner.canonical(tampered))
            with self.assertRaises(Exception):
                runner._with_ledger(state, key, lambda value, ignored: None)
            ledger.write_bytes(runner.canonical({"schema_version": "test"}))
            os.chmod(ledger, 0o644)
            with self.assertRaises(Exception):
                runner._with_ledger(state, key, lambda value, ignored: None)
            os.chmod(ledger, 0o600)
            external = root / "external-ledger"
            external.write_bytes(ledger.read_bytes())
            ledger.unlink()
            ledger.symlink_to(external)
            with self.assertRaises(Exception):
                runner._with_ledger(state, key, lambda value, ignored: None)
            self.assertFalse((state / "hmac.key").exists())

    def test_transport_capsule_body_or_metadata_tamper_fails_hmac_reconstruction(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            private = Path(name)
            unit_id = "capsule-tamper"
            key = b"z" * 32
            identity = {
                "scheduled_unit_id": unit_id,
                "request_id": "request-tamper",
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            runner._write_transport_capsule(
                private,
                unit_id,
                {"body": b"body", "http_status": 200, "provider_request_id": "req"},
                key,
                identity,
            )
            body_path = private / (runner._capsule_stem(unit_id) + ".body")
            body_path.write_bytes(b"changed")
            with self.assertRaises(Exception):
                runner._read_transport_capsule(private, unit_id, key, identity)

    def test_transport_capsule_cannot_be_swapped_between_unit_filenames(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as name:
            private = Path(name)
            key = b"y" * 32
            identity_one = {
                "scheduled_unit_id": "unit-one",
                "request_id": "request-one",
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            identity_two = {
                "scheduled_unit_id": "unit-two",
                "request_id": "request-two",
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 1,
            }
            runner._write_transport_capsule(
                private, "unit-one",
                {"body": b"body", "http_status": 200, "provider_request_id": None},
                key, identity_one,
            )
            stem_one = runner._capsule_stem("unit-one")
            stem_two = runner._capsule_stem("unit-two")
            (private / (stem_two + ".body")).write_bytes(
                (private / (stem_one + ".body")).read_bytes()
            )
            (private / (stem_two + ".json")).write_bytes(
                (private / (stem_one + ".json")).read_bytes()
            )
            with self.assertRaises(Exception):
                runner._read_transport_capsule(private, "unit-two", key, identity_two)

    def test_reserved_without_capsule_resumes_without_dispatch(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = [
            {
                "scheduled_unit_id": f"unit-{index:03d}",
                "prompt": f"private-prompt-{index}",
                "payload_sha256": runner.sha256(f"private-prompt-{index}".encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            for index in range(288)
        ]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            with self.assertRaises(SystemExit):
                runner._execute_schedule_test_core(
                    contract=contract,
                    plan=plan,
                    state_root=state,
                    output_root=output,
                    approval_consume=lambda scope: {"approved": True},
                    invoke=lambda item: (_ for _ in ()).throw(SystemExit(3)),
                    scorer_loader=lambda: {"unexpected": True},
                )
            calls: list[str] = []
            result = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: (
                    {"approved": True}
                    if scope["batch_id"] == "batch-2"
                    else (_ for _ in ()).throw(AssertionError("reapproval"))
                ),
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or b"unexpected"),
                scorer_loader=lambda: {"unexpected": True},
            )
            self.assertEqual(calls, [])
            self.assertEqual(result["status"], "provider_receipts_sealed_pending_scoring")

    def test_reserved_with_sealed_capsule_reconstructs_without_duplicate_call(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = [
            {
                "scheduled_unit_id": f"unit-{index:03d}",
                "prompt": f"private-prompt-{index}",
                "payload_sha256": runner.sha256(f"private-prompt-{index}".encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": 0,
            }
            for index in range(288)
        ]
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg_resume",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            batches = runner.build_batch_plans(plan)
            reservation = runner.calculate_worst_case_reservation(
                contract=contract, batches=batches
            )
            plan_sha = runner._plan_digest(batches)
            # The core derives bytes from this test-only seed; seed the same
            # durable state and capsule that a crash would leave behind.
            ledger_key = __import__("hashlib").sha256(
                b"contextguard/p3-v3-test-ledger/v1\0"
                + runner.canonical({"contract": contract, "plan_sha256": plan_sha})
            ).digest()
            runner._private_dir(output / "private")
            def init(state_value, key):
                runner._initialize_ledger(
                    state_value, contract=contract, batches=batches,
                    plan_sha256=plan_sha, reservation=reservation,
                )
            runner._with_ledger(state, ledger_key, init)
            runner._authorize_batch(
                state, ledger_key, batches[0],
                {"acknowledged": True},
            )
            runner._reserve_unit(state, ledger_key, plan[0]["scheduled_unit_id"])
            capsule_identity = {
                **plan[0],
                "request_id": runner._request_identity(plan[0]),
            }
            runner._write_transport_capsule(
                output / "private", plan[0]["scheduled_unit_id"],
                {"body": response, "http_status": 200, "provider_request_id": "private"},
                ledger_key,
                capsule_identity,
            )
            calls: list[str] = []
            result = runner._execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state,
                output_root=output,
                approval_consume=lambda scope: (
                    {"approved": True}
                    if scope["batch_id"] == "batch-2"
                    else (_ for _ in ()).throw(AssertionError("reapproval"))
                ),
                invoke=lambda item: (calls.append(item["scheduled_unit_id"]) or {
                    "body": response, "http_status": 200, "provider_request_id": "private"
                }),
                scorer_loader=lambda: (lambda capsules, prepared: {
                    "failed_units": 0, "passed_units": len(prepared),
                    "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                    "total_units": len(prepared), "status": "complete"
                }),
            )
            self.assertEqual(result["status"], "completed")
            self.assertNotIn(plan[0]["scheduled_unit_id"], calls)
            self.assertEqual(len(calls), 287)

    def test_authorized_run_consumes_exact_external_envelopes_and_records_digests(self) -> None:
        runner = load_runner()
        contract = json.loads(CONTRACT.read_bytes())
        plan = []
        for index in range(288):
            prompt = f"authorized-prompt-{index}"
            item = {
                "scheduled_unit_id": f"authorized-unit-{index:03d}",
                "prompt": prompt,
                "payload_sha256": runner.sha256(prompt.encode()),
                "task_id": "task",
                "arm_id": "a000",
                "repetition": index % 3,
            }
            item["request_id"] = runner._request_identity(item)
            plan.append(item)
        verification_key = bytes(range(32))
        registry_key = bytes(range(32, 64))
        response = json.dumps({
            "content": [{"text": "READY", "type": "text"}],
            "id": "msg_authorized",
            "model": "claude-sonnet-5",
            "role": "assistant",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "type": "message",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }, separators=(",", ":"), sort_keys=True).encode()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            state, output = root / "state", root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            batches = runner.build_batch_plans(plan)
            runner_sha = runner._runner_identity()
            approval_module = runner._load_bound_approval_module(
                contract=contract, repo_root=ROOT
            )
            approvals = []
            now = int(__import__("time").time())
            for index, batch in enumerate(batches):
                scope = runner.build_external_approval_scope(
                    contract=contract,
                    batch=batch,
                    plan_sha256=runner._plan_digest(batches),
                    runner_sha256=runner_sha,
                    output_root=output,
                )
                approvals.append(approval_module.create_approval(
                    scope=scope,
                    issued_at=now - 1,
                    expires_at=now + 300,
                    nonce=f"{index + 5:064x}",
                    revocation_handle=f"{index + 7:064x}",
                    signing_key=verification_key,
                ))
            with mock.patch.object(runner, "prepare_live_plan", return_value=plan), \
                mock.patch.object(runner, "_migrate_single_verified_capsule"), \
                mock.patch.object(runner, "invoke_anthropic", return_value={
                    "body": response,
                    "http_status": 200,
                    "provider_request_id": "req-private",
                }), \
                mock.patch.object(runner, "_bound_scorer_loader", return_value=lambda: (
                    lambda capsules, prepared: {
                        "failed_units": 0,
                        "passed_units": len(prepared),
                        "scorer_artifact_sha256": runner.EXPECTED_SCORER_SHA256,
                        "total_units": len(prepared),
                        "status": "complete",
                    }
                )):
                result = runner.run_live_authorized(
                    contract_path=CONTRACT,
                    repo_root=ROOT,
                    corpus_root=root,
                    output_root=output,
                    state_root=state,
                    previous_output_root=root,
                    previous_state_root=root,
                    approvals=approvals,
                    verification_key=verification_key,
                    registry_key=registry_key,
                    api_key=b"sk-ant-api03-test-secret-never-publish",
                )
            self.assertEqual(result["status"], "completed")
            ledger = json.loads((state / "ledger.json").read_bytes())
            for batch in ledger["batches"].values():
                self.assertIn("nonce_sha256", batch["authorization"])
                self.assertIn("scope_sha256", batch["authorization"])


if __name__ == "__main__":
    unittest.main()
