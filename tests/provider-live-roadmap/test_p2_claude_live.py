from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "research" / "provider-live-roadmap" / "p2" / "v1" / "live_runner.py"
CONTRACT_PATH = ROOT / "research" / "provider-live-roadmap" / "p2" / "v1" / "contract.json"
RESULT_PATH = ROOT / "research" / "provider-live-roadmap" / "p2" / "v1" / "result.json"
USAGE_ATTEMPT_RESULT_PATH = (
    ROOT
    / "research"
    / "provider-live-roadmap"
    / "p2"
    / "v1"
    / "usage-attempt-result.json"
)
USAGE_MEASUREMENT_RESULT_PATH = (
    ROOT
    / "research"
    / "provider-live-roadmap"
    / "p2"
    / "v1"
    / "usage-measurement-result.json"
)
G5_SCHEDULE = ROOT / "research" / "provider-free-roadmap" / "g5" / "v1" / "schedule.json"
G5_OBSERVER_SCHEMA = (
    ROOT
    / "research"
    / "provider-free-roadmap"
    / "g5"
    / "v1"
    / "schemas"
    / "authoritative-observation.schema.json"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("p2_claude_live_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load P2 live runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fake_public_inputs(schedule: dict) -> tuple[dict, dict]:
    tasks: dict[str, dict] = {}
    packs: dict[tuple[str, str], dict] = {}
    for block in schedule["blocks"]:
        task_id = block["task_id"]
        tasks.setdefault(
            task_id,
            {
                "prompt": f"Return the answer for {task_id}.",
                "stratum": block["stratum"],
                "task_id": task_id,
            },
        )
        for unit in block["units"]:
            key = (task_id, unit["arm"])
            rendered = f"pack:{task_id}:{unit['arm']}\n".encode("utf-8")
            packs.setdefault(
                key,
                {
                    "cost_microunits": len(rendered) + 256,
                    "manifest_sources": [
                        {
                            "path": "public.txt",
                            "slice": {"bytes": 6, "sha256": sha256(b"public")},
                            "source": {"bytes": 6, "sha256": sha256(b"public")},
                        }
                    ],
                    "packer_receipt_sha256": sha256(rendered + b"receipt"),
                    "rendered_pack": rendered,
                    "retrieval_plan": {"steps": []},
                    "selected_paths": ["public.txt"],
                },
            )
    return tasks, packs


def fake_claude_result(model: str, answer: str, *, cost_usd: float = 0.01) -> bytes:
    value = {
        "is_error": False,
        "num_turns": 1,
        "result": answer,
        "subtype": "success",
        "total_cost_usd": cost_usd,
        "type": "result",
        "usage": {
            "input_tokens": 11,
            "output_tokens": 3,
        },
        "modelUsage": {
            model: {
                "cacheCreationInputTokens": 0,
                "cacheReadInputTokens": 0,
                "canonicalModel": model,
                "inputTokens": 11,
                "outputTokens": 3,
                "provider": "firstParty",
            }
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class P2ClaudeLiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()
        cls.contract_raw = CONTRACT_PATH.read_bytes()
        cls.contract = json.loads(cls.contract_raw)
        cls.schedule_raw = G5_SCHEDULE.read_bytes()
        cls.schedule = json.loads(cls.schedule_raw)
        cls.schema_raw = G5_OBSERVER_SCHEMA.read_bytes()

    def test_contract_pins_exact_model_candidate_schedule_caps_and_observer(self) -> None:
        contract = self.contract
        self.assertEqual(contract["schema_version"], "contextguard.p2-claude-live-contract/v1")
        self.assertEqual(
            contract["approval_boundary"]["module_sha256"],
            sha256(
                (
                    ROOT
                    / "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py"
                ).read_bytes()
            ),
        )
        self.assertEqual(contract["provider"], {
            "id": "anthropic-first-party",
            "model_id": "claude-sonnet-5",
        })
        self.assertEqual(contract["limits"], {
            "call_cap": 240,
            "currency": "USD",
            "per_call_budget_usd": "0.35",
            "spend_cap_usd": "100.00",
            "timeout_seconds": 120,
        })
        self.assertEqual(contract["observer"], {
            "id": "claude-code-print-json-v1",
            "phase": "P2",
            "schema": "contextguard.g5-authoritative-observation/v1",
            "surface": "claude-print-json/v1",
        })
        self.assertEqual(contract["g5"]["schedule_sha256"], sha256(self.schedule_raw))
        self.assertEqual(contract["g5"]["observation_schema_sha256"], sha256(self.schema_raw))
        self.assertEqual(contract["source_candidate"]["commit_sha"], "540c6e02222f25346ca9c797197882cebbe5331d")
        self.assertEqual(contract["source_candidate"]["artifact_ids"], ["9163551917", "9163551685"])
        self.runner.validate_contract(contract, repo_root=ROOT)

    def test_contract_rejects_removed_claims_and_extra_binding_fields(self) -> None:
        mutations = []

        missing_claim = copy.deepcopy(self.contract)
        del missing_claim["claims"]["token_savings"]
        mutations.append(missing_claim)

        for group_name in ("approval_boundary", "g3", "g5"):
            extra_field = copy.deepcopy(self.contract)
            extra_field[group_name]["unapproved_extension"] = "0" * 64
            mutations.append(extra_field)

        for mutated in mutations:
            with self.subTest(group=next(
                name for name in ("claims", "approval_boundary", "g3", "g5")
                if mutated[name] != self.contract[name]
            )):
                with self.assertRaises(self.runner.LiveRunError):
                    self.runner.validate_contract(mutated, repo_root=ROOT)

    def test_contract_rejects_synchronized_approval_module_rewrite(self) -> None:
        bound_paths = (
            "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py",
            "packages/context-guard-receipt/schemas/external-approval.schema.json",
            "packages/context-guard-receipt/python/context_guard_receipt/phase_evaluation.py",
            "research/provider-free-roadmap/g3/freeze-lock.json",
            "research/provider-free-roadmap/g3/v1/manifest.json",
            "research/provider-free-roadmap/g3/v1/rehearse.py",
            "research/provider-free-roadmap/g5/freeze-lock.json",
            "research/provider-free-roadmap/g5/v1/schedule.json",
            "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
            "research/provider-free-roadmap/g5/v1/verify.py",
        )
        with tempfile.TemporaryDirectory() as name:
            copied_root = Path(name)
            for relative in bound_paths:
                destination = copied_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)

            approval_path = copied_root / bound_paths[0]
            approval_path.write_bytes(approval_path.read_bytes() + b"\n")
            mutated = copy.deepcopy(self.contract)
            mutated["approval_boundary"]["module_sha256"] = sha256(
                approval_path.read_bytes()
            )
            with self.assertRaises(self.runner.LiveRunError):
                self.runner.validate_contract(mutated, repo_root=copied_root)

    def test_parser_accepts_dated_first_party_helper_model_key(self) -> None:
        raw = json.loads(fake_claude_result("claude-sonnet-5", "READY"))
        raw["modelUsage"]["claude-haiku-4-5-20251001"] = {
            "cacheCreationInputTokens": 5,
            "cacheReadInputTokens": 7,
            "canonicalModel": "claude-haiku-4-5",
            "inputTokens": 2,
            "outputTokens": 1,
            "provider": "firstParty",
        }
        parsed = self.runner.parse_claude_result(
            json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            expected_model="claude-sonnet-5",
        )
        self.assertEqual(parsed["model_ids"], [
            "claude-haiku-4-5-20251001",
            "claude-sonnet-5",
        ])
        self.assertEqual(parsed["input_tokens"], 25)
        self.assertEqual(parsed["output_tokens"], 4)

        invalid = copy.deepcopy(raw)
        invalid["modelUsage"]["claude-haiku-4-5-nightly"] = invalid[
            "modelUsage"
        ].pop("claude-haiku-4-5-20251001")
        with self.assertRaises(self.runner.LiveRunError):
            self.runner.parse_claude_result(
                json.dumps(
                    invalid, sort_keys=True, separators=(",", ":")
                ).encode("utf-8"),
                expected_model="claude-sonnet-5",
            )

    def test_result_is_descriptive_hash_bound_and_blocks_unsupported_promotion(self) -> None:
        result = json.loads(RESULT_PATH.read_bytes())
        self.assertEqual(
            result["schema_version"], "contextguard.p2-claude-live-result/v1"
        )
        self.assertEqual(result["source"]["contract_sha256"], sha256(self.contract_raw))
        self.assertEqual(result["call_accounting"], {
            "analyzed_blocks": 57,
            "analyzed_units": 228,
            "excluded_blocks": 3,
            "excluded_units": 12,
            "provider_successes": 237,
            "scheduled_calls": 240,
            "transport_errors": 3,
        })
        self.assertEqual(result["usage_metrics"]["status"], "unavailable")
        self.assertTrue(result["p2_gate"]["closed_pack"]["implementation_readiness"])
        self.assertFalse(
            result["p2_gate"]["realistic_fallback"]["implementation_readiness"]
        )
        self.assertIn(
            "protected_omission",
            result["p2_gate"]["realistic_fallback"]["blockers"],
        )
        self.assertFalse(result["p3_gate"]["eligible"])
        self.assertEqual(set(result["claims"].values()), {False})
        self.assertNotIn("path", result["private_evidence"])

    def test_max_usage_attempt_is_hash_bound_and_refuses_arm_comparison(self) -> None:
        result = json.loads(USAGE_ATTEMPT_RESULT_PATH.read_bytes())
        self.assertEqual(
            result["schema_version"],
            "contextguard.p2-claude-max-usage-attempt/v1",
        )
        self.assertEqual(result["source"]["contract_sha256"], sha256(self.contract_raw))
        self.assertEqual(result["call_accounting"], {
            "analyzed_blocks": 0,
            "analyzed_units": 0,
            "excluded_blocks": 60,
            "excluded_units": 240,
            "provider_successes": 11,
            "scheduled_calls": 240,
            "timeouts": 1,
            "transport_errors": 228,
        })
        self.assertEqual(result["usage_measurement"]["comparison_status"], "unavailable")
        self.assertEqual(result["diagnosis"], {
            "corrected_parser_runner_sha256": sha256(RUNNER_PATH.read_bytes()),
            "recorded_transport_errors_are_confirmed_transport_failures": False,
            "root_cause": (
                "a dated first-party helper-model key was rejected when its "
                "canonical model omitted the date suffix"
            ),
            "status": "confirmed",
        })
        self.assertEqual(
            result["usage_measurement"]["reason"],
            "no complete four-arm block remained after transport exclusions",
        )
        self.assertEqual(result["usage_measurement"]["successful_call_tokens"], {
            "input": 61295,
            "output": 252,
            "total": 61547,
        })
        arm_usage_raw = json.dumps(
            result["usage_measurement"]["by_stratum_and_arm"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            sha256(arm_usage_raw),
            "b6c366728466e0c390711732fead2a6a36517d2800ba032e998c8bc86612fa49",
        )
        self.assertEqual(set(result["claims"].values()), {False})
        self.assertFalse(result["p3_gate"]["eligible"])
        self.assertNotIn("path", result["private_evidence"])

    def test_max_usage_measurement_binds_complete_blocks_and_descriptive_deltas(self) -> None:
        result = json.loads(USAGE_MEASUREMENT_RESULT_PATH.read_bytes())
        self.assertEqual(
            result["schema_version"],
            "contextguard.p2-claude-max-usage-measurement/v1",
        )
        self.assertEqual(result["source"], {
            "attempt_kind": "post_outcome_observer_repair_descriptive_only",
            "candidate_commit": "540c6e02222f25346ca9c797197882cebbe5331d",
            "contract_sha256": sha256(self.contract_raw),
            "controller_commit": "64e1b5595aa3377ec551f74150792784b3d5e041",
            "controller_runner_sha256": sha256(RUNNER_PATH.read_bytes()),
        })
        self.assertEqual(result["call_accounting"], {
            "analyzed_blocks": 55,
            "analyzed_units": 220,
            "excluded_blocks": 5,
            "excluded_units": 20,
            "provider_successes": 234,
            "scheduled_calls": 240,
            "transport_errors": 6,
        })
        closed = result["usage_measurement"]["closed_pack"]
        self.assertEqual(closed["complete_blocks"], 30)
        self.assertEqual(closed["arms"]["ordinary"]["total_tokens"], 196552)
        self.assertEqual(closed["arms"]["combined"]["total_tokens"], 182603)
        self.assertEqual(closed["arms"]["ordinary"]["correct"], 30)
        self.assertEqual(closed["arms"]["combined"]["correct"], 30)
        self.assertEqual(closed["contrasts"]["combined_minus_ordinary"], {
            "delta_tokens": -13949,
            "savings_basis_points": 710,
            "savings_percent_decimal": "7.096850",
        })
        self.assertFalse(closed["paired_sensitivity"]["inference_claim_allowed"])
        self.assertLess(
            closed["paired_sensitivity"]["signed_cluster_minimum"]["numerator"],
            0,
        )
        self.assertGreater(
            closed["paired_sensitivity"]["signed_cluster_maximum"]["numerator"],
            0,
        )
        realistic = result["usage_measurement"]["realistic_fallback"]
        self.assertEqual(realistic["complete_blocks"], 25)
        self.assertEqual(realistic["arms"]["ordinary"]["correct"], 0)
        self.assertEqual(realistic["arms"]["combined"]["correct"], 10)
        self.assertEqual(realistic["contrasts"]["combined_minus_ordinary"], {
            "delta_tokens": 1072,
            "savings_basis_points": -64,
            "savings_percent_decimal": "-0.637534",
        })
        self.assertFalse(realistic["paired_sensitivity"]["inference_claim_allowed"])
        self.assertEqual(set(result["claims"].values()), {False})
        self.assertFalse(result["p3_gate"]["eligible"])
        self.assertNotIn("path", result["private_evidence"])

    def test_one_use_scope_binds_every_request_environment_runtime_and_output(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        plan = self.runner.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        executable = Path("/bin/echo")
        environment = {
            "HOME": "/private/tmp/home",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp",
        }
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            os.chmod(root, 0o700)
            scope = self.runner.build_approval_scope(
                contract=self.contract,
                executable=executable,
                executable_sha256=sha256(executable.read_bytes()),
                environment=environment,
                output_root=root,
                plan=plan,
            )
        self.assertEqual(scope["provider"]["model_id"], "claude-sonnet-5")
        self.assertEqual(scope["limits"]["call_cap"], 240)
        self.assertEqual(scope["limits"]["spend_cap"], "100.00")
        self.assertEqual(scope["runtime"]["environment_sha256"], sha256(self.runner.canonical(environment)))
        self.assertEqual(scope["runtime"]["argv_sha256"], self.runner.argv_plan_sha256(
            contract=self.contract, executable=executable, plan=plan
        ))
        mutated = copy.deepcopy(plan)
        mutated[0]["prompt"] += " drift"
        self.assertNotEqual(
            scope["runtime"]["argv_sha256"],
            self.runner.argv_plan_sha256(contract=self.contract, executable=executable, plan=mutated),
        )

    def test_authorized_materializer_is_one_use_and_replay_fails_before_action(self) -> None:
        module = self.runner.load_approval_boundary(self.contract, repo_root=ROOT)
        key = bytes(range(32))
        registry_key = bytes(reversed(range(32)))
        now = int(__import__("time").time())
        tasks, packs = fake_public_inputs(self.schedule)
        plan = self.runner.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            os.chmod(root, 0o700)
            state = root / "state"
            output = root / "output"
            state.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            scope = self.runner.build_approval_scope(
                contract=self.contract,
                executable=Path("/bin/echo"),
                executable_sha256=sha256(Path("/bin/echo").read_bytes()),
                environment={
                    "HOME": "/private/tmp/home", "LANG": "C.UTF-8",
                    "PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp",
                },
                output_root=output,
                plan=plan,
            )
            packet = module.create_approval(
                scope=scope,
                issued_at=now - 1,
                expires_at=now + 3600,
                nonce="1" * 64,
                revocation_handle="2" * 64,
                signing_key=key,
            )
            calls: list[int] = []
            self.assertEqual(
                self.runner.consume_authorized(
                    contract=self.contract,
                    approval=packet,
                    requested_scope=scope,
                    verification_key=key,
                    registry_key=registry_key,
                    state_root=state,
                    materialize=lambda _scope: calls.append(1) or "ok",
                    repo_root=ROOT,
                ),
                "ok",
            )
            with self.assertRaises(Exception):
                self.runner.consume_authorized(
                    contract=self.contract,
                    approval=packet,
                    requested_scope=scope,
                    verification_key=key,
                    registry_key=registry_key,
                    state_root=state,
                    materialize=lambda _scope: calls.append(2),
                    repo_root=ROOT,
                )
        self.assertEqual(calls, [1])

    def test_request_plan_is_exactly_the_frozen_240_units_and_hash_bound(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        plan = self.runner.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        self.assertEqual(len(plan), 240)
        self.assertEqual(
            [item["scheduled_unit_id"] for item in plan],
            [
                unit["scheduled_unit_id"]
                for block in self.schedule["blocks"]
                for unit in sorted(block["units"], key=lambda value: value["assigned_order"])
            ],
        )
        self.assertEqual(len({item["request_id"] for item in plan}), 240)
        self.assertEqual(len({item["payload_sha256"] for item in plan}), 24)
        self.assertTrue(all("public.txt" not in item["prompt"] for item in plan))
        self.assertTrue(all("Return exactly one answer token" in item["prompt"] for item in plan))
        self.assertEqual(
            self.runner.request_plan_sha256(plan),
            self.runner.request_plan_sha256(copy.deepcopy(plan)),
        )

    def test_real_frozen_capture_exposes_only_24_public_packs_until_scorer_load(self) -> None:
        capture = self.runner.capture_frozen_packs(contract=self.contract, repo_root=ROOT)
        self.assertEqual(len(capture.tasks), 6)
        self.assertEqual(len(capture.packs), 24)
        self.assertEqual(capture.scorer_load_count, 0)
        self.assertTrue(all(pack["rendered_pack"] for pack in capture.packs.values()))
        self.assertTrue(all("expected_output" not in task for task in capture.tasks.values()))
        scorer = capture.load_scorer()
        self.assertEqual(capture.scorer_load_count, 1)
        self.assertEqual(set(scorer["answers"]), set(capture.tasks))
        self.assertEqual(set(scorer["oracle"]), set(capture.tasks))

    def test_result_parser_rejects_model_drift_error_and_oversize_without_echo(self) -> None:
        parsed = self.runner.parse_claude_result(
            fake_claude_result("claude-sonnet-5", "ANSWER"),
            expected_model="claude-sonnet-5",
        )
        self.assertEqual(parsed["answer"], "ANSWER")
        self.assertEqual(parsed["input_tokens"], 11)
        self.assertEqual(parsed["output_tokens"], 3)

        multi_model = json.loads(fake_claude_result("claude-sonnet-5", "ANSWER"))
        multi_model["modelUsage"]["claude-haiku-helper"] = {
            "cacheCreationInputTokens": 1,
            "cacheReadInputTokens": 4,
            "canonicalModel": "claude-haiku-helper",
            "inputTokens": 2,
            "outputTokens": 1,
            "provider": "firstParty",
        }
        parsed_multi = self.runner.parse_claude_result(
            json.dumps(multi_model, sort_keys=True, separators=(",", ":")).encode(),
            expected_model="claude-sonnet-5",
        )
        self.assertEqual(parsed_multi["input_tokens"], 18)
        self.assertEqual(parsed_multi["output_tokens"], 4)
        self.assertEqual(
            parsed_multi["model_ids"], ["claude-haiku-helper", "claude-sonnet-5"]
        )

        cases = [
            fake_claude_result("claude-sonnet-4", "MODEL_DRIFT_MARKER"),
            json.dumps({"is_error": True, "result": "ERROR_MARKER"}).encode(),
            b"x" * (self.runner.MAX_CLAUDE_OUTPUT_BYTES + 1),
        ]
        for raw in cases:
            with self.subTest(size=len(raw)):
                with self.assertRaises(self.runner.LiveRunError) as caught:
                    self.runner.parse_claude_result(raw, expected_model="claude-sonnet-5")
                self.assertNotIn("MARKER", str(caught.exception))

    def test_all_provider_calls_finish_and_seal_before_scorer_load(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        plan = self.runner.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        calls: list[str] = []
        scorer_loaded_at: list[int] = []

        def invoke(item: dict) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return fake_claude_result("claude-sonnet-5", f"answer-{item['task_id']}")

        expected = {task_id: f"answer-{task_id}" for task_id in tasks}

        def load_scorer() -> dict[str, str]:
            scorer_loaded_at.append(len(calls))
            return expected

        with tempfile.TemporaryDirectory() as name:
            output_root = Path(name)
            os.chmod(output_root, 0o700)
            evidence = self.runner.execute_schedule(
                contract=self.contract,
                schedule=self.schedule,
                observation_schema_bytes=self.schema_raw,
                tasks=tasks,
                packs=packs,
                output_root=output_root,
                invoke=invoke,
                scorer_loader=load_scorer,
            )
            self.assertFalse((output_root / "raw").exists())

        self.assertEqual(len(calls), 240)
        self.assertEqual(scorer_loaded_at, [240])
        self.assertEqual(len(evidence["observations"]), 240)
        self.assertEqual(len(evidence["sealed_runs"]), 240)
        self.assertTrue(all(row["correctness"]["outcome"] == "correct" for row in evidence["observations"]))
        self.assertNotIn("answer-train", json.dumps(evidence["sealed_runs"]))
        self.assertEqual(
            evidence["summary"],
            self.runner.summarize_with_frozen_g5(
                evidence["observations"],
                schedule_bytes=self.schedule_raw,
                schema_bytes=self.schema_raw,
                repo_root=ROOT,
            ),
        )

    def test_aggregate_spend_overrun_stops_before_the_next_provider_call(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        limited = copy.deepcopy(self.contract)
        limited["limits"]["spend_cap_usd"] = "0.015"
        calls: list[str] = []
        scorer_calls: list[int] = []

        def invoke(item: dict) -> bytes:
            calls.append(item["scheduled_unit_id"])
            return fake_claude_result(
                "claude-sonnet-5", f"answer-{item['task_id']}", cost_usd=0.01
            )

        with tempfile.TemporaryDirectory() as name:
            output_root = Path(name)
            os.chmod(output_root, 0o700)
            with self.assertRaises(self.runner.LiveRunError) as caught:
                self.runner.execute_schedule(
                    contract=limited,
                    schedule=self.schedule,
                    observation_schema_bytes=self.schema_raw,
                    tasks=tasks,
                    packs=packs,
                    output_root=output_root,
                    invoke=invoke,
                    scorer_loader=lambda: scorer_calls.append(len(calls)),
                )

        self.assertEqual(str(caught.exception), "spend_cap_exceeded")
        self.assertEqual(len(calls), 2)
        self.assertEqual(scorer_calls, [])

    def test_phase_record_promotes_only_closed_pack_and_keeps_graph_diagnostic(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        oracle = {
            task_id: {
                "required_paths": ["public.txt"] if task["stratum"] == "closed_pack" else ["missing.py"]
            }
            for task_id, task in tasks.items()
        }
        for (task_id, arm), pack in packs.items():
            if tasks[task_id]["stratum"] == "realistic_fallback":
                pack["retrieval_plan"] = {
                    "steps": [{
                        "path": "missing.py",
                        "slice": {"bytes": 7, "sha256": sha256(b"missing")},
                        "source": {"bytes": 7, "sha256": sha256(b"missing")},
                    }]
                }

        records = self.runner.build_p2_phase_records(
            observed_at=100,
            retention_seconds=60,
            tasks=tasks,
            packs=packs,
            oracle=oracle,
        )
        closed = self.runner.evaluate_phase_record(records["closed_pack"], repo_root=ROOT)
        graph = self.runner.evaluate_phase_record(records["realistic_fallback"], repo_root=ROOT)
        self.assertTrue(closed["implementation_readiness"])
        self.assertFalse(closed["activation_authority"])
        self.assertFalse(graph["implementation_readiness"])
        self.assertIn("protected_omission", graph["blockers"])

    def test_public_evidence_is_minimized_hash_bound_and_rejects_nested_raw_fields(self) -> None:
        observations = [{"scheduled_unit_id": f"unit-{index}"} for index in range(240)]
        sealed = [
            {
                "scheduled_unit_id": f"unit-{index}",
                "client_cost_micro_usd": 1,
                "model_ids": ["claude-sonnet-5"],
                "payload_sha256": "3" * 64,
                "request_id": f"request-{index}",
                "response_bytes": 1,
                "response_sha256": "4" * 64,
            }
            for index in range(240)
        ]
        for item in sealed:
            item["seal_sha256"] = sha256(self.runner.canonical(item))
        execution = {
            "observations": observations,
            "request_plan_sha256": "1" * 64,
            "sealed_runs": sealed,
            "summary": {"accounting": {"randomized_units": 240}},
            "total_client_cost_micro_usd": 240,
        }
        phase_records = {
            "closed_pack": {"schema_version": "contextguard.phase-evaluation.p2/v1"},
            "realistic_fallback": {"schema_version": "contextguard.phase-evaluation.p2/v1"},
        }
        phase_results = {
            "closed_pack": {"implementation_readiness": True},
            "realistic_fallback": {"implementation_readiness": False},
        }
        evidence = self.runner.build_public_evidence(
            contract_raw=self.contract_raw,
            execution=execution,
            phase_records=phase_records,
            phase_results=phase_results,
            executable_sha256="2" * 64,
        )
        # This synthetic shape checks publication minimization and local
        # commitments only; the full frozen G5 recomputation is covered by the
        # 240-observation execution test above.
        self.runner.validate_public_evidence(
            evidence, contract_raw=self.contract_raw, recompute=False
        )
        serialized = json.dumps(evidence).lower()
        self.assertNotIn('"prompt"', serialized)
        self.assertNotIn('"answer"', serialized)
        self.assertNotIn('"session_id"', serialized)

        tampered = copy.deepcopy(evidence)
        tampered["sealed_runs"][0]["nested"] = {"prompt": "PRIVATE_MARKER"}
        with self.assertRaises(self.runner.LiveRunError) as caught:
            self.runner.validate_public_evidence(
                tampered, contract_raw=self.contract_raw, recompute=False
            )
        self.assertNotIn("PRIVATE_MARKER", str(caught.exception))

    def test_authorized_orchestrator_publishes_only_replayable_minimized_evidence(self) -> None:
        tasks, packs = fake_public_inputs(self.schedule)
        expected_answers = {
            task_id: f"answer-{task_id}" for task_id in tasks
        }
        oracle = {}
        for task_id, task in tasks.items():
            required_path = (
                "public.txt" if task["stratum"] == "closed_pack" else "missing.py"
            )
            oracle[task_id] = {
                "expected_output": expected_answers[task_id],
                "required_paths": [required_path],
            }
            if task["stratum"] == "realistic_fallback":
                for arm in ("ordinary", "adaptive_only", "symbol_only", "combined"):
                    packs[(task_id, arm)]["retrieval_plan"] = {
                        "steps": [{
                            "path": required_path,
                            "slice": {"bytes": 7, "sha256": sha256(b"missing")},
                            "source": {"bytes": 7, "sha256": sha256(b"missing")},
                        }]
                    }

        class FakeCapture:
            scorer_load_count = 0

            def __init__(self, public_tasks: dict, public_packs: dict) -> None:
                self.tasks = public_tasks
                self.packs = public_packs

            def load_scorer(self) -> dict:
                self.scorer_load_count += 1
                return {
                    "answers": expected_answers,
                    "oracle": oracle,
                    "score": {"status": "fixture"},
                }

        capture = FakeCapture(tasks, packs)
        plan = self.runner.build_request_plan(
            contract=self.contract,
            schedule=self.schedule,
            tasks=tasks,
            packs=packs,
        )
        executable = Path("/bin/echo")
        executable_digest = sha256(executable.read_bytes())
        environment = {
            "HOME": "/private/tmp/home",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp",
        }
        boundary = self.runner.load_approval_boundary(self.contract, repo_root=ROOT)
        signing_key = bytes(range(32))
        registry_key = bytes(reversed(range(32)))
        now = int(__import__("time").time())
        calls: list[str] = []

        original_capture = self.runner.capture_frozen_packs
        original_resolve = self.runner.resolve_claude_runtime
        original_invoke = self.runner.invoke_claude
        try:
            self.runner.capture_frozen_packs = lambda **_kwargs: capture
            self.runner.resolve_claude_runtime = lambda *_args, **_kwargs: (
                executable, environment, executable_digest
            )

            def invoke(item: dict, **_kwargs) -> bytes:
                calls.append(item["scheduled_unit_id"])
                return fake_claude_result(
                    "claude-sonnet-5", expected_answers[item["task_id"]]
                )

            self.runner.invoke_claude = invoke
            with tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                os.chmod(root, 0o700)
                output = root / "output"
                state = root / "state"
                output.mkdir(mode=0o700)
                state.mkdir(mode=0o700)
                scope = self.runner.build_approval_scope(
                    contract=self.contract,
                    executable=executable,
                    executable_sha256=executable_digest,
                    environment=environment,
                    output_root=output,
                    plan=plan,
                )
                approval = boundary.create_approval(
                    scope=scope,
                    issued_at=now - 1,
                    expires_at=now + 3600,
                    nonce="a" * 64,
                    revocation_handle="b" * 64,
                    signing_key=signing_key,
                )
                result = self.runner.run_live_authorized(
                    contract_path=CONTRACT_PATH,
                    repo_root=ROOT,
                    output_root=output,
                    state_root=state,
                    approval=approval,
                    verification_key=signing_key,
                    registry_key=registry_key,
                    executable=executable,
                )
                evidence_path = output / "p2-live-evidence.json"
                evidence = json.loads(evidence_path.read_bytes())
                self.runner.validate_public_evidence(
                    evidence, contract_raw=self.contract_raw, repo_root=ROOT
                )
                self.assertEqual(oct(evidence_path.stat().st_mode & 0o777), "0o600")
                self.assertFalse((output / "raw").exists())
                self.assertEqual(result["status"], "p2_shadow_recorded")
                self.assertTrue(result["p2_closed_pack_ready"])
                self.assertFalse(result["p2_realistic_fallback_ready"])

                with self.assertRaises(Exception):
                    self.runner.run_live_authorized(
                        contract_path=CONTRACT_PATH,
                        repo_root=ROOT,
                        output_root=output,
                        state_root=state,
                        approval=approval,
                        verification_key=signing_key,
                        registry_key=registry_key,
                        executable=executable,
                    )
        finally:
            self.runner.capture_frozen_packs = original_capture
            self.runner.resolve_claude_runtime = original_resolve
            self.runner.invoke_claude = original_invoke

        self.assertEqual(len(calls), 240)
        self.assertEqual(capture.scorer_load_count, 1)

    def test_direct_mutable_execution_refuses_before_provider_access(self) -> None:
        reached = False

        def forbidden(*_args, **_kwargs):
            nonlocal reached
            reached = True
            raise AssertionError("provider reached")

        original = self.runner.subprocess.Popen
        self.runner.subprocess.Popen = forbidden
        try:
            self.assertEqual(self.runner.main([]), 2)
        finally:
            self.runner.subprocess.Popen = original
        self.assertFalse(reached)


if __name__ == "__main__":
    unittest.main()
