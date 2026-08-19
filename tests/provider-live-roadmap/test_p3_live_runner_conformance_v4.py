from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ("v3", "v4")


def load_runner(version: str):
    path = ROOT / f"research/provider-live-roadmap/p3-api/{version}/live_runner.py"
    spec = importlib.util.spec_from_file_location(
        f"contextguard_live_conformance_{version}", path
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"{version} runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def v4_selection(runner, prompt: str) -> dict[str, object]:
    prompt_raw = prompt.encode("utf-8")
    return {
        "decision_sha256": "a" * 64,
        "ordinary_prompt_ceiling_bytes": 14678,
        "policy": runner.EXPECTED_POLICY_IDENTITY,
        "requested": {
            "arm_id": "a111",
            "cell_id": "requests_boundary_hardening:a111",
            "prompt_bytes": 22436,
            "prompt_sha256": "c" * 64,
        },
        "selected": {
            "arm_id": "a110",
            "cell_id": "requests_boundary_hardening:a110",
            "prompt_bytes": len(prompt_raw),
            "prompt_sha256": runner.sha256(prompt_raw),
        },
    }


def plan_for(runner, version: str) -> tuple[list[dict[str, object]], object | None]:
    prompt = "conformance provider input"
    selection = v4_selection(runner, prompt) if version == "v4" else None
    plan: list[dict[str, object]] = []
    for index in range(288):
        item: dict[str, object] = {
            "scheduled_unit_id": f"{version}-conformance-{index:03d}",
            "prompt": prompt,
            "payload_sha256": runner.sha256(prompt.encode("utf-8")),
            "task_id": "requests_boundary_hardening" if version == "v4" else "task",
            "arm_id": "a111" if version == "v4" else "a000",
            "repetition": index % 3,
        }
        if selection is not None:
            item["selection_identity"] = selection
        item["request_id"] = runner._request_identity(item)
        plan.append(item)
    return plan, selection


def selection_patches(stack: ExitStack, runner, selection: object | None) -> None:
    if selection is not None:
        stack.enter_context(
            mock.patch.object(
                runner, "_bound_selection_identity", return_value=selection
            )
        )
        stack.enter_context(
            mock.patch.object(
                runner, "_expected_bound_selection", return_value=selection
            )
        )


class LiveRunnerConformanceTests(unittest.TestCase):
    def test_unknown_receipt_and_timeout_stop_after_one_dispatch(self) -> None:
        for version in VERSIONS:
            runner = load_runner(version)
            contract = json.loads(
                (ROOT / f"research/provider-live-roadmap/p3-api/{version}/live-contract.json").read_bytes()
            )
            plan, selection = plan_for(runner, version)
            cases = (
                lambda: {"body": b"{}", "http_status": 500, "provider_request_id": None},
                lambda: (_ for _ in ()).throw(TimeoutError("timeout")),
            )
            for case_index, invoke_case in enumerate(cases):
                with self.subTest(version=version, case=case_index), tempfile.TemporaryDirectory() as name, ExitStack() as stack:
                    selection_patches(stack, runner, selection)
                    root = Path(name)
                    state, output = root / "state", root / "output"
                    state.mkdir(mode=0o700)
                    output.mkdir(mode=0o700)
                    calls: list[str] = []
                    result = runner._execute_schedule_test_core(
                        contract=contract,
                        plan=plan,
                        state_root=state,
                        output_root=output,
                        approval_consume=lambda scope: {"approved": scope["batch_id"]},
                        invoke=lambda item: (
                            calls.append(item["scheduled_unit_id"]) or invoke_case()
                        ),
                        scorer_loader=lambda: (_ for _ in ()).throw(
                            AssertionError("scorer ran before complete receipts")
                        ),
                    )
                    self.assertEqual(calls, [plan[0]["scheduled_unit_id"]])
                    self.assertEqual(
                        result["status"],
                        "provider_receipts_sealed_pending_scoring",
                    )
                    evidence = json.loads(
                        (output / "p3-api-evidence.json").read_bytes()
                    )
                    self.assertEqual(
                        evidence["accounting"]["spend_status"], "unknown"
                    )
                    self.assertEqual(
                        evidence["accounting"]["usage_complete_units"], 0
                    )

    def test_ledger_tamper_and_capsule_substitution_fail_closed(self) -> None:
        for version in VERSIONS:
            runner = load_runner(version)
            plan, selection = plan_for(runner, version)
            with self.subTest(version=version), tempfile.TemporaryDirectory() as name, ExitStack() as stack:
                selection_patches(stack, runner, selection)
                root = Path(name)
                state = root / "state"
                state.mkdir(mode=0o700)
                key = b"k" * 32
                runner._with_ledger(
                    state,
                    key,
                    lambda value, ignored: value.update(
                        {"schema_version": "conformance"}
                    ),
                )
                ledger = state / "ledger.json"
                changed = json.loads(ledger.read_bytes())
                changed["schema_version"] = "tampered"
                ledger.write_bytes(runner.canonical(changed))
                with self.assertRaisesRegex(
                    runner.LiveRunError, "^ledger_tampered$"
                ):
                    runner._with_ledger(
                        state, key, lambda value, ignored: None
                    )

                private = root / "private"
                private.mkdir(mode=0o700)
                first, second = plan[:2]
                runner._write_transport_capsule(
                    private,
                    first["scheduled_unit_id"],
                    {
                        "body": b"body",
                        "http_status": 200,
                        "provider_request_id": None,
                    },
                    key,
                    first,
                )
                first_stem = runner._capsule_stem(first["scheduled_unit_id"])
                second_stem = runner._capsule_stem(second["scheduled_unit_id"])
                for suffix in (".body", ".json"):
                    destination = private / (second_stem + suffix)
                    destination.write_bytes(
                        (private / (first_stem + suffix)).read_bytes()
                    )
                    destination.chmod(0o600)
                metadata_path = private / (second_stem + ".json")
                metadata = json.loads(metadata_path.read_bytes())
                for field in (
                    "arm_id",
                    "repetition",
                    "request_id",
                    "scheduled_unit_id",
                    "task_id",
                ):
                    metadata[field] = second[field]
                if "selection_identity" in metadata:
                    metadata["selection_identity"] = second["selection_identity"]
                metadata_path.write_bytes(runner.canonical(metadata))
                metadata_path.chmod(0o600)
                with self.assertRaisesRegex(
                    runner.LiveRunError, "^transport_capsule_tampered$"
                ):
                    runner._read_transport_capsule(
                        private,
                        second["scheduled_unit_id"],
                        key,
                        second,
                    )

    def test_recovered_over_cap_ledger_refuses_before_approval_or_dispatch(self) -> None:
        for version in VERSIONS:
            runner = load_runner(version)
            contract = json.loads(
                (ROOT / f"research/provider-live-roadmap/p3-api/{version}/live-contract.json").read_bytes()
            )
            plan, selection = plan_for(runner, version)
            with self.subTest(version=version), tempfile.TemporaryDirectory() as name, ExitStack() as stack:
                selection_patches(stack, runner, selection)
                root = Path(name)
                state, output = root / "state", root / "output"
                state.mkdir(mode=0o700)
                output.mkdir(mode=0o700)
                batches = runner.build_batch_plans(plan)
                plan_sha = runner._plan_digest(batches)
                ledger_key = hashlib.sha256(
                    f"contextguard/p3-{version}-test-ledger/v1\0".encode("ascii")
                    + runner.canonical({"contract": contract, "plan_sha256": plan_sha})
                ).digest()
                reservation = runner.calculate_worst_case_reservation(
                    contract=contract, batches=batches
                )
                runner._with_ledger(
                    state,
                    ledger_key,
                    lambda value, key: runner._initialize_ledger(
                        value,
                        contract=contract,
                        batches=batches,
                        plan_sha256=plan_sha,
                        reservation=reservation,
                    ),
                )
                recovered_usage = {
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                    "input_tokens": 20_000_000,
                    "list_price_micro_usd": 40_000_001,
                    "output_tokens": 0,
                    "provider_total_input_tokens": 20_000_000,
                    "provider_total_tokens": 20_000_000,
                }
                recovered_record = runner._terminal_record(
                    item=plan[0],
                    capsule={
                        "body": b"{}",
                        "http_status": 200,
                        "provider_request_id": None,
                    },
                    status="completed",
                    error="none",
                    parsed={"usage": recovered_usage},
                    started=1,
                    ended=2,
                )

                def seed_recovered_terminal(value, key):
                    del key
                    unit_id = plan[0]["scheduled_unit_id"]
                    value["units"][unit_id].update(
                        {"reserved": True, "status": "reserved"}
                    )
                    runner._apply_terminal(
                        value, unit_id=unit_id, record=recovered_record
                    )

                runner._with_ledger(state, ledger_key, seed_recovered_terminal)
                approvals: list[str] = []
                calls: list[str] = []
                runner._execute_schedule_test_core(
                    contract=contract,
                    plan=plan,
                    state_root=state,
                    output_root=output,
                    approval_consume=lambda scope: approvals.append(scope["batch_id"]),
                    invoke=lambda item: calls.append(item["scheduled_unit_id"]),
                    scorer_loader=lambda: (_ for _ in ()).throw(
                        AssertionError("scorer must not run for an over-cap ledger")
                    ),
                )
                self.assertEqual(approvals, [])
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
