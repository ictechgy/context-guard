"""Candidate-blind S002 scheduling/accounting/inference specification.

Authored against the exact S001 merge base.  The test module names real S002
production boundaries directly and contains no alternative implementation of
those boundaries.  Its RED state on the base is intentional: S002 symbols do
not exist there.
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests.s002_contract_harness import (
    EnvironmentSpy,
    ProcessDouble,
    TraceRecorder,
    canonical_json_bytes,
    load_canonical_fixture,
    sha256_hex,
    validate_offline_access_trace,
    validate_s002_diff_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "context-guard-kit" / "benchmark_runner.py"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "s002_direct_behavior_cases_v2.json"
FIXTURE = load_canonical_fixture(FIXTURE_PATH)

S002_BOUNDARIES = (
    "fold_study_attempt_events",
    "_execute_measurement_study",
    "_analyze_measurement_study",
    "_run_measurement_study_slot",
    "classify_success_checker",
    "_study_fold_interrupted_launches",
    "generate_measurement_study_slots",
    "validate_measurement_study_slots",
    "generate_balanced_study_schedule",
    "parse_measurement_terminal_usage",
    "compute_measurement_study_estimators",
    "bootstrap_task_cluster",
    "splitmix64_next",
    "type7_quantile",
    "build_blinded_correction_packets",
    "shuffle_correction_packets",
    "correction_packet_identity_map",
    "correction_packet_permutation",
    "resolve_correction_scores",
    "compute_correction_non_regression",
    "_study_revalidate_terminal_evidence",
    "run_measurement_study_action",
    "build_measurement_study_manifest",
    "validate_measurement_study_manifest",
    "run_measurement_cli_probes",
    "create_measurement_probe_layout",
    "validate_measurement_probe_layout",
)


def _load_runner():
    name = "_s002_candidate_blind_runner"
    loader = importlib.machinery.SourceFileLoader(name, str(RUNNER))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise AssertionError("cannot load canonical benchmark runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def _event(run_id: str, attempt: int, state: str, **extra: object) -> dict[str, object]:
    return {
        "schema_version": "contextguard.bench.study-attempt-index.v1",
        "study_manifest_sha256": "a" * 64,
        "run_id": run_id,
        "attempt": attempt,
        "state": state,
        **extra,
    }


def _complete_attempts(*, treatment_retry: bool = False) -> list[dict[str, object]]:
    attempts: list[dict[str, object]] = []
    for task_index, task in enumerate(FIXTURE["task_ids"]):
        for repetition in range(3):
            for arm in ("baseline", "treatment"):
                attempts.append(
                    {
                        "task": task,
                        "repetition": repetition,
                        "arm": arm,
                        "attempt": 0,
                        "consumed": True,
                        "terminal_status": "success",
                        "usage": {
                            "input_tokens": 10 + task_index,
                            "cache_creation_input_tokens": 2,
                            "cache_read_input_tokens": 3,
                            "output_tokens": 5,
                        },
                    }
                )
                if treatment_retry and arm == "treatment" and task_index == 0 and repetition == 0:
                    attempts[-1]["terminal_status"] = "valid_task_failure_v1"
                    attempts.append(
                        {
                            "task": task,
                            "repetition": repetition,
                            "arm": arm,
                            "attempt": 1,
                            "consumed": True,
                            "terminal_status": "success",
                            "usage": {
                                "input_tokens": 11,
                                "cache_creation_input_tokens": 2,
                                "cache_read_input_tokens": 3,
                                "output_tokens": 5,
                            },
                        }
                    )
    return attempts


def _golden_estimator_attempts() -> list[dict[str, object]]:
    attempts: list[dict[str, object]] = []
    token_differences = FIXTURE["bootstrap"]["token_differences"]
    retry_differences = FIXTURE["bootstrap"]["retry_differences"]
    for task_index, task in enumerate(FIXTURE["task_ids"]):
        for repetition in range(3):
            baseline_retried = retry_differences[task_index][repetition] == -1
            if baseline_retried:
                attempts.extend(
                    [
                        {
                            "task": task, "repetition": repetition, "arm": "baseline",
                            "attempt": 0, "consumed": True,
                            "terminal_status": "valid_task_failure_v1",
                            "usage": {"input_tokens": 50, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0},
                        },
                        {
                            "task": task, "repetition": repetition, "arm": "baseline",
                            "attempt": 1, "consumed": True, "terminal_status": "success",
                            "usage": {"input_tokens": 50, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0},
                        },
                    ]
                )
            else:
                attempts.append(
                    {
                        "task": task, "repetition": repetition, "arm": "baseline",
                        "attempt": 0, "consumed": True, "terminal_status": "success",
                        "usage": {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 0},
                    }
                )
            attempts.append(
                {
                    "task": task, "repetition": repetition, "arm": "treatment",
                    "attempt": 0, "consumed": True, "terminal_status": "success",
                    "usage": {
                        "input_tokens": 100 + token_differences[task_index][repetition],
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "output_tokens": 0,
                    },
                }
            )
    return attempts


def _checker_result(runner, **changes: object):
    fields: dict[str, object] = {
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "output_truncated": False,
        "stdout_bytes": b"",
        "stderr_bytes": b"",
        "launch_error": False,
    }
    fields.update(changes)
    return runner.BoundedProcessResult(**fields)


class BenchmarkMeasurementInferenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = _load_runner()
        missing = [name for name in S002_BOUNDARIES if not hasattr(cls.runner, name)]
        if missing:
            raise AssertionError("missing S002 production symbols: " + ",".join(missing))

    def test_resume_exact_attempt_identity(self):
        events = [
            _event("run-initial", 0, "planned"),
            _event("run-initial", 0, "launch_reserved"),
            _event("run-initial", 0, "launched", consumed=True),
            _event("run-initial", 0, "terminal", consumed=True, terminal_status="valid_task_failure_v1"),
            _event("run-retry", 1, "conditional"),
            _event("run-retry", 1, "eligible"),
        ]
        folded = self.runner.fold_study_attempt_events(events)
        self.assertEqual(tuple(folded), (("run-initial", 0), ("run-retry", 1)))
        trace = TraceRecorder()
        result = self.runner._execute_measurement_study(
            action="resume", manifest={"slots": []}, folded_attempts=folded,
            run_slot=trace.callback("slot", result={"state": "terminal"}),
        )
        self.assertEqual([call["args"][0]["run_id"] for call in trace.calls], ["run-retry"])
        self.assertEqual(result["selected_run_ids"], ["run-retry"])

    def test_retry_history_is_append_only(self):
        events = [
            _event("run-0", 0, "planned"),
            _event("run-0", 0, "launch_reserved"),
            _event("run-0", 0, "launched", consumed=True),
            _event("run-0", 0, "terminal", consumed=True, terminal_status="valid_task_failure_v1"),
            _event("run-1", 1, "conditional"), _event("run-1", 1, "eligible"),
            _event("run-1", 1, "launch_reserved"),
            _event("run-1", 1, "launched", consumed=True),
            _event("run-1", 1, "terminal", consumed=True, terminal_status="valid_task_failure_v1"),
        ]
        folded = self.runner.fold_study_attempt_events(events)
        self.assertEqual([item["attempt"] for item in folded.values()], [0, 1])
        execution = self.runner._execute_measurement_study(
            action="resume", manifest={"slots": []}, folded_attempts=folded,
            run_slot=lambda _slot: self.fail("terminal failed retry must not relaunch"),
        )
        self.assertFalse(execution["study_valid"])
        self.assertEqual(execution["consumed_attempt_count"], 2)
        report = self.runner._analyze_measurement_study(manifest={}, folded_attempts=folded, corrections=None)
        self.assertFalse(report["valid"])
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertEqual(report["consumed_attempt_count"], 2)

    def test_prelaunch_refusal_consumes_zero(self):
        trace = TraceRecorder()
        result = self.runner._run_measurement_study_slot(
            slot={"run_id": "refused", "attempt": 0},
            validate_slot=trace.callback("validation", failure=ValueError("unsafe cwd")),
            launch=trace.callback("provider_process"), append_event=trace.callback("append"),
        )
        self.assertEqual(result, {"state": "prelaunch_refused", "consumed": False, "reason": "slot_validation_refused"})
        self.assertNotIn("provider_process", [call["kind"] for call in trace.calls])

    def test_postlaunch_abort_consumes_one(self):
        trace = TraceRecorder()
        events = []
        result = self.runner._run_measurement_study_slot(
            slot={"run_id": "launched", "attempt": 0}, validate_slot=lambda _slot: None,
            launch=trace.callback("provider_process", result=ProcessDouble()),
            append_event=lambda event: events.append(dict(event)),
            after_launch=trace.callback("postlaunch", failure=RuntimeError("accounting write failed")),
            terminate=trace.callback("terminate"), reap=trace.callback("reap"),
        )
        self.assertEqual(result["state"], "invalid")
        self.assertTrue(result["consumed"])
        self.assertEqual([call["kind"] for call in trace.calls], ["provider_process", "postlaunch", "terminate", "reap"])
        self.assertEqual([event["state"] for event in events], ["launched", "terminal"])
        self.assertEqual(events[-1]["terminal_status"], "post_launch_accounting_failure")
        cleanup = []
        with self.assertRaisesRegex(RuntimeError, "durability failure"):
            self.runner._run_measurement_study_slot(
                slot={"run_id": "launch-accounting", "attempt": 0},
                validate_slot=lambda _slot: None,
                launch=lambda _slot: ProcessDouble(),
                append_event=lambda _event: (_ for _ in ()).throw(
                    RuntimeError("durability failure")
                ),
                terminate=lambda _process: cleanup.append("terminate"),
                reap=lambda _process: cleanup.append("reap"),
            )
        self.assertEqual(cleanup, ["terminate", "reap"])
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            slot = {
                "pair_id": "pair-1", "run_id": "run-1",
                "task_id": FIXTURE["task_ids"][0], "repetition": 0,
                "arm": "baseline", "attempt": 0, "state": "planned",
            }
            production_events = []
            fake_variant = SimpleNamespace(
                measurement=SimpleNamespace(artifact_root=root)
            )
            fake_result = SimpleNamespace(
                notes="task_success",
                tokens={
                    "input_tokens": 2, "cache_creation": 3,
                    "cache_read": 5, "output_tokens": 7,
                },
            )
            root_fd = self.runner.os.open(root, self.runner.os.O_RDONLY)
            with (
                mock.patch.object(
                    self.runner, "_study_variant_for_slot",
                    return_value=fake_variant,
                ),
                mock.patch.object(
                    self.runner, "_ensure_directory_no_symlink",
                    return_value=root_fd,
                ),
                mock.patch.object(
                    self.runner, "_run_measurement_fixture_locked",
                    side_effect=lambda *args, **kwargs: (
                        kwargs["on_process_started"](), fake_result
                    )[1],
                ),
                mock.patch.object(
                    self.runner, "_measurement_existing_context",
                    return_value=SimpleNamespace(
                        receipt_path=root / "missing-receipt.json"
                    ),
                ),
                mock.patch.object(
                    self.runner, "append_study_attempt_event",
                    side_effect=lambda _path, event: production_events.append(
                        dict(event)
                    ),
                ),
            ):
                outcome = self.runner._run_measurement_study_slot(
                    slot=slot, task=object(), variant=object(),
                    claude_bin="claude", project_root=root,
                    attempts_path=root / "attempts.jsonl",
                    manifest_sha256="a" * 64,
                )
            self.assertEqual(outcome, "post_launch_infra_invalid")
            self.assertEqual(
                [event["state"] for event in production_events],
                ["launch_reserved", "launched", "terminal"],
            )
            terminal = production_events[-1]
            self.assertEqual(
                terminal["terminal_classification"],
                "post_launch_infra_invalid",
            )
            self.assertIsNone(terminal["receipt_sha256"])
            folded = self.runner.fold_study_attempt_events(
                [slot], production_events, manifest_sha256="a" * 64,
            )
            self.assertEqual(folded["run-1"]["state"], "terminal")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            slot = {
                "pair_id": "pair-reserved", "run_id": "run-reserved",
                "task_id": FIXTURE["task_ids"][0], "repetition": 0,
                "arm": "baseline", "attempt": 0, "state": "planned",
            }
            fake_variant = SimpleNamespace(
                measurement=SimpleNamespace(artifact_root=root)
            )
            durable_events = []
            attempted_states = []

            def persist_until_launch(_path, event):
                attempted_states.append(event["state"])
                if event["state"] != "launch_reserved":
                    raise OSError("persistent attempt-index failure")
                durable_events.append(dict(event))

            def open_root(*_args, **_kwargs):
                return self.runner.os.open(root, self.runner.os.O_RDONLY)

            with (
                mock.patch.object(
                    self.runner, "_study_variant_for_slot",
                    return_value=fake_variant,
                ),
                mock.patch.object(
                    self.runner, "_ensure_directory_no_symlink",
                    side_effect=open_root,
                ),
                mock.patch.object(
                    self.runner, "_run_measurement_fixture_locked",
                    side_effect=lambda *args, **kwargs: kwargs[
                        "on_process_started"
                    ](),
                ),
                mock.patch.object(
                    self.runner, "append_study_attempt_event",
                    side_effect=persist_until_launch,
                ),
            ):
                with self.assertRaisesRegex(
                    OSError, "persistent attempt-index failure"
                ):
                    self.runner._run_measurement_study_slot(
                        slot=slot, task=object(), variant=object(),
                        claude_bin="claude", project_root=root,
                        attempts_path=root / "attempts.jsonl",
                        manifest_sha256="b" * 64,
                    )
            self.assertEqual(
                attempted_states,
                ["launch_reserved", "launched", "launched"],
            )
            self.assertEqual(
                [event["state"] for event in durable_events],
                ["launch_reserved"],
            )
            folded = self.runner.fold_study_attempt_events(
                [slot], durable_events, manifest_sha256="b" * 64,
            )
            recovered_events = []
            with (
                mock.patch.object(
                    self.runner, "_study_variant_for_slot",
                    return_value=fake_variant,
                ),
                mock.patch.object(
                    self.runner, "_ensure_directory_no_symlink",
                    side_effect=open_root,
                ),
                mock.patch.object(
                    self.runner, "_measurement_recover_raw_only_run",
                    side_effect=ValueError("no raw process evidence"),
                ),
                mock.patch.object(
                    self.runner, "_measurement_existing_context",
                    return_value=SimpleNamespace(
                        receipt_path=root / "missing-receipt.json"
                    ),
                ),
                mock.patch.object(
                    self.runner, "append_study_attempt_event",
                    side_effect=lambda _path, event: recovered_events.append(
                        dict(event)
                    ),
                ),
            ):
                recovered = self.runner._study_fold_interrupted_launches(
                    manifest={"slots": [slot]}, folded=folded,
                    tasks=[SimpleNamespace(id=slot["task_id"])],
                    variants=[object(), object()],
                    attempts_path=root / "attempts.jsonl",
                    manifest_sha256="b" * 64,
                )
            self.assertTrue(recovered)
            self.assertEqual(
                [event["state"] for event in recovered_events],
                ["launched", "terminal"],
            )
            recovered_fold = self.runner.fold_study_attempt_events(
                [slot], durable_events + recovered_events,
                manifest_sha256="b" * 64,
            )
            self.assertEqual(recovered_fold["run-reserved"]["state"], "terminal")
            self.assertTrue(recovered_fold["run-reserved"]["consumed"])
            self.assertEqual(
                recovered_fold["run-reserved"]["terminal_classification"],
                "recovered_process_status_unknown",
            )

    def test_retry_eligibility_is_exact(self):
        eligible = self.runner.classify_success_checker(
            _checker_result(self.runner, returncode=1)
        )
        invalid = self.runner.classify_success_checker(
            _checker_result(self.runner, returncode=2)
        )
        self.assertEqual(eligible, "valid_task_failure_v1")
        self.assertEqual(invalid, "success_checker_infra_invalid")
        retry_slot = {"run_id": "retry-1", "attempt": 1, "state": "eligible"}
        trace = TraceRecorder()
        scheduled = self.runner._execute_measurement_study(
            action="resume", manifest={"slots": [retry_slot]},
            folded_attempts={
                ("initial-0", 0): {
                    "run_id": "initial-0", "attempt": 0, "state": "terminal",
                    "terminal_status": eligible, "consumed": True,
                }
            },
            run_slot=trace.callback("slot", result={"state": "terminal"}),
        )
        self.assertEqual([call["args"][0]["run_id"] for call in trace.calls], ["retry-1"])
        self.assertEqual(scheduled["selected_run_ids"], ["retry-1"])
        trace.calls.clear()
        blocked = self.runner._execute_measurement_study(
            action="resume", manifest={"slots": [retry_slot]},
            folded_attempts={
                ("initial-0", 0): {
                    "run_id": "initial-0", "attempt": 0, "state": "terminal",
                    "terminal_status": invalid, "consumed": True,
                }
            },
            run_slot=trace.callback("slot"),
        )
        self.assertEqual(trace.calls, [])
        self.assertFalse(blocked["study_valid"])

    def test_recovered_unknown_never_relaunches(self):
        events = [
            _event("interrupted", 0, "planned"),
            _event("interrupted", 0, "launch_reserved"),
        ]
        recovered = self.runner._study_fold_interrupted_launches(events, raw_run_ids={"interrupted"})
        self.assertEqual(recovered[("interrupted", 0)]["terminal_status"], "recovered_process_status_unknown")
        self.assertTrue(recovered[("interrupted", 0)]["consumed"])
        trace = TraceRecorder()
        result = self.runner._execute_measurement_study(
            action="resume", manifest={"slots": []}, folded_attempts=recovered,
            run_slot=trace.callback("slot"),
        )
        self.assertEqual(trace.calls, [])
        self.assertEqual(result["selected_run_ids"], [])
        slots = [
            {
                "pair_id": f"pair-{index}", "run_id": f"run-{index}",
                "task_id": f"task-{index}", "repetition": 0,
                "arm": "baseline", "attempt": 0, "state": "planned",
            }
            for index in (1, 2)
        ]
        folded = {
            slot["run_id"]: {
                **slot,
                "state": "launch_reserved" if index == 0 else "launched",
            }
            for index, slot in enumerate(slots)
        }
        recovered_events = []
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fake_variant = SimpleNamespace(
                measurement=SimpleNamespace(artifact_root=root)
            )

            def open_root(*_args, **_kwargs):
                return self.runner.os.open(root, self.runner.os.O_RDONLY)

            with (
                mock.patch.object(
                    self.runner, "_study_variant_for_slot",
                    return_value=fake_variant,
                ),
                mock.patch.object(
                    self.runner, "_ensure_directory_no_symlink",
                    side_effect=open_root,
                ),
                mock.patch.object(
                    self.runner, "_measurement_recover_raw_only_run",
                ),
                mock.patch.object(
                    self.runner, "_measurement_existing_context",
                    side_effect=lambda _spec, run_id: SimpleNamespace(
                        receipt_path=root / f"{run_id}-missing.json"
                    ),
                ),
                mock.patch.object(
                    self.runner, "append_study_attempt_event",
                    side_effect=lambda _path, event: recovered_events.append(
                        dict(event)
                    ),
                ),
            ):
                recovered_any = self.runner._study_fold_interrupted_launches(
                    manifest={"slots": slots}, folded=folded,
                    tasks=[
                        SimpleNamespace(id="task-1"),
                        SimpleNamespace(id="task-2"),
                    ],
                    variants=[object(), object()],
                    attempts_path=root / "attempts.jsonl",
                    manifest_sha256="a" * 64,
                )
        self.assertTrue(recovered_any)
        self.assertEqual(
            [
                (event["run_id"], event["state"])
                for event in recovered_events
            ],
            [
                ("run-1", "launched"),
                ("run-1", "terminal"),
                ("run-2", "terminal"),
            ],
        )

    def test_real_slot_set_and_manifest_join(self):
        slots = self.runner.generate_measurement_study_slots(
            task_ids=FIXTURE["task_ids"], repetitions=3, arms=("baseline", "treatment"),
            namespace="s002-spec", candidate_hash="b" * 64,
        )
        self.assertEqual(len(slots), 144)
        self.assertEqual(sum(slot["state"] == "planned" for slot in slots), 72)
        self.assertEqual(sum(slot["state"] == "conditional" for slot in slots), 72)
        manifest_hash = "c" * 64
        joined = [dict(slot, study_manifest_sha256=manifest_hash) for slot in slots]
        self.assertEqual(self.runner.validate_measurement_study_slots(joined, manifest_hash=manifest_hash), tuple(joined))

    def test_schedule_balance_and_identity(self):
        schedule = self.runner.generate_balanced_study_schedule(
            task_ids=FIXTURE["task_ids"], repetitions=3,
            schedule_seed=FIXTURE["study_plan"]["schedule_seed"], namespace="s002-spec",
            candidate_hash="d" * 64,
        )
        self.assertEqual(len(schedule), 36)
        self.assertEqual([pair["first_arm"] for pair in schedule], FIXTURE["schedule"]["first_arms"])
        self.assertEqual(sum(pair["first_arm"] == "baseline" for pair in schedule), 18)
        self.assertEqual(sum(pair["first_arm"] == "treatment" for pair in schedule), 18)
        self.assertEqual(len({run_id for pair in schedule for run_id in pair["run_ids"]}), 72)
        self.assertEqual(sha256_hex(canonical_json_bytes([pair["first_arm"] for pair in schedule])), FIXTURE["schedule"]["sha256"])
        for seed in range(10_000):
            trial = self.runner.generate_balanced_study_schedule(
                task_ids=FIXTURE["task_ids"], repetitions=3,
                schedule_seed=f"0x{seed:016X}", namespace="s002-balance",
                candidate_hash="d" * 64,
            )
            self.assertEqual(len(trial), 36)
            self.assertEqual(sum(pair["first_arm"] == "baseline" for pair in trial), 18)
            self.assertEqual(sum(pair["first_arm"] == "treatment" for pair in trial), 18)
            self.assertEqual(
                {(pair["task"], pair["repetition"]) for pair in trial},
                {(task, repetition) for task in FIXTURE["task_ids"] for repetition in range(3)},
            )

    def test_terminal_usage_bucket_schema(self):
        streams = FIXTURE["terminal_streams"]
        parsed = self.runner.parse_measurement_terminal_usage(streams["valid"].encode())
        self.assertEqual(parsed, {"input_tokens": 11, "cache_creation_input_tokens": 13, "cache_read_input_tokens": 17, "output_tokens": 19, "primary_tokens": 60})
        raw = streams["valid"].encode()
        self.assertEqual(len(raw), 164)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "e3bf1b6b4f6e40c5c79e6ecf0ca847a0417b905bcf2e095993b0ccb4b8cd134c",
        )
        malformed = {
            "additional": streams["additional_bucket"],
            "duplicate": streams["duplicate_key"],
            "string": streams["string_number"],
            "bool": streams["valid"].replace('"input_tokens":11', '"input_tokens":true'),
            "negative": streams["valid"].replace('"input_tokens":11', '"input_tokens":-1'),
            "fraction": streams["valid"].replace('"input_tokens":11', '"input_tokens":1.5'),
            "exponent": streams["valid"].replace('"input_tokens":11', '"input_tokens":1e1'),
            "leading_plus": streams["valid"].replace('"input_tokens":11', '"input_tokens":+1'),
            "missing": streams["valid"].replace('"input_tokens":11,', ""),
            "renamed": streams["valid"].replace('"input_tokens":11', '"prompt_tokens":11'),
            "overflow": streams["valid"].replace('"input_tokens":11', '"input_tokens":1000000000001'),
            "sum_overflow": streams["valid"]
            .replace('"input_tokens":11', '"input_tokens":300000000000')
            .replace('"cache_creation_input_tokens":13', '"cache_creation_input_tokens":300000000000')
            .replace('"cache_read_input_tokens":17', '"cache_read_input_tokens":300000000000')
            .replace('"output_tokens":19', '"output_tokens":300000000000'),
        }
        for name, text in malformed.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.runner.parse_measurement_terminal_usage(text.encode())

    def test_complete_pair_weighting(self):
        attempts = _complete_attempts(treatment_retry=True)
        result = self.runner.compute_measurement_study_estimators(attempts)
        self.assertTrue(result["complete_pairs"])
        self.assertEqual(result["paired_unit_count"], 36)
        self.assertEqual(result["consumed_attempt_count"], len(attempts))
        failed = next(item for item in attempts if item["terminal_status"] == "valid_task_failure_v1")
        self.assertIn(sum(failed["usage"].values()), result["arm_unit_totals"]["task-01:0:treatment"]["attempt_tokens"])
        self.assertEqual(
            result["arm_unit_totals"]["task-01:0:treatment"]["primary_tokens"],
            sum(sum(item["usage"].values()) for item in attempts if item["task"] == "task-01" and item["repetition"] == 0 and item["arm"] == "treatment"),
        )
        incomplete = attempts[:-1]
        invalid = self.runner.compute_measurement_study_estimators(incomplete)
        self.assertFalse(invalid["complete_pairs"])
        self.assertIsNone(invalid["delta"])
        self.assertIsNone(invalid["gamma"])
        self.assertEqual(invalid["paired_unit_count"], 35)
        noncanonical = [dict(item) for item in attempts]
        noncanonical[0]["usage"] = {
            **noncanonical[0]["usage"],
            "total_tokens": sum(noncanonical[0]["usage"].values()),
        }
        schema_invalid = self.runner.compute_measurement_study_estimators(
            noncanonical
        )
        self.assertFalse(schema_invalid["complete_pairs"])
        production_attempts = [
            {
                "task_id": item["task"], "repetition": item["repetition"],
                "arm": item["arm"], "attempt": item["attempt"],
                "consumed": item["consumed"],
                "successful": item["terminal_status"] == "success",
                "terminal_classification": item["terminal_status"],
                "primary_tokens": sum(item["usage"].values()),
            }
            for item in attempts
        ]
        recovered_unknown = next(
            item for item in production_attempts
            if item["terminal_classification"] == "valid_task_failure_v1"
        )
        recovered_unknown["terminal_classification"] = (
            "recovered_process_status_unknown"
        )
        production_invalid = self.runner.compute_measurement_study_estimators(
            production_attempts, task_order=FIXTURE["task_ids"],
        )
        self.assertFalse(production_invalid["valid"])

    def test_task_cluster_bootstrap_unit(self):
        golden = FIXTURE["bootstrap"]
        result = self.runner.bootstrap_task_cluster(
            token_differences=golden["token_differences"], retry_differences=golden["retry_differences"],
            seed=FIXTURE["study_plan"]["inference_seed"], replicates=10000,
        )
        self.assertEqual(result["sampled_task_indices"][:36], golden["first_indices"])
        self.assertEqual(sha256_hex(bytes(result["sampled_task_indices"])), golden["index_sha256"])
        self.assertEqual(len(result["sampled_task_indices"]), 120000)
        self.assertEqual(result["token_q025"], Fraction(-5))
        self.assertEqual(result["token_q975"], Fraction(227, 80))
        self.assertEqual(result["retry_q025"], Fraction(-7, 36))
        self.assertEqual(result["retry_q975"], Fraction(-1, 36))

    def test_splitmix_bootstrap_constants(self):
        state = int(FIXTURE["prng"]["seed"], 16)
        states = FIXTURE["prng"]["states"][1:]
        values = FIXTURE["prng"]["values"]
        for state_text, value_text in zip(states, values, strict=True):
            state, value = self.runner.splitmix64_next(state)
            self.assertEqual(state, int(state_text, 16))
            self.assertEqual(value, int(value_text, 16))

    def test_type7_and_delta_upper_bound(self):
        self.assertEqual(self.runner.type7_quantile([0, 10, 20, 30, 40], Fraction(1, 4)), Fraction(10))
        result = self.runner.compute_measurement_study_estimators(_golden_estimator_attempts())
        self.assertEqual(result["delta"], Fraction(-1))
        self.assertEqual(result["delta_q025"], Fraction(-5))
        self.assertEqual(result["delta_q975"], Fraction(227, 80))

    def test_retry_upper_bound_gate(self):
        report = self.runner._analyze_measurement_study(
            manifest={"sha256": "e" * 64}, folded_attempts={}, corrections={"measured": True},
            estimator={"complete_pairs": True, "delta_q975": Fraction(-1), "gamma": Fraction(0), "gamma_q975": Fraction(1, 100)},
        )
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertFalse(report["gates"]["retry_non_regression"])

    def test_correction_null_and_blinding(self):
        outputs = [{"task": task, "repetition": rep, "arm": arm, "output": f"{task}-{rep}-{arm}", "tokens": 1} for task in FIXTURE["task_ids"] for rep in range(3) for arm in ("baseline", "treatment")]
        packets = self.runner.build_blinded_correction_packets(outputs)
        self.assertEqual(len(packets), 72)
        self.assertEqual([packet["packet_id"] for packet in packets], [f"A{i:03d}" for i in range(1, 73)])
        for packet in packets:
            self.assertTrue(set(packet).isdisjoint({"arm", "settings", "tokens", "cost", "hooks", "run_id", "path"}))
        shuffled = self.runner.shuffle_correction_packets(
            packets, seed=FIXTURE["study_plan"]["correction_shuffle_seed"]
        )
        self.assertTrue(all(
            set(item) == {"assessment_id", "output"} for item in shuffled
        ))
        identity_map = self.runner.correction_packet_identity_map(
            packets, seed=FIXTURE["study_plan"]["correction_shuffle_seed"],
        )
        by_packet = {packet["packet_id"]: packet for packet in packets}
        self.assertEqual(
            [
                by_packet[identity_map[item["assessment_id"]]]["source_index"]
                for item in shuffled[:18]
            ],
            FIXTURE["correction"]["first_indices"],
        )
        reordered = list(outputs)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(ValueError, "order mismatch"):
            self.runner.build_blinded_correction_packets(reordered)
        wrong_map = {f"A{i:03d}": i for i in range(1, 73)}
        with self.assertRaises(ValueError):
            self.runner.shuffle_correction_packets(
                packets, seed=FIXTURE["study_plan"]["correction_shuffle_seed"],
                packet_id_map=wrong_map,
            )
        self.assertEqual(self.runner.compute_correction_non_regression(None), {"measured": False, "valid": False})
        self.assertEqual(self.runner.compute_correction_non_regression([])["measured"], True)
        report = self.runner._analyze_measurement_study(
            manifest={"sha256": "a" * 64}, folded_attempts={},
            estimator={"complete_pairs": True, "delta_q975": Fraction(-1), "gamma": Fraction(0), "gamma_q975": Fraction(0)},
            corrections=None,
        )
        self.assertEqual(report["verdict"], "inconclusive")
        self.assertFalse(report["gates"]["correction_non_regression"])

    def test_score_resolution_and_shuffle(self):
        golden = FIXTURE["correction"]
        permutation = self.runner.correction_packet_permutation(72, seed=FIXTURE["study_plan"]["correction_shuffle_seed"])
        self.assertEqual(permutation[:18], golden["first_indices"])
        self.assertEqual(sha256_hex(bytes(permutation)), golden["permutation_sha256"])
        self.assertEqual([self.runner.resolve_correction_scores(scores) for scores in golden["numeric_scores"]], [0, 2, 1])
        for scores in golden["unresolved_scores"]:
            with self.assertRaises(ValueError):
                self.runner.resolve_correction_scores(scores)
        packets = [
            {
                "packet_id": f"A{i:03d}", "source_index": i - 1,
                "output": f"candidate-output-{i}",
            }
            for i in range(1, 73)
        ]
        shuffled = self.runner.shuffle_correction_packets(
            packets, seed=FIXTURE["study_plan"]["correction_shuffle_seed"]
        )
        identity_map = self.runner.correction_packet_identity_map(
            packets, seed=FIXTURE["study_plan"]["correction_shuffle_seed"],
        )
        resolved = [
            {
                "packet_id": identity_map[packet["assessment_id"]],
                "score": self.runner.resolve_correction_scores([0, 0, 0]),
            }
            for packet in shuffled
        ]
        correction = self.runner.compute_correction_non_regression(resolved)
        self.assertEqual(correction["severity_point"], Fraction(0))
        self.assertEqual(correction["severity_q975"], Fraction(0))
        self.assertEqual(correction["incidence_point"], Fraction(0))
        self.assertEqual(correction["incidence_q975"], Fraction(0))
        report = self.runner._analyze_measurement_study(
            manifest={"sha256": "b" * 64}, folded_attempts={},
            estimator={"complete_pairs": True, "delta_q975": Fraction(-1), "gamma": Fraction(0), "gamma_q975": Fraction(0)},
            corrections=correction,
        )
        self.assertTrue(report["gates"]["correction_non_regression"])
        self.assertEqual(report["verdict"], "synthetic_offline_contract_pass")

    def test_claim_scope_is_synthetic_only(self):
        report = self.runner._analyze_measurement_study(
            manifest={"sha256": "f" * 64}, folded_attempts={}, corrections=None,
            estimator={"complete_pairs": False}, provenance="synthetic_offline",
        )
        self.assertIsNone(report["claim"])
        self.assertEqual(report["claim_scope"], "synthetic_offline_only_no_empirical_savings_claim")
        rendered = json.dumps(report, sort_keys=True).lower()
        for forbidden in ("product-wide", "default-on", "general repositories", "future versions"):
            self.assertNotIn(forbidden, rendered)

    def test_resume_revalidates_s001_bindings(self):
        evidence = {
            "receipt_schema": "contextguard.bench.raw-receipt.v2",
            "index_schema": "contextguard.bench.artifact-index.v2",
            "receipt_sha256": "1" * 64,
            "settings_sha256": "2" * 64,
            "candidate_hash": "3" * 64,
            "binding_set_sha256": "4" * 64,
        }
        self.assertEqual(self.runner._study_revalidate_terminal_evidence(evidence, expected=dict(evidence))["receipt_sha256"], "1" * 64)
        changed = dict(evidence, settings_sha256="9" * 64)
        with self.assertRaises(ValueError):
            self.runner._study_revalidate_terminal_evidence(changed, expected=evidence)

    def test_offline_forbidden_access_seams(self):
        trace = TraceRecorder()
        env_spy = EnvironmentSpy(
            {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "ANTHROPIC_API_KEY": "forbidden",
                "CLAUDE_CODE_OAUTH_TOKEN": "forbidden",
                "AWS_SECRET_ACCESS_KEY": "forbidden",
            },
            ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_SECRET_ACCESS_KEY"),
        )
        probe_responses = iter(
            [
                {"returncode": 0, "stdout": "Claude 1.0\n", "stderr": "", "timed_out": False, "output_truncated": False},
                {
                    "returncode": 0,
                    "stdout": "--settings --setting-sources --include-hook-events --no-session-persistence stream-json\n",
                    "stderr": "", "timed_out": False, "output_truncated": False,
                },
            ]
        )

        def bounded_probe(argv, **kwargs):
            trace.record("metadata_probe", argv=argv)
            return next(probe_responses)

        def write_artifact(_path, _payload):
            trace.record("artifact_write", argv=[])

        with tempfile.TemporaryDirectory() as raw:
            output_root = Path(raw) / "study"
            with (
                mock.patch.object(
                    socket, "socket",
                    trace.callback("network", failure=AssertionError("network forbidden")),
                ),
                mock.patch.object(
                    self.runner.subprocess, "Popen",
                    trace.callback("provider_process", failure=AssertionError("provider forbidden")),
                ),
                mock.patch.object(
                    self.runner.subprocess, "run",
                    trace.callback("keychain", failure=AssertionError("keychain forbidden")),
                ),
                mock.patch.object(self.runner.os, "environ", env_spy),
            ):
                probes = self.runner.run_measurement_cli_probes(
                    "claude", run_command=bounded_probe
                )
                action = self.runner.run_measurement_study_action(
                    action="prepare", study_plan=FIXTURE["study_plan"],
                    task_ids=FIXTURE["task_ids"], variants=("baseline", "treatment"),
                    output_root=output_root, claude_bin="claude",
                    cli_probe_result=probes, write_artifact=write_artifact,
                )
        self.assertEqual(action["action"], "prepare")
        result = validate_offline_access_trace(trace.calls)
        self.assertEqual([kind for kind, _ in result], ["metadata_probe", "metadata_probe", "artifact_write"])
        self.assertEqual(
            [call["kind"] for call in trace.calls if call["kind"] in {"network", "provider_process", "task_process", "keychain", "auth", "credential_env"}],
            [],
        )
        self.assertEqual(env_spy.forbidden_reads, [])
        bypass_spy = EnvironmentSpy(
            {"ANTHROPIC_API_KEY": "forbidden"},
            ("ANTHROPIC_API_KEY",),
        )
        self.assertEqual(dict(bypass_spy)["ANTHROPIC_API_KEY"], "forbidden")
        self.assertIn("ANTHROPIC_API_KEY", bypass_spy)
        self.assertEqual(
            dict(bypass_spy.items())["ANTHROPIC_API_KEY"],
            "forbidden",
        )
        self.assertEqual(
            bypass_spy.copy()["ANTHROPIC_API_KEY"],
            "forbidden",
        )
        self.assertGreaterEqual(
            bypass_spy.forbidden_reads.count("ANTHROPIC_API_KEY"), 4
        )
        forbidden_trace = list(trace.calls)
        forbidden_trace.insert(2, {"kind": "provider_process", "argv": ["claude", "-p", "task"]})
        with self.assertRaisesRegex(AssertionError, "forbidden offline access: provider_process"):
            validate_offline_access_trace(forbidden_trace)

    def test_scope_invariant_diff_inputs(self):
        diff = FIXTURE["scope_diff"]
        self.assertEqual(validate_s002_diff_bundle(diff), tuple(diff["changed_paths"]))
        for changed in (
            dict(diff, read_threshold_after=48001),
            dict(diff, phase5_touched=True),
            dict(diff, access_trace=[{"kind": "credential_env"}]),
        ):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                validate_s002_diff_bundle(changed)

    def test_study_cli_surface_and_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plan = root / "plan.json"; tasks = root / "tasks.json"; variants = root / "variants.json"; output = root / "out"
            plan.write_bytes(canonical_json_bytes(FIXTURE["study_plan"]))
            tasks.write_bytes(canonical_json_bytes([]))
            variants.write_bytes(canonical_json_bytes([]))
            trace = TraceRecorder()
            argv = ["context-guard-bench", "--tasks", str(tasks), "--variants", str(variants), "--measurement-study-plan", str(plan), "--measurement-study-action", "prepare", "--measurement-study-output-root", str(output)]
            for action_name in ("prepare", "run", "resume", "analyze"):
                action_argv = list(argv)
                action_argv[action_argv.index("prepare")] = action_name
                with (
                    self.subTest(action=action_name),
                    mock.patch.object(
                        self.runner, "run_measurement_study_action",
                        trace.callback("dispatch", result=0),
                    ),
                ):
                    self.assertEqual(self.runner.main(action_argv[1:]), 0)
            self.assertEqual(len(trace.calls), 4)
            partials = (
                ["--measurement-study-plan", str(plan)],
                ["--measurement-study-action", "prepare"],
                ["--measurement-study-output-root", str(output)],
                ["--measurement-study-plan", str(plan), "--measurement-study-action", "prepare"],
                ["--measurement-study-plan", str(plan), "--measurement-study-output-root", str(output)],
                ["--measurement-study-action", "prepare", "--measurement-study-output-root", str(output)],
            )
            conflicts = (
                ["--resume"],
                ["--dry-run"],
                ["--csv", str(root / "legacy.csv")],
                ["--baseline-variant", "treatment"],
                ["--task-id", "task-01"],
                ["--variant", "baseline"],
                ["--evidence-jsonl", str(root / "evidence.jsonl")],
                ["--ledger-jsonl", str(root / "ledger.jsonl")],
                ["--report-json", str(root / "report.json")],
                ["--dashboard-md", str(root / "dashboard.md")],
            )
            common = ["--tasks", str(tasks), "--variants", str(variants)]
            for flags in partials:
                with self.subTest(partial=flags), self.assertRaises(SystemExit):
                    self.runner.main(common + flags)
            for flags in conflicts:
                with self.subTest(conflict=flags), self.assertRaises(SystemExit):
                    self.runner.main(argv[1:] + flags)
            unsupported = list(argv)
            unsupported[unsupported.index("prepare")] = "unsupported"
            with self.assertRaises(SystemExit):
                self.runner.main(unsupported[1:])
            legacy_trace = TraceRecorder()
            with mock.patch.object(self.runner, "run_measurement_study_action", legacy_trace.callback("study")):
                legacy_rc = self.runner.main(common + ["--dry-run"])
            self.assertEqual(legacy_rc, 0)
            self.assertEqual(legacy_trace.calls, [])
            tasks.write_bytes(canonical_json_bytes({"tasks": []}))
            with self.assertRaises(SystemExit):
                self.runner.main(common + ["--dry-run"])

    def test_manifest_input_class_mismatches(self):
        inputs = {
            "study_plan": FIXTURE["study_plan"], "tasks": {"task_ids": FIXTURE["task_ids"]},
            "variants": {"arms": ["baseline", "treatment"]}, "cli_probe": {"schema_version": "contextguard.bench.cli-probe.v1"},
            "runner_sha256": "5" * 64, "mirror_sha256": "5" * 64,
        }
        manifest = self.runner.build_measurement_study_manifest(**inputs)
        self.assertEqual(
            manifest["schema_version"],
            self.runner.MEASUREMENT_STUDY_DIRECT_MANIFEST_SCHEMA_VERSION,
        )
        self.assertNotEqual(
            manifest["schema_version"],
            self.runner.MEASUREMENT_STUDY_MANIFEST_SCHEMA_VERSION,
        )
        raw = canonical_json_bytes(manifest)
        self.assertEqual(raw, self.runner.build_measurement_study_manifest(**inputs, canonical_bytes=True))
        self.assertEqual(self.runner.validate_measurement_study_manifest(raw, expected=manifest), manifest)
        malformed = dict(manifest)
        malformed.pop("runner_sha256")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            self.runner.validate_measurement_study_manifest(
                canonical_json_bytes(malformed)
            )
        for key in ("study_plan", "tasks", "variants", "cli_probe"):
            malformed = dict(manifest)
            malformed[key] = {}
            with self.subTest(empty_nested=key), self.assertRaisesRegex(
                ValueError, "schema|invalid"
            ):
                self.runner.validate_measurement_study_manifest(
                    canonical_json_bytes(malformed)
                )
        unequal_hashes = dict(manifest)
        unequal_hashes["mirror_sha256"] = "6" * 64
        with self.assertRaisesRegex(ValueError, "parity mismatch"):
            self.runner.validate_measurement_study_manifest(
                canonical_json_bytes(unequal_hashes)
            )
        for key in inputs:
            altered = dict(manifest)
            altered[key] = {"drift": True} if isinstance(altered.get(key), dict) else "6" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.runner.validate_measurement_study_manifest(canonical_json_bytes(altered), expected=manifest)

    def test_process_started_callback_contract(self):
        trace = TraceRecorder()
        original_popen = subprocess.Popen
        original_selector = self.runner.selectors.DefaultSelector

        def observed_popen(*args, **kwargs):
            trace.record("popen")
            return original_popen(*args, **kwargs)

        def started():
            trace.record("callback")

        class ObservedSelector:
            def __init__(self):
                self._selector = original_selector()
                self._selector_recorded = False
                self._read_recorded = False

            def register(self, *args, **kwargs):
                if not self._selector_recorded:
                    trace.record("selector")
                    self._selector_recorded = True
                return self._selector.register(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                return self._selector.unregister(*args, **kwargs)

            def get_map(self):
                return self._selector.get_map()

            def select(self, *args, **kwargs):
                if not self._read_recorded:
                    trace.record("read")
                    self._read_recorded = True
                return self._selector.select(*args, **kwargs)

            def close(self):
                return self._selector.close()

        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(self.runner.subprocess, "Popen", observed_popen),
            mock.patch.object(self.runner.selectors, "DefaultSelector", ObservedSelector),
        ):
            result = self.runner.run_bounded_command(
                [sys.executable, "-c", "print('ok')"], cwd=Path(raw), timeout_seconds=5,
                max_output_bytes=1024, on_process_started=started,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(
            [call["kind"] for call in trace.calls],
            ["popen", "callback", "selector", "read"],
        )
        with tempfile.TemporaryDirectory() as raw:
            legacy = self.runner.run_bounded_command([sys.executable, "-c", "print('ok')"], cwd=Path(raw), timeout_seconds=5, max_output_bytes=1024)
        self.assertEqual((legacy.returncode, legacy.stdout), (0, "ok\n"))
        refused_trace = TraceRecorder()
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(self.runner.subprocess, "Popen", side_effect=OSError("refused")),
            self.assertRaises(self.runner._MeasurementLaunchError),
        ):
            self.runner.run_bounded_command(
                [sys.executable, "-c", "pass"], cwd=Path(raw), timeout_seconds=5,
                max_output_bytes=1024,
                on_process_started=refused_trace.callback("callback"),
            )
        self.assertEqual(refused_trace.calls, [])
        processes = []
        original_popen = subprocess.Popen

        def capture_popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(self.runner.subprocess, "Popen", capture_popen),
            mock.patch.object(
                self.runner, "_signal_process_group",
                wraps=self.runner._signal_process_group,
            ) as signal_group,
            self.assertRaisesRegex(RuntimeError, "durability failure"),
        ):
            self.runner.run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                cwd=Path(raw), timeout_seconds=5, max_output_bytes=1024,
                on_process_started=lambda: (_ for _ in ()).throw(RuntimeError("durability failure")),
            )
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())
        self.assertGreaterEqual(signal_group.call_count, 1)

    def test_terminal_result_usage_location(self):
        streams = FIXTURE["terminal_streams"]
        self.assertEqual(self.runner.parse_measurement_terminal_usage(streams["valid"].encode())["primary_tokens"], 60)
        with self.assertRaises(ValueError):
            self.runner.parse_measurement_terminal_usage(streams["nested"].encode())

    def test_probe_order_isolation_and_limits(self):
        trace = TraceRecorder()
        responses = iter([
            {"returncode": 0, "stdout": "Claude 1.0\n", "stderr": ""},
            {"returncode": 0, "stdout": "--settings --setting-sources --include-hook-events --no-session-persistence stream-json\n", "stderr": ""},
        ])
        result = self.runner.run_measurement_cli_probes(
            "claude", run_command=lambda argv, **kwargs: (trace.record("metadata_probe", argv=argv, **kwargs) or next(responses)),
        )
        self.assertEqual([call["argv"] for call in trace.calls], [["claude", "--version"], ["claude", "--help"]])
        for call in trace.calls:
            self.assertEqual(call["timeout_seconds"], 10.0)
            self.assertEqual(call["max_output_bytes"], 65536)
            self.assertEqual(set(call["env"]), set(FIXTURE["probe"]["environment_names"]))
        self.assertEqual(result["schema_version"], "contextguard.bench.cli-probe.v1")
        capability_spec = SimpleNamespace(
            cli_capabilities=(
                "--settings", "--setting-sources", "--include-hook-events",
                "--no-session-persistence", "stream-json",
            )
        )
        capability_result = SimpleNamespace(
            returncode=0, timed_out=False, output_truncated=False,
            stdout="--settings --setting-sources --include-hook-events --no-session-persistence stream-json\n",
            stderr="",
        )
        with (
            tempfile.TemporaryDirectory() as raw,
            mock.patch.object(
                self.runner, "_measurement_preflight_env",
                return_value=mock.MagicMock(
                    __enter__=lambda _self: ({}, Path(raw)),
                    __exit__=lambda _self, *_args: False,
                ),
            ),
            mock.patch.object(self.runner, "run_bounded_command", return_value=capability_result),
        ):
            self.assertIsNone(
                self.runner.validate_measurement_cli_capabilities("claude", capability_spec)
            )
        action_trace = TraceRecorder()
        with tempfile.TemporaryDirectory() as raw:
            action = self.runner.run_measurement_study_action(
                action="prepare", study_plan=FIXTURE["study_plan"],
                task_ids=FIXTURE["task_ids"], variants=("baseline", "treatment"),
                output_root=Path(raw) / "out", claude_bin="claude",
                cli_probe_runner=lambda *_args, **_kwargs: (
                    action_trace.record("probe_equality") or result
                ),
                perform_action=lambda *_args, **_kwargs: (
                    action_trace.record("later_work") or {"action": "prepare"}
                ),
            )
        self.assertEqual(action["action"], "prepare")
        self.assertEqual([call["kind"] for call in action_trace.calls], ["probe_equality", "later_work"])
        failed_trace = TraceRecorder()
        with tempfile.TemporaryDirectory() as raw:
            failed_root = Path(raw) / "out"
            drifted = dict(result, version_stdout_sha256="0" * 64)
            with self.assertRaises(ValueError):
                self.runner.run_measurement_study_action(
                    action="prepare", study_plan=FIXTURE["study_plan"],
                    task_ids=FIXTURE["task_ids"], variants=("baseline", "treatment"),
                    output_root=failed_root, claude_bin="claude",
                    expected_cli_probe=result,
                    cli_probe_runner=lambda *_args, **_kwargs: (
                        failed_trace.record("probe_drift") or drifted
                    ),
                    perform_action=lambda *_args, **_kwargs: (
                        failed_trace.record("later_work") or {"action": "prepare"}
                    ),
                )
            self.assertEqual([call["kind"] for call in failed_trace.calls], ["probe_drift"])
            self.assertFalse(failed_root.exists())

    def test_prelaunch_refused_is_durable_terminal(self):
        events = [_event("retry", 1, "conditional"), _event("retry", 1, "eligible"), _event("retry", 1, "prelaunch_refused", consumed=False, reason="validation_refused")]
        folded = self.runner.fold_study_attempt_events(events)
        self.assertEqual(folded[("retry", 1)]["state"], "prelaunch_refused")
        trace = TraceRecorder()
        result = self.runner._execute_measurement_study(action="resume", manifest={"slots": []}, folded_attempts=folded, run_slot=trace.callback("slot"))
        self.assertEqual(trace.calls, [])
        self.assertFalse(result["study_valid"])

    def test_checker_outcome_matrix(self):
        allowed = (
            (_checker_result(self.runner, returncode=0), "task_success"),
            (_checker_result(self.runner, returncode=1), "valid_task_failure_v1"),
        )
        invalid_rows = [
            _checker_result(
                self.runner, returncode=125, output_truncated=True,
                stdout="truncated", stdout_bytes=b"truncated",
            ),
            _checker_result(
                self.runner, returncode=125, output_truncated=True,
                stderr="truncated", stderr_bytes=b"truncated",
            ),
            _checker_result(
                self.runner, returncode=125, output_truncated=True,
                stdout_bytes=b"x" * 65_537,
            ),
            _checker_result(
                self.runner, returncode=125, output_truncated=True,
                stdout_bytes=(b"x\n" * 4_097),
            ),
            _checker_result(
                self.runner, returncode=125, output_truncated=True,
                stdout_bytes=b"x" * 16_385,
            ),
            _checker_result(self.runner, returncode=124, timed_out=True),
            _checker_result(self.runner, returncode=-15),
            _checker_result(self.runner, returncode=-1, stderr="abnormal process status"),
            _checker_result(self.runner, returncode=126, launch_error=True),
        ]
        invalid_rows.extend(
            _checker_result(self.runner, returncode=returncode)
            for returncode in range(2, 256)
        )
        for row, result in allowed:
            with self.subTest(allowed=row):
                self.assertEqual(self.runner.classify_success_checker(row), result)
        for row in invalid_rows:
            with self.subTest(invalid=row):
                self.assertEqual(
                    self.runner.classify_success_checker(row),
                    "success_checker_infra_invalid",
                )
        prechecker_invalid_reasons = (
            "terminal_evidence_invalid",
            "fixture_parse_rejection",
            "unsafe_success_command",
            "unsafe_success_cwd",
            "success_checker_launch_failure",
            "success_checker_stdout_truncation",
            "success_checker_stderr_truncation",
            "success_checker_output_byte_limit",
            "success_checker_output_line_limit",
            "success_checker_output_line_byte_limit",
            "success_checker_timeout",
            "success_checker_signal",
            "success_checker_abnormal_exit",
        )
        retry_slot = {"run_id": "retry-checker", "attempt": 1, "state": "eligible"}
        classified_rows = [
            (row, self.runner.classify_success_checker(row), None)
            for row in [item[0] for item in allowed] + invalid_rows
        ]
        classified_rows.extend(
            (None, "success_checker_infra_invalid", reason)
            for reason in prechecker_invalid_reasons
        )
        for row, classification, reason in classified_rows:
            trace = TraceRecorder()
            execution = self.runner._execute_measurement_study(
                action="resume", manifest={"slots": [retry_slot]},
                folded_attempts={
                    ("initial-checker", 0): {
                        "run_id": "initial-checker", "attempt": 0, "state": "terminal",
                        "terminal_status": classification, "infra_reason": reason,
                        "consumed": True,
                    }
                },
                run_slot=trace.callback("slot", result={"state": "terminal"}),
            )
            if classification == "valid_task_failure_v1":
                self.assertEqual([call["args"][0]["run_id"] for call in trace.calls], ["retry-checker"])
                self.assertEqual(execution["selected_run_ids"], ["retry-checker"])
            else:
                self.assertEqual(trace.calls, [])

    def test_probe_root_canonicalization(self):
        with tempfile.TemporaryDirectory() as first_parent, tempfile.TemporaryDirectory() as second_parent:
            first = self.runner.create_measurement_probe_layout(Path(first_parent))
            second = self.runner.create_measurement_probe_layout(Path(second_parent))
            for layout in (first, second):
                canonical = self.runner.validate_measurement_probe_layout(layout)
                self.assertEqual(canonical["paths"], FIXTURE["probe"]["canonical_paths"])
                self.assertEqual(stat.S_IMODE(Path(layout["root"]).lstat().st_mode), 0o700)
                self.assertTrue(all(stat.S_ISDIR(Path(path).lstat().st_mode) for key, path in layout.items() if key != "root"))
            self.assertNotEqual(first["root"], second["root"])
            self.assertEqual(self.runner.validate_measurement_probe_layout(first)["paths"], self.runner.validate_measurement_probe_layout(second)["paths"])
            manifest = self.runner.build_measurement_study_manifest(
                study_plan=FIXTURE["study_plan"], tasks={"task_ids": FIXTURE["task_ids"]},
                variants={"arms": ["baseline", "treatment"]},
                cli_probe={"schema_version": "contextguard.bench.cli-probe.v1", "paths": FIXTURE["probe"]["canonical_paths"]},
                runner_sha256="5" * 64, mirror_sha256="5" * 64,
            )
            manifest_bytes = canonical_json_bytes(manifest)
            self.assertNotIn(str(first["root"]).encode(), manifest_bytes)
            self.assertNotIn(str(second["root"]).encode(), manifest_bytes)
            self.assertEqual(
                self.runner.validate_measurement_study_manifest(manifest_bytes, expected=manifest),
                manifest,
            )
            with self.assertRaises(ValueError):
                self.runner.run_measurement_study_action(
                    action="prepare", study_plan=FIXTURE["study_plan"],
                    task_ids=FIXTURE["task_ids"], variants=("baseline", "treatment"),
                    output_root=Path(first_parent) / "out", claude_bin="claude",
                    probe_layout=first, prior_probe_roots={str(first["root"])},
                )
            victim = Path(first["home"])
            victim.rmdir(); victim.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.runner.validate_measurement_probe_layout(first)
            victim.unlink()
            outside = Path(first_parent) / "outside"
            outside.write_text("hardlinked object", encoding="utf-8")
            os.link(outside, victim)
            with self.assertRaises(ValueError):
                self.runner.validate_measurement_probe_layout(first)
            victim.unlink()
            victim.symlink_to(outside)
            with self.assertRaises(ValueError):
                self.runner.validate_measurement_probe_layout(first)
            victim.unlink()
            victim.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                self.runner.validate_measurement_probe_layout(first)


if __name__ == "__main__":
    unittest.main()
