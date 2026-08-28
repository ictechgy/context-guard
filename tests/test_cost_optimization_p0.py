from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECEIPT_ENTRYPOINTS = (
    ROOT
    / "packages"
    / "context-guard-receipt"
    / "python"
    / "context_guard_receipt"
    / "bootstrap.py",
)


def write_canonical_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def run_receipt_evaluator(
    entrypoint: Path, evaluator: str, envelope: object
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp:
        envelope_path = Path(temp) / "evaluation.json"
        write_canonical_json(envelope_path, envelope)
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(entrypoint),
                "receipt",
                "evaluate",
                evaluator,
                "--input",
                str(envelope_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


class FullWireBudgetTests(unittest.TestCase):
    def run_full_wire(
        self,
        entrypoint: Path,
        baseline: dict[str, object],
        candidate: dict[str, object],
        *extra: str,
    ) -> subprocess.CompletedProcess[str]:
        protected_pointers = ["/system"]
        extra_arguments = list(extra)
        while "--protected-pointer" in extra_arguments:
            index = extra_arguments.index("--protected-pointer")
            protected_pointers.append(extra_arguments[index + 1])
            del extra_arguments[index : index + 2]
        envelope = {
            "baseline": baseline,
            "candidate": candidate,
            "enforce": "--enforce" in extra_arguments,
            "protected_pointers": protected_pointers,
            "schema_version": "contextguard.full-wire-budget-request/v1",
        }
        return run_receipt_evaluator(entrypoint, "full-wire", envelope)

    def test_full_wire_blocks_total_growth_even_when_context_is_smaller(self) -> None:
        secret_marker = "sk-test-do-not-emit-1234567890"
        baseline = {
            "model": "sonnet",
            "max_tokens": 512,
            "system": "stable instructions",
            "tools": [{"name": "read", "description": "small"}],
            "messages": [{"role": "user", "content": "x" * 4_000 + secret_marker}],
        }
        candidate = {
            "model": "sonnet",
            "max_tokens": 512,
            "system": "stable instructions",
            "tools": [{"name": "read", "description": "y" * 6_000}],
            "messages": [{"role": "user", "content": "short"}],
        }

        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = self.run_full_wire(entrypoint, baseline, candidate, "--enforce")
                self.assertEqual(result.returncode, 3, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["decision"], "block")
                self.assertIn(
                    "candidate_request_exceeds_baseline", report["blocking_reasons"]
                )
                self.assertGreater(report["wire_budget"]["delta_bytes"], 0)
                self.assertFalse(report["privacy"]["raw_request_emitted"])
                self.assertFalse(report["privacy"]["raw_request_stored"])
                self.assertNotIn(secret_marker, result.stdout)
                self.assertNotIn(secret_marker, result.stderr)

    def test_full_wire_allows_smaller_candidate_with_stable_protected_content(self) -> None:
        baseline = {
            "model": "sonnet",
            "max_tokens": 512,
            "system": [{"type": "text", "text": "stable"}],
            "tools": [{"name": "read", "description": "schema"}],
            "messages": [{"role": "user", "content": "context" * 1_000}],
        }
        candidate = {
            "model": "sonnet",
            "max_tokens": 512,
            "system": [{"type": "text", "text": "stable"}],
            "tools": [{"name": "read", "description": "schema"}],
            "messages": [{"role": "user", "content": "context" * 10}],
        }

        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = self.run_full_wire(entrypoint, baseline, candidate, "--enforce")
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["decision"], "allow")
                self.assertEqual(report["blocking_reasons"], [])
                self.assertLess(report["wire_budget"]["delta_bytes"], 0)
                self.assertTrue(report["protected_content"]["all_unchanged"])
                self.assertTrue(report["output_budget"]["non_increasing"])

    def test_full_wire_blocks_protected_change_and_output_budget_growth(self) -> None:
        baseline = {
            "model": "sonnet",
            "max_tokens": 256,
            "system": "do not change",
            "messages": [{"role": "user", "content": "baseline" * 100}],
        }
        candidate = {
            "model": "sonnet",
            "max_tokens": 1_024,
            "system": "changed",
            "messages": [{"role": "user", "content": "small"}],
        }

        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = self.run_full_wire(entrypoint, baseline, candidate, "--enforce")
                self.assertEqual(result.returncode, 3, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(
                    report["blocking_reasons"],
                    ["output_budget_increased", "protected_content_changed"],
                )
                self.assertEqual(
                    report["protected_content"]["changed_pointer_indexes"], [1]
                )
                self.assertEqual(report["output_budget"]["baseline_max_tokens"], 256)
                self.assertEqual(report["output_budget"]["candidate_max_tokens"], 1_024)

    def test_full_wire_never_reflects_protected_pointer_text(self) -> None:
        secret_pointer = "/sk-test-sensitive-field-name"
        baseline = {
            "model": "sonnet",
            "max_tokens": 32,
            "system": "stable",
            "messages": [],
        }
        candidate = dict(baseline)

        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = self.run_full_wire(
                    entrypoint,
                    baseline,
                    candidate,
                    "--protected-pointer",
                    secret_pointer,
                    "--enforce",
                )
                self.assertEqual(result.returncode, 3, result.stderr)
                report = json.loads(result.stdout)
                self.assertNotIn(secret_pointer, result.stdout)
                self.assertNotIn(secret_pointer, result.stderr)
                self.assertIn(2, report["protected_content"]["missing_pointer_indexes"])


class CostCalibrationTests(unittest.TestCase):
    MODEL_HMAC = "a" * 64

    def calibration_envelope(self, *, minimum_samples: int = 3) -> dict[str, object]:
        preflights = []
        observations = []
        for index, cache_read_tokens in enumerate((0, 20, 0), start=1):
            request_hmac = f"{index:064x}"
            preflights.append(
                {
                    "estimated_input_tokens": 100,
                    "model_hmac": self.MODEL_HMAC,
                    "output_token_budget": 1_000,
                    "predicted_cache_state": "hit" if index == 2 else "miss",
                    "request_hmac": request_hmac,
                }
            )
            observations.append(
                {
                    "model_hmac": self.MODEL_HMAC,
                    "observed_cache_read_tokens": cache_read_tokens,
                    "observed_input_tokens": 120,
                    "observed_output_tokens": 200,
                    "request_hmac": request_hmac,
                }
            )
        return {
            "minimum_samples": minimum_samples,
            "observations": observations,
            "preflights": preflights,
            "schema_version": "contextguard.cost-calibration-request/v1",
        }

    def test_calibration_joins_hmac_pairs_and_recommends_integer_corrections(self) -> None:
        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = run_receipt_evaluator(
                    entrypoint, "calibration", self.calibration_envelope()
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["matched_pair_count"], 3)
                self.assertEqual(report["unmatched_preflight_count"], 0)
                self.assertEqual(report["unmatched_observation_count"], 0)
                group = report["groups"][0]
                self.assertEqual(group["model_hmac"], self.MODEL_HMAC)
                self.assertEqual(group["sample_count"], 3)
                self.assertEqual(group["readiness"], "recommendation_ready")
                self.assertEqual(
                    group["input_estimate_multiplier_basis_points"], 12_000
                )
                self.assertEqual(group["cache_prediction_accuracy_basis_points"], 10_000)
                self.assertEqual(group["output_budget_utilization_basis_points"], 2_000)
                self.assertFalse(report["authority"]["auto_apply_allowed"])

    def test_calibration_with_insufficient_samples_emits_no_recommendation(self) -> None:
        envelope = self.calibration_envelope(minimum_samples=5)
        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = run_receipt_evaluator(entrypoint, "calibration", envelope)
                self.assertEqual(result.returncode, 0, result.stderr)
                group = json.loads(result.stdout)["groups"][0]
                self.assertEqual(group["readiness"], "insufficient_evidence")
                self.assertIsNone(group["input_estimate_multiplier_basis_points"])
                self.assertIsNone(group["cache_prediction_accuracy_basis_points"])
                self.assertIsNone(group["output_budget_utilization_basis_points"])

    def test_calibration_rejects_non_hmac_identity_without_reflection(self) -> None:
        secret_label = "sk-test-calibration-identity"
        envelope = self.calibration_envelope()
        envelope["preflights"][0]["request_hmac"] = secret_label  # type: ignore[index]
        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = run_receipt_evaluator(entrypoint, "calibration", envelope)
                self.assertEqual(result.returncode, 65)
                self.assertEqual(result.stdout, "")
                self.assertNotIn(secret_label, result.stderr)


class CostOptimizationCliTests(unittest.TestCase):
    def test_route_v2_cli_emits_shadow_total_cost_decision(self) -> None:
        envelope = {
            "baseline_total_microusd": 1_000,
            "candidate": {
                "cache": 20,
                "expansion": 30,
                "helper": 50,
                "local": 0,
                "provider_input": 200,
                "provider_output": 250,
                "retry": 0,
            },
            "context": {
                "evidence_complete": True,
                "full_wire_ceiling_respected": True,
                "quality_gate": "pass",
                "risk": "low",
            },
            "policy": {
                "minimum_savings_basis_points": 1_000,
                "minimum_savings_microusd": 100,
            },
            "schema_version": "contextguard.total-cost-route-request/v1",
        }
        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = run_receipt_evaluator(entrypoint, "route-v2", envelope)
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["decision"]["mode"], "shadow")
                self.assertEqual(
                    report["decision"]["recommended_disposition"], "defer"
                )
                self.assertEqual(
                    report["decision"]["candidate_total_microusd"], 550
                )
                self.assertFalse(report["decision"]["runtime_applied"])
                self.assertFalse(report["authority"]["runtime_route_authorized"])

    def test_calibration_rejects_unbounded_model_group_fanout(self) -> None:
        package_python = (
            ROOT / "packages" / "context-guard-receipt" / "python"
        )
        if str(package_python) not in sys.path:
            sys.path.insert(0, str(package_python))
        from context_guard_receipt.cost_optimization import (
            FullWireError,
            evaluate_cost_calibration,
        )

        preflights = []
        observations = []
        for index in range(65):
            model_hmac = f"{index + 1:064x}"
            request_hmac = f"{index + 101:064x}"
            preflights.append(
                {
                    "estimated_input_tokens": 10,
                    "model_hmac": model_hmac,
                    "output_token_budget": 10,
                    "predicted_cache_state": "unknown",
                    "request_hmac": request_hmac,
                }
            )
            observations.append(
                {
                    "model_hmac": model_hmac,
                    "observed_cache_read_tokens": 0,
                    "observed_input_tokens": 10,
                    "observed_output_tokens": 1,
                    "request_hmac": request_hmac,
                }
            )
        envelope = {
            "minimum_samples": 1,
            "observations": observations,
            "preflights": preflights,
            "schema_version": "contextguard.cost-calibration-request/v1",
        }
        with self.assertRaises(FullWireError):
            evaluate_cost_calibration(envelope)
        for entrypoint in RECEIPT_ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = run_receipt_evaluator(entrypoint, "calibration", envelope)
                self.assertEqual(result.returncode, 65)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
