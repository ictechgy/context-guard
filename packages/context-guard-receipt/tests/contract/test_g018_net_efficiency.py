from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
ROOT = PACKAGE_ROOT.parents[1]
ENTRYPOINT = (
    ROOT
    / "packages"
    / "context-guard-receipt"
    / "python"
    / "context_guard_receipt"
    / "bootstrap.py"
)


def run_evaluator(name: str, envelope: object) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        request = Path(directory) / "request.json"
        request.write_text(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(ENTRYPOINT),
                "receipt",
                "evaluate",
                name,
                "--input",
                str(request),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


def run_metrics(
    *,
    success: bool,
    quality: int,
    provider_cost: int,
    shifted_cost: int,
    wall_time: int,
    output_tokens: int,
    model_requests: int,
) -> dict[str, object]:
    return {
        "cache_read_tokens": 1_000,
        "cache_write_tokens": 100,
        "correction_turns": 0,
        "model_requests": model_requests,
        "provider_cost_microusd": provider_cost,
        "provider_input_tokens": 2_000,
        "provider_output_tokens": output_tokens,
        "quality_basis_points": quality,
        "rehydration_calls": 0,
        "shifted_cost_microusd": shifted_cost,
        "success": success,
        "tool_calls": 4,
        "tool_yields": 2,
        "wall_time_ms": wall_time,
    }


class NetEfficiencyTests(unittest.TestCase):
    def envelope(self) -> dict[str, object]:
        pairs = []
        for index in range(3):
            pairs.append(
                {
                    "baseline": run_metrics(
                        success=True,
                        quality=9_000,
                        provider_cost=1_000,
                        shifted_cost=100,
                        wall_time=1_000 + index,
                        output_tokens=500,
                        model_requests=5,
                    ),
                    "candidate": run_metrics(
                        success=True,
                        quality=9_000,
                        provider_cost=700,
                        shifted_cost=100,
                        wall_time=800 + index,
                        output_tokens=350,
                        model_requests=4,
                    ),
                    "pair_hmac": f"{index + 201:064x}",
                    "task_hmac": f"{index + 1:064x}",
                    "run_window_hmac": f"{(index % 2) + 101:064x}",
                }
            )
        return {
            "pairs": pairs,
            "policy": {
                "maximum_correction_turn_regression_basis_points": 0,
                "maximum_cost_per_success_regression_basis_points": 0,
                "maximum_model_request_regression_basis_points": 0,
                "maximum_output_regression_basis_points": 0,
                "maximum_p95_wall_time_regression_basis_points": 0,
                "maximum_rehydration_call_regression_basis_points": 0,
                "maximum_tool_call_regression_basis_points": 0,
                "maximum_tool_yield_regression_basis_points": 0,
                "minimum_distinct_run_windows": 2,
                "minimum_net_improvement_basis_points": 1_000,
                "quality_noninferiority_margin_basis_points": 0,
                "success_noninferiority_margin_basis_points": 0,
            },
            "schema_version": "contextguard.net-efficiency-request/v1",
        }

    def test_net_efficiency_recommends_only_quality_safe_full_cost_improvement(self) -> None:
        result = run_evaluator("net-efficiency", self.envelope())

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "recommend")
        self.assertTrue(report["quality"]["noninferior"])
        self.assertGreaterEqual(
            report["efficiency"]["cost_per_success_improvement_basis_points"],
            1_000,
        )
        self.assertGreaterEqual(
            report["efficiency"]["p95_wall_time_improvement_basis_points"],
            1_000,
        )
        self.assertEqual(report["blocking_reasons"], [])
        self.assertFalse(report["authority"]["runtime_apply_allowed"])

    def test_net_efficiency_blocks_cheap_failure_and_output_round_trip_regression(self) -> None:
        envelope = self.envelope()
        candidate = envelope["pairs"][0]["candidate"]  # type: ignore[index]
        candidate.update(  # type: ignore[union-attr]
            {
                "success": False,
                "quality_basis_points": 0,
                "provider_cost_microusd": 1,
                "provider_output_tokens": 900,
                "model_requests": 8,
            }
        )

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("success_rate_regressed", report["blocking_reasons"])
        self.assertIn("quality_regressed", report["blocking_reasons"])
        self.assertIn("matched_pair_failed", report["blocking_reasons"])
        self.assertIn("output_tokens_regressed", report["blocking_reasons"])
        self.assertIn("model_requests_regressed", report["blocking_reasons"])

    def test_net_efficiency_allows_repeated_tasks_across_unique_pairs(self) -> None:
        envelope = self.envelope()
        envelope["pairs"][1]["task_hmac"] = envelope["pairs"][0]["task_hmac"]  # type: ignore[index]

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "recommend")
        self.assertEqual(report["matched_pair_count"], 3)
        self.assertEqual(report["matched_task_count"], 2)

    def test_net_efficiency_holds_shifted_correction_and_tool_work(self) -> None:
        envelope = self.envelope()
        envelope["pairs"][0]["candidate"].update(  # type: ignore[index]
            {
                "correction_turns": 1,
                "rehydration_calls": 1,
                "tool_calls": 10,
                "tool_yields": 5,
            }
        )

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("correction_turns_regressed", report["blocking_reasons"])
        self.assertIn("rehydration_calls_regressed", report["blocking_reasons"])
        self.assertIn("tool_calls_regressed", report["blocking_reasons"])
        self.assertIn("tool_yields_regressed", report["blocking_reasons"])

    def test_net_efficiency_holds_when_canary_windows_are_not_distinct(self) -> None:
        envelope = self.envelope()
        for pair in envelope["pairs"]:  # type: ignore[union-attr]
            pair["run_window_hmac"] = "f" * 64

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("insufficient_canary_windows", report["blocking_reasons"])
        self.assertEqual(report["canary"]["distinct_run_window_count"], 1)
        self.assertEqual(report["canary"]["minimum_distinct_run_windows"], 2)

    def test_net_efficiency_holds_when_baseline_has_no_valid_success(self) -> None:
        envelope = self.envelope()
        for pair in envelope["pairs"]:  # type: ignore[union-attr]
            pair["baseline"]["success"] = False
            pair["baseline"]["quality_basis_points"] = 0

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn(
            "baseline_has_no_successful_tasks", report["blocking_reasons"]
        )

    def test_net_efficiency_does_not_round_tiny_cost_improvement_to_full_savings(self) -> None:
        envelope = self.envelope()
        template = envelope["pairs"][0]  # type: ignore[index]
        pairs = []
        for index in range(256):
            pair = json.loads(json.dumps(template))
            pair["pair_hmac"] = f"{index + 1:064x}"
            pair["run_window_hmac"] = f"{(index % 2) + 500:064x}"
            pair["task_hmac"] = f"{(index % 16) + 700:064x}"
            pair["baseline"].update(
                {
                    "provider_cost_microusd": 1,
                    "provider_output_tokens": 500,
                    "model_requests": 5,
                    "shifted_cost_microusd": 0,
                    "wall_time_ms": 1_000,
                }
            )
            pair["candidate"].update(
                {
                    "provider_cost_microusd": 0 if index == 0 else 1,
                    "provider_output_tokens": 500,
                    "model_requests": 5,
                    "shifted_cost_microusd": 0,
                    "wall_time_ms": 1_000,
                }
            )
            pairs.append(pair)
        envelope["pairs"] = pairs

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertEqual(
            report["efficiency"]["cost_per_success_improvement_basis_points"],
            39,
        )
        self.assertEqual(
            report["efficiency"]["candidate"]["cost_per_success_microusd"],
            1,
        )
        self.assertIn("insufficient_net_improvement", report["blocking_reasons"])

    def test_noninferiority_margin_cannot_hide_a_matched_candidate_failure(self) -> None:
        envelope = self.envelope()
        envelope["pairs"] = envelope["pairs"][:2]  # type: ignore[index]
        envelope["policy"]["success_noninferiority_margin_basis_points"] = 5_000  # type: ignore[index]
        envelope["policy"]["quality_noninferiority_margin_basis_points"] = 5_000  # type: ignore[index]
        failed = envelope["pairs"][1]["candidate"]  # type: ignore[index]
        failed.update(
            {
                "provider_cost_microusd": 0,
                "provider_output_tokens": 500,
                "model_requests": 5,
                "quality_basis_points": 0,
                "shifted_cost_microusd": 0,
                "success": False,
                "wall_time_ms": 500,
            }
        )
        successful = envelope["pairs"][0]["candidate"]  # type: ignore[index]
        successful.update(
            {
                "provider_output_tokens": 500,
                "model_requests": 5,
            }
        )

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("matched_pair_failed", report["blocking_reasons"])

    def test_basis_point_thresholds_use_exact_comparisons(self) -> None:
        model_envelope = self.envelope()
        model_envelope["pairs"] = model_envelope["pairs"][:1]  # type: ignore[index]
        model_envelope["policy"]["minimum_distinct_run_windows"] = 1  # type: ignore[index]
        model_envelope["policy"][  # type: ignore[index]
            "maximum_model_request_regression_basis_points"
        ] = 3_333
        baseline = model_envelope["pairs"][0]["baseline"]  # type: ignore[index]
        candidate = model_envelope["pairs"][0]["candidate"]  # type: ignore[index]
        baseline.update({"model_requests": 3, "wall_time_ms": 1_000})
        candidate.update(
            {
                "model_requests": 4,
                "provider_cost_microusd": 500,
                "wall_time_ms": 800,
            }
        )

        model_result = run_evaluator("net-efficiency", model_envelope)

        self.assertEqual(model_result.returncode, 0, model_result.stderr)
        model_report = json.loads(model_result.stdout)
        self.assertEqual(model_report["decision"], "hold")
        self.assertIn("model_requests_regressed", model_report["blocking_reasons"])

        latency_envelope = self.envelope()
        latency_envelope["pairs"] = latency_envelope["pairs"][:1]  # type: ignore[index]
        latency_envelope["policy"]["minimum_distinct_run_windows"] = 1  # type: ignore[index]
        latency_envelope["policy"]["minimum_net_improvement_basis_points"] = 3_334  # type: ignore[index]
        baseline = latency_envelope["pairs"][0]["baseline"]  # type: ignore[index]
        candidate = latency_envelope["pairs"][0]["candidate"]  # type: ignore[index]
        baseline.update({"provider_cost_microusd": 1_000, "wall_time_ms": 3})
        candidate.update(
            {
                "model_requests": baseline["model_requests"],
                "provider_cost_microusd": 1_000,
                "provider_output_tokens": baseline["provider_output_tokens"],
                "wall_time_ms": 2,
            }
        )

        latency_result = run_evaluator("net-efficiency", latency_envelope)

        self.assertEqual(latency_result.returncode, 0, latency_result.stderr)
        latency_report = json.loads(latency_result.stdout)
        self.assertEqual(latency_report["decision"], "hold")
        self.assertIn(
            "insufficient_net_improvement", latency_report["blocking_reasons"]
        )

    def test_repeated_task_cannot_dilute_another_tasks_quality_collapse(self) -> None:
        envelope = self.envelope()
        template = envelope["pairs"][0]  # type: ignore[index]
        pairs = []
        for index in range(100):
            pair = json.loads(json.dumps(template))
            pair["pair_hmac"] = f"{index + 1:064x}"
            pair["run_window_hmac"] = f"{(index % 2) + 900:064x}"
            pair["task_hmac"] = "a" * 64 if index < 99 else "b" * 64
            pair["candidate"]["provider_cost_microusd"] = 500
            pair["candidate"]["wall_time_ms"] = 500
            if index == 99:
                pair["candidate"]["quality_basis_points"] = 0
            pairs.append(pair)
        envelope["pairs"] = pairs
        envelope["policy"]["quality_noninferiority_margin_basis_points"] = 90  # type: ignore[index]

        result = run_evaluator("net-efficiency", envelope)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("task_quality_regressed", report["blocking_reasons"])
        self.assertFalse(report["quality"]["task_quality_noninferior"])

    def test_net_efficiency_holds_candidates_dominated_on_cost_or_latency(self) -> None:
        for field, value, expected_reason in (
            ("provider_cost_microusd", 2_000, "cost_per_success_regressed"),
            ("wall_time_ms", 2_000, "p95_wall_time_regressed"),
        ):
            with self.subTest(field=field):
                envelope = self.envelope()
                for pair in envelope["pairs"]:  # type: ignore[union-attr]
                    pair["candidate"][field] = value

                result = run_evaluator("net-efficiency", envelope)

                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["decision"], "hold")
                self.assertIn(expected_reason, report["blocking_reasons"])


class PrefixPlanTests(unittest.TestCase):
    def test_prefix_plan_detects_tool_drift_and_prefers_native_deferred_loading(self) -> None:
        result = run_evaluator(
            "prefix-plan",
            {
                "baseline": {
                    "context_management_hmac": "a" * 64,
                    "effort_hmac": "b" * 64,
                    "stable_prefix_tokens": 12_000,
                    "system_hmac": "c" * 64,
                    "tools_hmac": "d" * 64,
                    "verbosity_hmac": "e" * 64,
                },
                "cache_policy": {
                    "expected_reuses": 10,
                    "minimum_cacheable_tokens": 1_024,
                    "read_multiplier_basis_points": 1_000,
                    "write_multiplier_basis_points": 12_500,
                },
                "candidate": {
                    "context_management_hmac": "a" * 64,
                    "effort_hmac": "b" * 64,
                    "stable_prefix_tokens": 8_000,
                    "system_hmac": "c" * 64,
                    "tools_hmac": "f" * 64,
                    "verbosity_hmac": "e" * 64,
                },
                "capabilities": {
                    "supports_deferred_tools": True,
                    "supports_explicit_breakpoints": True,
                },
                "schema_version": "contextguard.prefix-plan-request/v1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["changed_components"], ["tools"])
        self.assertFalse(report["cache_prefix_preserved"])
        self.assertEqual(
            report["recommendation"], "evaluate_native_deferred_loading"
        )
        self.assertTrue(report["amortization"]["candidate_cache_eligible"])
        self.assertNotIn("a" * 64, result.stdout)
        self.assertNotIn("f" * 64, result.stdout)


class FanoutPlanTests(unittest.TestCase):
    def test_fanout_plan_requires_independent_multi_call_payload_reduction(self) -> None:
        result = run_evaluator(
            "fanout-plan",
            {
                "policy": {
                    "maximum_shifted_cost_microusd": 500,
                    "minimum_operations": 3,
                    "minimum_payload_reduction_basis_points": 2_000,
                },
                "schema_version": "contextguard.fanout-plan-request/v1",
                "workload": {
                    "estimated_model_round_trips_baseline": 8,
                    "estimated_returned_bytes": 10_000,
                    "estimated_source_bytes": 100_000,
                    "independent": True,
                    "operation_count": 8,
                    "sequential_dependency": False,
                    "shifted_cost_microusd": 100,
                },
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "eligible")
        self.assertEqual(report["blocking_reasons"], [])
        self.assertEqual(report["projected_model_round_trip_reduction"], 7)
        self.assertEqual(report["payload_reduction_basis_points"], 9_000)
        self.assertFalse(report["authority"]["execution_authorized"])

    def test_fanout_plan_holds_sequential_single_call_work(self) -> None:
        result = run_evaluator(
            "fanout-plan",
            {
                "policy": {
                    "maximum_shifted_cost_microusd": 500,
                    "minimum_operations": 3,
                    "minimum_payload_reduction_basis_points": 2_000,
                },
                "schema_version": "contextguard.fanout-plan-request/v1",
                "workload": {
                    "estimated_model_round_trips_baseline": 1,
                    "estimated_returned_bytes": 100,
                    "estimated_source_bytes": 100,
                    "independent": False,
                    "operation_count": 1,
                    "sequential_dependency": True,
                    "shifted_cost_microusd": 0,
                },
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["decision"], "hold")
        self.assertIn("sequential_dependency", report["blocking_reasons"])
        self.assertIn("insufficient_operations", report["blocking_reasons"])
        self.assertIn("no_round_trip_reduction", report["blocking_reasons"])


class PrunePlanTests(unittest.TestCase):
    def test_prune_plan_selects_only_stale_exact_unprotected_results_at_boundary(self) -> None:
        result = run_evaluator(
            "prune-plan",
            {
                "items": [
                    {
                        "age_turns": 9,
                        "bytes": 8_000,
                        "exact_fallback": True,
                        "protected": False,
                        "rehydration_count": 0,
                    },
                    {
                        "age_turns": 20,
                        "bytes": 12_000,
                        "exact_fallback": True,
                        "protected": True,
                        "rehydration_count": 0,
                    },
                    {
                        "age_turns": 20,
                        "bytes": 12_000,
                        "exact_fallback": False,
                        "protected": False,
                        "rehydration_count": 0,
                    },
                ],
                "policy": {
                    "maximum_pruned_bytes": 16_000,
                    "maximum_rehydrations": 1,
                    "minimum_age_turns": 5,
                    "minimum_result_bytes": 2_000,
                },
                "schema_version": "contextguard.prune-plan-request/v1",
                "task_boundary": True,
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["selected_indexes"], [0])
        self.assertEqual(report["projected_pruned_bytes"], 8_000)
        self.assertEqual(report["retained_reason_counts"]["protected"], 1)
        self.assertEqual(report["retained_reason_counts"]["fallback_unavailable"], 1)
        self.assertFalse(report["authority"]["transcript_mutation_allowed"])


class ShadowPolicyTests(unittest.TestCase):
    def test_shadow_policy_keeps_noop_on_tie_and_rejects_incomplete_candidates(self) -> None:
        result = run_evaluator(
            "shadow-policy",
            {
                "candidates": [
                    {
                        "cost_per_success_microusd": 1_000,
                        "evidence_complete": True,
                        "lane": "no_op",
                        "net_efficiency_decision": "baseline",
                        "p95_wall_time_ms": 1_000,
                        "quality_noninferior": True,
                    },
                    {
                        "cost_per_success_microusd": 1_000,
                        "evidence_complete": True,
                        "lane": "output_control",
                        "net_efficiency_decision": "recommend",
                        "p95_wall_time_ms": 1_000,
                        "quality_noninferior": True,
                    },
                    {
                        "cost_per_success_microusd": 100,
                        "evidence_complete": False,
                        "lane": "fanout",
                        "net_efficiency_decision": "recommend",
                        "p95_wall_time_ms": 100,
                        "quality_noninferior": True,
                    },
                ],
                "schema_version": "contextguard.shadow-policy-request/v1",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["selected_lane"], "no_op")
        self.assertEqual(report["reason"], "no_improvement_over_noop")
        self.assertFalse(report["authority"]["runtime_route_authorized"])
        self.assertFalse(report["runtime_applied"])

    def test_shadow_policy_rejects_an_incomplete_noop_baseline(self) -> None:
        result = run_evaluator(
            "shadow-policy",
            {
                "candidates": [
                    {
                        "cost_per_success_microusd": 1_000,
                        "evidence_complete": False,
                        "lane": "no_op",
                        "net_efficiency_decision": "baseline",
                        "p95_wall_time_ms": 1_000,
                        "quality_noninferior": True,
                    }
                ],
                "schema_version": "contextguard.shadow-policy-request/v1",
            },
        )

        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")

    def test_evaluators_reject_unclosed_input_without_reflecting_marker(self) -> None:
        marker = "sk-test-net-efficiency-do-not-reflect"
        result = run_evaluator(
            "shadow-policy",
            {
                "candidates": [],
                "schema_version": "contextguard.shadow-policy-request/v1",
                marker: marker,
            },
        )

        self.assertEqual(result.returncode, 65)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(marker, result.stderr)


class ArithmeticBoundaryTests(unittest.TestCase):
    def test_derived_signed_64_overflow_is_rejected_before_result_construction(self) -> None:
        package_python = PACKAGE_ROOT / "python"
        if str(package_python) not in sys.path:
            sys.path.insert(0, str(package_python))
        from context_guard_receipt.net_efficiency import (
            NetEfficiencyError,
            evaluate_fanout_plan,
            evaluate_net_efficiency,
            evaluate_prefix_plan,
        )

        net_envelope = NetEfficiencyTests().envelope()
        net_envelope["pairs"][0]["baseline"]["provider_cost_microusd"] = (  # type: ignore[index]
            2**63 - 1
        )
        prefix_envelope = {
            "baseline": {
                "context_management_hmac": "a" * 64,
                "effort_hmac": "b" * 64,
                "stable_prefix_tokens": 2**63 - 1,
                "system_hmac": "c" * 64,
                "tools_hmac": "d" * 64,
                "verbosity_hmac": "e" * 64,
            },
            "cache_policy": {
                "expected_reuses": 1_000_000,
                "minimum_cacheable_tokens": 1,
                "read_multiplier_basis_points": 100_000,
                "write_multiplier_basis_points": 100_000,
            },
            "candidate": {
                "context_management_hmac": "a" * 64,
                "effort_hmac": "b" * 64,
                "stable_prefix_tokens": 2**63 - 1,
                "system_hmac": "c" * 64,
                "tools_hmac": "d" * 64,
                "verbosity_hmac": "e" * 64,
            },
            "capabilities": {
                "supports_deferred_tools": False,
                "supports_explicit_breakpoints": True,
            },
            "schema_version": "contextguard.prefix-plan-request/v1",
        }
        fanout_envelope = {
            "policy": {
                "maximum_shifted_cost_microusd": 0,
                "minimum_operations": 1,
                "minimum_payload_reduction_basis_points": 0,
            },
            "schema_version": "contextguard.fanout-plan-request/v1",
            "workload": {
                "estimated_model_round_trips_baseline": 2,
                "estimated_returned_bytes": 2**63 - 1,
                "estimated_source_bytes": 1,
                "independent": True,
                "operation_count": 2,
                "sequential_dependency": False,
                "shifted_cost_microusd": 0,
            },
        }

        for evaluator, envelope in (
            (evaluate_net_efficiency, net_envelope),
            (evaluate_prefix_plan, prefix_envelope),
            (evaluate_fanout_plan, fanout_envelope),
        ):
            with self.subTest(evaluator=evaluator.__name__):
                with self.assertRaises(NetEfficiencyError) as caught:
                    evaluator(envelope)
                self.assertEqual(caught.exception.code, "derived_integer_out_of_range")


if __name__ == "__main__":
    unittest.main()
