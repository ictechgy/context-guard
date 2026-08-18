import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
V4 = ROOT / "research/provider-live-roadmap/p3-api/v4"
POLICY = V4 / "budget_policy.py"
REPORT = V4 / "budget-policy-report.json"


def load_policy():
    spec = importlib.util.spec_from_file_location("p3_v4_budget_policy", POLICY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class BudgetPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = load_policy()
        cls.capture_raw = (V3 / "provider-input-freeze.json").read_bytes()
        cls.evidence_raw = (V3 / "provider-evidence.json").read_bytes()
        cls.result_raw = (V3 / "result.json").read_bytes()
        cls.report_raw = REPORT.read_bytes()
        cls.report = json.loads(cls.report_raw)

    def test_report_recomputes_exactly_from_frozen_v3_evidence(self):
        rebuilt = self.policy.build_report(
            self.capture_raw,
            self.result_raw,
            self.evidence_raw,
        )
        self.assertEqual(self.report_raw, self.policy.canonical(rebuilt))
        self.policy.validate_report(
            self.report,
            capture_raw=self.capture_raw,
            evidence_raw=self.evidence_raw,
            result_raw=self.result_raw,
        )
        self.assertEqual(
            self.report["source"]["provider_input_freeze_sha256"],
            hashlib.sha256(self.capture_raw).hexdigest(),
        )
        self.assertEqual(
            self.report["source"]["observed_result_sha256"],
            hashlib.sha256(self.result_raw).hexdigest(),
        )
        self.assertEqual(
            self.report["source"]["provider_evidence_sha256"],
            hashlib.sha256(self.evidence_raw).hexdigest(),
        )

    def test_every_selected_prompt_is_an_existing_frozen_cell_with_no_growth(self):
        capture = json.loads(self.capture_raw)
        cells = {cell["cell_id"]: cell for cell in capture["cells"]}
        self.assertEqual(len(self.report["decisions"]), 96)
        for decision in self.report["decisions"]:
            selected = cells[decision["selected_cell_id"]]
            self.assertEqual(selected["prompt_sha256"], decision["selected_prompt_sha256"])
            self.assertEqual(selected["prompt_bytes"], decision["selected_prompt_bytes"])
            self.assertLessEqual(
                decision["selected_prompt_bytes"],
                decision["ordinary_prompt_ceiling_bytes"],
            )
            self.assertLessEqual(
                set(decision["applied_factors"]),
                set(decision["requested_factors"]),
            )

    def test_policy_closes_the_measured_symbol_and_graph_growth(self):
        diagnosis = self.report["diagnosis"]
        self.assertEqual(diagnosis["historical_cells_over_ordinary_ceiling"], 48)
        self.assertEqual(diagnosis["historical_max_prompt_growth_bytes"], 12_049)
        self.assertEqual(diagnosis["historical_total_prompt_bytes"], 1_269_938)
        self.assertEqual(diagnosis["symbol_projection_bytes_range"], [1_311, 2_121])
        self.assertEqual(diagnosis["graph_changed_tasks"], [
            "requests_boundary_hardening",
            "requests_bug_fix",
            "requests_feature",
            "requests_maintenance",
        ])

        summary = self.report["policy_summary"]
        self.assertEqual(summary["selected_cells_over_ordinary_ceiling"], 0)
        self.assertEqual(summary["selected_max_prompt_growth_bytes"], 0)
        self.assertEqual(summary["selected_total_prompt_bytes"], 1_053_798)
        self.assertEqual(summary["historical_prompt_bytes_avoided"], 216_140)
        self.assertEqual(summary["historical_scheduled_input_tokens"], 1_541_826)
        self.assertEqual(summary["projected_selected_input_tokens"], 1_277_418)
        self.assertEqual(summary["provider_observed_input_tokens_avoided"], 264_408)
        self.assertEqual(summary["provider_observed_input_tokens_avoided_percent"], "17.149017")
        self.assertEqual(summary["factor_decisions"], {
            "adaptive": {"applied": 24, "suppressed_or_no_op": 24},
            "graph_closure": {"applied": 0, "suppressed_or_no_op": 48},
            "symbol_memory": {"applied": 12, "suppressed_or_no_op": 36},
        })

    def test_adaptive_funds_symbol_and_graph_cannot_exceed_the_ceiling(self):
        decisions = {row["requested_cell_id"]: row for row in self.report["decisions"]}
        requests_all = decisions["requests_boundary_hardening:a111"]
        self.assertEqual(requests_all["selected_cell_id"], "requests_boundary_hardening:a110")
        self.assertEqual(requests_all["applied_factors"], ["adaptive", "symbol_memory"])
        self.assertEqual(
            requests_all["factor_outcomes"]["graph_closure"],
            "insufficient_adaptive_headroom",
        )

        no_adaptive = decisions["requests_boundary_hardening:a011"]
        self.assertEqual(no_adaptive["selected_cell_id"], "requests_boundary_hardening:a000")
        self.assertEqual(no_adaptive["applied_factors"], [])

        no_candidates = decisions["typescript_bug_fix:a111"]
        self.assertEqual(no_candidates["selected_cell_id"], "typescript_bug_fix:a000")
        self.assertEqual(
            no_candidates["factor_outcomes"]["graph_closure"],
            "no_provider_byte_change",
        )

        selected = self.policy.select_provider_cell(
            self.capture_raw,
            task_id="requests_boundary_hardening",
            requested_arm_id="a111",
        )
        self.assertEqual(selected, requests_all)
        with self.assertRaisesRegex(ValueError, "unknown_budget_policy_task"):
            self.policy.select_provider_cell(
                self.capture_raw,
                task_id="unknown",
                requested_arm_id="a111",
            )
        with self.assertRaisesRegex(ValueError, "unknown_budget_policy_arm"):
            self.policy.select_provider_cell(
                self.capture_raw,
                task_id="requests_boundary_hardening",
                requested_arm_id="a999",
            )

    def test_tampered_report_or_source_evidence_is_rejected(self):
        altered = copy.deepcopy(self.report)
        altered["policy_summary"]["selected_cells_over_ordinary_ceiling"] = 1
        with self.assertRaisesRegex(ValueError, "budget_policy_report_mismatch"):
            self.policy.validate_report(
                altered,
                capture_raw=self.capture_raw,
                evidence_raw=self.evidence_raw,
                result_raw=self.result_raw,
            )

        altered_capture = bytearray(self.capture_raw)
        altered_capture[-2] ^= 1
        with self.assertRaisesRegex(ValueError, "unexpected_provider_input_freeze"):
            self.policy.build_report(
                bytes(altered_capture),
                self.result_raw,
                self.evidence_raw,
            )

    def test_claims_remain_fail_closed_without_a_new_provider_run(self):
        self.assertEqual(self.report["diagnosis"]["all_on_a111_vs_a000"], {
            "input_token_percent_reduction": "-19.897942",
            "output_token_percent_reduction": "-5.720541",
            "total_provider_token_percent_reduction": "-14.236343",
        })
        self.assertEqual(self.report["claims"], {
            "historical_v3_result_changed": False,
            "input_prompt_byte_growth_prevented_by_construction": True,
            "input_token_replay_projection_proven_for_frozen_prompts": True,
            "output_token_reduction_proven": False,
            "provider_calls_for_this_policy": 0,
            "quality_preservation_proven": False,
            "total_provider_token_reduction_proven": False,
        })


if __name__ == "__main__":
    unittest.main()
