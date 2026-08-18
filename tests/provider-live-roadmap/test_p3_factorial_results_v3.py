import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
ANALYZER = V3 / "analyze_results.py"
EVIDENCE = V3 / "provider-evidence.json"
RESULT = V3 / "result.json"


def load_analyzer():
    spec = importlib.util.spec_from_file_location("p3_v3_results", ANALYZER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FactorialResultsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.analyzer = load_analyzer()
        cls.evidence_raw = EVIDENCE.read_bytes()
        cls.evidence = json.loads(cls.evidence_raw)
        cls.result_raw = RESULT.read_bytes()
        cls.result = json.loads(cls.result_raw)

    def test_published_result_recomputes_exactly(self):
        rebuilt = self.analyzer.build_result(
            self.evidence_raw,
            preregistration_raw=(V3 / "preregistration.json").read_bytes(),
            corpus_raw=(V3 / "corpus-manifest.json").read_bytes(),
            schedule_raw=(V3 / "schedule.json").read_bytes(),
            contract_raw=(V3 / "live-contract.json").read_bytes(),
        )
        self.assertEqual(
            self.result_raw,
            self.analyzer.canonical(rebuilt),
        )
        self.analyzer.validate_result(
            self.result,
            evidence_raw=self.evidence_raw,
            preregistration_raw=(V3 / "preregistration.json").read_bytes(),
            corpus_raw=(V3 / "corpus-manifest.json").read_bytes(),
            schedule_raw=(V3 / "schedule.json").read_bytes(),
            contract_raw=(V3 / "live-contract.json").read_bytes(),
        )

    def test_source_and_provider_accounting_are_exact(self):
        self.assertEqual(
            self.result["source"]["provider_evidence_sha256"],
            hashlib.sha256(self.evidence_raw).hexdigest(),
        )
        self.assertEqual(self.result["scope"], {
            "arms": 8,
            "independent_project_clusters": 3,
            "repetitions_per_task_arm": 3,
            "scheduled_units": 288,
            "tasks": 12,
        })
        usage = self.result["provider_usage"]
        self.assertEqual(usage["completed_calls"], 288)
        self.assertEqual(usage["input_tokens"], 1_541_826)
        self.assertEqual(usage["output_tokens"], 958_075)
        self.assertEqual(usage["total_provider_tokens"], 2_499_901)
        self.assertEqual(usage["calculated_list_price_micro_usd"], 12_664_402)

    def test_primary_contrast_and_main_effects_are_preregistered(self):
        primary = self.result["primary_contrast"]
        self.assertEqual(primary["contrast"], "a111_minus_a000")
        self.assertEqual(
            primary["metrics"]["total_provider_tokens"]["delta"]["fraction"],
            {"denominator": 12, "numerator": 13_841},
        )
        self.assertEqual(
            primary["metrics"]["total_provider_tokens"]["percent_reduction"],
            "-14.236343",
        )
        effects = self.result["factorial_effects"]
        self.assertEqual(set(effects), {
            "adaptive",
            "adaptive_x_graph_closure",
            "adaptive_x_symbol_memory",
            "adaptive_x_symbol_memory_x_graph_closure",
            "graph_closure",
            "symbol_memory",
            "symbol_memory_x_graph_closure",
        })
        self.assertEqual(
            effects["adaptive"]["metrics"]["total_provider_tokens"]["delta"]["fraction"],
            {"denominator": 48, "numerator": -51_667},
        )
        self.assertEqual(
            effects["symbol_memory"]["metrics"]["total_provider_tokens"]["delta"]["fraction"],
            {"denominator": 144, "numerator": 131_887},
        )
        self.assertEqual(
            effects["graph_closure"]["metrics"]["total_provider_tokens"]["delta"]["fraction"],
            {"denominator": 144, "numerator": 181_879},
        )

    def test_quality_and_cost_claims_fail_closed(self):
        self.assertEqual(self.result["quality"]["passed_units"], 0)
        self.assertEqual(self.result["quality"]["failed_units"], 288)
        self.assertFalse(self.result["quality"]["quality_gate_met"])
        self.assertFalse(self.result["claims"]["quality_preserving_savings"])
        self.assertFalse(self.result["claims"]["all_task_quality_guarantee"])
        self.assertFalse(self.result["claims"]["future_project_generalization"])
        self.assertFalse(self.result["claims"]["provider_confirmed_exact_usd_savings"])
        self.assertEqual(self.result["cost_evidence"]["provider_billed_usd"]["status"], "unavailable")
        self.assertEqual(
            self.result["cost_evidence"]["calculated_list_price_usd"],
            "12.664402",
        )
        self.assertEqual(
            {row["passed_units"] for row in self.result["quality"]["by_project"].values()},
            {0},
        )
        self.assertEqual(
            {row["total_units"] for row in self.result["quality"]["by_project"].values()},
            {96},
        )
        self.assertEqual(
            {row["passed_units"] for row in self.result["quality"]["by_taxonomy"].values()},
            {0},
        )
        self.assertEqual(
            {row["total_units"] for row in self.result["quality"]["by_taxonomy"].values()},
            {72},
        )

    def test_committed_evidence_excludes_private_transport_fields(self):
        forbidden = {
            "answer", "api_key", "content", "prompt", "request_id",
            "response_body", "signature", "thinking",
        }

        def keys(value):
            found = set()
            if isinstance(value, dict):
                found.update(value)
                for child in value.values():
                    found.update(keys(child))
            elif isinstance(value, list):
                for child in value:
                    found.update(keys(child))
            return found

        self.assertFalse(forbidden & keys(self.evidence))

    def test_cluster_sensitivity_is_complete_and_descriptive(self):
        sensitivity = self.result["finite_corpus_sensitivity"]
        self.assertEqual(sensitivity["claim"], "descriptive_finite_corpus_sensitivity_only")
        self.assertEqual(len(sensitivity["project_rows"]), 3)
        self.assertEqual(len(sensitivity["leave_one_project_out"]), 3)
        self.assertEqual(len(sensitivity["ordered_project_cluster_resamples"]), 27)
        self.assertEqual(
            {len(row["selected_projects"]) for row in sensitivity["ordered_project_cluster_resamples"]},
            {3},
        )

    def test_mutations_are_rejected_by_exact_recomputation(self):
        altered = copy.deepcopy(self.result)
        altered["quality"]["passed_units"] = 1
        with self.assertRaisesRegex(ValueError, "result_mismatch"):
            self.analyzer.validate_result(
                altered,
                evidence_raw=self.evidence_raw,
                preregistration_raw=(V3 / "preregistration.json").read_bytes(),
                corpus_raw=(V3 / "corpus-manifest.json").read_bytes(),
                schedule_raw=(V3 / "schedule.json").read_bytes(),
                contract_raw=(V3 / "live-contract.json").read_bytes(),
            )

    def test_schedule_identity_tamper_is_rejected(self):
        altered = copy.deepcopy(self.evidence)
        first, second = altered["sealed_units"][:2]
        first["scheduled_unit_id"], second["scheduled_unit_id"] = (
            second["scheduled_unit_id"], first["scheduled_unit_id"]
        )
        with self.assertRaisesRegex(ValueError, "schedule_evidence_mismatch"):
            self.analyzer.build_result(
                self.analyzer.canonical(altered),
                preregistration_raw=(V3 / "preregistration.json").read_bytes(),
                corpus_raw=(V3 / "corpus-manifest.json").read_bytes(),
                schedule_raw=(V3 / "schedule.json").read_bytes(),
                contract_raw=(V3 / "live-contract.json").read_bytes(),
            )

    def test_usage_tamper_is_rejected_before_analysis(self):
        altered = copy.deepcopy(self.evidence)
        altered["sealed_units"][0]["usage"]["input_tokens"] += 1
        with self.assertRaisesRegex(ValueError, "invalid_provider_evidence"):
            self.analyzer.build_result(
                self.analyzer.canonical(altered),
                preregistration_raw=(V3 / "preregistration.json").read_bytes(),
                corpus_raw=(V3 / "corpus-manifest.json").read_bytes(),
                schedule_raw=(V3 / "schedule.json").read_bytes(),
                contract_raw=(V3 / "live-contract.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
