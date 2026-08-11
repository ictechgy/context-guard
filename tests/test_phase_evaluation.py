from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLKIT_ROOT = ROOT / "context-guard-kit"
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))

from phase_evaluation import evaluate_p2, evaluate_p3, evaluate_p4, evaluate_p5, evaluate_p6


class P2ShadowEvaluationTests(unittest.TestCase):
    def valid_record(self) -> dict[str, object]:
        return {
            "schema_version": "contextguard.phase-evaluation.p2/v1",
            "phase_id": "p2",
            "baseline_fallback_verified": True,
            "activation_authorized": True,
            "dependency_gates_passed": True,
            "observed_at": 100,
            "minimum_recall_basis_points": 9_000,
            "records": [
                {
                    "record_id": "r1",
                    "stratum": "refactor",
                    "relevant": True,
                    "candidate_omission": True,
                    "recalled": True,
                    "source_digest": "sha256:" + "1" * 64,
                    "rehydrated_digest": "sha256:" + "1" * 64,
                    "fresh_until": 101,
                    "protection": "eligible",
                    "construction_cost_microunits": 12,
                },
                {
                    "record_id": "r2",
                    "stratum": "refactor",
                    "relevant": False,
                    "candidate_omission": False,
                    "recalled": False,
                    "source_digest": "sha256:" + "2" * 64,
                    "rehydrated_digest": None,
                    "fresh_until": 101,
                    "protection": "protected",
                    "construction_cost_microunits": 3,
                },
            ],
        }

    def test_valid_shadow_records_are_locally_ready_but_never_grant_authority(self) -> None:
        result = evaluate_p2(self.valid_record())
        self.assertTrue(result["implementation_readiness"])
        self.assertTrue(result["evaluation_evidence_complete"])
        self.assertTrue(result["activation_eligibility"])
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        self.assertEqual(result["construction_cost_microunits"], 15)
        self.assertEqual(
            result["strata"],
            [{
                "stratum": "refactor",
                "relevant_record_count": 1,
                "recalled_relevant_record_count": 1,
                "recall_basis_points": 10_000,
                "threshold_passed": True,
            }],
        )
        self.assertIn("external_activation_authority_required", result["blockers"])

    def test_protected_retained_record_is_safe_but_protected_omission_is_blocked(self) -> None:
        safe = evaluate_p2(self.valid_record())
        self.assertTrue(safe["implementation_readiness"])

        unsafe = self.valid_record()
        unsafe["records"][1]["candidate_omission"] = True
        result = evaluate_p2(unsafe)
        self.assertFalse(result["implementation_readiness"])
        self.assertIn("protected_omission", result["blockers"])

    def test_each_unsafe_omission_condition_fails_closed(self) -> None:
        mutations = {
            "incomplete": lambda row: row.pop("recalled"),
            "stale": lambda row: row.__setitem__("fresh_until", 100),
            "non_rehydratable": lambda row: row.__setitem__("rehydrated_digest", "sha256:" + "2" * 64),
            "cost": lambda row: row.__setitem__("construction_cost_microunits", None),
            "malformed": lambda row: row.__setitem__("unexpected", True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                record = self.valid_record()
                mutate(record["records"][0])
                result = evaluate_p2(record)
                self.assertFalse(result["implementation_readiness"])
                self.assertFalse(result["activation_authority"])
                self.assertFalse(result["claim_authority"])
                self.assertEqual(result["fallback"], "exact_unchanged_baseline")

    def test_recall_threshold_is_computed_per_stratum(self) -> None:
        record = self.valid_record()
        missed = copy.deepcopy(record["records"][0])
        missed["record_id"] = "r3"
        missed["stratum"] = "debug"
        missed["recalled"] = False
        record["records"].append(missed)
        result = evaluate_p2(record)
        self.assertFalse(result["implementation_readiness"])
        self.assertIn("recall_threshold_failed", result["blockers"])
        self.assertEqual(result["strata"][0]["stratum"], "debug")
        self.assertFalse(result["strata"][0]["threshold_passed"])


class P3CanaryEvaluationTests(unittest.TestCase):
    def valid_record(self) -> dict[str, object]:
        def attempt(
            attempt_id: str,
            pair_id: str,
            arm: str,
            *,
            provider_cost: int,
        ) -> dict[str, object]:
            return {
                "attempt_id": attempt_id,
                "pair_id": pair_id,
                "arm": arm,
                "task_success": True,
                "corrections": 0,
                "retrievals": [] if arm == "baseline" else [
                    {"retrieval_id": attempt_id + "-get", "exact": True}
                ],
                "measurement": {
                    "primary_tokens": 1_000,
                    "provider_cost_microunits": provider_cost,
                    "retry_cost_microunits": 0,
                    "correction_cost_microunits": 0,
                    "retrieval_cost_microunits": 2,
                    "external_cost_microunits": 0,
                    "local_compute_cost_microunits": 1,
                },
            }

        return {
            "schema_version": "contextguard.phase-evaluation.p3/v1",
            "phase_id": "p3",
            "baseline_fallback_verified": True,
            "activation_authorized": True,
            "dependency_gates_passed": True,
            "claim_scope_bound": True,
            "evidence_origin": "provider_measured",
            "matched_pair_ids": ["pair-1"],
            "attempts": [
                attempt("b1", "pair-1", "baseline", provider_cost=100),
                attempt("c1", "pair-1", "canary", provider_cost=80),
            ],
            "thresholds": {
                "maximum_failure_rate_increase_basis_points": 999,
                "require_corrections_non_inferior": True,
                "require_fully_loaded_cost_improvement": True,
            },
        }

    def test_complete_matched_population_is_eligible_but_local_input_never_grants_authority(self) -> None:
        result = evaluate_p3(self.valid_record())
        self.assertTrue(result["implementation_readiness"])
        self.assertTrue(result["provider_evidence"])
        self.assertTrue(result["activation_eligibility"])
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        self.assertEqual(result["evaluated_pair_count"], 1)
        self.assertEqual(result["evaluated_retrieval_count"], 1)
        self.assertEqual(result["baseline_fully_loaded_cost_microunits"], 103)
        self.assertEqual(result["canary_fully_loaded_cost_microunits"], 83)
        self.assertIn("external_activation_authority_required", result["blockers"])
        self.assertIn("external_claim_authority_required", result["blockers"])

    def test_missing_extra_or_duplicate_pair_member_blocks_complete_population(self) -> None:
        mutations = ("missing", "extra", "duplicate-arm")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                record = self.valid_record()
                if mutation == "missing":
                    record["attempts"].pop()
                elif mutation == "extra":
                    extra = copy.deepcopy(record["attempts"][0])
                    extra["attempt_id"] = "unmatched"
                    extra["pair_id"] = "pair-x"
                    record["attempts"].append(extra)
                else:
                    record["attempts"][1]["arm"] = "baseline"
                result = evaluate_p3(record)
                self.assertFalse(result["provider_evidence"])
                self.assertFalse(result["activation_eligibility"])
                self.assertIn("matched_population_incomplete", result["blockers"])

    def test_retrieval_failure_correction_and_fully_loaded_cost_are_computed_not_asserted(self) -> None:
        mutations = {
            "retrieval": lambda value: value["attempts"][1]["retrievals"][0].__setitem__("exact", False),
            "failure": lambda value: value["attempts"][1].__setitem__("task_success", False),
            "correction": lambda value: value["attempts"][1].__setitem__("corrections", 1),
            "cost": lambda value: value["attempts"][1]["measurement"].__setitem__("provider_cost_microunits", 120),
            "missing-cost": lambda value: value["attempts"][1]["measurement"].__setitem__("external_cost_microunits", None),
        }
        expected = {
            "retrieval": "exact_retrieval_incomplete",
            "failure": "failure_guardrail_failed",
            "correction": "correction_guardrail_failed",
            "cost": "fully_loaded_cost_not_improved",
            "missing-cost": "provider_measurement_incomplete",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                record = self.valid_record()
                mutate(record)
                result = evaluate_p3(record)
                self.assertFalse(result["activation_eligibility"])
                self.assertFalse(result["activation_authority"])
                self.assertFalse(result["claim_authority"])
                self.assertIn(expected[name], result["blockers"])


class P4RouterEvaluationTests(unittest.TestCase):
    def valid_record(self) -> dict[str, object]:
        def outcome(*, quality: int, cost: int, provider: int) -> dict[str, object]:
            return {
                "quality_basis_points": quality,
                "total_cost_microunits": cost,
                "cache_accounting": {
                    "creation_microunits": 2,
                    "read_microunits": 1,
                    "invalidation_microunits": 1,
                    "latency_microunits": 1,
                    "provider_cost_microunits": provider,
                },
            }

        return {
            "schema_version": "contextguard.phase-evaluation.p4/v1",
            "phase_id": "p4",
            "baseline_fallback_verified": True,
            "dependency_gates_passed": True,
            "activation_authorized": True,
            "minimum_confidence_basis_points": 8_000,
            "trials": [{
                "trial_id": "route-1",
                "advisory_status": "selected",
                "advisory_route": "on",
                "confidence_basis_points": 9_000,
                "bypass_reasons": [],
                "outcomes": {
                    "advisory": outcome(quality=9_500, cost=80, provider=75),
                    "always_pass_through": outcome(quality=9_400, cost=100, provider=95),
                    "always_on": outcome(quality=9_500, cost=90, provider=85),
                },
            }],
        }

    def test_nonnegative_regret_is_advisory_only_and_never_grants_runtime_authority(self) -> None:
        result = evaluate_p4(self.valid_record())
        self.assertTrue(result["evaluation_evidence_complete"])
        self.assertTrue(result["activation_eligibility"])
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        self.assertEqual(result["runtime_route_changed"], False)
        self.assertEqual(result["selected_route"], "on")
        self.assertEqual(result["trials"][0]["regret_microunits"], 10)
        self.assertEqual(result["trials"][0]["evaluation_route"], "on")

    def test_negative_regret_low_confidence_and_quality_regression_select_pass_through(self) -> None:
        def make_negative_regret(trial: dict[str, object]) -> None:
            trial["outcomes"]["advisory"]["total_cost_microunits"] = 91
            trial["outcomes"]["advisory"]["cache_accounting"]["provider_cost_microunits"] = 86

        mutations = {
            "negative_regret": make_negative_regret,
            "low_confidence": lambda trial: trial.__setitem__("confidence_basis_points", 7_999),
            "quality_regression": lambda trial: trial["outcomes"]["advisory"].__setitem__("quality_basis_points", 9_399),
        }
        expected = {
            "negative_regret": "negative_regret",
            "low_confidence": "low_confidence",
            "quality_regression": "quality_regression",
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                record = self.valid_record()
                mutate(record["trials"][0])
                result = evaluate_p4(record)
                self.assertEqual(result["selected_route"], "pass_through")
                self.assertEqual(result["trials"][0]["evaluation_route"], "pass_through")
                self.assertIn(expected[name], result["trials"][0]["bypass_reasons"])
                self.assertFalse(result["activation_eligibility"])
                self.assertFalse(result["runtime_route_changed"])

    def test_missing_each_cache_dimension_fails_closed(self) -> None:
        for field in (
            "creation_microunits",
            "read_microunits",
            "invalidation_microunits",
            "latency_microunits",
            "provider_cost_microunits",
        ):
            with self.subTest(field=field):
                record = self.valid_record()
                record["trials"][0]["outcomes"]["always_on"]["cache_accounting"].pop(field)
                result = evaluate_p4(record)
                self.assertEqual(result["selected_route"], "pass_through")
                self.assertIn("cache_accounting_incomplete", result["blockers"])
                self.assertIn("cache_accounting_incomplete", result["trials"][0]["bypass_reasons"])

    def test_abstentions_failures_confidence_and_caller_bypass_reasons_remain_visible(self) -> None:
        record = self.valid_record()
        abstention = copy.deepcopy(record["trials"][0])
        abstention["trial_id"] = "route-2"
        abstention["advisory_status"] = "abstained"
        abstention["advisory_route"] = None
        abstention["confidence_basis_points"] = 4_000
        abstention["bypass_reasons"] = ["unsupported_shape"]
        failure = copy.deepcopy(abstention)
        failure["trial_id"] = "route-3"
        failure["advisory_status"] = "failed"
        failure["confidence_basis_points"] = 0
        failure["bypass_reasons"] = ["router_error"]
        record["trials"].extend([abstention, failure])

        result = evaluate_p4(record)
        self.assertEqual(result["abstention_count"], 1)
        self.assertEqual(result["failure_count"], 1)
        self.assertEqual(result["confidence_basis_points"], [9_000, 4_000, 0])
        self.assertEqual(
            result["bypass_reason_counts"],
            {"abstained": 1, "failed": 1, "low_confidence": 2, "router_error": 1, "unsupported_shape": 1},
        )
        self.assertEqual(result["selected_route"], "pass_through")
        self.assertFalse(result["runtime_route_changed"])

    def test_malformed_route_identity_is_not_reflected_in_output(self) -> None:
        record = self.valid_record()
        record["trials"][0]["trial_id"] = {"private": "value"}
        record["trials"][0]["advisory_status"] = ["selected"]
        record["trials"][0]["advisory_route"] = {"route": "on"}

        report = evaluate_p4(record)["trials"][0]
        self.assertIsNone(report["trial_id"])
        self.assertIsNone(report["advisory_status"])
        self.assertIsNone(report["advisory_route"])

    def test_malformed_trial_keeps_confidence_rows_index_aligned(self) -> None:
        record = self.valid_record()
        record["trials"].append({"unexpected": True})

        result = evaluate_p4(record)

        self.assertEqual(result["evaluated_trial_count"], 2)
        self.assertEqual(len(result["trials"]), 2)
        self.assertEqual(result["confidence_basis_points"], [9_000, 0])

    def test_bypass_reason_must_match_the_closed_result_vocabulary(self) -> None:
        record = self.valid_record()
        record["trials"][0]["bypass_reasons"] = ["private.marker"]

        result = evaluate_p4(record)

        report = result["trials"][0]
        self.assertEqual(report["evaluation_route"], "pass_through")
        self.assertEqual(report["bypass_reasons"], ["malformed_record"])
        self.assertNotIn("private.marker", str(result))


class P5AdjunctEvaluationTests(unittest.TestCase):
    def valid_record(self) -> dict[str, object]:
        def adjunct(adjunct_id: str, suffix: str) -> dict[str, object]:
            return {
                "adjunct_id": adjunct_id,
                "revision_digest": "sha256:" + "1" * 64,
                "source_digest": "sha256:" + "2" * 64,
                "test_digest": "sha256:" + "3" * 64,
                "evidence_digests": ["sha256:" + suffix * 64],
                "failure_cases": [
                    {"case_id": "case-a", "exit_status": 1, "root_cause": "compile", "duplicate_of": None},
                    {"case_id": "case-b", "exit_status": 1, "root_cause": "compile", "duplicate_of": "case-a"},
                ],
                "bypass_verified": True,
                "fallback_verified": True,
                "baseline_quality_basis_points": 9_000,
                "adjunct_quality_basis_points": 9_100,
                "baseline_cost_microunits": 100,
                "adjunct_cost_microunits": 90,
            }

        return {
            "schema_version": "contextguard.phase-evaluation.p5/v1",
            "phase_id": "p5",
            "dependency_gates_passed": True,
            "activation_authorized": True,
            "current_revision_digest": "sha256:" + "1" * 64,
            "current_source_digest": "sha256:" + "2" * 64,
            "current_test_digest": "sha256:" + "3" * 64,
            "adjuncts": [
                adjunct("execution_twin", "4"),
                adjunct("failure_cone", "5"),
                adjunct("typed_blueprint", "6"),
            ],
        }

    def test_each_complete_adjunct_is_independently_eligible_but_advisory_only(self) -> None:
        result = evaluate_p5(self.valid_record())
        self.assertEqual(result["evaluated_adjunct_count"], 3)
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        self.assertFalse(result["runtime_changed"])
        self.assertEqual(
            [(item["adjunct_id"], item["decision"]) for item in result["adjuncts"]],
            [("execution_twin", "eligible"), ("failure_cone", "eligible"), ("typed_blueprint", "eligible")],
        )

    def test_stale_revision_source_or_test_disables_only_the_affected_adjunct(self) -> None:
        fields = ("revision_digest", "source_digest", "test_digest")
        expected = ("stale_revision", "stale_source", "stale_test_state")
        for field, blocker in zip(fields, expected):
            with self.subTest(field=field):
                record = self.valid_record()
                record["adjuncts"][1][field] = "sha256:" + "9" * 64
                result = evaluate_p5(record)
                reports = {item["adjunct_id"]: item for item in result["adjuncts"]}
                self.assertEqual(reports["failure_cone"]["decision"], "bypass")
                self.assertIn(blocker, reports["failure_cone"]["blockers"])
                self.assertEqual(reports["execution_twin"]["decision"], "eligible")
                self.assertEqual(reports["typed_blueprint"]["decision"], "eligible")

    def test_different_exit_status_or_root_cause_is_never_deduplicated(self) -> None:
        for field, value in (("exit_status", 2), ("root_cause", "link")):
            with self.subTest(field=field):
                record = self.valid_record()
                record["adjuncts"][1]["failure_cases"][1][field] = value
                result = evaluate_p5(record)
                reports = {item["adjunct_id"]: item for item in result["adjuncts"]}
                self.assertEqual(reports["failure_cone"]["decision"], "bypass")
                self.assertIn("distinct_failure_deduplicated", reports["failure_cone"]["blockers"])
                self.assertEqual(reports["execution_twin"]["decision"], "eligible")

    def test_every_gate_is_independent_and_reversible(self) -> None:
        mutations = {
            "evidence_incomplete": lambda item: item.__setitem__("evidence_digests", []),
            "bypass_unverified": lambda item: item.__setitem__("bypass_verified", False),
            "exact_fallback_unverified": lambda item: item.__setitem__("fallback_verified", False),
            "quality_regression": lambda item: item.__setitem__("adjunct_quality_basis_points", 8_999),
            "fully_loaded_cost_not_improved": lambda item: item.__setitem__("adjunct_cost_microunits", 100),
        }
        for blocker, mutate in mutations.items():
            with self.subTest(blocker=blocker):
                record = self.valid_record()
                mutate(record["adjuncts"][2])
                blocked = evaluate_p5(record)
                reports = {item["adjunct_id"]: item for item in blocked["adjuncts"]}
                self.assertEqual(reports["typed_blueprint"]["decision"], "bypass")
                self.assertIn(blocker, reports["typed_blueprint"]["blockers"])
                self.assertEqual(reports["execution_twin"]["decision"], "eligible")
                self.assertEqual(reports["failure_cone"]["decision"], "eligible")

                restored = self.valid_record()
                restored_result = evaluate_p5(restored)
                restored_reports = {item["adjunct_id"]: item for item in restored_result["adjuncts"]}
                self.assertEqual(restored_reports["typed_blueprint"]["decision"], "eligible")

    def test_invalid_adjunct_identity_is_not_reflected_in_output(self) -> None:
        record = self.valid_record()
        record["adjuncts"][0]["adjunct_id"] = {"private": "value"}

        report = evaluate_p5(record)["adjuncts"][0]
        self.assertIsNone(report["adjunct_id"])


class P6SpecializedTrackEvaluationTests(unittest.TestCase):
    TRACKS = (
        "context_leases",
        "scout_surgeon",
        "counterfactual_ledger",
        "negative_firewall",
        "bounded_compilation",
    )

    def valid_record(self) -> dict[str, object]:
        def track(track_id: str, suffix: str) -> dict[str, object]:
            return {
                "track_id": track_id,
                "surface": "evaluation_only",
                "workload_digest": "sha256:" + suffix * 64,
                "baseline_digest": "sha256:" + "a" * 64,
                "scope_digest": "sha256:" + "c" * 64,
                "privacy_boundary_digest": "sha256:" + "d" * 64,
                "privacy_verified": True,
                "baseline_quality_basis_points": 9_000,
                "track_quality_basis_points": 9_100,
                "population_count": 10,
                "baseline_failure_count": 1,
                "track_failure_count": 1,
                "maximum_failure_rate_increase_basis_points": 999,
                "baseline_corrections": 1,
                "track_corrections": 1,
                "cost_model_digest": "sha256:" + "e" * 64,
                "baseline_cost_microunits": 100,
                "track_cost_microunits": 90,
                "fallback_verified": True,
                "rollback_verified": True,
                "activation_authorized": True,
                "provider_evidence_digest": "sha256:" + "b" * 64,
            }

        return {
            "schema_version": "contextguard.phase-evaluation.p6/v1",
            "phase_id": "p6",
            "dependency_gates_passed": True,
            "tracks": [track(track_id, str(index + 1)) for index, track_id in enumerate(self.TRACKS)],
        }

    def test_complete_tracks_keep_all_evidence_independent_and_never_change_runtime(self) -> None:
        result = evaluate_p6(self.valid_record())
        self.assertEqual(result["evaluated_track_count"], 5)
        self.assertFalse(result["runtime_changed"])
        self.assertFalse(result["activation_authority"])
        self.assertFalse(result["claim_authority"])
        for report, track_id in zip(result["tracks"], self.TRACKS):
            self.assertEqual(report["track_id"], track_id)
            self.assertEqual(report["decision"], "eligible")
            self.assertTrue(report["workload_evidence"])
            self.assertTrue(report["baseline_evidence"])
            self.assertTrue(report["scope_evidence"])
            self.assertTrue(report["privacy_evidence"])
            self.assertTrue(report["quality_evidence"])
            self.assertTrue(report["failure_guardrail_evidence"])
            self.assertTrue(report["correction_guardrail_evidence"])
            self.assertTrue(report["cost_model_evidence"])
            self.assertTrue(report["cost_evidence"])
            self.assertTrue(report["fallback_evidence"])
            self.assertTrue(report["rollback_evidence"])
            self.assertTrue(report["authority_evidence"])
            self.assertTrue(report["provider_evidence"])
            self.assertFalse(report["generalization_allowed"])

    def test_failed_or_uneconomic_track_falls_back_without_generalizing(self) -> None:
        mutations = {
            "privacy_evidence_incomplete": lambda track: track.__setitem__("privacy_verified", False),
            "quality_regression": lambda track: track.__setitem__("track_quality_basis_points", 8_999),
            "fully_loaded_cost_not_improved": lambda track: track.__setitem__("track_cost_microunits", 100),
            "exact_fallback_unverified": lambda track: track.__setitem__("fallback_verified", False),
            "rollback_unverified": lambda track: track.__setitem__("rollback_verified", False),
            "activation_not_recorded": lambda track: track.__setitem__("activation_authorized", False),
            "provider_measurement_incomplete": lambda track: track.__setitem__("provider_evidence_digest", None),
            "scope_evidence_incomplete": lambda track: track.__setitem__("scope_digest", "invalid"),
            "failure_guardrail_failed": lambda track: track.__setitem__("track_failure_count", 2),
            "correction_guardrail_failed": lambda track: track.__setitem__("track_corrections", 2),
            "cost_model_incomplete": lambda track: track.__setitem__("cost_model_digest", "invalid"),
        }
        for blocker, mutate in mutations.items():
            with self.subTest(blocker=blocker):
                record = self.valid_record()
                mutate(record["tracks"][2])
                reports = {item["track_id"]: item for item in evaluate_p6(record)["tracks"]}
                self.assertEqual(reports["counterfactual_ledger"]["decision"], "fallback")
                self.assertEqual(reports["counterfactual_ledger"]["fallback"], "exact_unchanged_baseline")
                self.assertIn(blocker, reports["counterfactual_ledger"]["blockers"])
                self.assertEqual(reports["context_leases"]["decision"], "eligible")
                self.assertEqual(reports["bounded_compilation"]["decision"], "eligible")

    def test_workload_and_baseline_are_required_per_track(self) -> None:
        for field, blocker in (
            ("workload_digest", "workload_evidence_incomplete"),
            ("baseline_digest", "baseline_evidence_incomplete"),
        ):
            with self.subTest(field=field):
                record = self.valid_record()
                record["tracks"][1][field] = "invalid"
                reports = {item["track_id"]: item for item in evaluate_p6(record)["tracks"]}
                self.assertEqual(reports["scout_surgeon"]["decision"], "fallback")
                self.assertIn(blocker, reports["scout_surgeon"]["blockers"])
                self.assertEqual(reports["negative_firewall"]["decision"], "eligible")

    def test_plan_only_track_is_non_runtime_and_claim_blocked_even_with_complete_evidence(self) -> None:
        record = self.valid_record()
        record["tracks"][4]["surface"] = "plan_only"
        result = evaluate_p6(record)
        report = {item["track_id"]: item for item in result["tracks"]}["bounded_compilation"]
        self.assertEqual(report["decision"], "plan_only")
        self.assertIn("plan_only_non_runtime", report["blockers"])
        self.assertFalse(report["activation_eligibility"])
        self.assertFalse(report["claim_authority"])
        self.assertFalse(result["runtime_changed"])

    def test_malformed_phase_identity_cannot_report_track_readiness(self) -> None:
        record = self.valid_record()
        record["schema_version"] = "contextguard.phase-evaluation.p6/v2"

        result = evaluate_p6(record)

        self.assertFalse(result["implementation_readiness"])
        self.assertFalse(result["evaluation_evidence_complete"])
        self.assertFalse(result["activation_eligibility"])
        self.assertIn("malformed_record", result["blockers"])
        self.assertTrue(
            all("malformed_record" in report["blockers"] for report in result["tracks"])
        )

    def test_invalid_track_identity_and_surface_are_not_reflected_in_output(self) -> None:
        record = self.valid_record()
        record["tracks"][0]["track_id"] = {"private": "value"}
        record["tracks"][0]["surface"] = ["evaluation_only"]

        report = evaluate_p6(record)["tracks"][0]
        self.assertIsNone(report["track_id"])
        self.assertIsNone(report["surface"])


if __name__ == "__main__":
    unittest.main()
