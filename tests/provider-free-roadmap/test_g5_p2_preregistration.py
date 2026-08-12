from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "research/provider-free-roadmap/g5/v1"
G4 = ROOT / "research/provider-free-roadmap/g4"


def captured(name: str, path: Path) -> bytes:
    value = globals().get(name)
    if value is None:
        return path.read_bytes()
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must contain captured bytes")
    return value


def captured_map(name: str, paths: list[Path]) -> dict[str, bytes]:
    value = globals().get(name)
    if value is None:
        return {path.name: path.read_bytes() for path in paths}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(raw, bytes) for key, raw in value.items()
    ):
        raise TypeError(f"{name} must contain a captured byte map")
    return value


def load_verifier() -> types.ModuleType:
    raw = captured("__G5_CAPTURED_VERIFIER_BYTES__", V1 / "verify.py")
    module = types.ModuleType("captured_g5_verifier")
    module.__file__ = str(V1 / "verify.py")
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


class G5P2PreregistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verify = load_verifier()
        cls.inputs = {
            "prereg_bytes": captured("__G5_CAPTURED_PREREG_BYTES__", V1 / "preregistration.json"),
            "schedule_bytes": captured("__G5_CAPTURED_SCHEDULE_BYTES__", V1 / "schedule.json"),
            "schema_bytes": captured_map(
                "__G5_CAPTURED_SCHEMA_BYTES__", sorted((V1 / "schemas").glob("*.json"))
            ),
            "g4_lock_bytes": captured("__G5_CAPTURED_G4_LOCK_BYTES__", G4 / "freeze-lock.json"),
            "g4_verifier_bytes": captured("__G5_CAPTURED_G4_VERIFIER_BYTES__", G4 / "v1/verify.py"),
            "g4_policy_bytes": captured("__G5_CAPTURED_G4_POLICY_BYTES__", G4 / "v1/claim-policy.json"),
            "g4_schema_bytes": captured_map(
                "__G5_CAPTURED_G4_SCHEMA_BYTES__", sorted((G4 / "v1/schemas").glob("*.json"))
            ),
        }
        cls.prereg = json.loads(cls.inputs["prereg_bytes"])
        cls.schedule = json.loads(cls.inputs["schedule_bytes"])

    def test_captured_contract_validates_without_execution_or_observations(self) -> None:
        self.assertEqual(self.verify.validate_captured(**self.inputs), {
            "block_count": 60, "status": "preregistered_contract_only", "unit_count": 240,
        })
        self.assertEqual(self.prereg["observation_status"], "no_observations")
        self.assertIs(self.prereg["execution_authorized"], False)
        self.assertEqual(self.prereg["sample_size_rationale"], "capacity_fixed_not_effect_estimate")
        self.assertIs(self.prereg["sample_size_derived_from_g3_g4_outcomes"], False)

    def test_candidate_validation_is_exhaustive_not_partial_prose_matching(self) -> None:
        mutations = {
            "estimand": lambda value: value["directional_descriptive_estimands"].__setitem__(0, "observed_winner"),
            "sample": lambda value: value["design"]["fixed_counts"].update(primary_blocks_total=61),
            "stopping": lambda value: value["design"]["stopping_rule"].update(kind="stop_when_significant"),
            "exclusion": lambda value: value["design"]["pre_outcome_exclusions"].pop(),
            "algorithm": lambda value: value["design"]["randomization"].update(algorithm_id="wallclock_shuffle"),
            "seed": lambda value: value["design"]["randomization"].update(seed="changed"),
            "limit": lambda value: value["future_execution_boundary"].update(maximum_scheduled_units=259),
            "reference": lambda value: value["upstream_contract"].update(g4_tree_sha256="0" * 64),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(self.prereg)
                mutation(changed)
                with self.assertRaisesRegex(Exception, "candidate differs"):
                    self.verify.validate_candidate(
                        self.verify.canonical(changed), expected_prereg_bytes=self.inputs["prereg_bytes"],
                        **{key: value for key, value in self.inputs.items() if key != "prereg_bytes"},
                    )

    def test_schedule_exactly_freezes_60_primary_blocks_without_replacements(self) -> None:
        blocks = self.schedule["blocks"]
        self.assertEqual((len(blocks), sum(block["kind"] == "primary" for block in blocks)), (60, 60))
        units = [unit for block in blocks for unit in block["units"]]
        self.assertEqual((len(units), len({unit["scheduled_unit_id"] for unit in units})), (240, 240))
        counts = {}
        for block in blocks[:60]:
            for unit in block["units"]:
                counts[(block["stratum"], unit["arm"])] = counts.get((block["stratum"], unit["arm"]), 0) + 1
        self.assertEqual(set(counts.values()), {30})

    def test_schedule_rejects_cardinality_imbalance_pseudoreplication_and_wallclock(self) -> None:
        mutations = {
            "cardinality": lambda value: value["blocks"].pop(),
            "imbalance": lambda value: value["blocks"][0]["units"][0].update(arm="combined"),
            "pseudoreplication": lambda value: value["blocks"][1].update(lineage_id="train_closed"),
            "wallclock": lambda value: value.update(seed="2026-08-12T12:34:56Z"),
        }
        schema = json.loads(self.inputs["schema_bytes"]["schedule.schema.json"])
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(self.schedule)
                mutation(changed)
                with self.assertRaises(Exception):
                    self.verify.validate_schema(changed, schema, schema, "schedule")
                    self.verify.validate_schedule(changed)

    def test_all_schemas_are_recursively_closed_and_actually_loaded(self) -> None:
        for name, raw in self.inputs["schema_bytes"].items():
            with self.subTest(schema=name):
                self.verify.audit_schema(json.loads(raw), name)
        self.verify.validate_captured(**self.inputs)

    def test_observer_schema_has_only_minimized_bounded_fields(self) -> None:
        schema = json.loads(
            self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        )
        self.verify.validate_observation_schema_contract(schema)
        serialized = json.dumps(schema).lower()
        for forbidden in ("prompt", "response_body", "headers", "url", "credential", "environment", "arbitrary_path"):
            self.assertNotIn(forbidden, serialized)

    def observation(self) -> tuple[dict, dict]:
        block = self.schedule["blocks"][0]
        unit = block["units"][0]
        scheduled = {
            **{key: block[key] for key in ("block_id", "task_id", "lineage_id", "partition", "stratum", "repetition")},
            **unit,
        }
        metric = {"availability": "observed", "unavailable_reason": "not_applicable", "value": 1}
        value = {
            "schema_version": "contextguard.g5-authoritative-observation/v1",
            "observer_version": "contextguard.g5-minimized-observer/v1",
            **scheduled, "payload_sha256": "1" * 64, "model_identity": "future-model-v1",
            "request_id": "request-1", "receipt_id": "receipt-1", "unit_status": "completed",
            "completion_event": "normal_completion", "event_count": 1,
            "pack_start_monotonic_ns": 10, "pack_end_monotonic_ns": 20,
            "correctness": {"availability": "observed", "outcome": "correct", "unavailable_reason": "not_applicable"},
            "input_usage": copy.deepcopy(metric), "output_usage": copy.deepcopy(metric),
            "correction_count": copy.deepcopy(metric), "correction_tokens": copy.deepcopy(metric),
            "retrieval_count": copy.deepcopy(metric), "retrieval_bytes": copy.deepcopy(metric),
            "retrieval_tokens": copy.deepcopy(metric),
            "billing_receipt": {"authority": "authoritative_provider_receipt", "reference": "billing-1", "status": "observed"},
            "cost_components": [
                {"amount_minor": 1, "availability": "observed", "component": component,
                 "currency": "USD", "receipt_reference": "billing-1", "unavailable_reason": "not_applicable"}
                for component in ("provider_input", "provider_output", "provider_correction")
            ],
            "exclusion_reason": "none", "audit_status": "eligible",
        }
        return value, scheduled

    def make_unavailable(self, value: dict) -> None:
        for name in (
            "input_usage", "output_usage", "correction_count", "correction_tokens",
            "retrieval_count", "retrieval_bytes", "retrieval_tokens",
        ):
            value[name] = {
                "availability": "unavailable", "unavailable_reason": "excluded_unit",
                "value": None,
            }
        value["correctness"] = {
            "availability": "unavailable", "outcome": "unavailable",
            "unavailable_reason": "excluded_unit",
        }
        value["billing_receipt"] = {
            "authority": "unavailable", "reference": None, "status": "unavailable",
        }
        for component in value["cost_components"]:
            component.update(
                amount_minor=None, availability="unavailable", currency=None,
                receipt_reference=None, unavailable_reason="excluded_unit",
            )

    def observations_for_schedule(self) -> list[dict]:
        observations = []
        differences = {
            "train_closed": -2, "calibration_closed": 0, "evaluation_closed": 2,
            "train_graph": -2, "calibration_graph": 0, "evaluation_graph": 2,
        }
        for block in self.schedule["blocks"]:
            for unit in block["units"]:
                scheduled = {
                    **{key: block[key] for key in (
                        "block_id", "task_id", "lineage_id", "partition", "stratum",
                        "repetition",
                    )},
                    **unit,
                }
                value, _ = self.observation()
                value.update(scheduled)
                suffix = unit["scheduled_unit_id"]
                value.update(
                    request_id=f"request-{suffix}", receipt_id=f"receipt-{suffix}"
                )
                value["billing_receipt"]["reference"] = f"billing-{suffix}"
                for component in value["cost_components"]:
                    component["receipt_reference"] = f"billing-{suffix}"
                value["input_usage"]["value"] = (
                    10 + differences[block["lineage_id"]]
                    if unit["arm"] == "combined" else 10
                )
                observations.append(value)
        return observations

    def test_observer_semantics_reject_zero_for_unavailable_and_price_estimates(self) -> None:
        value, scheduled = self.observation()
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        self.verify.validate_observation(value, schema, scheduled)
        mutations = {
            "zero unavailable": lambda item: item["input_usage"].update(availability="unavailable", unavailable_reason="receipt_unavailable", value=0),
            "price estimate": lambda item: item["billing_receipt"].update(authority="unavailable"),
            "wallclock": lambda item: item.update(pack_end_monotonic_ns=9),
            "assignment": lambda item: item.update(arm="ordinary" if item["arm"] != "ordinary" else "combined"),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(value)
                mutation(changed)
                with self.assertRaises(Exception):
                    self.verify.validate_observation(changed, schema, scheduled)

    def test_unavailable_metrics_and_costs_are_null_never_zero(self) -> None:
        value, scheduled = self.observation()
        for name in ("input_usage", "output_usage", "correction_count", "correction_tokens", "retrieval_count", "retrieval_bytes", "retrieval_tokens"):
            value[name] = {"availability": "unavailable", "unavailable_reason": "receipt_unavailable", "value": None}
        value["billing_receipt"] = {"authority": "unavailable", "reference": None, "status": "unavailable"}
        for component in value["cost_components"]:
            component.update(amount_minor=None, availability="unavailable", currency=None, receipt_reference=None, unavailable_reason="receipt_unavailable")
        self.verify.validate_observation(
            value, self.inputs["schema_bytes"]["authoritative-observation.schema.json"], scheduled
        )

    def test_contract_contains_no_results_observations_evidence_or_approval(self) -> None:
        self.assertFalse(self.verify.recursive_keys(self.prereg) & self.verify.FORBIDDEN_PREREG_KEYS)
        names = {path.name for path in V1.iterdir() if path.is_file()}
        self.assertEqual(names, {"README.md", "preregistration.json", "schedule.json", "verify.py"})

    def test_upstream_binding_is_only_frozen_g4_contract_not_g3_g4_outcomes(self) -> None:
        self.assertEqual(set(self.prereg["upstream_contract"]), {
            "g4_claim_policy_sha256", "g4_freeze_lock_path", "g4_freeze_lock_sha256",
            "g4_schema_set_bytes", "g4_schema_set_sha256", "g4_tree_sha256", "g4_verifier_sha256",
        })
        self.assertNotIn("aggregate", json.dumps(self.prereg).lower())

    def test_analysis_is_stratified_paired_clustered_exact_and_no_claim(self) -> None:
        analysis = self.prereg["analysis"]
        self.assertEqual(analysis["primary_contrast"], "combined_minus_ordinary")
        self.assertEqual(analysis["cluster_unit"], "task_lineage")
        self.assertIn("separately_no_pooled", analysis["stratification"])
        self.assertEqual(analysis["mode"], "descriptive_measurement_readiness_only")
        self.assertIn("no_inferential_hypothesis_rejection", analysis["interpretation_policy"])
        self.assertEqual(set(self.prereg["claims"].values()), {False})
        self.assertNotIn("price_schedule", json.dumps(self.prereg).lower())

    def test_analysis_is_descriptive_not_impossible_three_cluster_inference(self) -> None:
        analysis = self.prereg["analysis"]
        serialized = json.dumps(analysis).lower()
        for forbidden in ("holm", "p_value", "randomization_test", "sign_flip", "significance", "claim_gate"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(analysis["mode"], "descriptive_measurement_readiness_only")
        self.assertEqual(analysis["independent_clusters_per_stratum"], 3)
        self.assertEqual(analysis["repetition_role"], "technical_repeats_never_independent_clusters")
        self.assertEqual(analysis["lineage_reduction"], {
            "missing_handling": "mean_of_available_within_repetition_paired_differences_with_observed_and_unavailable_pair_counts_reported_no_imputation",
            "rounding": "none_exact_rational_numerator_sum_denominator_available_count",
            "statistic": "arithmetic_mean_of_combined_minus_ordinary_within_repetition_differences_per_task_lineage_and_stratum",
            "ties": "retain_equal_values_as_zero_paired_difference",
        })
        self.assertEqual(analysis["descriptive_cluster_enumeration"], {
            "enumeration": "all_2_power_3_task_lineage_sign_assignments_per_stratum",
            "interpretation": "finite_frozen_corpus_descriptive_sensitivity_only_not_confidence_interval_or_test",
            "rank_rule": "sort_exact_rational_signed_means_ascending_retain_ties",
            "reported_endpoints": "rank_1_minimum_rank_4_lower_median_rank_5_upper_median_rank_8_maximum",
            "signed_mean_formula": "for_each_of_8_sign_vectors_compute_exact_rational_sum_of_sign_times_three_lineage_means_divided_by_3",
            "rounding": "none_exact_rational",
        })

    def test_six_descriptive_estimands_have_closed_metric_formulas(self) -> None:
        definitions = getattr(self.verify, "DESCRIPTIVE_METRIC_DEFINITIONS", None)
        self.assertEqual(definitions, {
            "authoritative_total_cost_minor": "sum_provider_input_provider_output_provider_correction_amount_minor_when_all_observed_from_one_receipt_and_one_currency_else_unavailable",
            "correctness": "correct_equals_1_incorrect_equals_0_unavailable_is_null",
            "input_usage": "input_usage.value_when_observed_else_null",
            "pack_latency_ns": "pack_end_monotonic_ns_minus_pack_start_monotonic_ns_for_eligible_completed_unit",
            "retrieval_count": "retrieval_count.value_when_observed_else_null",
            "total_usage": "input_usage.value_plus_output_usage.value_plus_correction_tokens.value_when_all_observed_else_null",
        })
        self.assertEqual(self.prereg["analysis"]["metric_definitions"], definitions)

    def test_descriptive_metric_derivation_and_exact_cluster_vector(self) -> None:
        derive = getattr(self.verify, "derive_descriptive_metric", None)
        summarize = getattr(self.verify, "summarize_authenticated_observations", None)
        self.assertTrue(callable(derive), "missing closed descriptive metric derivation")
        self.assertTrue(callable(summarize), "missing authenticated observation summarizer")
        observation, _ = self.observation()
        self.assertEqual({
            metric: derive(observation, metric)
            for metric in self.verify.DESCRIPTIVE_METRIC_DEFINITIONS
        }, {
            "authoritative_total_cost_minor": {"currency": "USD", "value": 3},
            "correctness": {"currency": None, "value": 1},
            "input_usage": {"currency": None, "value": 1},
            "pack_latency_ns": {"currency": None, "value": 10},
            "retrieval_count": {"currency": None, "value": 1},
            "total_usage": {"currency": None, "value": 3},
        })
        observations = self.observations_for_schedule()
        result = summarize(
            observations,
            schedule_bytes=self.inputs["schedule_bytes"],
            schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
        )
        summary = result["metrics"]["input_usage"]["closed_pack"]["contrast"]
        self.assertEqual(summary["lineages"], [
            {"currency": None, "difference_mean": {"denominator": 1, "numerator": 0}, "lineage_id": "calibration_closed", "observed_pair_count": 10, "unavailable_pair_count": 0},
            {"currency": None, "difference_mean": {"denominator": 1, "numerator": 2}, "lineage_id": "evaluation_closed", "observed_pair_count": 10, "unavailable_pair_count": 0},
            {"currency": None, "difference_mean": {"denominator": 1, "numerator": -2}, "lineage_id": "train_closed", "observed_pair_count": 10, "unavailable_pair_count": 0},
        ])
        self.assertEqual(summary["signed_cluster_sensitivity"], {
            "assignment_count": 8,
            "currency": None,
            "endpoints": {
                "lower_median_rank_4": {"denominator": 1, "numerator": 0},
                "maximum_rank_8": {"denominator": 3, "numerator": 4},
                "minimum_rank_1": {"denominator": 3, "numerator": -4},
                "upper_median_rank_5": {"denominator": 1, "numerator": 0},
            },
            "ties": "retained",
        })
        combined = next(
            item for item in observations
            if item["block_id"] == "primary-001" and item["arm"] == "combined"
        )
        combined["input_usage"] = {
            "availability": "unavailable", "unavailable_reason": "not_observed",
            "value": None,
        }
        missing_result = summarize(
            observations,
            schedule_bytes=self.inputs["schedule_bytes"],
            schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
        )
        missing_summary = missing_result["metrics"]["input_usage"]["closed_pack"]["contrast"]
        self.assertEqual(
            (missing_summary["lineages"][2]["observed_pair_count"],
             missing_summary["lineages"][2]["unavailable_pair_count"]),
            (9, 1),
        )
        self.assertEqual(
            missing_result["metrics"]["input_usage"]["closed_pack"]["arms"]["combined"],
            {"denominator": 30, "observed": 29, "unavailable": 1},
        )

    def test_public_pair_rows_cannot_produce_a_descriptive_result(self) -> None:
        pairs = [
            {"combined": 10, "currency": None, "lineage_id": lineage,
             "ordinary": 10, "repetition": repetition, "stratum": "closed_pack"}
            for lineage in ("train_closed", "calibration_closed", "evaluation_closed")
            for repetition in range(1, 11)
        ]
        with self.assertRaisesRegex(Exception, "authenticated|observation"):
            self.verify.summarize_descriptive_pairs(pairs, "input_usage")

    def test_module_exports_no_pair_row_result_producer(self) -> None:
        pairs = [
            {"combined": 10, "currency": None, "lineage_id": lineage,
             "ordinary": 10, "repetition": repetition, "stratum": "closed_pack"}
            for lineage in ("train_closed", "calibration_closed", "evaluation_closed")
            for repetition in range(1, 11)
        ]
        producers = []
        for name, candidate in vars(self.verify).items():
            if callable(candidate) and "summar" in name and name != "summarize_authenticated_observations":
                try:
                    result = candidate(copy.deepcopy(pairs), "input_usage")
                except Exception:
                    continue
                if isinstance(result, dict) and "signed_cluster_sensitivity" in result:
                    producers.append(name)
        self.assertEqual(producers, [], f"pair-row result producers: {producers}")

    def test_pair_rows_reject_impossible_metric_domains(self) -> None:
        for metric, ordinary, combined in (
            ("input_usage", -1, 1),
            ("authoritative_total_cost_minor", -1, 1),
            ("correctness", 7, 9),
        ):
            with self.subTest(metric=metric):
                pairs = [
                    {"combined": combined,
                     "currency": "USD" if metric == "authoritative_total_cost_minor" else None,
                     "lineage_id": lineage, "ordinary": ordinary,
                     "repetition": repetition, "stratum": "closed_pack"}
                    for lineage in ("train_closed", "calibration_closed", "evaluation_closed")
                    for repetition in range(1, 11)
                ]
                with self.assertRaisesRegex(Exception, "domain|nonnegative|correctness"):
                    self.verify.summarize_descriptive_pairs(pairs, metric)

    def test_authenticated_batch_reducer_is_required_and_schedule_bound(self) -> None:
        reducer = getattr(self.verify, "summarize_authenticated_observations", None)
        self.assertTrue(callable(reducer), "missing authenticated observation batch reducer")
        observations = self.observations_for_schedule()
        changed_schedule = bytearray(self.inputs["schedule_bytes"])
        changed_schedule[-2] ^= 1
        changed_schema = bytearray(
            self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        )
        changed_schema[-2] ^= 1
        for label, schedule_bytes, schema_bytes in (
            ("schedule", bytes(changed_schedule), self.inputs["schema_bytes"]["authoritative-observation.schema.json"]),
            ("schema", self.inputs["schedule_bytes"], bytes(changed_schema)),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(Exception, "binding"):
                    reducer(
                        observations, schedule_bytes=schedule_bytes,
                        schema_bytes=schema_bytes,
                    )

    def test_authenticated_batch_rejects_missing_duplicate_and_unscheduled_units(self) -> None:
        reducer = getattr(self.verify, "summarize_authenticated_observations", None)
        self.assertTrue(callable(reducer), "missing authenticated observation batch reducer")
        observations = self.observations_for_schedule()
        for label, mutate in {
            "missing": lambda values: values.pop(),
            "duplicate unit": lambda values: values.__setitem__(1, copy.deepcopy(values[0])),
            "duplicate request": lambda values: values[1].update(request_id=values[0]["request_id"]),
            "duplicate receipt": lambda values: values[1].update(receipt_id=values[0]["receipt_id"]),
            "unscheduled": lambda values: values[0].update(scheduled_unit_id="unit-unscheduled-01"),
        }.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(observations)
                mutate(changed)
                with self.assertRaisesRegex(Exception, "240|duplicate|schedule|unscheduled|identity"):
                    reducer(
                        changed,
                        schedule_bytes=self.inputs["schedule_bytes"],
                        schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
                    )

    def test_authenticated_batch_excludes_entire_four_arm_block_and_partial_cost(self) -> None:
        reducer = getattr(self.verify, "summarize_authenticated_observations", None)
        self.assertTrue(callable(reducer), "missing authenticated observation batch reducer")
        observations = self.observations_for_schedule()
        first_block = self.schedule["blocks"][0]
        adaptive_id = next(
            unit["scheduled_unit_id"] for unit in first_block["units"]
            if unit["arm"] == "adaptive_only"
        )
        failed = next(item for item in observations if item["scheduled_unit_id"] == adaptive_id)
        failed.update(
            unit_status="excluded", completion_event="transport_error",
            audit_status="excluded", exclusion_reason="transport_error",
        )
        self.make_unavailable(failed)
        cost_partial = next(
            item for item in observations
            if item["block_id"] == "primary-002" and item["arm"] == "ordinary"
        )
        cost_partial["cost_components"][0].update(
            amount_minor=None, availability="unavailable", currency=None,
            receipt_reference=None, unavailable_reason="not_in_authoritative_receipt",
        )
        result = reducer(
            observations,
            schedule_bytes=self.inputs["schedule_bytes"],
            schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
        )
        self.assertEqual(result["accounting"], {
            "analyzed_blocks": 59, "analyzed_units": 236,
            "excluded_blocks": 1, "excluded_units": 4,
            "randomized_blocks": 60, "randomized_units": 240,
            "randomized_blocks_equals_analyzed_blocks_plus_excluded_blocks": True,
            "randomized_units_equals_analyzed_units_plus_excluded_units": True,
        })
        self.assertEqual(
            result["metrics"]["input_usage"]["closed_pack"]["contrast"]["availability"],
            {"denominator": 30, "observed_pair_count": 29, "unavailable_pair_count": 1},
        )
        self.assertEqual(
            result["metrics"]["authoritative_total_cost_minor"]["realistic_fallback"]["contrast"]["availability"],
            {"denominator": 30, "observed_pair_count": 29, "unavailable_pair_count": 1},
        )
        self.assertEqual(result["terminal_exclusion_reason_counts"], {
            reason: 1 if reason == "transport_error" else 0
            for reason in self.verify.EXCLUSION_REASONS
        })
        self.assertEqual(result["block_exclusion_counts"], {
            "block_policy_analytic_exclusion": 1,
            "terminal_excluded_unit": 1,
        })
        self.assertEqual(result["block_exclusion_reason_sets"], {
            "primary-001": ["transport_error"],
        })
        for metric in self.verify.DESCRIPTIVE_METRIC_DEFINITIONS:
            for stratum in ("closed_pack", "realistic_fallback"):
                by_arm = result["metrics"][metric][stratum]["arms"]
                self.assertEqual(set(by_arm), set(self.verify.ARMS))
                for arm, availability in by_arm.items():
                    expected_unavailable = (
                        1 if stratum == "closed_pack" else
                        1 if metric == "authoritative_total_cost_minor" and arm == "ordinary" else 0
                    )
                    self.assertEqual(availability, {
                        "denominator": 30,
                        "observed": 30 - expected_unavailable,
                        "unavailable": expected_unavailable,
                    })
        symbol_observations = self.observations_for_schedule()
        symbol_id = next(
            unit["scheduled_unit_id"] for unit in first_block["units"]
            if unit["arm"] == "symbol_only"
        )
        symbol_failed = next(
            item for item in symbol_observations
            if item["scheduled_unit_id"] == symbol_id
        )
        symbol_failed.update(
            unit_status="excluded", completion_event="transport_error",
            audit_status="excluded", exclusion_reason="transport_error",
        )
        self.make_unavailable(symbol_failed)
        symbol_result = reducer(
            symbol_observations,
            schedule_bytes=self.inputs["schedule_bytes"],
            schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
        )
        self.assertEqual(
            symbol_result["metrics"]["input_usage"]["closed_pack"]["contrast"]["availability"],
            {"denominator": 30, "observed_pair_count": 29, "unavailable_pair_count": 1},
        )

    def test_authenticated_batch_reports_multiple_terminal_and_block_reasons(self) -> None:
        observations = self.observations_for_schedule()
        for block_id, arm, reason in (
            ("primary-001", "adaptive_only", "transport_error"),
            ("primary-002", "symbol_only", "timeout"),
        ):
            failed = next(
                item for item in observations
                if item["block_id"] == block_id and item["arm"] == arm
            )
            failed.update(
                unit_status="excluded", completion_event=reason,
                audit_status="excluded", exclusion_reason=reason,
            )
            self.make_unavailable(failed)
            failed["completion_event"] = reason
            failed["exclusion_reason"] = reason
        result = self.verify.summarize_authenticated_observations(
            observations,
            schedule_bytes=self.inputs["schedule_bytes"],
            schema_bytes=self.inputs["schema_bytes"]["authoritative-observation.schema.json"],
        )
        self.assertEqual(result["terminal_exclusion_reason_counts"]["transport_error"], 1)
        self.assertEqual(result["terminal_exclusion_reason_counts"]["timeout"], 1)
        self.assertEqual(result["block_exclusion_counts"], {
            "block_policy_analytic_exclusion": 2,
            "terminal_excluded_unit": 2,
        })
        self.assertEqual(result["block_exclusion_reason_sets"], {
            "primary-001": ["transport_error"],
            "primary-002": ["timeout"],
        })

    def test_billing_receipt_reference_is_observed_nonnull_or_unavailable_null(self) -> None:
        schema = json.loads(
            self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        )
        reference_schema = schema["properties"]["billing_receipt"]["properties"]["reference"]
        self.assertEqual(reference_schema.get("type"), ["string", "null"])

    def test_schedule_has_no_uneven_replacement_blocks_and_maximum_240(self) -> None:
        self.assertEqual(self.schedule["block_count"], 60)
        self.assertEqual(self.schedule["unit_count"], 240)
        self.assertEqual({block["kind"] for block in self.schedule["blocks"]}, {"primary"})
        self.assertEqual(self.prereg["design"]["fixed_counts"]["replacement_blocks_maximum"], 0)
        self.assertEqual(self.prereg["design"]["fixed_counts"]["scheduled_units_maximum"], 240)
        self.assertEqual(self.prereg["future_execution_boundary"]["maximum_scheduled_units"], 240)

    def test_observer_state_product_is_closed_and_metrics_unavailable_when_excluded(self) -> None:
        base, scheduled = self.observation()
        schema = json.loads(
            self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        )
        reasons = (
            "unscheduled_unit", "duplicate_request_id", "duplicate_receipt_id",
            "assignment_identity_mismatch", "payload_identity_mismatch",
            "task_arm_stratum_partition_or_repetition_mismatch", "observer_version_mismatch",
            "model_identity_mismatch", "provider_receipt_not_authoritative", "transport_error",
            "timeout", "cancellation", "missing_required_field", "malformed_required_field",
            "nonmonotonic_timestamp", "incomplete_four_arm_block",
        )
        self.assertEqual(
            set(schema["properties"]["completion_event"]["enum"]),
            {"normal_completion", *reasons},
        )
        for status in ("completed", "excluded"):
            for event in ("normal_completion", *reasons):
                for audit in ("eligible", "excluded"):
                    for reason in ("none", *reasons):
                        value = copy.deepcopy(base)
                        value.update(unit_status=status, completion_event=event, audit_status=audit, exclusion_reason=reason)
                        valid = (status, event, audit, reason) == (
                            "completed", "normal_completion", "eligible", "none"
                        ) or (status == "excluded" and event == reason and audit == "excluded" and reason != "none")
                        if valid and status == "excluded":
                            self.make_unavailable(value)
                        if valid:
                            self.verify.validate_observation(
                                value, self.inputs["schema_bytes"]["authoritative-observation.schema.json"], scheduled
                            )
                        else:
                            with self.assertRaises(Exception):
                                self.verify.validate_observation(
                                    value, self.inputs["schema_bytes"]["authoritative-observation.schema.json"], scheduled
                                )

    def test_observer_rejects_excluded_unit_with_any_observed_metric(self) -> None:
        value, scheduled = self.observation()
        value.update(unit_status="excluded", completion_event="transport_error", audit_status="excluded", exclusion_reason="transport_error")
        self.make_unavailable(value)
        value["retrieval_count"] = {"availability": "observed", "unavailable_reason": "not_applicable", "value": 0}
        with self.assertRaisesRegex(Exception, "excluded|unavailable|state"):
            self.verify.validate_observation(
                value, self.inputs["schema_bytes"]["authoritative-observation.schema.json"], scheduled
            )

    def test_completed_record_rejects_incoherent_metric_correctness_and_receipt_states(self) -> None:
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        cases = {
            "metric excluded reason": lambda value: value["input_usage"].update(
                availability="unavailable", unavailable_reason="excluded_unit", value=None
            ),
            "observed correctness excluded reason": lambda value: value["correctness"].update(
                availability="observed", outcome="correct", unavailable_reason="excluded_unit"
            ),
            "unavailable correctness not applicable": lambda value: value["correctness"].update(
                availability="unavailable", outcome="unavailable", unavailable_reason="not_applicable"
            ),
            "unavailable authority observed status": lambda value: (
                value["billing_receipt"].update(
                    authority="unavailable", reference=None, status="observed"
                ),
                [
                    component.update(
                        amount_minor=None, availability="unavailable", currency=None,
                        receipt_reference=None, unavailable_reason="receipt_unavailable",
                    )
                    for component in value["cost_components"]
                ],
            ),
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                value, scheduled = self.observation()
                mutation(value)
                with self.assertRaisesRegex(Exception, "metric|correctness|receipt|state|reason|authority"):
                    self.verify.validate_observation(value, schema, scheduled)

    def test_completed_metric_availability_value_reason_product(self) -> None:
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        reasons = (
            "not_applicable", "not_in_authoritative_receipt", "receipt_unavailable",
            "not_observed", "excluded_unit",
        )
        for availability in ("observed", "unavailable"):
            for reason in reasons:
                for metric_value in (0, None):
                    with self.subTest(availability=availability, reason=reason, value=metric_value):
                        value, scheduled = self.observation()
                        value["input_usage"] = {
                            "availability": availability, "unavailable_reason": reason,
                            "value": metric_value,
                        }
                        valid = (
                            availability == "observed" and reason == "not_applicable"
                            and metric_value == 0
                        ) or (
                            availability == "unavailable"
                            and reason in {"not_in_authoritative_receipt", "receipt_unavailable", "not_observed"}
                            and metric_value is None
                        )
                        if valid:
                            self.verify.validate_observation(value, schema, scheduled)
                        else:
                            with self.assertRaises(Exception):
                                self.verify.validate_observation(value, schema, scheduled)

    def test_completed_correctness_availability_outcome_reason_product(self) -> None:
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        for availability in ("observed", "unavailable"):
            for outcome in ("correct", "incorrect", "unavailable"):
                for reason in ("not_applicable", "not_observed", "excluded_unit"):
                    with self.subTest(availability=availability, outcome=outcome, reason=reason):
                        value, scheduled = self.observation()
                        value["correctness"] = {
                            "availability": availability, "outcome": outcome,
                            "unavailable_reason": reason,
                        }
                        valid = (
                            availability == "observed" and outcome in {"correct", "incorrect"}
                            and reason == "not_applicable"
                        ) or (
                            availability == "unavailable" and outcome == "unavailable"
                            and reason == "not_observed"
                        )
                        if valid:
                            self.verify.validate_observation(value, schema, scheduled)
                        else:
                            with self.assertRaises(Exception):
                                self.verify.validate_observation(value, schema, scheduled)

    def test_completed_billing_authority_status_reference_product(self) -> None:
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        for authority in ("authoritative_provider_receipt", "unavailable"):
            for status in ("observed", "unavailable"):
                for reference in ("billing-1", None):
                    with self.subTest(authority=authority, status=status, reference=reference):
                        value, scheduled = self.observation()
                        value["billing_receipt"] = {
                            "authority": authority, "reference": reference, "status": status,
                        }
                        observed = (authority, status, reference) == (
                            "authoritative_provider_receipt", "observed", "billing-1"
                        )
                        unavailable = (authority, status, reference) == (
                            "unavailable", "unavailable", None
                        )
                        if not observed:
                            for component in value["cost_components"]:
                                component.update(
                                    amount_minor=None, availability="unavailable", currency=None,
                                    receipt_reference=None, unavailable_reason="receipt_unavailable",
                                )
                        if observed or unavailable:
                            self.verify.validate_observation(value, schema, scheduled)
                        else:
                            with self.assertRaises(Exception):
                                self.verify.validate_observation(value, schema, scheduled)

    def test_observer_rejects_mixed_currency_receipt_and_paired_summary(self) -> None:
        value, scheduled = self.observation()
        schema = self.inputs["schema_bytes"]["authoritative-observation.schema.json"]
        value["cost_components"][1]["currency"] = "EUR"
        with self.assertRaisesRegex(Exception, "currency"):
            self.verify.validate_observation(value, schema, scheduled)

    def test_paired_cost_summary_requires_same_currency(self) -> None:
        validator = getattr(self.verify, "validate_paired_currency", None)
        self.assertTrue(callable(validator), "missing same-currency paired-summary validator")
        left, _ = self.observation()
        right, _ = self.observation()
        for component in right["cost_components"]:
            component["currency"] = "EUR"
        with self.assertRaisesRegex(Exception, "currency"):
            validator(left, right)
        pairs = [
            {"combined": 2, "currency": currency, "lineage_id": lineage,
             "ordinary": 1, "repetition": repetition, "stratum": "closed_pack"}
            for lineage, currency in (
                ("train_closed", "USD"), ("calibration_closed", "EUR"),
                ("evaluation_closed", "USD"),
            )
            for repetition in range(1, 11)
        ]
        with self.assertRaisesRegex(Exception, "currency"):
            self.verify.summarize_descriptive_pairs(
                pairs, "authoritative_total_cost_minor"
            )
        for pair in pairs:
            pair["currency"] = None
        with self.assertRaisesRegex(Exception, "currency"):
            self.verify.summarize_descriptive_pairs(
                pairs, "authoritative_total_cost_minor"
            )

    def test_provider_model_network_credential_and_runner_remain_blocked(self) -> None:
        self.assertEqual(self.prereg["future_execution_boundary"], {
            "status": "future_authorization_required", "provider": "unselected",
            "model": "unselected", "credential": "unselected", "network": "not_authorized",
            "write_root": "unselected", "maximum_scheduled_units": 240, "runner": "absent",
        })

    def test_audited_negative_network_dns_process_and_write_probes(self) -> None:
        self.assertEqual(self.verify.audited_negative_probes(), {
            "dns_denials": 1, "network_denials": 1, "process_denials": 1, "write_denials": 1,
        })

    def test_bound_child_is_lang_only_and_direct_mutable_verifier_refuses(self) -> None:
        if "__G5_CAPTURED_VERIFIER_BYTES__" in globals():
            self.assertEqual(sys.flags.isolated, 1)
            self.assertEqual(sys.flags.dont_write_bytecode, 1)
            self.assertEqual(os.environ.get("LANG"), "C.UTF-8")
            self.assertTrue(set(os.environ) <= {"LANG", "__CF_USER_TEXT_ENCODING"})
        self.assertEqual(self.verify.main([]), 2)


if __name__ == "__main__":
    unittest.main()
