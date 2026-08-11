"""Pure, fail-closed P2-P6 evaluation over caller-supplied local records.

The module computes eligibility only.  Caller-supplied records can never grant
runtime activation or public-claim authority.
"""

from __future__ import annotations

import re
from typing import Final


_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MAX_RECORDS: Final = 10_000
_P2_TOP: Final = frozenset(
    {
        "schema_version",
        "phase_id",
        "baseline_fallback_verified",
        "activation_authorized",
        "dependency_gates_passed",
        "observed_at",
        "minimum_recall_basis_points",
        "records",
    }
)
_P2_ROW: Final = frozenset(
    {
        "record_id",
        "stratum",
        "relevant",
        "candidate_omission",
        "recalled",
        "source_digest",
        "rehydrated_digest",
        "fresh_until",
        "protection",
        "construction_cost_microunits",
    }
)
_P3_TOP: Final = frozenset(
    {
        "schema_version",
        "phase_id",
        "baseline_fallback_verified",
        "activation_authorized",
        "dependency_gates_passed",
        "claim_scope_bound",
        "evidence_origin",
        "matched_pair_ids",
        "attempts",
        "thresholds",
    }
)
_P3_ATTEMPT: Final = frozenset(
    {
        "attempt_id",
        "pair_id",
        "arm",
        "task_success",
        "corrections",
        "retrievals",
        "measurement",
    }
)
_P3_RETRIEVAL: Final = frozenset({"retrieval_id", "exact"})
_P3_MEASUREMENT: Final = frozenset(
    {
        "primary_tokens",
        "provider_cost_microunits",
        "retry_cost_microunits",
        "correction_cost_microunits",
        "retrieval_cost_microunits",
        "external_cost_microunits",
        "local_compute_cost_microunits",
    }
)
_P3_COST_FIELDS: Final = _P3_MEASUREMENT - {"primary_tokens"}
_P3_THRESHOLDS: Final = frozenset(
    {
        "maximum_failure_rate_increase_basis_points",
        "require_corrections_non_inferior",
        "require_fully_loaded_cost_improvement",
    }
)
_P4_TOP: Final = frozenset(
    {
        "schema_version",
        "phase_id",
        "baseline_fallback_verified",
        "dependency_gates_passed",
        "activation_authorized",
        "minimum_confidence_basis_points",
        "trials",
    }
)
_P4_TRIAL: Final = frozenset(
    {
        "trial_id",
        "advisory_status",
        "advisory_route",
        "confidence_basis_points",
        "bypass_reasons",
        "outcomes",
    }
)
_P4_OUTCOMES: Final = frozenset(
    {"advisory", "always_pass_through", "always_on"}
)
_P4_OUTCOME: Final = frozenset(
    {"quality_basis_points", "total_cost_microunits", "cache_accounting"}
)
_P4_CACHE: Final = frozenset(
    {
        "creation_microunits",
        "read_microunits",
        "invalidation_microunits",
        "latency_microunits",
        "provider_cost_microunits",
    }
)
_P5_TOP: Final = frozenset(
    {
        "schema_version",
        "phase_id",
        "dependency_gates_passed",
        "activation_authorized",
        "current_revision_digest",
        "current_source_digest",
        "current_test_digest",
        "adjuncts",
    }
)
_P5_ADJUNCT_IDS: Final = frozenset(
    {"execution_twin", "failure_cone", "typed_blueprint"}
)
_P5_ADJUNCT: Final = frozenset(
    {
        "adjunct_id",
        "revision_digest",
        "source_digest",
        "test_digest",
        "evidence_digests",
        "failure_cases",
        "bypass_verified",
        "fallback_verified",
        "baseline_quality_basis_points",
        "adjunct_quality_basis_points",
        "baseline_cost_microunits",
        "adjunct_cost_microunits",
    }
)
_P5_FAILURE_CASE: Final = frozenset(
    {"case_id", "exit_status", "root_cause", "duplicate_of"}
)
_P6_TOP: Final = frozenset(
    {"schema_version", "phase_id", "dependency_gates_passed", "tracks"}
)
_P6_TRACK_IDS: Final = frozenset(
    {
        "context_leases",
        "scout_surgeon",
        "counterfactual_ledger",
        "negative_firewall",
        "bounded_compilation",
    }
)
_P6_TRACK: Final = frozenset(
    {
        "track_id",
        "surface",
        "workload_digest",
        "baseline_digest",
        "scope_digest",
        "privacy_boundary_digest",
        "privacy_verified",
        "baseline_quality_basis_points",
        "track_quality_basis_points",
        "population_count",
        "baseline_failure_count",
        "track_failure_count",
        "maximum_failure_rate_increase_basis_points",
        "baseline_corrections",
        "track_corrections",
        "cost_model_digest",
        "baseline_cost_microunits",
        "track_cost_microunits",
        "fallback_verified",
        "rollback_verified",
        "activation_authorized",
        "provider_evidence_digest",
    }
)


def _exact_dict(value: object, keys: frozenset[str]) -> bool:
    return type(value) is dict and set(value) == keys


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _closed_result(phase_id: str, blockers: list[str], **values: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "contextguard.phase-evaluation.result/v1",
        "phase_id": phase_id,
        "implementation_readiness": False,
        "evaluation_evidence_complete": False,
        "provider_evidence": False,
        "activation_eligibility": False,
        "activation_authority": False,
        "claim_authority": False,
        "fallback": "exact_unchanged_baseline",
        "blockers": _deduplicate(blockers),
    }
    result.update(values)
    return result


def evaluate_p2(record: object) -> dict[str, object]:
    """Evaluate P2 shadow recall and exact rehydration without applying a route."""

    if not _exact_dict(record, _P2_TOP):
        return _closed_result(
            "p2",
            ["malformed_record", "external_activation_authority_required"],
            evaluated_record_count=0,
            construction_cost_microunits=0,
            strata=[],
        )
    data = record
    blockers: list[str] = []
    if (
        data["schema_version"] != "contextguard.phase-evaluation.p2/v1"
        or data["phase_id"] != "p2"
    ):
        blockers.append("malformed_record")
    for field in (
        "baseline_fallback_verified",
        "activation_authorized",
        "dependency_gates_passed",
    ):
        if type(data[field]) is not bool:
            blockers.append("malformed_record")

    observed_at = data["observed_at"]
    threshold = data["minimum_recall_basis_points"]
    rows = data["records"]
    if not _nonnegative_integer(observed_at):
        blockers.append("malformed_record")
        observed_at = 0
    if type(threshold) is not int or not 0 <= threshold <= 10_000:
        blockers.append("malformed_record")
        threshold = 10_000
    if type(rows) is not list or not rows or len(rows) > _MAX_RECORDS:
        blockers.append("malformed_record")
        rows = []

    record_ids: set[str] = set()
    stratum_counts: dict[str, list[int]] = {}
    construction_cost = 0
    for row in rows:
        if not _exact_dict(row, _P2_ROW):
            blockers.append("malformed_record")
            continue
        record_id = row["record_id"]
        stratum = row["stratum"]
        if not _valid_identifier(record_id) or record_id in record_ids:
            blockers.append("malformed_record")
        else:
            record_ids.add(record_id)
        if not _valid_identifier(stratum):
            blockers.append("malformed_record")
            continue
        if any(
            type(row[field]) is not bool
            for field in ("relevant", "candidate_omission", "recalled")
        ):
            blockers.append("malformed_record")
            continue
        if not _valid_digest(row["source_digest"]):
            blockers.append("non_rehydratable_record")
        if not _nonnegative_integer(row["fresh_until"]) or row["fresh_until"] <= observed_at:
            blockers.append("stale_record")
        protection = row["protection"]
        if protection not in {"eligible", "protected", "ambiguous"}:
            blockers.append("malformed_record")
        if not _nonnegative_integer(row["construction_cost_microunits"]):
            blockers.append("construction_cost_incomplete")
        else:
            construction_cost += row["construction_cost_microunits"]

        if row["candidate_omission"]:
            if protection != "eligible":
                blockers.append("protected_omission")
            if not _valid_digest(row["rehydrated_digest"]):
                blockers.append("non_rehydratable_record")
            elif row["rehydrated_digest"] != row["source_digest"]:
                blockers.append("non_rehydratable_record")
        elif row["rehydrated_digest"] is not None:
            blockers.append("malformed_record")

        counts = stratum_counts.setdefault(stratum, [0, 0])
        if row["relevant"]:
            counts[0] += 1
            if row["recalled"]:
                counts[1] += 1

    strata: list[dict[str, object]] = []
    if not any(relevant for relevant, _ in stratum_counts.values()):
        blockers.append("recall_unavailable")
    for stratum in sorted(stratum_counts):
        relevant, recalled = stratum_counts[stratum]
        if relevant == 0:
            continue
        recall_basis_points = recalled * 10_000 // relevant
        threshold_passed = recall_basis_points >= threshold
        if not threshold_passed:
            blockers.append("recall_threshold_failed")
        strata.append(
            {
                "stratum": stratum,
                "relevant_record_count": relevant,
                "recalled_relevant_record_count": recalled,
                "recall_basis_points": recall_basis_points,
                "threshold_passed": threshold_passed,
            }
        )
    if data["baseline_fallback_verified"] is not True:
        blockers.append("exact_fallback_unverified")

    local_blockers = {
        "malformed_record",
        "non_rehydratable_record",
        "stale_record",
        "protected_omission",
        "construction_cost_incomplete",
        "recall_unavailable",
        "recall_threshold_failed",
        "exact_fallback_unverified",
    }
    local_ready = not any(blocker in local_blockers for blocker in blockers)
    activation_eligible = (
        local_ready
        and data["dependency_gates_passed"] is True
        and data["activation_authorized"] is True
    )
    if data["dependency_gates_passed"] is not True:
        blockers.append("dependency_gates_incomplete")
    if data["activation_authorized"] is not True:
        blockers.append("activation_not_recorded")
    blockers.append("external_activation_authority_required")
    return _closed_result(
        "p2",
        blockers,
        implementation_readiness=local_ready,
        evaluation_evidence_complete=local_ready,
        activation_eligibility=activation_eligible,
        evaluated_record_count=len(rows),
        construction_cost_microunits=construction_cost,
        strata=strata,
    )


def evaluate_p3(record: object) -> dict[str, object]:
    """Evaluate P3 matched canary evidence and computed guardrails."""

    if not _exact_dict(record, _P3_TOP):
        return _closed_result(
            "p3",
            ["malformed_record", "external_activation_authority_required", "external_claim_authority_required"],
            evaluated_attempt_count=0,
            evaluated_pair_count=0,
            evaluated_retrieval_count=0,
            baseline_fully_loaded_cost_microunits=0,
            canary_fully_loaded_cost_microunits=0,
        )
    data = record
    blockers: list[str] = []
    if (
        data["schema_version"] != "contextguard.phase-evaluation.p3/v1"
        or data["phase_id"] != "p3"
    ):
        blockers.append("malformed_record")
    for field in (
        "baseline_fallback_verified",
        "activation_authorized",
        "dependency_gates_passed",
        "claim_scope_bound",
    ):
        if type(data[field]) is not bool:
            blockers.append("malformed_record")

    pair_ids = data["matched_pair_ids"]
    attempts = data["attempts"]
    if (
        type(pair_ids) is not list
        or not pair_ids
        or len(pair_ids) > _MAX_RECORDS
        or any(not _valid_identifier(pair_id) for pair_id in pair_ids)
        or len(set(pair_ids)) != len(pair_ids)
    ):
        blockers.append("malformed_record")
        pair_ids = []
    if (
        type(attempts) is not list
        or not attempts
        or len(attempts) > _MAX_RECORDS * 2
    ):
        blockers.append("malformed_record")
        attempts = []

    thresholds = data["thresholds"]
    if not _exact_dict(thresholds, _P3_THRESHOLDS):
        blockers.append("malformed_record")
        thresholds = {}
    maximum_failure_increase = thresholds.get(
        "maximum_failure_rate_increase_basis_points"
    )
    if type(maximum_failure_increase) is not int or not 0 <= maximum_failure_increase <= 10_000:
        blockers.append("malformed_record")
        maximum_failure_increase = 0
    if thresholds.get("require_corrections_non_inferior") is not True:
        blockers.append("required_guardrail_disabled")
    if thresholds.get("require_fully_loaded_cost_improvement") is not True:
        blockers.append("required_guardrail_disabled")

    expected_pairs = set(pair_ids)
    attempt_ids: set[str] = set()
    pair_members: dict[str, dict[str, dict[str, object]]] = {}
    retrieval_count = 0
    measurement_complete = True
    for attempt in attempts:
        if not _exact_dict(attempt, _P3_ATTEMPT):
            blockers.append("malformed_record")
            continue
        attempt_id = attempt["attempt_id"]
        pair_id = attempt["pair_id"]
        arm = attempt["arm"]
        if not _valid_identifier(attempt_id) or attempt_id in attempt_ids:
            blockers.append("malformed_record")
        else:
            attempt_ids.add(attempt_id)
        if not _valid_identifier(pair_id) or pair_id not in expected_pairs:
            blockers.append("matched_population_incomplete")
        if arm not in {"baseline", "canary"}:
            blockers.append("malformed_record")
        elif _valid_identifier(pair_id) and pair_id in expected_pairs:
            members = pair_members.setdefault(pair_id, {})
            if arm in members:
                blockers.append("matched_population_incomplete")
            else:
                members[arm] = attempt
        if type(attempt["task_success"]) is not bool:
            blockers.append("malformed_record")
        if not _nonnegative_integer(attempt["corrections"]):
            blockers.append("malformed_record")

        retrievals = attempt["retrievals"]
        if type(retrievals) is not list or len(retrievals) > _MAX_RECORDS:
            blockers.append("malformed_record")
            retrievals = []
        retrieval_ids: set[str] = set()
        for retrieval in retrievals:
            if not _exact_dict(retrieval, _P3_RETRIEVAL):
                blockers.append("malformed_record")
                continue
            retrieval_id = retrieval["retrieval_id"]
            if not _valid_identifier(retrieval_id) or retrieval_id in retrieval_ids:
                blockers.append("malformed_record")
            else:
                retrieval_ids.add(retrieval_id)
            if retrieval["exact"] is not True:
                blockers.append("exact_retrieval_incomplete")
            retrieval_count += 1

        measurement = attempt["measurement"]
        if not _exact_dict(measurement, _P3_MEASUREMENT) or any(
            not _nonnegative_integer(measurement.get(field))
            for field in _P3_MEASUREMENT
        ):
            blockers.append("provider_measurement_incomplete")
            measurement_complete = False

    if set(pair_members) != expected_pairs or any(
        set(pair_members.get(pair_id, {})) != {"baseline", "canary"}
        for pair_id in expected_pairs
    ):
        blockers.append("matched_population_incomplete")
    if len(attempts) != len(expected_pairs) * 2:
        blockers.append("matched_population_incomplete")

    baseline_failures = 0
    canary_failures = 0
    baseline_corrections = 0
    canary_corrections = 0
    baseline_cost = 0
    canary_cost = 0
    complete_pairs = 0
    for pair_id in pair_ids:
        members = pair_members.get(pair_id, {})
        if set(members) != {"baseline", "canary"}:
            continue
        complete_pairs += 1
        baseline = members["baseline"]
        canary = members["canary"]
        if type(baseline["task_success"]) is bool:
            baseline_failures += int(not baseline["task_success"])
        if type(canary["task_success"]) is bool:
            canary_failures += int(not canary["task_success"])
        if _nonnegative_integer(baseline["corrections"]):
            baseline_corrections += baseline["corrections"]
        if _nonnegative_integer(canary["corrections"]):
            canary_corrections += canary["corrections"]
        for arm_name, member in (("baseline", baseline), ("canary", canary)):
            measurement = member["measurement"]
            if not _exact_dict(measurement, _P3_MEASUREMENT) or any(
                not _nonnegative_integer(measurement.get(field))
                for field in _P3_MEASUREMENT
            ):
                continue
            total = sum(measurement[field] for field in _P3_COST_FIELDS)
            if arm_name == "baseline":
                baseline_cost += total
            else:
                canary_cost += total

    if complete_pairs:
        if (
            (canary_failures - baseline_failures) * 10_000
            > maximum_failure_increase * complete_pairs
        ):
            blockers.append("failure_guardrail_failed")
        if canary_corrections > baseline_corrections:
            blockers.append("correction_guardrail_failed")
        if measurement_complete and canary_cost >= baseline_cost:
            blockers.append("fully_loaded_cost_not_improved")
    if data["evidence_origin"] != "provider_measured":
        blockers.append("provider_measurement_incomplete")
        measurement_complete = False
    if data["baseline_fallback_verified"] is not True:
        blockers.append("exact_fallback_unverified")

    local_blockers = {
        "malformed_record",
        "matched_population_incomplete",
        "exact_retrieval_incomplete",
        "exact_fallback_unverified",
        "required_guardrail_disabled",
    }
    evaluation_blockers = local_blockers | {
        "provider_measurement_incomplete",
        "failure_guardrail_failed",
        "correction_guardrail_failed",
        "fully_loaded_cost_not_improved",
    }
    implementation_ready = not any(blocker in local_blockers for blocker in blockers)
    provider_evidence = measurement_complete and not any(
        blocker in {
            "malformed_record",
            "matched_population_incomplete",
            "provider_measurement_incomplete",
        }
        for blocker in blockers
    )
    evaluation_complete = not any(blocker in evaluation_blockers for blocker in blockers)
    activation_eligible = (
        evaluation_complete
        and data["dependency_gates_passed"] is True
        and data["activation_authorized"] is True
        and data["claim_scope_bound"] is True
    )
    if data["dependency_gates_passed"] is not True:
        blockers.append("dependency_gates_incomplete")
    if data["activation_authorized"] is not True:
        blockers.append("activation_not_recorded")
    if data["claim_scope_bound"] is not True:
        blockers.append("claim_scope_unbound")
    blockers.extend(
        ["external_activation_authority_required", "external_claim_authority_required"]
    )
    return _closed_result(
        "p3",
        blockers,
        implementation_readiness=implementation_ready,
        evaluation_evidence_complete=evaluation_complete,
        provider_evidence=provider_evidence,
        activation_eligibility=activation_eligible,
        evaluated_attempt_count=len(attempts),
        evaluated_pair_count=complete_pairs,
        evaluated_retrieval_count=retrieval_count,
        baseline_failure_count=baseline_failures,
        canary_failure_count=canary_failures,
        baseline_correction_count=baseline_corrections,
        canary_correction_count=canary_corrections,
        baseline_fully_loaded_cost_microunits=baseline_cost,
        canary_fully_loaded_cost_microunits=canary_cost,
    )


def evaluate_p4(record: object) -> dict[str, object]:
    """Evaluate advisory router regret without changing a runtime route."""

    empty_values = {
        "runtime_route_changed": False,
        "selected_route": "pass_through",
        "evaluated_trial_count": 0,
        "abstention_count": 0,
        "failure_count": 0,
        "confidence_basis_points": [],
        "bypass_reason_counts": {},
        "trials": [],
    }
    if not _exact_dict(record, _P4_TOP):
        return _closed_result(
            "p4",
            ["malformed_record", "external_activation_authority_required"],
            **empty_values,
        )
    data = record
    blockers: list[str] = []
    if (
        data["schema_version"] != "contextguard.phase-evaluation.p4/v1"
        or data["phase_id"] != "p4"
    ):
        blockers.append("malformed_record")
    for field in (
        "baseline_fallback_verified",
        "dependency_gates_passed",
        "activation_authorized",
    ):
        if type(data[field]) is not bool:
            blockers.append("malformed_record")

    minimum_confidence = data["minimum_confidence_basis_points"]
    if type(minimum_confidence) is not int or not 0 <= minimum_confidence <= 10_000:
        blockers.append("malformed_record")
        minimum_confidence = 10_000
    trials = data["trials"]
    if type(trials) is not list or not trials or len(trials) > _MAX_RECORDS:
        blockers.append("malformed_record")
        trials = []

    trial_ids: set[str] = set()
    reports: list[dict[str, object]] = []
    confidences: list[int] = []
    reason_counts: dict[str, int] = {}
    abstention_count = 0
    failure_count = 0
    advisory_routes: set[str] = set()
    all_trials_eligible = bool(trials)
    for trial in trials:
        reasons: list[str] = []
        regret: int | None = None
        confidence = 0
        status: object = None
        advisory_route: object = None
        trial_id: object = None
        if not _exact_dict(trial, _P4_TRIAL):
            reasons.append("malformed_record")
        else:
            raw_trial_id = trial["trial_id"]
            raw_status = trial["advisory_status"]
            raw_advisory_route = trial["advisory_route"]
            if not _valid_identifier(raw_trial_id) or raw_trial_id in trial_ids:
                reasons.append("malformed_record")
            else:
                trial_id = raw_trial_id
                trial_ids.add(trial_id)
            if type(raw_status) is not str or raw_status not in {
                "selected",
                "abstained",
                "failed",
            }:
                reasons.append("malformed_record")
            else:
                status = raw_status
            if status == "selected":
                if type(raw_advisory_route) is not str or raw_advisory_route not in {
                    "pass_through",
                    "on",
                }:
                    reasons.append("malformed_record")
                else:
                    advisory_route = raw_advisory_route
                    advisory_routes.add(advisory_route)
            elif raw_advisory_route is not None:
                reasons.append("malformed_record")
            if status == "abstained":
                abstention_count += 1
                reasons.append("abstained")
            elif status == "failed":
                failure_count += 1
                reasons.append("failed")

            confidence_value = trial["confidence_basis_points"]
            if type(confidence_value) is not int or not 0 <= confidence_value <= 10_000:
                reasons.append("malformed_record")
            else:
                confidence = confidence_value
            confidences.append(confidence)
            if confidence < minimum_confidence:
                reasons.append("low_confidence")

            supplied_reasons = trial["bypass_reasons"]
            if (
                type(supplied_reasons) is not list
                or any(not _valid_identifier(reason) for reason in supplied_reasons)
            ):
                reasons.append("malformed_record")
            else:
                reasons.extend(supplied_reasons)

            outcomes = trial["outcomes"]
            parsed: dict[str, tuple[int, int]] = {}
            if not _exact_dict(outcomes, _P4_OUTCOMES):
                reasons.append("cache_accounting_incomplete")
            else:
                for policy in sorted(_P4_OUTCOMES):
                    outcome = outcomes[policy]
                    if not _exact_dict(outcome, _P4_OUTCOME):
                        reasons.append("cache_accounting_incomplete")
                        continue
                    quality = outcome["quality_basis_points"]
                    total_cost = outcome["total_cost_microunits"]
                    accounting = outcome["cache_accounting"]
                    if (
                        type(quality) is not int
                        or not 0 <= quality <= 10_000
                        or not _nonnegative_integer(total_cost)
                        or not _exact_dict(accounting, _P4_CACHE)
                        or any(
                            not _nonnegative_integer(accounting.get(field))
                            for field in _P4_CACHE
                        )
                    ):
                        reasons.append("cache_accounting_incomplete")
                        continue
                    if total_cost != sum(accounting[field] for field in _P4_CACHE):
                        reasons.append("cache_accounting_incomplete")
                        continue
                    parsed[policy] = (quality, total_cost)
            if set(parsed) == _P4_OUTCOMES:
                fixed = min(
                    (parsed["always_pass_through"], parsed["always_on"]),
                    key=lambda value: (-value[0], value[1]),
                )
                advisory = parsed["advisory"]
                regret = fixed[1] - advisory[1]
                if advisory[0] < fixed[0]:
                    reasons.append("quality_regression")
                if regret < 0:
                    reasons.append("negative_regret")

        reasons = _deduplicate(reasons)
        eligible = not reasons
        if not eligible:
            all_trials_eligible = False
        evaluation_route = advisory_route if eligible else "pass_through"
        reports.append(
            {
                "trial_id": trial_id,
                "advisory_status": status,
                "advisory_route": advisory_route,
                "confidence_basis_points": confidence,
                "regret_microunits": regret,
                "evaluation_route": evaluation_route,
                "bypass_reasons": reasons,
            }
        )
        for reason in reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            if reason in {
                "malformed_record",
                "cache_accounting_incomplete",
                "quality_regression",
                "negative_regret",
                "low_confidence",
                "abstained",
                "failed",
            }:
                blockers.append(reason)

    if data["baseline_fallback_verified"] is not True:
        blockers.append("exact_fallback_unverified")
    evaluation_blockers = {
        "malformed_record",
        "cache_accounting_incomplete",
        "quality_regression",
        "negative_regret",
        "low_confidence",
        "abstained",
        "failed",
        "exact_fallback_unverified",
    }
    evaluation_complete = all_trials_eligible and not any(
        blocker in evaluation_blockers for blocker in blockers
    )
    activation_eligible = (
        evaluation_complete
        and data["dependency_gates_passed"] is True
        and data["activation_authorized"] is True
    )
    if data["dependency_gates_passed"] is not True:
        blockers.append("dependency_gates_incomplete")
    if data["activation_authorized"] is not True:
        blockers.append("activation_not_recorded")
    blockers.append("external_activation_authority_required")
    selected_route = (
        next(iter(advisory_routes))
        if evaluation_complete and len(advisory_routes) == 1
        else "pass_through"
    )
    return _closed_result(
        "p4",
        blockers,
        implementation_readiness=not any(
            blocker in {"malformed_record", "exact_fallback_unverified"}
            for blocker in blockers
        ),
        evaluation_evidence_complete=evaluation_complete,
        activation_eligibility=activation_eligible,
        runtime_route_changed=False,
        selected_route=selected_route,
        evaluated_trial_count=len(trials),
        abstention_count=abstention_count,
        failure_count=failure_count,
        confidence_basis_points=confidences,
        bypass_reason_counts={key: reason_counts[key] for key in sorted(reason_counts)},
        trials=reports,
    )


def evaluate_p5(record: object) -> dict[str, object]:
    """Evaluate each P5 adjunct independently without applying any adjunct."""

    empty_values = {
        "runtime_changed": False,
        "evaluated_adjunct_count": 0,
        "eligible_adjuncts": [],
        "adjuncts": [],
    }
    if not _exact_dict(record, _P5_TOP):
        return _closed_result(
            "p5",
            ["malformed_record", "external_activation_authority_required"],
            **empty_values,
        )
    data = record
    phase_blockers: list[str] = []
    if (
        data["schema_version"] != "contextguard.phase-evaluation.p5/v1"
        or data["phase_id"] != "p5"
    ):
        phase_blockers.append("malformed_record")
    for field in ("dependency_gates_passed", "activation_authorized"):
        if type(data[field]) is not bool:
            phase_blockers.append("malformed_record")
    for field in (
        "current_revision_digest",
        "current_source_digest",
        "current_test_digest",
    ):
        if not _valid_digest(data[field]):
            phase_blockers.append("malformed_record")

    adjuncts = data["adjuncts"]
    if type(adjuncts) is not list or len(adjuncts) != len(_P5_ADJUNCT_IDS):
        phase_blockers.append("malformed_record")
        adjuncts = []

    reports: list[dict[str, object]] = []
    seen_adjuncts: set[str] = set()
    eligible_adjuncts: list[str] = []
    for adjunct in adjuncts:
        blockers = list(phase_blockers)
        adjunct_id: object = None
        if not _exact_dict(adjunct, _P5_ADJUNCT):
            blockers.append("malformed_record")
        else:
            raw_adjunct_id = adjunct["adjunct_id"]
            if (
                type(raw_adjunct_id) is not str
                or raw_adjunct_id not in _P5_ADJUNCT_IDS
                or raw_adjunct_id in seen_adjuncts
            ):
                blockers.append("malformed_record")
            else:
                adjunct_id = raw_adjunct_id
                seen_adjuncts.add(adjunct_id)

            freshness_fields = (
                ("revision_digest", "current_revision_digest", "stale_revision"),
                ("source_digest", "current_source_digest", "stale_source"),
                ("test_digest", "current_test_digest", "stale_test_state"),
            )
            for bound_field, current_field, blocker in freshness_fields:
                if not _valid_digest(adjunct[bound_field]):
                    blockers.append("malformed_record")
                elif adjunct[bound_field] != data[current_field]:
                    blockers.append(blocker)

            evidence = adjunct["evidence_digests"]
            if (
                type(evidence) is not list
                or not evidence
                or len(evidence) > _MAX_RECORDS
                or any(not _valid_digest(digest) for digest in evidence)
                or len(set(evidence)) != len(evidence)
            ):
                blockers.append("evidence_incomplete")

            failures = adjunct["failure_cases"]
            prior_failures: dict[str, tuple[int, str]] = {}
            if type(failures) is not list or not failures or len(failures) > _MAX_RECORDS:
                blockers.append("differentiation_incomplete")
            else:
                for failure in failures:
                    if not _exact_dict(failure, _P5_FAILURE_CASE):
                        blockers.append("differentiation_incomplete")
                        continue
                    case_id = failure["case_id"]
                    exit_status = failure["exit_status"]
                    root_cause = failure["root_cause"]
                    duplicate_of = failure["duplicate_of"]
                    if (
                        not _valid_identifier(case_id)
                        or case_id in prior_failures
                        or not _nonnegative_integer(exit_status)
                        or not _valid_identifier(root_cause)
                        or (duplicate_of is not None and not _valid_identifier(duplicate_of))
                    ):
                        blockers.append("differentiation_incomplete")
                        continue
                    if duplicate_of is not None:
                        original = prior_failures.get(duplicate_of)
                        if original is None:
                            blockers.append("differentiation_incomplete")
                        elif original != (exit_status, root_cause):
                            blockers.append("distinct_failure_deduplicated")
                    prior_failures[case_id] = (exit_status, root_cause)

            if adjunct["bypass_verified"] is not True:
                blockers.append("bypass_unverified")
            if adjunct["fallback_verified"] is not True:
                blockers.append("exact_fallback_unverified")
            baseline_quality = adjunct["baseline_quality_basis_points"]
            adjunct_quality = adjunct["adjunct_quality_basis_points"]
            if any(
                type(value) is not int or not 0 <= value <= 10_000
                for value in (baseline_quality, adjunct_quality)
            ):
                blockers.append("quality_evidence_incomplete")
            elif adjunct_quality < baseline_quality:
                blockers.append("quality_regression")
            baseline_cost = adjunct["baseline_cost_microunits"]
            adjunct_cost = adjunct["adjunct_cost_microunits"]
            if not _nonnegative_integer(baseline_cost) or not _nonnegative_integer(adjunct_cost):
                blockers.append("cost_evidence_incomplete")
            elif adjunct_cost >= baseline_cost:
                blockers.append("fully_loaded_cost_not_improved")

        blockers = _deduplicate(blockers)
        eligible = not blockers
        if eligible and type(adjunct_id) is str:
            eligible_adjuncts.append(adjunct_id)
        reports.append(
            {
                "adjunct_id": adjunct_id,
                "decision": "eligible" if eligible else "bypass",
                "reversible": bool(
                    _exact_dict(adjunct, _P5_ADJUNCT)
                    and adjunct["bypass_verified"] is True
                    and adjunct["fallback_verified"] is True
                ),
                "blockers": blockers,
            }
        )

    if seen_adjuncts != _P5_ADJUNCT_IDS:
        phase_blockers.append("malformed_record")
    if data["dependency_gates_passed"] is not True:
        phase_blockers.append("dependency_gates_incomplete")
    if data["activation_authorized"] is not True:
        phase_blockers.append("activation_not_recorded")
    phase_blockers.append("external_activation_authority_required")
    all_eligible = len(eligible_adjuncts) == len(_P5_ADJUNCT_IDS)
    return _closed_result(
        "p5",
        phase_blockers,
        implementation_readiness=all_eligible,
        evaluation_evidence_complete=all_eligible,
        activation_eligibility=(
            all_eligible
            and data["dependency_gates_passed"] is True
            and data["activation_authorized"] is True
        ),
        runtime_changed=False,
        evaluated_adjunct_count=len(adjuncts),
        eligible_adjuncts=eligible_adjuncts,
        adjuncts=reports,
    )


def evaluate_p6(record: object) -> dict[str, object]:
    """Evaluate frozen P6 tracks independently without changing runtime state."""

    empty_values = {
        "runtime_changed": False,
        "evaluated_track_count": 0,
        "eligible_tracks": [],
        "tracks": [],
    }
    if not _exact_dict(record, _P6_TOP):
        return _closed_result(
            "p6",
            ["malformed_record", "external_activation_authority_required", "claim_blocked"],
            **empty_values,
        )
    data = record
    phase_blockers: list[str] = []
    if (
        data["schema_version"] != "contextguard.phase-evaluation.p6/v1"
        or data["phase_id"] != "p6"
        or type(data["dependency_gates_passed"]) is not bool
    ):
        phase_blockers.append("malformed_record")

    tracks = data["tracks"]
    if type(tracks) is not list or len(tracks) != len(_P6_TRACK_IDS):
        phase_blockers.append("malformed_record")
        tracks = []

    reports: list[dict[str, object]] = []
    eligible_tracks: list[str] = []
    seen_tracks: set[str] = set()
    for track in tracks:
        blockers: list[str] = []
        track_id: object = None
        evidence = {
            "workload_evidence": False,
            "baseline_evidence": False,
            "scope_evidence": False,
            "privacy_evidence": False,
            "quality_evidence": False,
            "failure_guardrail_evidence": False,
            "correction_guardrail_evidence": False,
            "cost_model_evidence": False,
            "cost_evidence": False,
            "fallback_evidence": False,
            "rollback_evidence": False,
            "authority_evidence": False,
            "provider_evidence": False,
        }
        surface: object = None
        if not _exact_dict(track, _P6_TRACK):
            blockers.append("malformed_record")
        else:
            raw_track_id = track["track_id"]
            raw_surface = track["surface"]
            if (
                type(raw_track_id) is not str
                or raw_track_id not in _P6_TRACK_IDS
                or raw_track_id in seen_tracks
            ):
                blockers.append("malformed_record")
            else:
                track_id = raw_track_id
                seen_tracks.add(track_id)
            if type(raw_surface) is not str or raw_surface not in {
                "evaluation_only",
                "plan_only",
            }:
                blockers.append("malformed_record")
            else:
                surface = raw_surface

            evidence["workload_evidence"] = _valid_digest(track["workload_digest"])
            if not evidence["workload_evidence"]:
                blockers.append("workload_evidence_incomplete")
            evidence["baseline_evidence"] = _valid_digest(track["baseline_digest"])
            if not evidence["baseline_evidence"]:
                blockers.append("baseline_evidence_incomplete")
            evidence["scope_evidence"] = _valid_digest(track["scope_digest"])
            if not evidence["scope_evidence"]:
                blockers.append("scope_evidence_incomplete")
            evidence["privacy_evidence"] = (
                _valid_digest(track["privacy_boundary_digest"])
                and track["privacy_verified"] is True
            )
            if not evidence["privacy_evidence"]:
                blockers.append("privacy_evidence_incomplete")

            baseline_quality = track["baseline_quality_basis_points"]
            track_quality = track["track_quality_basis_points"]
            quality_values_valid = all(
                type(value) is int and 0 <= value <= 10_000
                for value in (baseline_quality, track_quality)
            )
            evidence["quality_evidence"] = quality_values_valid
            if not quality_values_valid:
                blockers.append("quality_evidence_incomplete")
            elif track_quality < baseline_quality:
                blockers.append("quality_regression")

            population_count = track["population_count"]
            baseline_failure_count = track["baseline_failure_count"]
            track_failure_count = track["track_failure_count"]
            maximum_failure_increase = track[
                "maximum_failure_rate_increase_basis_points"
            ]
            failure_values_valid = (
                type(population_count) is int
                and 1 <= population_count <= _MAX_RECORDS
                and type(baseline_failure_count) is int
                and 0 <= baseline_failure_count <= population_count
                and type(track_failure_count) is int
                and 0 <= track_failure_count <= population_count
                and type(maximum_failure_increase) is int
                and 0 <= maximum_failure_increase <= 10_000
            )
            if not failure_values_valid:
                blockers.append("failure_evidence_incomplete")
            else:
                failure_guardrail_passed = (
                    (track_failure_count - baseline_failure_count) * 10_000
                    <= maximum_failure_increase * population_count
                )
                evidence["failure_guardrail_evidence"] = failure_guardrail_passed
                if not failure_guardrail_passed:
                    blockers.append("failure_guardrail_failed")

            baseline_corrections = track["baseline_corrections"]
            track_corrections = track["track_corrections"]
            correction_values_valid = _nonnegative_integer(
                baseline_corrections
            ) and _nonnegative_integer(track_corrections)
            if not correction_values_valid:
                blockers.append("correction_evidence_incomplete")
            else:
                correction_guardrail_passed = track_corrections <= baseline_corrections
                evidence["correction_guardrail_evidence"] = correction_guardrail_passed
                if not correction_guardrail_passed:
                    blockers.append("correction_guardrail_failed")

            evidence["cost_model_evidence"] = _valid_digest(track["cost_model_digest"])
            if not evidence["cost_model_evidence"]:
                blockers.append("cost_model_incomplete")

            baseline_cost = track["baseline_cost_microunits"]
            track_cost = track["track_cost_microunits"]
            costs_valid = _nonnegative_integer(baseline_cost) and _nonnegative_integer(track_cost)
            evidence["cost_evidence"] = costs_valid
            if not costs_valid:
                blockers.append("cost_evidence_incomplete")
            elif track_cost >= baseline_cost:
                blockers.append("fully_loaded_cost_not_improved")

            evidence["fallback_evidence"] = track["fallback_verified"] is True
            if not evidence["fallback_evidence"]:
                blockers.append("exact_fallback_unverified")
            evidence["rollback_evidence"] = track["rollback_verified"] is True
            if not evidence["rollback_evidence"]:
                blockers.append("rollback_unverified")
            evidence["authority_evidence"] = track["activation_authorized"] is True
            if not evidence["authority_evidence"]:
                blockers.append("activation_not_recorded")
            evidence["provider_evidence"] = _valid_digest(track["provider_evidence_digest"])
            if not evidence["provider_evidence"]:
                blockers.append("provider_measurement_incomplete")
            if surface == "plan_only":
                blockers.append("plan_only_non_runtime")

        if data["dependency_gates_passed"] is not True:
            blockers.append("dependency_gates_incomplete")
        blockers = _deduplicate(blockers)
        plan_only = surface == "plan_only"
        eligible = not blockers and not plan_only
        if eligible and type(track_id) is str:
            eligible_tracks.append(track_id)
        reports.append(
            {
                "track_id": track_id,
                "surface": surface,
                "decision": "plan_only" if plan_only else ("eligible" if eligible else "fallback"),
                "fallback": "exact_unchanged_baseline",
                "activation_eligibility": eligible,
                "activation_authority": False,
                "claim_authority": False,
                "generalization_allowed": False,
                "blockers": blockers,
                **evidence,
            }
        )

    if seen_tracks != _P6_TRACK_IDS:
        phase_blockers.append("malformed_record")
    if data["dependency_gates_passed"] is not True:
        phase_blockers.append("dependency_gates_incomplete")
    phase_blockers.extend(["external_activation_authority_required", "claim_blocked"])
    all_eligible = len(eligible_tracks) == len(_P6_TRACK_IDS)
    return _closed_result(
        "p6",
        phase_blockers,
        implementation_readiness=all_eligible,
        evaluation_evidence_complete=all_eligible,
        provider_evidence=bool(reports) and all(report["provider_evidence"] for report in reports),
        activation_eligibility=all_eligible and data["dependency_gates_passed"] is True,
        runtime_changed=False,
        evaluated_track_count=len(tracks),
        eligible_tracks=eligible_tracks,
        tracks=reports,
    )
