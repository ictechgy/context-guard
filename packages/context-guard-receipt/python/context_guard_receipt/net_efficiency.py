"""Provider-free net-efficiency and shadow planning contracts."""

from __future__ import annotations

from typing import Final

from .canonical import JSONLimits
from .contracts import evidence_boundary


NET_EFFICIENCY_REQUEST_VERSION: Final = "contextguard.net-efficiency-request/v1"
NET_EFFICIENCY_RESULT_VERSION: Final = "contextguard.net-efficiency-result/v1"
PREFIX_PLAN_REQUEST_VERSION: Final = "contextguard.prefix-plan-request/v1"
PREFIX_PLAN_RESULT_VERSION: Final = "contextguard.prefix-plan-result/v1"
FANOUT_PLAN_REQUEST_VERSION: Final = "contextguard.fanout-plan-request/v1"
FANOUT_PLAN_RESULT_VERSION: Final = "contextguard.fanout-plan-result/v1"
PRUNE_PLAN_REQUEST_VERSION: Final = "contextguard.prune-plan-request/v1"
PRUNE_PLAN_RESULT_VERSION: Final = "contextguard.prune-plan-result/v1"
SHADOW_POLICY_REQUEST_VERSION: Final = "contextguard.shadow-policy-request/v1"
SHADOW_POLICY_RESULT_VERSION: Final = "contextguard.shadow-policy-result/v1"
MAX_MATCHED_PAIRS: Final = 256
MAX_PRUNE_ITEMS: Final = 256
MAX_SHADOW_CANDIDATES: Final = 16
MAX_INTEGER: Final = 2**63 - 1

INPUT_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_total_values=100_000,
    max_object_members=64,
    max_string_bytes=1024,
)
RESULT_LIMITS: Final = JSONLimits(
    max_document_bytes=256 * 1024,
    max_depth=16,
    max_total_values=4096,
    max_object_members=64,
    max_string_bytes=1024,
)


class NetEfficiencyError(ValueError):
    """Stable validation failure without caller-controlled detail."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _closed(value: object, keys: set[str], code: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise NetEfficiencyError(code)
    return value


def _integer(value: object, code: str, *, maximum: int = MAX_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise NetEfficiencyError(code)
    return value


def _hmac(value: object, code: str) -> str:
    if not (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    ):
        raise NetEfficiencyError(code)
    return value


def _basis_points_change(baseline: int, candidate: int) -> int | None:
    if baseline == 0:
        return 0 if candidate == 0 else None
    return (candidate - baseline) * 10_000 // baseline


def _basis_points_improvement(baseline: int, candidate: int) -> int | None:
    change = _basis_points_change(baseline, candidate)
    return None if change is None else -change


def _p95(values: list[int]) -> int:
    ordered = sorted(values)
    index = max(0, (95 * len(ordered) + 99) // 100 - 1)
    return ordered[index]


_RUN_KEYS = {
    "cache_read_tokens",
    "cache_write_tokens",
    "correction_turns",
    "model_requests",
    "provider_cost_microusd",
    "provider_input_tokens",
    "provider_output_tokens",
    "quality_basis_points",
    "rehydration_calls",
    "shifted_cost_microusd",
    "success",
    "tool_calls",
    "tool_yields",
    "wall_time_ms",
}


def _run(value: object) -> dict[str, object]:
    run = _closed(value, _RUN_KEYS, "invalid_run")
    if type(run["success"]) is not bool:
        raise NetEfficiencyError("invalid_run")
    for field in _RUN_KEYS - {"success"}:
        maximum = 10_000 if field == "quality_basis_points" else MAX_INTEGER
        _integer(run[field], "invalid_run", maximum=maximum)
    if not run["success"] and run["quality_basis_points"] != 0:
        raise NetEfficiencyError("invalid_run")
    return run


def _aggregate(runs: list[dict[str, object]]) -> dict[str, int]:
    success_count = sum(1 for run in runs if run["success"])
    total_cost = sum(
        int(run["provider_cost_microusd"]) + int(run["shifted_cost_microusd"])
        for run in runs
    )
    return {
        "cache_read_tokens": sum(int(run["cache_read_tokens"]) for run in runs),
        "cache_write_tokens": sum(int(run["cache_write_tokens"]) for run in runs),
        "correction_turns": sum(int(run["correction_turns"]) for run in runs),
        "cost_per_success_microusd": (
            total_cost // success_count if success_count else MAX_INTEGER
        ),
        "model_requests": sum(int(run["model_requests"]) for run in runs),
        "p95_wall_time_ms": _p95([int(run["wall_time_ms"]) for run in runs]),
        "provider_input_tokens": sum(
            int(run["provider_input_tokens"]) for run in runs
        ),
        "provider_output_tokens": sum(
            int(run["provider_output_tokens"]) for run in runs
        ),
        "quality_basis_points": sum(
            int(run["quality_basis_points"]) for run in runs
        )
        // len(runs),
        "rehydration_calls": sum(int(run["rehydration_calls"]) for run in runs),
        "success_count": success_count,
        "success_rate_basis_points": success_count * 10_000 // len(runs),
        "tool_calls": sum(int(run["tool_calls"]) for run in runs),
        "tool_yields": sum(int(run["tool_yields"]) for run in runs),
        "total_cost_microusd": total_cost,
    }


def evaluate_net_efficiency(envelope: object) -> dict[str, object]:
    request = _closed(
        envelope, {"pairs", "policy", "schema_version"}, "invalid_envelope"
    )
    if request["schema_version"] != NET_EFFICIENCY_REQUEST_VERSION:
        raise NetEfficiencyError("invalid_envelope")
    pairs = request["pairs"]
    if type(pairs) is not list or not pairs or len(pairs) > MAX_MATCHED_PAIRS:
        raise NetEfficiencyError("invalid_pairs")
    baseline_runs: list[dict[str, object]] = []
    candidate_runs: list[dict[str, object]] = []
    seen_pairs: set[str] = set()
    matched_tasks: set[str] = set()
    run_windows: set[str] = set()
    for value in pairs:
        pair = _closed(
            value,
            {
                "baseline",
                "candidate",
                "pair_hmac",
                "run_window_hmac",
                "task_hmac",
            },
            "invalid_pair",
        )
        pair_hmac = _hmac(pair["pair_hmac"], "invalid_pair")
        task_hmac = _hmac(pair["task_hmac"], "invalid_pair")
        run_window_hmac = _hmac(pair["run_window_hmac"], "invalid_pair")
        if pair_hmac in seen_pairs:
            raise NetEfficiencyError("duplicate_pair")
        seen_pairs.add(pair_hmac)
        matched_tasks.add(task_hmac)
        run_windows.add(run_window_hmac)
        baseline_runs.append(_run(pair["baseline"]))
        candidate_runs.append(_run(pair["candidate"]))

    policy = _closed(
        request["policy"],
        {
            "maximum_correction_turn_regression_basis_points",
            "maximum_cost_per_success_regression_basis_points",
            "maximum_model_request_regression_basis_points",
            "maximum_output_regression_basis_points",
            "maximum_p95_wall_time_regression_basis_points",
            "maximum_rehydration_call_regression_basis_points",
            "maximum_tool_call_regression_basis_points",
            "maximum_tool_yield_regression_basis_points",
            "minimum_distinct_run_windows",
            "minimum_net_improvement_basis_points",
            "quality_noninferiority_margin_basis_points",
            "success_noninferiority_margin_basis_points",
        },
        "invalid_policy",
    )
    for field, value in policy.items():
        maximum = MAX_MATCHED_PAIRS if field == "minimum_distinct_run_windows" else 10_000
        _integer(value, "invalid_policy", maximum=maximum)

    baseline = _aggregate(baseline_runs)
    candidate = _aggregate(candidate_runs)
    quality_noninferior = (
        candidate["quality_basis_points"]
        + int(policy["quality_noninferiority_margin_basis_points"])
        >= baseline["quality_basis_points"]
    )
    success_noninferior = (
        candidate["success_rate_basis_points"]
        + int(policy["success_noninferiority_margin_basis_points"])
        >= baseline["success_rate_basis_points"]
    )
    output_regression = _basis_points_change(
        baseline["provider_output_tokens"], candidate["provider_output_tokens"]
    )
    request_regression = _basis_points_change(
        baseline["model_requests"], candidate["model_requests"]
    )
    correction_regression = _basis_points_change(
        baseline["correction_turns"], candidate["correction_turns"]
    )
    rehydration_regression = _basis_points_change(
        baseline["rehydration_calls"], candidate["rehydration_calls"]
    )
    tool_call_regression = _basis_points_change(
        baseline["tool_calls"], candidate["tool_calls"]
    )
    tool_yield_regression = _basis_points_change(
        baseline["tool_yields"], candidate["tool_yields"]
    )
    cost_improvement = _basis_points_improvement(
        baseline["cost_per_success_microusd"],
        candidate["cost_per_success_microusd"],
    )
    latency_improvement = _basis_points_improvement(
        baseline["p95_wall_time_ms"], candidate["p95_wall_time_ms"]
    )
    cost_regression = (
        None if cost_improvement is None else -cost_improvement
    )
    latency_regression = (
        None if latency_improvement is None else -latency_improvement
    )
    blockers: list[str] = []
    if baseline["success_count"] == 0:
        blockers.append("baseline_has_no_successful_tasks")
    if len(run_windows) < int(policy["minimum_distinct_run_windows"]):
        blockers.append("insufficient_canary_windows")
    if not success_noninferior:
        blockers.append("success_rate_regressed")
    if not quality_noninferior:
        blockers.append("quality_regressed")
    if cost_regression is None or cost_regression > int(
        policy["maximum_cost_per_success_regression_basis_points"]
    ):
        blockers.append("cost_per_success_regressed")
    if latency_regression is None or latency_regression > int(
        policy["maximum_p95_wall_time_regression_basis_points"]
    ):
        blockers.append("p95_wall_time_regressed")
    if output_regression is None or output_regression > int(
        policy["maximum_output_regression_basis_points"]
    ):
        blockers.append("output_tokens_regressed")
    if request_regression is None or request_regression > int(
        policy["maximum_model_request_regression_basis_points"]
    ):
        blockers.append("model_requests_regressed")
    for regression, policy_field, reason in (
        (
            correction_regression,
            "maximum_correction_turn_regression_basis_points",
            "correction_turns_regressed",
        ),
        (
            rehydration_regression,
            "maximum_rehydration_call_regression_basis_points",
            "rehydration_calls_regressed",
        ),
        (
            tool_call_regression,
            "maximum_tool_call_regression_basis_points",
            "tool_calls_regressed",
        ),
        (
            tool_yield_regression,
            "maximum_tool_yield_regression_basis_points",
            "tool_yields_regressed",
        ),
    ):
        if regression is None or regression > int(policy[policy_field]):
            blockers.append(reason)
    minimum = int(policy["minimum_net_improvement_basis_points"])
    if not (
        cost_improvement is not None
        and cost_improvement >= minimum
        or latency_improvement is not None
        and latency_improvement >= minimum
    ):
        blockers.append("insufficient_net_improvement")

    return {
        "authority": {
            "provider_claim_authority": False,
            "runtime_apply_allowed": False,
            "shadow_only": True,
        },
        "blocking_reasons": sorted(set(blockers)),
        "canary": {
            "distinct_run_window_count": len(run_windows),
            "minimum_distinct_run_windows": int(
                policy["minimum_distinct_run_windows"]
            ),
        },
        "decision": "recommend" if not blockers else "hold",
        "efficiency": {
            "baseline": baseline,
            "candidate": candidate,
            "correction_turn_regression_basis_points": correction_regression,
            "cost_per_success_improvement_basis_points": cost_improvement,
            "model_request_regression_basis_points": request_regression,
            "output_token_regression_basis_points": output_regression,
            "p95_wall_time_improvement_basis_points": latency_improvement,
            "rehydration_call_regression_basis_points": rehydration_regression,
            "tool_call_regression_basis_points": tool_call_regression,
            "tool_yield_regression_basis_points": tool_yield_regression,
        },
        "evidence_boundary": evidence_boundary(),
        "matched_pair_count": len(pairs),
        "matched_task_count": len(matched_tasks),
        "privacy": {
            "pair_hmac_emitted": False,
            "raw_prompt_emitted": False,
            "run_window_hmac_emitted": False,
            "task_hmac_emitted": False,
            "task_hmac_stored": False,
        },
        "quality": {
            "noninferior": quality_noninferior and success_noninferior,
            "quality_noninferior": quality_noninferior,
            "success_noninferior": success_noninferior,
        },
        "schema_version": NET_EFFICIENCY_RESULT_VERSION,
    }


_PREFIX_KEYS = {
    "context_management_hmac",
    "effort_hmac",
    "stable_prefix_tokens",
    "system_hmac",
    "tools_hmac",
    "verbosity_hmac",
}
_PREFIX_COMPONENTS = (
    ("context_management", "context_management_hmac"),
    ("effort", "effort_hmac"),
    ("system", "system_hmac"),
    ("tools", "tools_hmac"),
    ("verbosity", "verbosity_hmac"),
)


def _prefix(value: object) -> dict[str, object]:
    prefix = _closed(value, _PREFIX_KEYS, "invalid_prefix")
    for _name, key in _PREFIX_COMPONENTS:
        _hmac(prefix[key], "invalid_prefix")
    _integer(prefix["stable_prefix_tokens"], "invalid_prefix")
    return prefix


def evaluate_prefix_plan(envelope: object) -> dict[str, object]:
    request = _closed(
        envelope,
        {"baseline", "cache_policy", "candidate", "capabilities", "schema_version"},
        "invalid_envelope",
    )
    if request["schema_version"] != PREFIX_PLAN_REQUEST_VERSION:
        raise NetEfficiencyError("invalid_envelope")
    baseline = _prefix(request["baseline"])
    candidate = _prefix(request["candidate"])
    cache = _closed(
        request["cache_policy"],
        {
            "expected_reuses",
            "minimum_cacheable_tokens",
            "read_multiplier_basis_points",
            "write_multiplier_basis_points",
        },
        "invalid_cache_policy",
    )
    _integer(cache["expected_reuses"], "invalid_cache_policy", maximum=1_000_000)
    _integer(cache["minimum_cacheable_tokens"], "invalid_cache_policy")
    _integer(cache["read_multiplier_basis_points"], "invalid_cache_policy", maximum=100_000)
    _integer(cache["write_multiplier_basis_points"], "invalid_cache_policy", maximum=100_000)
    capabilities = _closed(
        request["capabilities"],
        {"supports_deferred_tools", "supports_explicit_breakpoints"},
        "invalid_capabilities",
    )
    if any(type(value) is not bool for value in capabilities.values()):
        raise NetEfficiencyError("invalid_capabilities")

    changed = [
        name for name, key in _PREFIX_COMPONENTS if baseline[key] != candidate[key]
    ]
    tokens = int(candidate["stable_prefix_tokens"])
    minimum = int(cache["minimum_cacheable_tokens"])
    eligible = tokens >= minimum and minimum > 0
    cached_equivalent = (
        tokens
        * (
            int(cache["write_multiplier_basis_points"])
            + int(cache["expected_reuses"])
            * int(cache["read_multiplier_basis_points"])
        )
        // 10_000
    )
    uncached_equivalent = tokens * (int(cache["expected_reuses"]) + 1)
    amortizes = eligible and cached_equivalent < uncached_equivalent
    if "tools" in changed and capabilities["supports_deferred_tools"]:
        recommendation = "evaluate_native_deferred_loading"
    elif not eligible:
        recommendation = "avoid_subthreshold_prefix"
    elif changed:
        recommendation = "keep_session_prefix_stable"
    elif capabilities["supports_explicit_breakpoints"] and amortizes:
        recommendation = "preserve_prefix"
    else:
        recommendation = "no_op"

    return {
        "amortization": {
            "cached_input_equivalent_tokens": cached_equivalent,
            "candidate_cache_eligible": eligible,
            "expected_reuses": int(cache["expected_reuses"]),
            "projected_amortizes": amortizes,
            "uncached_input_equivalent_tokens": uncached_equivalent,
        },
        "authority": {
            "provider_claim_authority": False,
            "request_mutation_allowed": False,
            "shadow_only": True,
        },
        "cache_prefix_preserved": not changed,
        "changed_components": changed,
        "evidence_boundary": evidence_boundary(),
        "privacy": {"component_hmacs_emitted": False, "raw_prefix_emitted": False},
        "recommendation": recommendation,
        "schema_version": PREFIX_PLAN_RESULT_VERSION,
    }


def evaluate_fanout_plan(envelope: object) -> dict[str, object]:
    request = _closed(
        envelope,
        {"policy", "schema_version", "workload"},
        "invalid_envelope",
    )
    if request["schema_version"] != FANOUT_PLAN_REQUEST_VERSION:
        raise NetEfficiencyError("invalid_envelope")
    workload = _closed(
        request["workload"],
        {
            "estimated_model_round_trips_baseline",
            "estimated_returned_bytes",
            "estimated_source_bytes",
            "independent",
            "operation_count",
            "sequential_dependency",
            "shifted_cost_microusd",
        },
        "invalid_workload",
    )
    for field in (
        "estimated_model_round_trips_baseline",
        "estimated_returned_bytes",
        "estimated_source_bytes",
        "operation_count",
        "shifted_cost_microusd",
    ):
        _integer(workload[field], "invalid_workload")
    if (
        type(workload["independent"]) is not bool
        or type(workload["sequential_dependency"]) is not bool
    ):
        raise NetEfficiencyError("invalid_workload")
    policy = _closed(
        request["policy"],
        {
            "maximum_shifted_cost_microusd",
            "minimum_operations",
            "minimum_payload_reduction_basis_points",
        },
        "invalid_policy",
    )
    _integer(policy["maximum_shifted_cost_microusd"], "invalid_policy")
    _integer(policy["minimum_operations"], "invalid_policy", maximum=1_000_000)
    _integer(
        policy["minimum_payload_reduction_basis_points"],
        "invalid_policy",
        maximum=10_000,
    )

    source = int(workload["estimated_source_bytes"])
    returned = int(workload["estimated_returned_bytes"])
    payload_reduction = _basis_points_improvement(source, returned)
    round_trip_reduction = max(
        0, int(workload["estimated_model_round_trips_baseline"]) - 1
    )
    blockers: list[str] = []
    if not workload["independent"]:
        blockers.append("operations_not_independent")
    if workload["sequential_dependency"]:
        blockers.append("sequential_dependency")
    if int(workload["operation_count"]) < int(policy["minimum_operations"]):
        blockers.append("insufficient_operations")
    if round_trip_reduction == 0:
        blockers.append("no_round_trip_reduction")
    if (
        payload_reduction is None
        or payload_reduction
        < int(policy["minimum_payload_reduction_basis_points"])
    ):
        blockers.append("insufficient_payload_reduction")
    if int(workload["shifted_cost_microusd"]) > int(
        policy["maximum_shifted_cost_microusd"]
    ):
        blockers.append("shifted_cost_exceeds_policy")

    return {
        "authority": {
            "execution_authorized": False,
            "provider_claim_authority": False,
            "shadow_only": True,
        },
        "blocking_reasons": sorted(set(blockers)),
        "decision": "eligible" if not blockers else "hold",
        "evidence_boundary": evidence_boundary(),
        "payload_reduction_basis_points": payload_reduction,
        "projected_model_round_trip_reduction": round_trip_reduction,
        "schema_version": FANOUT_PLAN_RESULT_VERSION,
    }


_PRUNE_ITEM_KEYS = {
    "age_turns",
    "bytes",
    "exact_fallback",
    "protected",
    "rehydration_count",
}


def evaluate_prune_plan(envelope: object) -> dict[str, object]:
    request = _closed(
        envelope,
        {"items", "policy", "schema_version", "task_boundary"},
        "invalid_envelope",
    )
    if (
        request["schema_version"] != PRUNE_PLAN_REQUEST_VERSION
        or type(request["task_boundary"]) is not bool
    ):
        raise NetEfficiencyError("invalid_envelope")
    items = request["items"]
    if type(items) is not list or len(items) > MAX_PRUNE_ITEMS:
        raise NetEfficiencyError("invalid_items")
    checked: list[dict[str, object]] = []
    for value in items:
        item = _closed(value, _PRUNE_ITEM_KEYS, "invalid_item")
        for field in ("age_turns", "bytes", "rehydration_count"):
            _integer(item[field], "invalid_item")
        if type(item["exact_fallback"]) is not bool or type(item["protected"]) is not bool:
            raise NetEfficiencyError("invalid_item")
        checked.append(item)
    policy = _closed(
        request["policy"],
        {
            "maximum_pruned_bytes",
            "maximum_rehydrations",
            "minimum_age_turns",
            "minimum_result_bytes",
        },
        "invalid_policy",
    )
    for value in policy.values():
        _integer(value, "invalid_policy")

    reasons = {
        "budget": 0,
        "fallback_unavailable": 0,
        "not_task_boundary": 0,
        "protected": 0,
        "rehydration_limit": 0,
        "too_small": 0,
        "too_young": 0,
    }
    eligible: list[tuple[int, int, int]] = []
    for index, item in enumerate(checked):
        reason: str | None = None
        if not request["task_boundary"]:
            reason = "not_task_boundary"
        elif item["protected"]:
            reason = "protected"
        elif not item["exact_fallback"]:
            reason = "fallback_unavailable"
        elif int(item["age_turns"]) < int(policy["minimum_age_turns"]):
            reason = "too_young"
        elif int(item["bytes"]) < int(policy["minimum_result_bytes"]):
            reason = "too_small"
        elif int(item["rehydration_count"]) > int(policy["maximum_rehydrations"]):
            reason = "rehydration_limit"
        if reason is not None:
            reasons[reason] += 1
        else:
            eligible.append((-int(item["age_turns"]), -int(item["bytes"]), index))
    selected: list[int] = []
    projected = 0
    for _age, _bytes, index in sorted(eligible):
        size = int(checked[index]["bytes"])
        if projected + size > int(policy["maximum_pruned_bytes"]):
            reasons["budget"] += 1
            continue
        selected.append(index)
        projected += size
    selected.sort()
    return {
        "authority": {
            "provider_claim_authority": False,
            "transcript_mutation_allowed": False,
            "shadow_only": True,
        },
        "evidence_boundary": evidence_boundary(),
        "item_count": len(checked),
        "projected_pruned_bytes": projected,
        "retained_reason_counts": reasons,
        "schema_version": PRUNE_PLAN_RESULT_VERSION,
        "selected_indexes": selected,
        "task_boundary": request["task_boundary"],
    }


_LANES = (
    "no_op",
    "output_control",
    "fanout",
    "prefix",
    "prune",
    "batch",
    "model_route",
)


def evaluate_shadow_policy(envelope: object) -> dict[str, object]:
    request = _closed(
        envelope, {"candidates", "schema_version"}, "invalid_envelope"
    )
    if request["schema_version"] != SHADOW_POLICY_REQUEST_VERSION:
        raise NetEfficiencyError("invalid_envelope")
    candidates = request["candidates"]
    if (
        type(candidates) is not list
        or not candidates
        or len(candidates) > MAX_SHADOW_CANDIDATES
    ):
        raise NetEfficiencyError("invalid_candidates")
    checked: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in candidates:
        candidate = _closed(
            value,
            {
                "cost_per_success_microusd",
                "evidence_complete",
                "lane",
                "net_efficiency_decision",
                "p95_wall_time_ms",
                "quality_noninferior",
            },
            "invalid_candidate",
        )
        lane = candidate["lane"]
        if type(lane) is not str or lane not in _LANES or lane in seen:
            raise NetEfficiencyError("invalid_candidate")
        seen.add(lane)
        _integer(candidate["cost_per_success_microusd"], "invalid_candidate")
        _integer(candidate["p95_wall_time_ms"], "invalid_candidate")
        if (
            type(candidate["evidence_complete"]) is not bool
            or type(candidate["quality_noninferior"]) is not bool
            or candidate["net_efficiency_decision"]
            not in {"baseline", "hold", "recommend"}
        ):
            raise NetEfficiencyError("invalid_candidate")
        if lane == "no_op" and (
            candidate["net_efficiency_decision"] != "baseline"
            or not candidate["evidence_complete"]
            or not candidate["quality_noninferior"]
        ):
            raise NetEfficiencyError("invalid_candidate")
        if lane != "no_op" and candidate["net_efficiency_decision"] == "baseline":
            raise NetEfficiencyError("invalid_candidate")
        checked.append(candidate)
    if "no_op" not in seen:
        raise NetEfficiencyError("missing_noop")

    noop = next(candidate for candidate in checked if candidate["lane"] == "no_op")
    eligible = [
        candidate
        for candidate in checked
        if candidate["lane"] == "no_op"
        or (
            candidate["evidence_complete"]
            and candidate["quality_noninferior"]
            and candidate["net_efficiency_decision"] == "recommend"
        )
    ]
    rank = {lane: index for index, lane in enumerate(_LANES)}
    selected = min(
        eligible,
        key=lambda candidate: (
            int(candidate["cost_per_success_microusd"]),
            int(candidate["p95_wall_time_ms"]),
            rank[str(candidate["lane"])],
        ),
    )
    if (
        int(selected["cost_per_success_microusd"])
        >= int(noop["cost_per_success_microusd"])
        and int(selected["p95_wall_time_ms"]) >= int(noop["p95_wall_time_ms"])
    ):
        selected = noop
        reason = "no_improvement_over_noop"
    elif int(selected["cost_per_success_microusd"]) < int(
        noop["cost_per_success_microusd"]
    ):
        reason = "lower_full_cost"
    else:
        reason = "lower_p95_latency"

    return {
        "authority": {
            "provider_claim_authority": False,
            "runtime_route_authorized": False,
            "shadow_only": True,
        },
        "candidate_count": len(checked),
        "evidence_boundary": evidence_boundary(),
        "reason": reason,
        "rejected_candidate_count": len(checked) - len(eligible),
        "runtime_applied": False,
        "schema_version": SHADOW_POLICY_RESULT_VERSION,
        "selected_lane": selected["lane"],
    }
