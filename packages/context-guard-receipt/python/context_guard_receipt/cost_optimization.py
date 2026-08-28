"""Provider-free full-request budget gates for ContextGuard Receipt."""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from .canonical import JSONLimits, canonical_json_bytes
from .contracts import evidence_boundary


FULL_WIRE_REQUEST_VERSION: Final = "contextguard.full-wire-budget-request/v1"
FULL_WIRE_RESULT_VERSION: Final = "contextguard.full-wire-budget-result/v1"
COST_CALIBRATION_REQUEST_VERSION: Final = "contextguard.cost-calibration-request/v1"
COST_CALIBRATION_RESULT_VERSION: Final = "contextguard.cost-calibration-result/v1"
TOTAL_COST_ROUTE_REQUEST_VERSION: Final = "contextguard.total-cost-route-request/v1"
TOTAL_COST_ROUTE_RESULT_VERSION: Final = "contextguard.total-cost-route-result/v1"
MAX_PROTECTED_POINTERS: Final = 64
MAX_POINTER_BYTES: Final = 512
MAX_CALIBRATION_ROWS: Final = 4096
MAX_CALIBRATION_GROUPS: Final = 64

FULL_WIRE_INPUT_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=48,
    max_total_values=150_000,
    max_object_members=512,
    max_string_bytes=1024 * 1024,
)
FULL_WIRE_RESULT_LIMITS: Final = JSONLimits(
    max_document_bytes=64 * 1024,
    max_depth=12,
    max_total_values=512,
    max_object_members=64,
    max_string_bytes=1024,
)
REQUEST_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=48,
    max_total_values=150_000,
    max_object_members=512,
    max_string_bytes=1024 * 1024,
)


class FullWireError(ValueError):
    """Stable validation failure without caller-controlled detail."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_MISSING = object()


def _json_pointer(value: object, pointer: str) -> object:
    if pointer == "":
        return value
    if (
        type(pointer) is not str
        or not pointer.startswith("/")
        or len(pointer.encode("utf-8")) > MAX_POINTER_BYTES
    ):
        raise FullWireError("invalid_pointer")
    current = value
    for raw_part in pointer[1:].split("/"):
        index = 0
        while index < len(raw_part):
            if raw_part[index] != "~":
                index += 1
                continue
            if index + 1 >= len(raw_part) or raw_part[index + 1] not in {"0", "1"}:
                raise FullWireError("invalid_pointer")
            index += 2
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if type(current) is dict:
            if part not in current:
                return _MISSING
            current = current[part]
            continue
        if type(current) is list:
            if not part.isascii() or not part.isdecimal() or (
                len(part) > 1 and part.startswith("0")
            ):
                return _MISSING
            item_index = int(part, 10)
            if item_index >= len(current):
                return _MISSING
            current = current[item_index]
            continue
        return _MISSING
    return current


def _output_budget(request: dict[str, object]) -> int | None:
    if "max_tokens" not in request:
        return None
    value = request["max_tokens"]
    if type(value) is not int or value < 0:
        raise FullWireError("invalid_output_budget")
    return value


def _model(request: dict[str, object]) -> str:
    value = request.get("model")
    return value if type(value) is str else "unknown"


def evaluate_full_wire(envelope: object) -> dict[str, object]:
    if type(envelope) is not dict or set(envelope) != {
        "baseline",
        "candidate",
        "enforce",
        "protected_pointers",
        "schema_version",
    }:
        raise FullWireError("invalid_envelope")
    if envelope.get("schema_version") != FULL_WIRE_REQUEST_VERSION:
        raise FullWireError("invalid_envelope")
    baseline = envelope.get("baseline")
    candidate = envelope.get("candidate")
    pointers = envelope.get("protected_pointers")
    enforce = envelope.get("enforce")
    if (
        type(baseline) is not dict
        or type(candidate) is not dict
        or type(pointers) is not list
        or type(enforce) is not bool
        or len(pointers) > MAX_PROTECTED_POINTERS
        or any(type(pointer) is not str for pointer in pointers)
        or len(set(pointers)) != len(pointers)
    ):
        raise FullWireError("invalid_envelope")

    baseline_bytes = len(canonical_json_bytes(baseline, REQUEST_LIMITS))
    candidate_bytes = len(canonical_json_bytes(candidate, REQUEST_LIMITS))
    delta_bytes = candidate_bytes - baseline_bytes
    blockers: list[str] = []
    if delta_bytes > 0:
        blockers.append("candidate_request_exceeds_baseline")
    if _model(baseline) != _model(candidate):
        blockers.append("model_changed")

    changed_pointer_indexes: list[int] = []
    missing_pointer_indexes: list[int] = []
    for pointer_index, pointer in enumerate(pointers, start=1):
        baseline_value = _json_pointer(baseline, pointer)
        candidate_value = _json_pointer(candidate, pointer)
        if baseline_value is _MISSING or candidate_value is _MISSING:
            missing_pointer_indexes.append(pointer_index)
            changed_pointer_indexes.append(pointer_index)
        elif baseline_value != candidate_value:
            changed_pointer_indexes.append(pointer_index)
    if changed_pointer_indexes:
        blockers.append("protected_content_changed")

    baseline_output_budget = _output_budget(baseline)
    candidate_output_budget = _output_budget(candidate)
    output_non_increasing: bool | None
    if baseline_output_budget is None and candidate_output_budget is None:
        output_non_increasing = None
    elif baseline_output_budget is None or candidate_output_budget is None:
        output_non_increasing = False
        blockers.append("output_budget_unavailable")
    else:
        output_non_increasing = candidate_output_budget <= baseline_output_budget
        if not output_non_increasing:
            blockers.append("output_budget_increased")

    prefix_components = ("tools", "system")
    comparable_prefix_components = sum(
        component in baseline and component in candidate
        for component in prefix_components
    )
    preserved_prefix_components = sum(
        component in baseline
        and component in candidate
        and baseline[component] == candidate[component]
        for component in prefix_components
    )
    blocking_reasons = sorted(set(blockers))
    return {
        "blocking_reasons": blocking_reasons,
        "cache_prefix": {
            "all_comparable_preserved": (
                comparable_prefix_components == preserved_prefix_components
            ),
            "comparable_components": comparable_prefix_components,
            "decision_role": "diagnostic_only",
            "preserved_components": preserved_prefix_components,
        },
        "claim_boundary": {
            "canonical_json_bytes_are_provider_wire_bytes": False,
            "provider_token_or_cost_savings_claim_allowed": False,
            "requires_provider_measured_matched_success": True,
        },
        "decision": "block" if blocking_reasons else "allow",
        "enforcement": "enforced" if enforce else "passive",
        "evidence_boundary": evidence_boundary(),
        "output_budget": {
            "baseline_max_tokens": baseline_output_budget,
            "candidate_max_tokens": candidate_output_budget,
            "non_increasing": output_non_increasing,
        },
        "privacy": {
            "input_paths_emitted": False,
            "pointer_text_emitted": False,
            "raw_request_emitted": False,
            "raw_request_stored": False,
        },
        "protected_content": {
            "all_unchanged": not changed_pointer_indexes,
            "changed_pointer_indexes": changed_pointer_indexes,
            "missing_pointer_indexes": missing_pointer_indexes,
            "pointer_count": len(pointers),
        },
        "schema_version": FULL_WIRE_RESULT_VERSION,
        "wire_budget": {
            "baseline_bytes": baseline_bytes,
            "candidate_bytes": candidate_bytes,
            "ceiling_respected": delta_bytes <= 0,
            "delta_bytes": delta_bytes,
            "measurement": "observed_canonical_json_bytes",
        },
    }


def _is_hmac(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _median_integer(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) // 2


def _parse_preflight(value: object) -> tuple[tuple[str, str], dict[str, object]]:
    required = {
        "estimated_input_tokens",
        "model_hmac",
        "output_token_budget",
        "predicted_cache_state",
        "request_hmac",
    }
    if type(value) is not dict or set(value) != required:
        raise FullWireError("invalid_calibration_row")
    if (
        not _is_hmac(value.get("model_hmac"))
        or not _is_hmac(value.get("request_hmac"))
        or not _nonnegative_integer(value.get("estimated_input_tokens"))
        or not _nonnegative_integer(value.get("output_token_budget"))
        or value.get("predicted_cache_state") not in {"hit", "miss", "unknown"}
    ):
        raise FullWireError("invalid_calibration_row")
    key = (str(value["model_hmac"]), str(value["request_hmac"]))
    return key, value


def _parse_observation(value: object) -> tuple[tuple[str, str], dict[str, object]]:
    required = {
        "model_hmac",
        "observed_cache_read_tokens",
        "observed_input_tokens",
        "observed_output_tokens",
        "request_hmac",
    }
    if type(value) is not dict or set(value) != required:
        raise FullWireError("invalid_calibration_row")
    if (
        not _is_hmac(value.get("model_hmac"))
        or not _is_hmac(value.get("request_hmac"))
        or any(
            not _nonnegative_integer(value.get(field))
            for field in (
                "observed_cache_read_tokens",
                "observed_input_tokens",
                "observed_output_tokens",
            )
        )
    ):
        raise FullWireError("invalid_calibration_row")
    key = (str(value["model_hmac"]), str(value["request_hmac"]))
    return key, value


def _unique_rows(
    values: object,
    parser: Callable[[object], tuple[tuple[str, str], dict[str, object]]],
) -> dict[tuple[str, str], dict[str, object]]:
    if type(values) is not list or len(values) > MAX_CALIBRATION_ROWS:
        raise FullWireError("invalid_calibration_rows")
    rows: dict[tuple[str, str], dict[str, object]] = {}
    for value in values:
        key, row = parser(value)
        if key in rows:
            raise FullWireError("duplicate_calibration_identity")
        rows[key] = row
    return rows


def evaluate_cost_calibration(envelope: object) -> dict[str, object]:
    if type(envelope) is not dict or set(envelope) != {
        "minimum_samples",
        "observations",
        "preflights",
        "schema_version",
    }:
        raise FullWireError("invalid_calibration_envelope")
    minimum_samples = envelope.get("minimum_samples")
    if (
        envelope.get("schema_version") != COST_CALIBRATION_REQUEST_VERSION
        or type(minimum_samples) is not int
        or not 1 <= minimum_samples <= 1000
    ):
        raise FullWireError("invalid_calibration_envelope")
    preflights = _unique_rows(envelope.get("preflights"), _parse_preflight)
    observations = _unique_rows(envelope.get("observations"), _parse_observation)
    matched_keys = sorted(set(preflights).intersection(observations))

    grouped: dict[str, list[tuple[dict[str, object], dict[str, object]]]] = {}
    for key in matched_keys:
        grouped.setdefault(key[0], []).append((preflights[key], observations[key]))
    if len(grouped) > MAX_CALIBRATION_GROUPS:
        raise FullWireError("too_many_calibration_groups")

    groups: list[dict[str, object]] = []
    for model_hmac in sorted(grouped):
        rows = grouped[model_hmac]
        input_ratios: list[int] = []
        output_ratios: list[int] = []
        cache_predictions = 0
        cache_correct = 0
        for preflight, observation in rows:
            estimated_input = int(preflight["estimated_input_tokens"])
            observed_input = int(observation["observed_input_tokens"])
            if estimated_input > 0:
                input_ratios.append(
                    (observed_input * 10_000 + estimated_input // 2)
                    // estimated_input
                )
            output_budget = int(preflight["output_token_budget"])
            if output_budget > 0:
                output_ratios.append(
                    (int(observation["observed_output_tokens"]) * 10_000)
                    // output_budget
                )
            predicted_cache_state = preflight["predicted_cache_state"]
            if predicted_cache_state in {"hit", "miss"}:
                cache_predictions += 1
                observed_hit = int(observation["observed_cache_read_tokens"]) > 0
                if (predicted_cache_state == "hit") == observed_hit:
                    cache_correct += 1
        ready = len(rows) >= minimum_samples and len(input_ratios) == len(rows)
        groups.append(
            {
                "cache_prediction_accuracy_basis_points": (
                    cache_correct * 10_000 // cache_predictions
                    if ready and cache_predictions
                    else None
                ),
                "cache_prediction_sample_count": cache_predictions,
                "input_estimate_multiplier_basis_points": (
                    _median_integer(input_ratios) if ready else None
                ),
                "model_hmac": model_hmac,
                "output_budget_utilization_basis_points": (
                    _median_integer(output_ratios) if ready else None
                ),
                "readiness": (
                    "recommendation_ready" if ready else "insufficient_evidence"
                ),
                "sample_count": len(rows),
            }
        )

    return {
        "authority": {
            "auto_apply_allowed": False,
            "recommendation_only": True,
            "requires_matched_quality_gated_rollout": True,
        },
        "evidence_boundary": evidence_boundary(),
        "groups": groups,
        "matched_pair_count": len(matched_keys),
        "minimum_samples": minimum_samples,
        "privacy": {
            "hmac_identities_only": True,
            "raw_model_emitted": False,
            "raw_request_emitted": False,
            "raw_request_stored": False,
        },
        "schema_version": COST_CALIBRATION_RESULT_VERSION,
        "unmatched_observation_count": len(set(observations) - set(preflights)),
        "unmatched_preflight_count": len(set(preflights) - set(observations)),
    }


def evaluate_total_cost_route(envelope: object) -> dict[str, object]:
    from .router import (
        RouteV2Context,
        RouteV2Policy,
        TotalCostComponents,
        decide_total_cost_route,
    )

    if type(envelope) is not dict or set(envelope) != {
        "baseline_total_microusd",
        "candidate",
        "context",
        "policy",
        "schema_version",
    }:
        raise FullWireError("invalid_total_cost_route")
    if envelope.get("schema_version") != TOTAL_COST_ROUTE_REQUEST_VERSION:
        raise FullWireError("invalid_total_cost_route")
    candidate = envelope.get("candidate")
    context = envelope.get("context")
    policy = envelope.get("policy")
    if (
        type(candidate) is not dict
        or set(candidate) != {
            "cache",
            "expansion",
            "helper",
            "local",
            "provider_input",
            "provider_output",
            "retry",
        }
        or type(context) is not dict
        or set(context) != {
            "evidence_complete",
            "full_wire_ceiling_respected",
            "quality_gate",
            "risk",
        }
        or type(policy) is not dict
        or set(policy) != {
            "minimum_savings_basis_points",
            "minimum_savings_microusd",
        }
    ):
        raise FullWireError("invalid_total_cost_route")
    try:
        decision = decide_total_cost_route(
            baseline_total_microusd=envelope["baseline_total_microusd"],
            candidate=TotalCostComponents(**candidate),
            context=RouteV2Context(**context),
            policy=RouteV2Policy(**policy),
        )
    except (TypeError, ValueError):
        raise FullWireError("invalid_total_cost_route") from None
    return {
        "authority": {
            "provider_claim_authority": False,
            "runtime_route_authorized": False,
            "shadow_only": True,
        },
        "decision": {
            "baseline_total_microusd": decision.baseline_total_microusd,
            "candidate_total_microusd": decision.candidate_total_microusd,
            "mode": decision.mode,
            "predicted_savings_microusd": decision.predicted_savings_microusd,
            "reason": decision.reason,
            "recommended_disposition": decision.recommended_disposition,
            "runtime_applied": decision.runtime_applied,
            "savings_basis_points": decision.savings_basis_points,
        },
        "evidence_boundary": evidence_boundary(),
        "schema_version": TOTAL_COST_ROUTE_RESULT_VERSION,
    }
