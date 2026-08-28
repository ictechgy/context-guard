"""Pure, deterministic byte-benefit routing for G005 assembly."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from typing import Final


ROUTER_POLICY_VERSION: Final = "contextguard-receipt-router/v1"
MINIMUM_INPUT_BYTES: Final = 512
MINIMUM_SAVINGS_BYTES: Final = 256
MINIMUM_SAVINGS_BASIS_POINTS: Final = 1_000
_BASIS_POINTS: Final = 10_000
_MAX_MICROUSD: Final = 2**63 - 1


class RouteError(ValueError):
    """Stable validation failure without caller-controlled detail."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RouteDisposition(str, Enum):
    DEFER = "defer"
    PASS_THROUGH = "pass_through"


class RouteReason(str, Enum):
    BENEFICIAL = "beneficial"
    INPUT_TOO_SMALL = "input_too_small"
    SAVINGS_TOO_SMALL = "savings_too_small"
    SAVINGS_RATIO_TOO_SMALL = "savings_ratio_too_small"
    MANDATORY_EXPANSION_COST = "mandatory_expansion_cost"


@dataclass(frozen=True, slots=True)
class RouteCosts:
    input_bytes: int
    wrapper_bytes: int
    handle_bytes: int
    blueprint_bytes: int
    mandatory_expansion_bytes: int
    retained_wire_bytes: int

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value < 0:
                raise RouteError("invalid_cost")


@dataclass(frozen=True, slots=True)
class RouteDecision:
    disposition: RouteDisposition
    reason: RouteReason
    predicted_cost_bytes: int
    predicted_savings_bytes: int
    savings_basis_points: int


@dataclass(frozen=True, slots=True)
class TotalCostComponents:
    provider_input: int
    provider_output: int
    cache: int
    expansion: int
    retry: int
    helper: int
    local: int

    def __post_init__(self) -> None:
        total = 0
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or not 0 <= value <= _MAX_MICROUSD:
                raise RouteError("invalid_total_cost")
            total += value
        if total > _MAX_MICROUSD:
            raise RouteError("invalid_total_cost")

    def total(self) -> int:
        return sum(getattr(self, item.name) for item in fields(self))


@dataclass(frozen=True, slots=True)
class RouteV2Context:
    evidence_complete: bool
    full_wire_ceiling_respected: bool
    quality_gate: str
    risk: str

    def __post_init__(self) -> None:
        if (
            type(self.evidence_complete) is not bool
            or type(self.full_wire_ceiling_respected) is not bool
            or self.quality_gate not in {"pass", "fail", "unknown"}
            or self.risk not in {"low", "medium", "high"}
        ):
            raise RouteError("invalid_route_context")


@dataclass(frozen=True, slots=True)
class RouteV2Policy:
    minimum_savings_microusd: int
    minimum_savings_basis_points: int

    def __post_init__(self) -> None:
        if (
            type(self.minimum_savings_microusd) is not int
            or not 0 <= self.minimum_savings_microusd <= _MAX_MICROUSD
            or type(self.minimum_savings_basis_points) is not int
            or not 0 <= self.minimum_savings_basis_points <= _BASIS_POINTS
        ):
            raise RouteError("invalid_route_policy")


@dataclass(frozen=True, slots=True)
class RouteV2Decision:
    mode: str
    recommended_disposition: str
    reason: str
    baseline_total_microusd: int
    candidate_total_microusd: int
    predicted_savings_microusd: int
    savings_basis_points: int
    runtime_applied: bool


def _meets_benefit(input_bytes: int, predicted_cost_bytes: int) -> bool:
    savings = input_bytes - predicted_cost_bytes
    return (
        input_bytes >= MINIMUM_INPUT_BYTES
        and savings >= MINIMUM_SAVINGS_BYTES
        and savings * _BASIS_POINTS
        >= input_bytes * MINIMUM_SAVINGS_BASIS_POINTS
    )


def decide_route(costs: RouteCosts) -> RouteDecision:
    """Apply all thresholds with integer arithmetic and inclusive boundaries."""

    if type(costs) is not RouteCosts:
        raise RouteError("invalid_costs")
    predicted_cost = (
        costs.wrapper_bytes
        + costs.handle_bytes
        + costs.blueprint_bytes
        + costs.mandatory_expansion_bytes
        + costs.retained_wire_bytes
    )
    savings = costs.input_bytes - predicted_cost
    savings_basis_points = (
        savings * _BASIS_POINTS // costs.input_bytes if costs.input_bytes else 0
    )

    if costs.input_bytes < MINIMUM_INPUT_BYTES:
        disposition = RouteDisposition.PASS_THROUGH
        reason = RouteReason.INPUT_TOO_SMALL
    elif savings < MINIMUM_SAVINGS_BYTES:
        without_mandatory = predicted_cost - costs.mandatory_expansion_bytes
        if costs.mandatory_expansion_bytes and _meets_benefit(
            costs.input_bytes, without_mandatory
        ):
            disposition = RouteDisposition.PASS_THROUGH
            reason = RouteReason.MANDATORY_EXPANSION_COST
        else:
            disposition = RouteDisposition.PASS_THROUGH
            reason = RouteReason.SAVINGS_TOO_SMALL
    elif savings * _BASIS_POINTS < (
        costs.input_bytes * MINIMUM_SAVINGS_BASIS_POINTS
    ):
        without_mandatory = predicted_cost - costs.mandatory_expansion_bytes
        if costs.mandatory_expansion_bytes and _meets_benefit(
            costs.input_bytes, without_mandatory
        ):
            disposition = RouteDisposition.PASS_THROUGH
            reason = RouteReason.MANDATORY_EXPANSION_COST
        else:
            disposition = RouteDisposition.PASS_THROUGH
            reason = RouteReason.SAVINGS_RATIO_TOO_SMALL
    else:
        disposition = RouteDisposition.DEFER
        reason = RouteReason.BENEFICIAL

    return RouteDecision(
        disposition=disposition,
        reason=reason,
        predicted_cost_bytes=predicted_cost,
        predicted_savings_bytes=savings,
        savings_basis_points=savings_basis_points,
    )


def decide_total_cost_route(
    *,
    baseline_total_microusd: int,
    candidate: TotalCostComponents,
    context: RouteV2Context,
    policy: RouteV2Policy,
) -> RouteV2Decision:
    """Return shadow-only total-cost advice without applying a runtime route."""

    if (
        type(baseline_total_microusd) is not int
        or not 0 < baseline_total_microusd <= _MAX_MICROUSD
        or type(candidate) is not TotalCostComponents
        or type(context) is not RouteV2Context
        or type(policy) is not RouteV2Policy
    ):
        raise RouteError("invalid_total_cost_route")
    candidate_total = candidate.total()
    savings = baseline_total_microusd - candidate_total
    savings_basis_points = savings * _BASIS_POINTS // baseline_total_microusd

    if not context.evidence_complete:
        disposition, reason = "pass_through", "incomplete_evidence"
    elif not context.full_wire_ceiling_respected:
        disposition, reason = "pass_through", "full_wire_ceiling_failed"
    elif context.quality_gate == "fail":
        disposition, reason = "pass_through", "quality_gate_failed"
    elif context.quality_gate != "pass":
        disposition, reason = "pass_through", "quality_gate_unavailable"
    elif context.risk == "high":
        disposition, reason = "pass_through", "risk_not_eligible"
    elif savings <= 0:
        disposition, reason = "pass_through", "candidate_total_cost_not_lower"
    elif savings < policy.minimum_savings_microusd:
        disposition, reason = "pass_through", "absolute_savings_too_small"
    elif savings_basis_points < policy.minimum_savings_basis_points:
        disposition, reason = "pass_through", "relative_savings_too_small"
    else:
        disposition, reason = "defer", "beneficial_total_cost"

    return RouteV2Decision(
        mode="shadow",
        recommended_disposition=disposition,
        reason=reason,
        baseline_total_microusd=baseline_total_microusd,
        candidate_total_microusd=candidate_total,
        predicted_savings_microusd=savings,
        savings_basis_points=savings_basis_points,
        runtime_applied=False,
    )
