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
