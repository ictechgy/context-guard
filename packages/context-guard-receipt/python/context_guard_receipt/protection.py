"""Caller-grounded, fail-closed protection decisions for exact byte payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from .canonical import framed_sha256_hex
from .contracts import evidence_boundary


__all__ = [
    "CallerClassification",
    "DetectorSignal",
    "MAX_DETECTOR_SIGNALS",
    "MAX_PROTECTION_TOKEN_CHARACTERS",
    "MAX_PROTECTED_CONTENT_BYTES",
    "ProtectionAction",
    "ProtectionDecision",
    "ProtectionError",
    "ProtectionReason",
    "decide_protection",
]


PROTECTION_SCHEMA_VERSION: Final = "contextguard-receipt-protection-decision/v1"
PROTECTED_CONTENT_DOMAIN: Final = "contextguard-receipt/protected-content/v1"
MAX_PROTECTED_CONTENT_BYTES: Final = 1024 * 1024
MAX_DETECTOR_SIGNALS: Final = 64
MAX_PROTECTION_TOKEN_CHARACTERS: Final = 18


class CallerClassification(str, Enum):
    """Closed classifications supplied by the caller."""

    ELIGIBLE = "eligible"
    EXACT_REQUIRED = "exact_required"
    PROTECTED = "protected"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    SECURITY_SENSITIVE = "security_sensitive"
    REFUSE = "refuse"


class DetectorSignal(str, Enum):
    """Closed signals that may only escalate a caller classification."""

    EXACT_REQUIRED = "exact_required"
    PROTECTED = "protected"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    SECURITY_SENSITIVE = "security_sensitive"
    SECRET = "secret"


class ProtectionAction(str, Enum):
    """Closed actions produced by the protection policy."""

    ELIGIBLE = "eligible"
    PASS_THROUGH = "pass_through"
    REFUSE = "refuse"


class ProtectionReason(str, Enum):
    """Closed primary reasons, ordered separately by explicit policy precedence."""

    ELIGIBLE = "eligible"
    EXACT_REQUIRED = "exact_required"
    PROTECTED = "protected"
    UNKNOWN = "unknown"
    AMBIGUOUS = "ambiguous"
    SECURITY_SENSITIVE = "security_sensitive"
    REFUSE = "refuse"
    SECRET = "secret"


class ProtectionError(ValueError):
    """A stable, non-reflective protection-policy validation failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_REASON_PRECEDENCE: Final[dict[ProtectionReason, int]] = {
    ProtectionReason.ELIGIBLE: 0,
    ProtectionReason.UNKNOWN: 1,
    ProtectionReason.AMBIGUOUS: 2,
    ProtectionReason.EXACT_REQUIRED: 3,
    ProtectionReason.PROTECTED: 4,
    ProtectionReason.SECURITY_SENSITIVE: 5,
    ProtectionReason.SECRET: 6,
    ProtectionReason.REFUSE: 7,
}


@dataclass(frozen=True, slots=True, init=False)
class ProtectionDecision:
    """Immutable policy result; exact bytes exist only for pass-through decisions."""

    action: ProtectionAction
    reason: ProtectionReason
    exact_bytes: bytes | None = field(repr=False)
    _byte_length: int
    _content_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise ProtectionError("direct_construction_forbidden")

    def artifact(self) -> dict[str, object]:
        """Return closed metadata without exposing or locating the protected content."""

        return {
            "action": self.action.value,
            "byte_length": self._byte_length,
            "content_sha256": self._content_sha256,
            "evidence_boundary": evidence_boundary(),
            "reason": self.reason.value,
            "schema_version": PROTECTION_SCHEMA_VERSION,
        }


def _caller_reason(value: object) -> ProtectionReason:
    if type(value) is CallerClassification:
        return ProtectionReason(value.value)
    if type(value) is str and len(value) <= MAX_PROTECTION_TOKEN_CHARACTERS:
        try:
            return ProtectionReason(CallerClassification(value).value)
        except ValueError:
            pass
    raise ProtectionError("invalid_caller_classification")


def _signal_reason(value: object) -> ProtectionReason:
    if type(value) is DetectorSignal:
        return ProtectionReason(value.value)
    if type(value) is str and len(value) <= MAX_PROTECTION_TOKEN_CHARACTERS:
        try:
            return ProtectionReason(DetectorSignal(value).value)
        except ValueError:
            pass
    raise ProtectionError("invalid_detector_signal")


def _highest_reason(
    caller_reason: ProtectionReason,
    detector_signals: object,
) -> ProtectionReason:
    if type(detector_signals) not in (tuple, frozenset):
        raise ProtectionError("invalid_detector_signals")
    if len(detector_signals) > MAX_DETECTOR_SIGNALS:
        raise ProtectionError("too_many_detector_signals")
    primary = caller_reason
    for raw_signal in detector_signals:
        signal_reason = _signal_reason(raw_signal)
        if _REASON_PRECEDENCE[signal_reason] > _REASON_PRECEDENCE[primary]:
            primary = signal_reason
    return primary


def _action_for(reason: ProtectionReason) -> ProtectionAction:
    if reason is ProtectionReason.ELIGIBLE:
        return ProtectionAction.ELIGIBLE
    if reason in (ProtectionReason.SECRET, ProtectionReason.REFUSE):
        return ProtectionAction.REFUSE
    return ProtectionAction.PASS_THROUGH


def _new_decision(payload: bytes, reason: ProtectionReason) -> ProtectionDecision:
    action = _action_for(reason)
    decision = object.__new__(ProtectionDecision)
    object.__setattr__(decision, "action", action)
    object.__setattr__(decision, "reason", reason)
    object.__setattr__(
        decision,
        "exact_bytes",
        payload if action is ProtectionAction.PASS_THROUGH else None,
    )
    object.__setattr__(decision, "_byte_length", len(payload))
    object.__setattr__(
        decision,
        "_content_sha256",
        framed_sha256_hex(PROTECTED_CONTENT_DOMAIN, payload),
    )
    return decision


def decide_protection(
    payload: bytes,
    caller_classification: CallerClassification | str,
    detector_signals: object = (),
) -> ProtectionDecision:
    """Decide without decoding or transforming the exact caller-supplied bytes."""

    if type(payload) is not bytes:
        raise ProtectionError("invalid_payload_type")
    if len(payload) > MAX_PROTECTED_CONTENT_BYTES:
        raise ProtectionError("payload_too_large")

    primary_reason = _highest_reason(_caller_reason(caller_classification), detector_signals)
    return _new_decision(payload, primary_reason)
