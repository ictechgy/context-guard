"""Pure, privacy-preserving diagnostics for receipt assembly candidates."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Mapping

from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .protection import (
    MAX_DETECTOR_SIGNALS,
    CallerClassification,
    DetectorSignal,
    ProtectionAction,
    decide_protection,
)
from .router import ROUTER_POLICY_VERSION, RouteCosts, decide_route


__all__ = [
    "DiagnosticsError",
    "ParsedDiagnosticsRequest",
    "DiagnosticResult",
    "parse_diagnostics_request",
    "analyze_request",
    "analyze_diagnostics",
]


DIAGNOSTICS_REQUEST_SCHEMA_VERSION: Final = "contextguard-receipt-diagnostics-request/v1"
DIAGNOSTICS_REPORT_SCHEMA_VERSION: Final = "contextguard-receipt-diagnostics-report/v1"
SHADOW_FIREWALL_SCHEMA_VERSION: Final = "contextguard-receipt-shadow-firewall-finding/v1"
DIAGNOSTICS_POLICY_VERSION: Final = "contextguard-receipt-diagnostics-policy/v1"
MAX_DECODED_BYTES: Final = 900_000
PREFIX_SAMPLE_BYTES: Final = 65_536
PREFIX_WINDOW_BYTES: Final = 64
MAX_PREFIX_WINDOWS: Final = 1_024
SURGEON_REUSE_BASIS_POINTS: Final = 9_000
DIAGNOSTICS_POLICY_SHA256: Final = framed_sha256_hex(
    "contextguard-receipt/diagnostic-policy/v1",
    DIAGNOSTICS_POLICY_VERSION.encode("ascii"),
    ROUTER_POLICY_VERSION.encode("ascii"),
    PREFIX_SAMPLE_BYTES.to_bytes(8, byteorder="big", signed=False),
    PREFIX_WINDOW_BYTES.to_bytes(8, byteorder="big", signed=False),
    MAX_PREFIX_WINDOWS.to_bytes(8, byteorder="big", signed=False),
    SURGEON_REUSE_BASIS_POINTS.to_bytes(8, byteorder="big", signed=False),
)
_REQUEST_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=4,
    max_total_values=128,
    max_object_members=16,
    max_string_bytes=2 * 1024 * 1024,
)
_REQUEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "blueprint_b64u",
        "caller_classification",
        "current_prefix_b64u",
        "detector_signals",
        "handle_b64u",
        "input_b64u",
        "mandatory_expansion_b64u",
        "previous_prefix_b64u",
        "retained_wire_b64u",
        "schema_version",
        "subject_kind",
        "wrapper_b64u",
    }
)
_SUBJECT_KINDS: Final[frozenset[str]] = frozenset(
    {"evidence", "evidence_pack", "blueprint", "tool_schema_catalog", "command_capture"}
)
_B64URL: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3})?$"
)
_FINGERPRINT_DOMAIN: Final = "contextguard-receipt/diagnostics-evidence/v1"
_WINDOW_DOMAIN: Final = "contextguard-receipt/diagnostics-prefix-window/v1"
_PREFIX_FINGERPRINT_DOMAIN: Final = "contextguard-receipt/diagnostics-prefix-fingerprint/v1"
_STATE_SCOPES: Final[frozenset[str]] = frozenset({"process", "durable"})


class DiagnosticsError(ValueError):
    """Stable input-validation failure that never reflects supplied data."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"diagnostics rejected: {code}")


@dataclass(frozen=True, slots=True, init=False)
class ParsedDiagnosticsRequest:
    """Validated request whose binary fragments remain redacted in representations."""

    subject_kind: str
    caller_classification: str
    detector_signals: tuple[str, ...]
    _fragments: Mapping[str, bytes] = field(repr=False)
    _previous_prefix: bytes | None = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise DiagnosticsError("direct_construction_forbidden")

    def __repr__(self) -> str:
        return "ParsedDiagnosticsRequest(redacted=True)"


def _framed_hmac_sha256_hex(key: bytes, domain: str, *parts: bytes) -> str:
    """Return a domain-separated U64BE-framed HMAC without retaining the key."""

    mac = hmac.new(key, digestmod=hashlib.sha256)
    mac.update(domain.encode("ascii"))
    mac.update(b"\x00")
    for part in parts:
        mac.update(len(part).to_bytes(8, byteorder="big", signed=False))
        mac.update(part)
    return mac.hexdigest()


def _decode_b64url(value: object) -> bytes:
    if type(value) is not str or _B64URL.fullmatch(value) is None:
        raise DiagnosticsError("invalid_base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        raise DiagnosticsError("invalid_base64url") from None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise DiagnosticsError("invalid_base64url")
    return decoded


def _request(raw: bytes) -> tuple[
    str, str, tuple[str, ...], dict[str, bytes], bytes | None
]:
    if type(raw) is not bytes:
        raise DiagnosticsError("invalid_request")
    try:
        parsed = parse_canonical_json_bytes(raw, limits=_REQUEST_LIMITS)
    except CanonicalJSONError:
        raise DiagnosticsError("invalid_request") from None
    if type(parsed) is not dict or set(parsed) != _REQUEST_KEYS:
        raise DiagnosticsError("invalid_request")
    if parsed.get("schema_version") != DIAGNOSTICS_REQUEST_SCHEMA_VERSION:
        raise DiagnosticsError("invalid_request")
    subject_kind = parsed.get("subject_kind")
    if type(subject_kind) is not str or subject_kind not in _SUBJECT_KINDS:
        raise DiagnosticsError("invalid_request")
    caller = parsed.get("caller_classification")
    if type(caller) is not str:
        raise DiagnosticsError("invalid_request")
    try:
        caller = CallerClassification(caller).value
    except ValueError:
        raise DiagnosticsError("invalid_request") from None
    signals_value = parsed.get("detector_signals")
    if type(signals_value) is not list or any(type(signal) is not str for signal in signals_value):
        raise DiagnosticsError("invalid_request")
    if len(signals_value) > MAX_DETECTOR_SIGNALS or len(set(signals_value)) != len(
        signals_value
    ):
        raise DiagnosticsError("invalid_request")
    try:
        signals = tuple(sorted(DetectorSignal(signal).value for signal in signals_value))
    except ValueError:
        raise DiagnosticsError("invalid_request") from None
    encoded_names = (
        "blueprint_b64u",
        "current_prefix_b64u",
        "handle_b64u",
        "input_b64u",
        "mandatory_expansion_b64u",
        "retained_wire_b64u",
        "wrapper_b64u",
    )
    fragments = {name.removesuffix("_b64u"): _decode_b64url(parsed[name]) for name in encoded_names}
    previous_encoded = parsed.get("previous_prefix_b64u")
    if previous_encoded is not None and type(previous_encoded) is not str:
        raise DiagnosticsError("invalid_request")
    previous = None if previous_encoded is None else _decode_b64url(previous_encoded)
    if sum(len(value) for value in fragments.values()) + (len(previous) if previous else 0) > MAX_DECODED_BYTES:
        raise DiagnosticsError("decoded_too_large")
    return subject_kind, caller, signals, fragments, previous


def parse_diagnostics_request(raw: bytes) -> ParsedDiagnosticsRequest:
    """Validate a canonical request before any caller opens durable state."""

    subject_kind, caller, signals, fragments, previous = _request(raw)
    parsed = object.__new__(ParsedDiagnosticsRequest)
    object.__setattr__(parsed, "subject_kind", subject_kind)
    object.__setattr__(parsed, "caller_classification", caller)
    object.__setattr__(parsed, "detector_signals", signals)
    object.__setattr__(parsed, "_fragments", MappingProxyType(fragments))
    object.__setattr__(parsed, "_previous_prefix", previous)
    return parsed


def _prefix_windows(prefix: bytes, key: bytes) -> tuple[tuple[str, ...], int, bool]:
    sample = prefix[:PREFIX_SAMPLE_BYTES]
    window_count = min(
        (len(sample) + PREFIX_WINDOW_BYTES - 1) // PREFIX_WINDOW_BYTES,
        MAX_PREFIX_WINDOWS,
    )
    hashes = tuple(
        _framed_hmac_sha256_hex(
            key,
            _WINDOW_DOMAIN,
            index.to_bytes(8, byteorder="big", signed=False),
            sample[index * PREFIX_WINDOW_BYTES : (index + 1) * PREFIX_WINDOW_BYTES],
        )
        for index in range(window_count)
    )
    return hashes, window_count, len(prefix) > PREFIX_SAMPLE_BYTES


def _prefix_delta(current: bytes, previous: bytes | None, key: bytes) -> dict[str, object]:
    current_hashes, current_windows, current_truncated = _prefix_windows(current, key)
    current_hmac = _framed_hmac_sha256_hex(key, _PREFIX_FINGERPRINT_DOMAIN, b"current", current)
    if previous is None:
        return {
            "current_prefix_bytes": len(current),
            "current_prefix_hmac_sha256": current_hmac,
            "current_reuse_basis_points": 0,
            "current_sample_bytes": min(len(current), PREFIX_SAMPLE_BYTES),
            "current_truncated": current_truncated,
            "current_window_count": current_windows,
            "matched_window_count": 0,
            "prefix_delta_bytes": 0,
            "previous_prefix_bytes": 0,
            "previous_prefix_hmac_sha256": _framed_hmac_sha256_hex(
                key, _PREFIX_FINGERPRINT_DOMAIN, b"previous_absent"
            ),
            "previous_prefix_present": False,
            "previous_retention_basis_points": 0,
            "previous_sample_bytes": 0,
            "previous_truncated": False,
            "previous_window_count": 0,
            "rolling_status": "unavailable",
        }
    previous_hashes, previous_windows, previous_truncated = _prefix_windows(previous, key)
    reused = sum(
        hmac.compare_digest(current_hash, previous_hash)
        for current_hash, previous_hash in zip(current_hashes, previous_hashes)
    )
    return {
        "current_prefix_bytes": len(current),
        "current_prefix_hmac_sha256": current_hmac,
        "current_reuse_basis_points": reused * 10_000 // current_windows if current_windows else 0,
        "current_sample_bytes": min(len(current), PREFIX_SAMPLE_BYTES),
        "current_truncated": current_truncated,
        "current_window_count": current_windows,
        "matched_window_count": reused,
        "prefix_delta_bytes": len(current) - len(previous),
        "previous_prefix_bytes": len(previous),
        "previous_prefix_hmac_sha256": _framed_hmac_sha256_hex(
            key, _PREFIX_FINGERPRINT_DOMAIN, b"previous", previous
        ),
        "previous_prefix_present": True,
        "previous_retention_basis_points": reused * 10_000 // previous_windows if previous_windows else 0,
        "previous_sample_bytes": min(len(previous), PREFIX_SAMPLE_BYTES),
        "previous_truncated": previous_truncated,
        "previous_window_count": previous_windows,
        "rolling_status": "partial" if current_truncated or previous_truncated else "complete",
    }


def _advisory(
    *, protection_eligible: bool, protection_reason: str, route_reason: str,
    current_prefix: bytes, previous_prefix: bytes | None, prefix_delta: Mapping[str, object],
) -> tuple[str, str]:
    if not protection_eligible:
        reason = (
            "protection_refused"
            if protection_reason in {"secret", "refuse"}
            else "exact_path_required"
        )
        return "none", reason
    if route_reason != "beneficial":
        return "scout", route_reason
    if not current_prefix:
        return "scout", "prefix_evidence_empty"
    if previous_prefix is None:
        return "scout", "prior_prefix_missing"
    if bool(prefix_delta["current_truncated"]) or bool(prefix_delta["previous_truncated"]):
        return "scout", "rolling_sample_partial"
    if (
        int(prefix_delta["current_sample_bytes"]) < PREFIX_WINDOW_BYTES
        or int(prefix_delta["previous_sample_bytes"]) < PREFIX_WINDOW_BYTES
        or int(prefix_delta["current_reuse_basis_points"])
        < SURGEON_REUSE_BASIS_POINTS
        or int(prefix_delta["previous_retention_basis_points"])
        < SURGEON_REUSE_BASIS_POINTS
    ):
        return "scout", "prefix_churn_high"
    return "surgeon", "bounded_stable_benefit"


def _freeze(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return copy.deepcopy(value)


@dataclass(frozen=True, slots=True)
class DiagnosticResult:
    """Immutable, content-free diagnostics result with projection helpers."""

    _report: Mapping[str, object] = field(repr=False)
    _ledger: Mapping[str, object] = field(repr=False)

    def report(self, state_scope: str = "process") -> dict[str, object]:
        if type(state_scope) is not str or state_scope not in _STATE_SCOPES:
            raise DiagnosticsError("invalid_state_scope")
        result = _thaw(self._report)
        assert type(result) is dict
        result["state_scope"] = state_scope
        return result

    def firewall_report(self) -> dict[str, object]:
        firewall = _thaw(self._report["firewall"])
        assert type(firewall) is dict
        return firewall

    def ledger_fields(self) -> dict[str, object]:
        result = _thaw(self._ledger)
        assert type(result) is dict
        return result

    def __repr__(self) -> str:
        return "DiagnosticResult(redacted=True)"


def analyze_request(
    request: ParsedDiagnosticsRequest, *, fingerprint_key: bytes
) -> DiagnosticResult:
    """Analyze a validated request without I/O, raw-content output, or key retention."""

    if type(fingerprint_key) is not bytes or len(fingerprint_key) != 32:
        raise DiagnosticsError("invalid_fingerprint_key")
    if type(request) is not ParsedDiagnosticsRequest:
        raise DiagnosticsError("invalid_request")
    subject_kind = request.subject_kind
    caller = request.caller_classification
    signals = request.detector_signals
    fragments = request._fragments
    previous = request._previous_prefix
    try:
        protection = decide_protection(fragments["input"], caller, signals)
    except ValueError:
        raise DiagnosticsError("invalid_request") from None
    route = decide_route(
        RouteCosts(
            input_bytes=len(fragments["input"]),
            wrapper_bytes=len(fragments["wrapper"]),
            handle_bytes=len(fragments["handle"]),
            blueprint_bytes=len(fragments["blueprint"]),
            mandatory_expansion_bytes=len(fragments["mandatory_expansion"]),
            retained_wire_bytes=len(fragments["retained_wire"]),
        )
    )
    reason = protection.reason.value if protection.action is not ProtectionAction.ELIGIBLE else route.reason.value
    evidence_hmac = _framed_hmac_sha256_hex(
        fingerprint_key,
        _FINGERPRINT_DOMAIN,
        subject_kind.encode("ascii"),
        caller.encode("ascii"),
        len(signals).to_bytes(8, byteorder="big", signed=False),
        *(signal.encode("ascii") for signal in signals),
        fragments["blueprint"],
        fragments["current_prefix"],
        fragments["handle"],
        fragments["input"],
        fragments["mandatory_expansion"],
        b"\x00" if previous is None else b"\x01",
        b"" if previous is None else previous,
        fragments["retained_wire"],
        fragments["wrapper"],
    )
    prefix_delta = _prefix_delta(fragments["current_prefix"], previous, fingerprint_key)
    advisory, advisory_reason = _advisory(
        protection_eligible=protection.action is ProtectionAction.ELIGIBLE,
        protection_reason=protection.reason.value,
        route_reason=route.reason.value,
        current_prefix=fragments["current_prefix"],
        previous_prefix=previous,
        prefix_delta=prefix_delta,
    )
    firewall = {
        "applied": False,
        "evidence_boundary": evidence_boundary(),
        "evidence_hmac_sha256": evidence_hmac,
        "reason": reason,
        "schema_version": SHADOW_FIREWALL_SCHEMA_VERSION,
        "subject_kind": subject_kind,
        "would_block": reason != "beneficial",
    }
    route_report = {
        "blueprint_bytes": len(fragments["blueprint"]),
        "disposition": route.disposition.value,
        "handle_bytes": len(fragments["handle"]),
        "input_bytes": len(fragments["input"]),
        "mandatory_expansion_bytes": len(fragments["mandatory_expansion"]),
        "policy_version": ROUTER_POLICY_VERSION,
        "predicted_cost_bytes": route.predicted_cost_bytes,
        "predicted_savings_bytes": route.predicted_savings_bytes,
        "reason": route.reason.value,
        "retained_wire_bytes": len(fragments["retained_wire"]),
        "savings_basis_points": route.savings_basis_points,
        "wrapper_bytes": len(fragments["wrapper"]),
    }
    report = {
        "advisory": {"lane": advisory, "only": True, "reason": advisory_reason},
        "efficacy_claim_authority": False,
        "evidence_boundary": evidence_boundary(),
        "firewall": firewall,
        "live_observation_authority": False,
        "prefix_delta": prefix_delta,
        "provider_claim_authority": False,
        "provider_routing_authority": False,
        "route": route_report,
        "schema_version": DIAGNOSTICS_REPORT_SCHEMA_VERSION,
        "subject_kind": subject_kind,
    }
    ledger = {
        "advisory_lane": advisory,
        "advisory_only": True,
        "advisory_reason": advisory_reason,
        "applied": False,
        "blueprint_bytes": len(fragments["blueprint"]),
        "current_prefix_bytes": prefix_delta["current_prefix_bytes"],
        "current_prefix_hmac_sha256": prefix_delta["current_prefix_hmac_sha256"],
        "current_reuse_basis_points": prefix_delta["current_reuse_basis_points"],
        "current_sample_bytes": prefix_delta["current_sample_bytes"],
        "current_truncated": prefix_delta["current_truncated"],
        "current_window_count": prefix_delta["current_window_count"],
        "efficacy_claim_authority": False,
        "evidence_hmac_sha256": evidence_hmac,
        "firewall_reason": reason,
        "handle_bytes": len(fragments["handle"]),
        "input_bytes": len(fragments["input"]),
        "live_observation_authority": False,
        "mandatory_expansion_bytes": len(fragments["mandatory_expansion"]),
        "matched_window_count": prefix_delta["matched_window_count"],
        "policy_sha256": DIAGNOSTICS_POLICY_SHA256,
        "predicted_cost_bytes": route.predicted_cost_bytes,
        "predicted_savings_bytes": route.predicted_savings_bytes,
        "previous_prefix_bytes": prefix_delta["previous_prefix_bytes"],
        "previous_prefix_hmac_sha256": prefix_delta["previous_prefix_hmac_sha256"],
        "previous_prefix_present": prefix_delta["previous_prefix_present"],
        "previous_retention_basis_points": prefix_delta["previous_retention_basis_points"],
        "previous_sample_bytes": prefix_delta["previous_sample_bytes"],
        "previous_truncated": prefix_delta["previous_truncated"],
        "previous_window_count": prefix_delta["previous_window_count"],
        "provider_claim_authority": False,
        "provider_routing_authority": False,
        "prefix_delta_bytes": prefix_delta["prefix_delta_bytes"],
        "retained_wire_bytes": len(fragments["retained_wire"]),
        "rolling_status": prefix_delta["rolling_status"],
        "savings_basis_points": route.savings_basis_points,
        "subject_kind": subject_kind,
        "would_block": reason != "beneficial",
        "wrapper_bytes": len(fragments["wrapper"]),
    }
    return DiagnosticResult(_report=_freeze(report), _ledger=_freeze(ledger))


def analyze_diagnostics(raw: bytes, *, fingerprint_key: bytes) -> DiagnosticResult:
    """Convenience parser and analyzer for one canonical diagnostics request."""

    return analyze_request(parse_diagnostics_request(raw), fingerprint_key=fingerprint_key)
