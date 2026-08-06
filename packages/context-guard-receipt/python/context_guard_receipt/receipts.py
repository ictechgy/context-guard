"""Closed G005 artifacts and private exact-expansion envelopes."""

from __future__ import annotations

import hashlib
from typing import Final

from .canonical import JSONLimits, canonical_json_bytes
from .contracts import evidence_boundary
from .router import ROUTER_POLICY_VERSION, RouteCosts, RouteDecision


ASSEMBLY_RECEIPT_VERSION: Final = "contextguard-receipt-assembly-receipt/v1"
EVIDENCE_REFERENCE_VERSION: Final = "contextguard-receipt-evidence-reference/v1"
TYPED_BLUEPRINT_VERSION: Final = "contextguard-receipt-typed-blueprint/v1"
EXPANSION_ENVELOPE_VERSION: Final = "contextguard-receipt-expansion-envelope/v1"
EXPANSION_MAGIC: Final = b"CGRX1\x00"
SOURCE_CURRENT_BINDING: Final = "source_current"
_ENVELOPE_LIMITS: Final = JSONLimits(
    max_document_bytes=256 * 1024,
    max_depth=24,
    max_total_values=4096,
    max_object_members=64,
    max_string_bytes=16 * 1024,
)
_HEX_DIGEST_LENGTH: Final = 64
_SYMBOL_CANDIDATE_KEYS: Final = frozenset(
    {"end_byte", "occurrence", "qualified_name", "raw_range_sha256", "start_byte"}
)
_SYMBOL_EVIDENCE_KEYS: Final = frozenset(
    {
        "candidates",
        "capped",
        "complete",
        "deterministic",
        "end_byte",
        "evidence_kind",
        "fallback_used",
        "language_id",
        "occurrence",
        "parser_error",
        "producer_id",
        "qualified_name",
        "raw_range_sha256",
        "scan_complete",
        "schema_version",
        "source_sha256",
        "start_byte",
    }
)


class ReceiptError(ValueError):
    """Stable validation failure for a private receipt structure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _closed_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ReceiptError("invalid_source_recipe")
    return value  # type: ignore[return-value]


def _bounded_text(value: object, maximum_bytes: int) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= maximum_bytes
    except UnicodeEncodeError:
        return False


def _hex_digest(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == _HEX_DIGEST_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _byte_range(value: dict[str, object]) -> bool:
    start = value["start_byte"]
    end = value["end_byte"]
    return bool(
        type(start) is int
        and type(end) is int
        and start >= 0
        and end >= start
    )


def _validate_symbol_candidate(value: object) -> None:
    candidate = _closed_object(value, _SYMBOL_CANDIDATE_KEYS)
    if (
        not _byte_range(candidate)
        or type(candidate["occurrence"]) is not int
        or candidate["occurrence"] < 0  # type: ignore[operator]
        or not _bounded_text(candidate["qualified_name"], 1024)
        or not _hex_digest(candidate["raw_range_sha256"])
    ):
        raise ReceiptError("invalid_source_recipe")


def _validate_symbol_evidence(value: object) -> None:
    evidence = _closed_object(value, _SYMBOL_EVIDENCE_KEYS)
    candidates = evidence["candidates"]
    if type(candidates) is not list or len(candidates) > 16:
        raise ReceiptError("invalid_source_recipe")
    for candidate in candidates:
        _validate_symbol_candidate(candidate)
    if (
        evidence["complete"] is not True
        or evidence["deterministic"] is not True
        or evidence["scan_complete"] is not True
        or evidence["capped"] is not False
        or evidence["fallback_used"] is not False
        or evidence["parser_error"] is not False
        or evidence["evidence_kind"] != "caller_supplied_symbol_range"
        or evidence["schema_version"]
        != "contextguard-receipt-caller-symbol-evidence/v1"
        or not _byte_range(evidence)
        or type(evidence["occurrence"]) is not int
        or evidence["occurrence"] < 0  # type: ignore[operator]
        or not _bounded_text(evidence["language_id"], 64)
        or not _bounded_text(evidence["producer_id"], 128)
        or not _bounded_text(evidence["qualified_name"], 1024)
        or not _hex_digest(evidence["raw_range_sha256"])
        or not _hex_digest(evidence["source_sha256"])
    ):
        raise ReceiptError("invalid_source_recipe")


def validate_source_recipe(value: object) -> dict[str, object]:
    """Validate the closed source recipe shared by assembly and expansion."""

    source = _closed_object(value, frozenset({"relative_path", "selection"}))
    if not _bounded_text(source["relative_path"], 4096):
        raise ReceiptError("invalid_source_recipe")
    selection = source["selection"]
    if type(selection) is not dict:
        raise ReceiptError("invalid_source_recipe")
    kind = selection.get("kind")
    if kind == "file":
        _closed_object(selection, frozenset({"kind"}))
    elif kind == "range":
        selection = _closed_object(
            selection, frozenset({"kind", "start_byte", "end_byte"})
        )
        if not _byte_range(selection):
            raise ReceiptError("invalid_source_recipe")
    elif kind == "symbol":
        selection = _closed_object(selection, frozenset({"kind", "evidence"}))
        _validate_symbol_evidence(selection["evidence"])
    else:
        raise ReceiptError("invalid_source_recipe")
    return {"relative_path": source["relative_path"], "selection": selection}


def raw_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def route_artifact(costs: RouteCosts, decision: RouteDecision) -> dict[str, object]:
    return {
        "blueprint_bytes": costs.blueprint_bytes,
        "handle_bytes": costs.handle_bytes,
        "input_bytes": costs.input_bytes,
        "mandatory_expansion_bytes": costs.mandatory_expansion_bytes,
        "policy_version": ROUTER_POLICY_VERSION,
        "predicted_cost_bytes": decision.predicted_cost_bytes,
        "predicted_savings_bytes": decision.predicted_savings_bytes,
        "retained_wire_bytes": costs.retained_wire_bytes,
        "savings_basis_points": decision.savings_basis_points,
        "wrapper_bytes": costs.wrapper_bytes,
    }


def assembly_receipt(
    *,
    assembly_kind: str,
    disposition: str,
    reason: str,
    input_payload: bytes,
    output_payload: bytes,
    output_form: str,
    costs: RouteCosts,
    decision: RouteDecision,
) -> dict[str, object]:
    return {
        "artifact_kind": "assembly_receipt",
        "assembly_kind": assembly_kind,
        "disposition": disposition,
        "evidence_boundary": evidence_boundary(),
        "input": {
            "byte_length": len(input_payload),
            "content_sha256": raw_sha256(input_payload),
        },
        "output": {
            "byte_length": len(output_payload),
            "content_sha256": raw_sha256(output_payload),
            "form": output_form,
        },
        "reason": reason,
        "route": route_artifact(costs, decision),
        "schema_version": ASSEMBLY_RECEIPT_VERSION,
    }


def evidence_reference(
    *, payload: bytes, subject_identity_sha256: str, capability: str
) -> dict[str, object]:
    return {
        "artifact_kind": "evidence_reference",
        "byte_length": len(payload),
        "capability": capability,
        "content_sha256": raw_sha256(payload),
        "evidence_boundary": evidence_boundary(),
        "router_policy_version": ROUTER_POLICY_VERSION,
        "schema_version": EVIDENCE_REFERENCE_VERSION,
        "subject_identity_sha256": subject_identity_sha256,
    }


def typed_blueprint(blueprint: dict[str, object]) -> dict[str, object]:
    return {
        "artifact_kind": "typed_blueprint",
        "blueprint": blueprint,
        "evidence_boundary": evidence_boundary(),
        "router_policy_version": ROUTER_POLICY_VERSION,
        "schema_version": TYPED_BLUEPRINT_VERSION,
    }


def expansion_metadata(
    *,
    artifact_type: str,
    root_identity_sha256: str,
    root_state_sha256: str,
    subject_identity_sha256: str,
    payload: bytes,
    revalidation: dict[str, object],
) -> dict[str, object]:
    return {
        "artifact_kind": "expansion_envelope",
        "artifact_type": artifact_type,
        "binding_kind": SOURCE_CURRENT_BINDING,
        "evidence_boundary": evidence_boundary(),
        "payload": {
            "byte_length": len(payload),
            "content_sha256": raw_sha256(payload),
        },
        "revalidation": revalidation,
        "root_identity_sha256": root_identity_sha256,
        "root_state_sha256": root_state_sha256,
        "schema_version": EXPANSION_ENVELOPE_VERSION,
        "subject_identity_sha256": subject_identity_sha256,
    }


def pack_expansion_envelope(metadata: dict[str, object], payload: bytes) -> bytes:
    metadata_bytes = canonical_json_bytes(metadata, limits=_ENVELOPE_LIMITS)
    return (
        EXPANSION_MAGIC
        + len(metadata_bytes).to_bytes(4, byteorder="big", signed=False)
        + metadata_bytes
        + payload
    )


def envelope_limits() -> JSONLimits:
    return _ENVELOPE_LIMITS
