"""Exact, snapshot-bound G006 tool-schema catalog assembly."""

from __future__ import annotations

import base64
import binascii
import hashlib
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Protocol, cast

from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .protection import (
    ProtectionAction,
    ProtectionError,
    ProtectionReason,
    decide_protection,
)
from .router import RouteCosts, RouteDisposition, decide_route
from .store import ArtifactRequest, ArtifactType, predicted_capability_bytes
from .store import StoreError, StoreErrorCode


__all__ = [
    "CATALOG_FORMATS",
    "DESCRIPTOR_LIMITS",
    "MAX_CATALOG_BYTES",
    "MAX_TOOL_NAME_BYTES",
    "MAX_TOOL_SCHEMAS",
    "ToolSchemaDisposition",
    "ToolSchemaError",
    "ToolSchemaExpansionDisposition",
    "ToolSchemaExpansionResult",
    "ToolSchemaResult",
    "assemble_tool_schemas",
    "expand_tool_schema_catalog",
    "expand_tool_schema_item",
]


TOOL_SCHEMA_DESCRIPTOR_VERSION: Final = (
    "contextguard-receipt-tool-schema-descriptor/v1"
)
TOOL_SCHEMA_BUNDLE_VERSION: Final = "contextguard-receipt-tool-schema-bundle/v1"
TOOL_SCHEMA_CATALOG_REFERENCE_VERSION: Final = (
    "contextguard-receipt-tool-schema-catalog-reference/v1"
)
TOOL_SCHEMA_REFERENCE_VERSION: Final = (
    "contextguard-receipt-tool-schema-reference/v1"
)
TOOL_SCHEMA_RECEIPT_VERSION: Final = "contextguard-receipt-tool-schema-receipt/v1"
TOOL_SCHEMA_ENVELOPE_VERSION: Final = "contextguard-receipt-tool-schema-envelope/v1"
TOOL_SCHEMA_EXPANSION_REFUSAL_VERSION: Final = (
    "contextguard-receipt-tool-schema-expansion-refusal/v1"
)
TOOL_SCHEMA_MAGIC: Final = b"CGTS1\x00"
CATALOG_SNAPSHOT_BINDING: Final = "catalog_snapshot"
CATALOG_FORMATS: Final = frozenset(
    {"anthropic_tools/v1", "openai_functions/v1"}
)
MAX_CATALOG_BYTES: Final = 900_000
MAX_TOOL_SCHEMAS: Final = 256
MAX_TOOL_NAME_BYTES: Final = 256
MIN_PRIORITY: Final = -(2**31)
MAX_PRIORITY: Final = 2**31 - 1
DESCRIPTOR_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=32,
    max_total_values=65_536,
    max_object_members=64,
    max_string_bytes=1_300_000,
)
CATALOG_LIMITS: Final = JSONLimits(
    max_document_bytes=MAX_CATALOG_BYTES,
    max_depth=32,
    max_total_values=65_536,
    max_object_members=256,
    max_string_bytes=MAX_CATALOG_BYTES,
)
ENVELOPE_LIMITS: Final = JSONLimits(
    max_document_bytes=256 * 1024,
    max_depth=16,
    max_total_values=512,
    max_object_members=32,
    max_string_bytes=1024,
)

_FROZEN_UNICODE_DATABASE = unicodedata.ucd_3_2_0
_HANDLE_PLACEHOLDER: Final = "cgr1p_" + ("A" * 43)
_CAPABILITY_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_HEX_ALPHABET: Final = frozenset("0123456789abcdef")
_PROTECTION_PRIORITY: Final = {
    ProtectionReason.ELIGIBLE: 0,
    ProtectionReason.UNKNOWN: 1,
    ProtectionReason.AMBIGUOUS: 2,
    ProtectionReason.EXACT_REQUIRED: 3,
    ProtectionReason.PROTECTED: 4,
    ProtectionReason.SECURITY_SENSITIVE: 5,
    ProtectionReason.SECRET: 6,
    ProtectionReason.REFUSE: 7,
}
_VALUE_KEYS: Final = frozenset({"default", "example", "examples"})
_SENSITIVE_LABELS: Final = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "passwd",
    "password",
    "private_key",
    "secret",
    "session",
    "token",
)


class ToolSchemaError(ValueError):
    """Stable, non-reflective G006 descriptor failure."""

    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ToolSchemaDisposition(str, Enum):
    DEFERRED = "deferred"
    PASS_THROUGH = "pass_through"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ToolSchemaResult:
    disposition: ToolSchemaDisposition
    output_bytes: bytes = field(repr=False)
    receipt: dict[str, object]


class ToolSchemaExpansionDisposition(str, Enum):
    EXACT = "exact"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ToolSchemaExpansionResult:
    disposition: ToolSchemaExpansionDisposition
    output_bytes: bytes = field(repr=False)
    refusal: dict[str, object] | None


class IssuanceBackend(Protocol):
    def issue_batch(
        self, requests: tuple[ArtifactRequest, ...]
    ) -> tuple[object, ...]: ...


class RetrievalBackend(Protocol):
    def retrieve(
        self,
        handle: str,
        *,
        expected_namespace_id: str,
        expected_root_identity_sha256: str,
        expected_subject_identity_sha256: str,
        expected_artifact_type: ArtifactType,
    ) -> object: ...


class _ExpansionValidationError(ValueError):
    pass


class _BackendUnavailable(RuntimeError):
    pass


def _reject() -> None:
    raise ToolSchemaError("invalid_descriptor") from None


def _strict_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _reject()
    return value  # type: ignore[return-value]


def _decode_payload(value: object) -> bytes:
    if type(value) is not str or len(value) > 1_300_000 or "=" in value:
        _reject()
    try:
        encoded = value.encode("ascii", errors="strict")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)
        payload = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        _reject()
    if (
        len(payload) > MAX_CATALOG_BYTES
        or base64.urlsafe_b64encode(payload).rstrip(b"=") != encoded
    ):
        _reject()
    return payload


def _signals(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 64:
        _reject()
    if any(type(signal) is not str for signal in value) or len(set(value)) != len(value):
        _reject()
    return tuple(value)  # type: ignore[arg-type]


def _parse_metadata(value: object) -> tuple[dict[str, object], ...]:
    if type(value) is not list or len(value) > MAX_TOOL_SCHEMAS:
        _reject()
    parsed: list[dict[str, object]] = []
    for index, raw_item in enumerate(value):
        item = _strict_object(
            raw_item,
            frozenset(
                {
                    "caller_classification",
                    "detector_signals",
                    "priority",
                    "required",
                }
            ),
        )
        priority = item["priority"]
        if (
            type(item["required"]) is not bool
            or type(priority) is not int
            or priority < MIN_PRIORITY
            or priority > MAX_PRIORITY
            or type(item["caller_classification"]) is not str
        ):
            _reject()
        parsed.append(
            {
                "classification": item["caller_classification"],
                "index": index,
                "priority": priority,
                "required": item["required"],
                "signals": _signals(item["detector_signals"]),
            }
        )
    return tuple(parsed)


def _parse_descriptor(raw: bytes) -> tuple[str, bytes, tuple[dict[str, object], ...], int]:
    if type(raw) is not bytes:
        _reject()
    try:
        document = parse_canonical_json_bytes(raw, limits=DESCRIPTOR_LIMITS)
    except CanonicalJSONError:
        _reject()
    descriptor = _strict_object(
        document,
        frozenset(
            {"catalog_format", "items", "payload_b64u", "retain_count", "schema_version"}
        ),
    )
    catalog_format = descriptor["catalog_format"]
    retain_count = descriptor["retain_count"]
    if (
        descriptor["schema_version"] != TOOL_SCHEMA_DESCRIPTOR_VERSION
        or type(catalog_format) is not str
        or catalog_format not in CATALOG_FORMATS
        or type(retain_count) is not int
    ):
        _reject()
    payload = _decode_payload(descriptor["payload_b64u"])
    metadata = _parse_metadata(descriptor["items"])
    if retain_count < 0 or retain_count > len(metadata):
        _reject()
    return catalog_format, payload, metadata, retain_count


def _raw_element_spans(payload: bytes) -> tuple[tuple[int, int], ...]:
    """Return exact member ranges from a canonical top-level JSON array."""

    body = payload[:-1]
    if len(body) < 2 or body[0] != 0x5B or body[-1] != 0x5D:
        _reject()
    if body == b"[]":
        return ()
    spans: list[tuple[int, int]] = []
    cursor = 1
    while cursor < len(body) - 1:
        if len(spans) >= MAX_TOOL_SCHEMAS:
            _reject()
        start = cursor
        depth = 0
        in_string = False
        escaped = False
        while cursor < len(body) - 1:
            byte = body[cursor]
            if in_string:
                if escaped:
                    escaped = False
                elif byte == 0x5C:
                    escaped = True
                elif byte == 0x22:
                    in_string = False
            elif byte == 0x22:
                in_string = True
            elif byte in (0x5B, 0x7B):
                depth += 1
            elif byte in (0x5D, 0x7D):
                depth -= 1
                if depth < 0:
                    _reject()
            elif byte == 0x2C and depth == 0:
                break
            cursor += 1
        if in_string or depth != 0 or cursor <= start:
            _reject()
        spans.append((start, cursor))
        if cursor == len(body) - 1:
            break
        cursor += 1
        if cursor >= len(body) - 1:
            _reject()
    if not spans or spans[-1][1] != len(body) - 1:
        _reject()
    return tuple(spans)


def _parse_catalog(payload: bytes) -> tuple[tuple[dict[str, object], ...], tuple[tuple[int, int], ...]]:
    try:
        value = parse_canonical_json_bytes(payload, limits=CATALOG_LIMITS)
    except CanonicalJSONError:
        _reject()
    if type(value) is not list or len(value) > MAX_TOOL_SCHEMAS:
        _reject()
    spans = _raw_element_spans(payload)
    if len(spans) != len(value):
        _reject()
    parsed: list[dict[str, object]] = []
    for expected, (start, end) in zip(value, spans, strict=True):
        raw_slice = payload[start:end]
        try:
            verified = parse_canonical_json_bytes(raw_slice + b"\n", limits=CATALOG_LIMITS)
        except CanonicalJSONError:
            _reject()
        if verified != expected or type(verified) is not dict:
            _reject()
        parsed.append(verified)
    return tuple(parsed), spans


def _native_name(catalog_format: str, value: dict[str, object]) -> str | None:
    keys = frozenset(value)
    if catalog_format == "anthropic_tools/v1":
        if keys not in (
            frozenset({"input_schema", "name"}),
            frozenset({"description", "input_schema", "name"}),
        ) or type(value.get("input_schema")) is not dict:
            return None
    elif catalog_format == "openai_functions/v1":
        if keys not in (
            frozenset({"name", "parameters"}),
            frozenset({"description", "name", "parameters"}),
        ) or type(value.get("parameters")) is not dict:
            return None
    else:
        return None
    if "description" in value and type(value["description"]) is not str:
        return None
    name = value.get("name")
    if type(name) is not str or not name:
        return None
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None
    if (
        len(encoded) > MAX_TOOL_NAME_BYTES
        or _FROZEN_UNICODE_DATABASE.normalize("NFC", name) != name
        or any(_FROZEN_UNICODE_DATABASE.category(character).startswith("C") for character in name)
    ):
        return None
    return name


def _sensitive_label(value: str) -> bool:
    lowered = value.lower().replace("-", "_").replace(" ", "_")
    return any(label in lowered for label in _SENSITIVE_LABELS)


def _contains_sensitive_value(value: object, sensitive_path: bool = False) -> bool:
    if type(value) is list:
        return any(_contains_sensitive_value(item, sensitive_path) for item in value)
    if type(value) is not dict:
        return False
    for key, child in value.items():
        lowered = key.lower()
        if lowered in _VALUE_KEYS:
            return True
        child_sensitive = sensitive_path or _sensitive_label(key)
        if lowered in {"const", "enum"} and sensitive_path:
            return True
        if _contains_sensitive_value(child, child_sensitive):
            return True
    return False


def _strongest_protection(items: tuple[dict[str, object], ...]):
    strongest = None
    for item in items:
        try:
            decision = decide_protection(
                item["raw"], item["classification"], item["signals"]
            )
        except ProtectionError:
            _reject()
        if strongest is None or _PROTECTION_PRIORITY[decision.reason] > _PROTECTION_PRIORITY[strongest.reason]:
            strongest = decision
    return strongest


def _raw_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _catalog_identity(catalog_format: str, payload: bytes) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/tool-schema-catalog/v1",
        catalog_format.encode("ascii"),
        payload,
    )


def _catalog_subject(catalog_identity: str, payload: bytes) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/tool-schema-set-subject/v1",
        catalog_identity.encode("ascii"),
        payload,
    )


def _name_digest(name: str) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/tool-schema-name/v1", name.encode("utf-8")
    )


def _item_subject(
    *,
    catalog_identity: str,
    index: int,
    start: int,
    end: int,
    name_sha256: str,
    payload: bytes,
) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/tool-schema-item-subject/v1",
        catalog_identity.encode("ascii"),
        index.to_bytes(4, "big"),
        start.to_bytes(8, "big"),
        end.to_bytes(8, "big"),
        name_sha256.encode("ascii"),
        payload,
    )


def _pack_envelope(metadata: dict[str, object], payload: bytes) -> bytes:
    metadata_bytes = canonical_json_bytes(metadata, limits=ENVELOPE_LIMITS)
    return TOOL_SCHEMA_MAGIC + len(metadata_bytes).to_bytes(4, "big") + metadata_bytes + payload


def _payload_metadata(payload: bytes) -> dict[str, object]:
    return {"byte_length": len(payload), "content_sha256": _raw_sha256(payload)}


def _catalog_envelope(
    *, catalog_format: str, catalog_identity: str, subject: str, payload: bytes
) -> bytes:
    metadata = {
        "artifact_kind": "tool_schema_expansion_envelope",
        "artifact_type": ArtifactType.TOOL_SCHEMA_SET_BYTES.value,
        "binding_kind": CATALOG_SNAPSHOT_BINDING,
        "catalog_format": catalog_format,
        "catalog_identity_sha256": catalog_identity,
        "evidence_boundary": evidence_boundary(),
        "payload": _payload_metadata(payload),
        "schema_version": TOOL_SCHEMA_ENVELOPE_VERSION,
        "subject_identity_sha256": subject,
    }
    return _pack_envelope(metadata, payload)


def _item_envelope(
    *, catalog_format: str, catalog_identity: str, item: dict[str, object]
) -> bytes:
    payload = item["raw"]
    metadata = {
        "artifact_kind": "tool_schema_expansion_envelope",
        "artifact_type": ArtifactType.TOOL_SCHEMA_BYTES.value,
        "binding_kind": CATALOG_SNAPSHOT_BINDING,
        "catalog_format": catalog_format,
        "catalog_identity_sha256": catalog_identity,
        "evidence_boundary": evidence_boundary(),
        "input_index": item["index"],
        "normalized_name_sha256": item["name_sha256"],
        "payload": _payload_metadata(payload),
        "raw_range": {"end_byte": item["end"], "start_byte": item["start"]},
        "schema_version": TOOL_SCHEMA_ENVELOPE_VERSION,
        "subject_identity_sha256": item["subject_identity_sha256"],
    }
    return _pack_envelope(metadata, payload)  # type: ignore[arg-type]


def _catalog_reference(
    *,
    catalog_format: str,
    catalog_identity: str,
    subject: str,
    payload: bytes,
    capability: str,
    namespace_id: str,
) -> dict[str, object]:
    return {
        "artifact_kind": "tool_schema_catalog_reference",
        "byte_length": len(payload),
        "capability": capability,
        "catalog_format": catalog_format,
        "catalog_identity_sha256": catalog_identity,
        "content_sha256": _raw_sha256(payload),
        "namespace_id": namespace_id,
        "schema_version": TOOL_SCHEMA_CATALOG_REFERENCE_VERSION,
        "subject_identity_sha256": subject,
    }


def _item_reference(
    *, item: dict[str, object], catalog_identity: str, capability: str, namespace_id: str
) -> dict[str, object]:
    payload = item["raw"]
    return {
        "artifact_kind": "tool_schema_reference",
        "byte_length": len(payload),
        "capability": capability,
        "catalog_identity_sha256": catalog_identity,
        "content_sha256": _raw_sha256(payload),
        "input_index": item["index"],
        "name": item["name"],
        "namespace_id": namespace_id,
        "raw_range": {"end_byte": item["end"], "start_byte": item["start"]},
        "schema_version": TOOL_SCHEMA_REFERENCE_VERSION,
        "subject_identity_sha256": item["subject_identity_sha256"],
    }


def _encoded(value: object) -> bytes:
    return canonical_json_bytes(value)[:-1]


def _bundle_bytes(
    *,
    catalog_format: str,
    catalog_reference: dict[str, object],
    deferred: tuple[dict[str, object], ...],
    inline: tuple[dict[str, object], ...],
) -> bytes:
    inline_raw = b",".join(item["raw"] for item in inline)  # type: ignore[arg-type]
    return b"".join(
        (
            b'{"artifact_kind":"tool_schema_bundle","catalog_format":',
            _encoded(catalog_format),
            b',"catalog_reference":',
            _encoded(catalog_reference),
            b',"deferred":',
            _encoded(list(deferred)),
            b',"evidence_boundary":',
            _encoded(evidence_boundary()),
            b',"inline":[',
            inline_raw,
            b'],"schema_version":"',
            TOOL_SCHEMA_BUNDLE_VERSION.encode("ascii"),
            b'"}\n',
        )
    )


def _valid_digest(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in _HEX_ALPHABET for character in value)
    )


def _valid_issued(issued: object, expected: int) -> tuple[tuple[str, ...], str] | None:
    if type(issued) is not tuple or len(issued) != expected:
        return None
    handles: list[str] = []
    namespaces: set[str] = set()
    for value in issued:
        try:
            handle = value.handle
            namespace_id = value.namespace_id
        except Exception:
            return None
        if (
            type(handle) is not str
            or len(handle) != len(_HANDLE_PLACEHOLDER)
            or not handle.startswith("cgr1p_")
            or any(character not in _CAPABILITY_ALPHABET for character in handle[6:])
            or not _valid_digest(namespace_id)
        ):
            return None
        handles.append(handle)
        namespaces.add(namespace_id)
    if len(set(handles)) != len(handles) or len(namespaces) != 1:
        return None
    return tuple(handles), namespaces.pop()


def _backend(value: object) -> IssuanceBackend | None:
    try:
        method = getattr(value, "issue_batch")
    except Exception:
        return None
    return cast(IssuanceBackend, value) if callable(method) else None


def _receipt(
    *,
    disposition: ToolSchemaDisposition,
    reason: str,
    input_payload: bytes,
    output_payload: bytes,
    output_form: str,
    costs: RouteCosts,
    catalog_envelope_bytes: int = 0,
    deferred_raw_bytes: int = 0,
    deferred_envelope_bytes: int = 0,
    single_expansion_upper_bound_bytes: int = 0,
    all_expansion_upper_bound_bytes: int = 0,
) -> dict[str, object]:
    return {
        "artifact_kind": "tool_schema_receipt",
        "disposition": disposition.value,
        "evidence_boundary": evidence_boundary(),
        "input": _payload_metadata(input_payload),
        "output": {
            **_payload_metadata(output_payload),
            "form": output_form,
        },
        "reason": reason,
        "route": {
            "handle_bytes": costs.handle_bytes,
            "input_bytes": costs.input_bytes,
            "mandatory_expansion_bytes": costs.mandatory_expansion_bytes,
            "predicted_cost_bytes": (
                costs.wrapper_bytes
                + costs.handle_bytes
                + costs.blueprint_bytes
                + costs.mandatory_expansion_bytes
                + costs.retained_wire_bytes
            ),
            "retained_wire_bytes": costs.retained_wire_bytes,
            "wrapper_bytes": costs.wrapper_bytes,
        },
        "schema_version": TOOL_SCHEMA_RECEIPT_VERSION,
        "shifted_bytes": {
            "all_expansion_upper_bound_bytes": all_expansion_upper_bound_bytes,
            "catalog_stored_envelope_bytes": catalog_envelope_bytes,
            "deferred_raw_bytes": deferred_raw_bytes,
            "deferred_stored_envelope_bytes": deferred_envelope_bytes,
            "single_expansion_upper_bound_bytes": single_expansion_upper_bound_bytes,
        },
    }


def _terminal(
    disposition: ToolSchemaDisposition, payload: bytes, reason: str
) -> ToolSchemaResult:
    output = b"" if disposition is ToolSchemaDisposition.REFUSED else payload
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=len(payload),
        handle_bytes=0,
        blueprint_bytes=0,
        mandatory_expansion_bytes=0,
        retained_wire_bytes=0,
    )
    return ToolSchemaResult(
        disposition=disposition,
        output_bytes=output,
        receipt=_receipt(
            disposition=disposition,
            reason=reason,
            input_payload=payload,
            output_payload=output,
            output_form="none" if not output else "exact_catalog",
            costs=costs,
        ),
    )


def assemble_tool_schemas(
    descriptor_raw: bytes, *, store: object = None
) -> ToolSchemaResult:
    """Select exact inline schemas and atomically seal the catalog snapshot."""

    catalog_format, payload, metadata, retain_count = _parse_descriptor(descriptor_raw)
    catalog, spans = _parse_catalog(payload)
    if len(catalog) != len(metadata):
        _reject()

    parsed: list[dict[str, object]] = []
    for schema, policy, (start, end) in zip(catalog, metadata, spans, strict=True):
        parsed.append(
            {
                **policy,
                "end": end,
                "raw": payload[start:end],
                "schema": schema,
                "start": start,
            }
        )

    strongest = _strongest_protection(tuple(parsed))
    if strongest is not None and strongest.action is ProtectionAction.REFUSE:
        return _terminal(ToolSchemaDisposition.REFUSED, payload, strongest.reason.value)
    if strongest is not None and strongest.action is ProtectionAction.PASS_THROUGH:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, strongest.reason.value)

    seen_names: set[str] = set()
    for item in parsed:
        name = _native_name(catalog_format, item["schema"])  # type: ignore[arg-type]
        if name is None or _contains_sensitive_value(item["schema"]):
            return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "catalog_unsupported")
        if name in seen_names:
            return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "duplicate_name")
        seen_names.add(name)
        item["name"] = name
        item["name_sha256"] = _name_digest(name)

    ordered = tuple(
        sorted(
            parsed,
            key=lambda item: (
                not item["required"],
                -item["priority"],  # type: ignore[operator]
                item["name"],
                item["index"],
            ),
        )
    )
    required_count = sum(item["required"] is True for item in ordered)
    inline_count = max(required_count, retain_count)
    inline = ordered[:inline_count]
    deferred_items = ordered[inline_count:]
    if not deferred_items:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "no_deferred_schemas")

    catalog_identity = _catalog_identity(catalog_format, payload)
    catalog_subject = _catalog_subject(catalog_identity, payload)
    for item in parsed:
        item["subject_identity_sha256"] = _item_subject(
            catalog_identity=catalog_identity,
            index=item["index"],  # type: ignore[arg-type]
            start=item["start"],  # type: ignore[arg-type]
            end=item["end"],  # type: ignore[arg-type]
            name_sha256=item["name_sha256"],  # type: ignore[arg-type]
            payload=item["raw"],  # type: ignore[arg-type]
        )

    catalog_envelope = _catalog_envelope(
        catalog_format=catalog_format,
        catalog_identity=catalog_identity,
        subject=catalog_subject,
        payload=payload,
    )
    deferred_envelopes = tuple(
        _item_envelope(
            catalog_format=catalog_format,
            catalog_identity=catalog_identity,
            item=item,
        )
        for item in deferred_items
    )
    placeholder_catalog = _catalog_reference(
        catalog_format=catalog_format,
        catalog_identity=catalog_identity,
        subject=catalog_subject,
        payload=payload,
        capability=_HANDLE_PLACEHOLDER,
        namespace_id="a" * 64,
    )
    placeholder_deferred = tuple(
        _item_reference(
            item=item,
            catalog_identity=catalog_identity,
            capability=_HANDLE_PLACEHOLDER,
            namespace_id="a" * 64,
        )
        for item in deferred_items
    )
    placeholder_output = _bundle_bytes(
        catalog_format=catalog_format,
        catalog_reference=placeholder_catalog,
        deferred=placeholder_deferred,
        inline=inline,
    )
    retained_bytes = sum(len(item["raw"]) for item in inline)  # type: ignore[arg-type]
    handle_bytes = predicted_capability_bytes(len(deferred_items) + 1)
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=len(placeholder_output) - retained_bytes - handle_bytes,
        handle_bytes=handle_bytes,
        blueprint_bytes=0,
        mandatory_expansion_bytes=0,
        retained_wire_bytes=retained_bytes,
    )
    decision = decide_route(costs)
    if decision.disposition is not RouteDisposition.DEFER:
        return ToolSchemaResult(
            disposition=ToolSchemaDisposition.PASS_THROUGH,
            output_bytes=payload,
            receipt=_receipt(
                disposition=ToolSchemaDisposition.PASS_THROUGH,
                reason=decision.reason.value,
                input_payload=payload,
                output_payload=payload,
                output_form="exact_catalog",
                costs=costs,
            ),
        )

    backend = _backend(store)
    if backend is None:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "store_unavailable")
    requests = (
        ArtifactRequest(
            payload=catalog_envelope,
            root_identity_sha256=catalog_identity,
            subject_identity_sha256=catalog_subject,
            artifact_type=ArtifactType.TOOL_SCHEMA_SET_BYTES,
        ),
        *(
            ArtifactRequest(
                payload=envelope,
                root_identity_sha256=catalog_identity,
                subject_identity_sha256=item["subject_identity_sha256"],  # type: ignore[arg-type]
                artifact_type=ArtifactType.TOOL_SCHEMA_BYTES,
            )
            for item, envelope in zip(deferred_items, deferred_envelopes, strict=True)
        ),
    )
    try:
        issued = backend.issue_batch(requests)
    except Exception:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "store_unavailable")
    validated = _valid_issued(issued, len(requests))
    if validated is None:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "store_unavailable")
    handles, namespace_id = validated
    catalog_reference = _catalog_reference(
        catalog_format=catalog_format,
        catalog_identity=catalog_identity,
        subject=catalog_subject,
        payload=payload,
        capability=handles[0],
        namespace_id=namespace_id,
    )
    deferred_references = tuple(
        _item_reference(
            item=item,
            catalog_identity=catalog_identity,
            capability=handle,
            namespace_id=namespace_id,
        )
        for item, handle in zip(deferred_items, handles[1:], strict=True)
    )
    output = _bundle_bytes(
        catalog_format=catalog_format,
        catalog_reference=catalog_reference,
        deferred=deferred_references,
        inline=inline,
    )
    if len(output) != decision.predicted_cost_bytes:
        return _terminal(ToolSchemaDisposition.PASS_THROUGH, payload, "store_unavailable")
    deferred_raw_bytes = sum(len(item["raw"]) for item in deferred_items)  # type: ignore[arg-type]
    return ToolSchemaResult(
        disposition=ToolSchemaDisposition.DEFERRED,
        output_bytes=output,
        receipt=_receipt(
            disposition=ToolSchemaDisposition.DEFERRED,
            reason=decision.reason.value,
            input_payload=payload,
            output_payload=output,
            output_form="tool_schema_bundle",
            costs=costs,
            catalog_envelope_bytes=len(catalog_envelope),
            deferred_raw_bytes=deferred_raw_bytes,
            deferred_envelope_bytes=sum(map(len, deferred_envelopes)),
            single_expansion_upper_bound_bytes=max(
                len(payload),
                *(len(item["raw"]) for item in deferred_items),  # type: ignore[arg-type]
            ),
            all_expansion_upper_bound_bytes=len(payload) + deferred_raw_bytes,
        ),
    )


def _expansion_refusal(reason: str) -> ToolSchemaExpansionResult:
    return ToolSchemaExpansionResult(
        disposition=ToolSchemaExpansionDisposition.REFUSED,
        output_bytes=b"",
        refusal={
            "artifact_kind": "tool_schema_expansion_refusal",
            "evidence_boundary": evidence_boundary(),
            "reason": reason,
            "schema_version": TOOL_SCHEMA_EXPANSION_REFUSAL_VERSION,
            "status": "refused",
        },
    )


def _exact_expansion(payload: bytes) -> ToolSchemaExpansionResult:
    return ToolSchemaExpansionResult(
        disposition=ToolSchemaExpansionDisposition.EXACT,
        output_bytes=payload,
        refusal=None,
    )


def _valid_capability(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == len(_HANDLE_PLACEHOLDER)
        and value.startswith("cgr1p_")
        and all(character in _CAPABILITY_ALPHABET for character in value[6:])
    )


def _bounded_nonnegative(value: object, maximum: int) -> bool:
    return bool(type(value) is int and 0 <= value <= maximum)


def _catalog_reference_fields(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != frozenset(
        {
            "artifact_kind",
            "byte_length",
            "capability",
            "catalog_format",
            "catalog_identity_sha256",
            "content_sha256",
            "namespace_id",
            "schema_version",
            "subject_identity_sha256",
        }
    ):
        raise _ExpansionValidationError
    if (
        value["artifact_kind"] != "tool_schema_catalog_reference"
        or value["schema_version"] != TOOL_SCHEMA_CATALOG_REFERENCE_VERSION
        or type(value["catalog_format"]) is not str
        or value["catalog_format"] not in CATALOG_FORMATS
        or not _bounded_nonnegative(value["byte_length"], MAX_CATALOG_BYTES)
        or not _valid_capability(value["capability"])
        or not _valid_digest(value["catalog_identity_sha256"])
        or not _valid_digest(value["content_sha256"])
        or not _valid_digest(value["namespace_id"])
        or not _valid_digest(value["subject_identity_sha256"])
    ):
        raise _ExpansionValidationError
    return value


def _item_reference_fields(value: object) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != frozenset(
        {
            "artifact_kind",
            "byte_length",
            "capability",
            "catalog_identity_sha256",
            "content_sha256",
            "input_index",
            "name",
            "namespace_id",
            "raw_range",
            "schema_version",
            "subject_identity_sha256",
        }
    ):
        raise _ExpansionValidationError
    raw_range = value["raw_range"]
    if type(raw_range) is not dict or frozenset(raw_range) != frozenset(
        {"end_byte", "start_byte"}
    ):
        raise _ExpansionValidationError
    name = value["name"]
    if type(name) is not str or _native_name(
        "anthropic_tools/v1", {"input_schema": {}, "name": name}
    ) is None:
        raise _ExpansionValidationError
    start = raw_range["start_byte"]
    end = raw_range["end_byte"]
    if (
        value["artifact_kind"] != "tool_schema_reference"
        or value["schema_version"] != TOOL_SCHEMA_REFERENCE_VERSION
        or not _bounded_nonnegative(value["byte_length"], MAX_CATALOG_BYTES)
        or not _bounded_nonnegative(value["input_index"], MAX_TOOL_SCHEMAS - 1)
        or not _valid_capability(value["capability"])
        or not _valid_digest(value["catalog_identity_sha256"])
        or not _valid_digest(value["content_sha256"])
        or not _valid_digest(value["namespace_id"])
        or not _valid_digest(value["subject_identity_sha256"])
        or type(start) is not int
        or type(end) is not int
        or start < 1
        or end <= start
        or end > MAX_CATALOG_BYTES
        or value["byte_length"] != end - start
    ):
        raise _ExpansionValidationError
    return value


def _retrieval_backend(value: object) -> RetrievalBackend | None:
    try:
        method = getattr(value, "retrieve")
    except Exception:
        return None
    return cast(RetrievalBackend, value) if callable(method) else None


def _retrieve_bound(
    backend: RetrievalBackend,
    reference: dict[str, object],
    artifact_type: ArtifactType,
) -> object:
    try:
        return backend.retrieve(
            reference["capability"],  # type: ignore[arg-type]
            expected_namespace_id=reference["namespace_id"],  # type: ignore[arg-type]
            expected_root_identity_sha256=reference["catalog_identity_sha256"],  # type: ignore[arg-type]
            expected_subject_identity_sha256=reference["subject_identity_sha256"],  # type: ignore[arg-type]
            expected_artifact_type=artifact_type,
        )
    except StoreError as error:
        if error.code is StoreErrorCode.CAPABILITY_REJECTED:
            raise _ExpansionValidationError from None
        raise _BackendUnavailable from None
    except Exception:
        raise _BackendUnavailable from None


def _closed_metadata(value: object, artifact_type: ArtifactType) -> dict[str, object]:
    common = {
        "artifact_kind",
        "artifact_type",
        "binding_kind",
        "catalog_format",
        "catalog_identity_sha256",
        "evidence_boundary",
        "payload",
        "schema_version",
        "subject_identity_sha256",
    }
    expected = (
        common
        if artifact_type is ArtifactType.TOOL_SCHEMA_SET_BYTES
        else common | {"input_index", "normalized_name_sha256", "raw_range"}
    )
    if type(value) is not dict or set(value) != expected:
        raise _ExpansionValidationError
    if (
        value["artifact_kind"] != "tool_schema_expansion_envelope"
        or value["artifact_type"] != artifact_type.value
        or value["binding_kind"] != CATALOG_SNAPSHOT_BINDING
        or value["schema_version"] != TOOL_SCHEMA_ENVELOPE_VERSION
        or value["evidence_boundary"] != evidence_boundary()
        or type(value["catalog_format"]) is not str
        or value["catalog_format"] not in CATALOG_FORMATS
        or not _valid_digest(value["catalog_identity_sha256"])
        or not _valid_digest(value["subject_identity_sha256"])
    ):
        raise _ExpansionValidationError
    payload_metadata = value["payload"]
    if type(payload_metadata) is not dict or frozenset(payload_metadata) != frozenset(
        {"byte_length", "content_sha256"}
    ):
        raise _ExpansionValidationError
    if (
        not _bounded_nonnegative(payload_metadata["byte_length"], MAX_CATALOG_BYTES)
        or not _valid_digest(payload_metadata["content_sha256"])
    ):
        raise _ExpansionValidationError
    if artifact_type is ArtifactType.TOOL_SCHEMA_BYTES:
        raw_range = value["raw_range"]
        if type(raw_range) is not dict or frozenset(raw_range) != frozenset(
            {"end_byte", "start_byte"}
        ):
            raise _ExpansionValidationError
        if (
            not _bounded_nonnegative(value["input_index"], MAX_TOOL_SCHEMAS - 1)
            or not _valid_digest(value["normalized_name_sha256"])
            or type(raw_range["start_byte"]) is not int
            or type(raw_range["end_byte"]) is not int
            or raw_range["start_byte"] < 1
            or raw_range["end_byte"] <= raw_range["start_byte"]
            or raw_range["end_byte"] > MAX_CATALOG_BYTES
        ):
            raise _ExpansionValidationError
    return value


def _unpack_envelope(
    raw: object, artifact_type: ArtifactType
) -> tuple[dict[str, object], bytes]:
    if type(raw) is not bytes or len(raw) < len(TOOL_SCHEMA_MAGIC) + 5:
        raise _ExpansionValidationError
    if not raw.startswith(TOOL_SCHEMA_MAGIC):
        raise _ExpansionValidationError
    offset = len(TOOL_SCHEMA_MAGIC)
    metadata_length = int.from_bytes(raw[offset : offset + 4], "big")
    metadata_start = offset + 4
    metadata_end = metadata_start + metadata_length
    if metadata_length <= 0 or metadata_end > len(raw):
        raise _ExpansionValidationError
    try:
        metadata_raw = raw[metadata_start:metadata_end]
        metadata = parse_canonical_json_bytes(metadata_raw, limits=ENVELOPE_LIMITS)
    except CanonicalJSONError:
        raise _ExpansionValidationError from None
    metadata = _closed_metadata(metadata, artifact_type)
    payload = raw[metadata_end:]
    payload_metadata = metadata["payload"]
    if (
        payload_metadata["byte_length"] != len(payload)  # type: ignore[index]
        or payload_metadata["content_sha256"] != _raw_sha256(payload)  # type: ignore[index]
    ):
        raise _ExpansionValidationError
    return metadata, payload


def _stored_envelope(
    stored: object,
    reference: dict[str, object],
    artifact_type: ArtifactType,
) -> tuple[dict[str, object], bytes]:
    try:
        raw = stored.payload
        byte_length = stored.byte_length
        namespace_id = stored.namespace_id
        root_identity = stored.root_identity_sha256
        subject_identity = stored.subject_identity_sha256
        stored_type = stored.artifact_type
    except Exception:
        raise _ExpansionValidationError from None
    if (
        type(raw) is not bytes
        or type(byte_length) is not int
        or byte_length != len(raw)
        or namespace_id != reference["namespace_id"]
        or root_identity != reference["catalog_identity_sha256"]
        or subject_identity != reference["subject_identity_sha256"]
        or stored_type is not artifact_type
    ):
        raise _ExpansionValidationError
    metadata, payload = _unpack_envelope(raw, artifact_type)
    if (
        metadata["catalog_identity_sha256"] != reference["catalog_identity_sha256"]
        or metadata["subject_identity_sha256"] != reference["subject_identity_sha256"]
        or len(payload) != reference["byte_length"]
        or _raw_sha256(payload) != reference["content_sha256"]
    ):
        raise _ExpansionValidationError
    return metadata, payload


def _validated_catalog_snapshot(
    reference: dict[str, object], stored: object
) -> tuple[dict[str, object], bytes, tuple[dict[str, object], ...], tuple[tuple[int, int], ...]]:
    metadata, payload = _stored_envelope(
        stored, reference, ArtifactType.TOOL_SCHEMA_SET_BYTES
    )
    catalog_format = reference["catalog_format"]
    catalog_identity = reference["catalog_identity_sha256"]
    if (
        metadata["catalog_format"] != catalog_format
        or _catalog_identity(catalog_format, payload) != catalog_identity  # type: ignore[arg-type]
        or _catalog_subject(catalog_identity, payload)  # type: ignore[arg-type]
        != reference["subject_identity_sha256"]
    ):
        raise _ExpansionValidationError
    try:
        catalog, spans = _parse_catalog(payload)
    except ToolSchemaError:
        raise _ExpansionValidationError from None
    return metadata, payload, catalog, spans


def expand_tool_schema_catalog(
    catalog_reference: object, *, store: object
) -> ToolSchemaExpansionResult:
    """Expand an immutable catalog snapshot from its complete closed reference."""

    try:
        reference = _catalog_reference_fields(catalog_reference)
    except Exception:
        return _expansion_refusal("reference_rejected")
    backend = _retrieval_backend(store)
    if backend is None:
        return _expansion_refusal("store_unavailable")
    try:
        stored = _retrieve_bound(backend, reference, ArtifactType.TOOL_SCHEMA_SET_BYTES)
        _metadata, payload, _catalog, _spans = _validated_catalog_snapshot(
            reference, stored
        )
    except _BackendUnavailable:
        return _expansion_refusal("store_unavailable")
    except Exception:
        return _expansion_refusal("artifact_invalid")
    return _exact_expansion(payload)


def expand_tool_schema_item(
    catalog_reference: object, item_reference: object, *, store: object
) -> ToolSchemaExpansionResult:
    """Expand one item only when its reference is bound to the catalog snapshot."""

    try:
        catalog_ref = _catalog_reference_fields(catalog_reference)
        item_ref = _item_reference_fields(item_reference)
        if (
            item_ref["catalog_identity_sha256"]
            != catalog_ref["catalog_identity_sha256"]
            or item_ref["namespace_id"] != catalog_ref["namespace_id"]
        ):
            raise _ExpansionValidationError
    except Exception:
        return _expansion_refusal("reference_rejected")
    backend = _retrieval_backend(store)
    if backend is None:
        return _expansion_refusal("store_unavailable")
    try:
        catalog_stored = _retrieve_bound(
            backend, catalog_ref, ArtifactType.TOOL_SCHEMA_SET_BYTES
        )
        _catalog_metadata, _payload, catalog, spans = _validated_catalog_snapshot(
            catalog_ref, catalog_stored
        )
        item_stored = _retrieve_bound(backend, item_ref, ArtifactType.TOOL_SCHEMA_BYTES)
        item_metadata, item_payload = _stored_envelope(
            item_stored, item_ref, ArtifactType.TOOL_SCHEMA_BYTES
        )

        input_index = item_ref["input_index"]
        if input_index >= len(catalog):  # type: ignore[operator]
            raise _ExpansionValidationError
        start, end = spans[input_index]  # type: ignore[index]
        raw_range = item_ref["raw_range"]
        if (
            raw_range != {"end_byte": end, "start_byte": start}
            or item_metadata["raw_range"] != raw_range
            or item_metadata["input_index"] != input_index
            or item_metadata["catalog_format"] != catalog_ref["catalog_format"]
            or item_payload != _payload[start:end]
        ):
            raise _ExpansionValidationError
        name = _native_name(
            catalog_ref["catalog_format"], catalog[input_index]  # type: ignore[arg-type,index]
        )
        if name is None or name != item_ref["name"]:
            raise _ExpansionValidationError
        name_sha256 = _name_digest(name)
        subject = _item_subject(
            catalog_identity=catalog_ref["catalog_identity_sha256"],  # type: ignore[arg-type]
            index=input_index,  # type: ignore[arg-type]
            start=start,
            end=end,
            name_sha256=name_sha256,
            payload=item_payload,
        )
        if (
            item_metadata["normalized_name_sha256"] != name_sha256
            or item_ref["subject_identity_sha256"] != subject
            or item_metadata["subject_identity_sha256"] != subject
        ):
            raise _ExpansionValidationError
    except _BackendUnavailable:
        return _expansion_refusal("store_unavailable")
    except Exception:
        return _expansion_refusal("artifact_invalid")
    return _exact_expansion(item_payload)
