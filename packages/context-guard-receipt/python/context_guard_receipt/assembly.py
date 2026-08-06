"""Pass-through-first G005 evidence and typed-blueprint assembly."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Protocol, cast

from .blueprint import build_blueprint_body
from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)
from .identity import IdentityError, identify_source
from .evidence_pack import (
    deferred_segment,
    encode_evidence_pack,
    retained_segment,
    retained_wire_bytes,
)
from .protection import (
    ProtectionAction,
    ProtectionDecision,
    ProtectionError,
    ProtectionReason,
    decide_protection,
)
from .receipts import (
    ReceiptError,
    assembly_receipt,
    evidence_reference,
    expansion_metadata,
    pack_expansion_envelope,
    raw_sha256,
    typed_blueprint,
    validate_source_recipe,
)
from .router import RouteCosts, RouteDecision, RouteDisposition, decide_route
from .store import (
    ArtifactRequest,
    ArtifactType,
    predicted_capability_bytes,
)


MAX_ASSEMBLY_PAYLOAD_BYTES: Final = 900_000
MAX_BLUEPRINT_ITEMS: Final = 64
MAX_EVIDENCE_RANGES: Final = 64
DESCRIPTOR_LIMITS: Final = JSONLimits(
    max_document_bytes=2 * 1024 * 1024,
    max_depth=24,
    max_total_values=8192,
    max_object_members=64,
    max_string_bytes=1_300_000,
)
_HANDLE_PLACEHOLDER: Final = "cgr1p_" + ("A" * 43)
_CAPABILITY_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_HEX_ALPHABET: Final = frozenset("0123456789abcdef")
_PHASES: Final = frozenset(
    {"required_before_edit", "required_before_claim", "optional_evidence"}
)
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


class AssemblyError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AssemblyDisposition(str, Enum):
    DEFERRED = "deferred"
    PASS_THROUGH = "pass_through"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class AssemblyResult:
    disposition: AssemblyDisposition
    output_bytes: bytes = field(repr=False)
    receipt: dict[str, object]


class IssuanceBackend(Protocol):
    """Minimum capability needed from a durable assembly backend."""

    def issue_batch(
        self, requests: tuple[ArtifactRequest, ...]
    ) -> tuple[object, ...]: ...


def _reject(code: str) -> None:
    raise AssemblyError(code) from None


def _strict_keys(value: object, expected: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected:
        _reject("invalid_descriptor")
    return value  # type: ignore[return-value]


def _issuance_backend(value: object) -> IssuanceBackend | None:
    try:
        method = getattr(value, "issue_batch")
    except Exception:
        return None
    if not callable(method):
        return None
    return cast(IssuanceBackend, value)


def _valid_sha256(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in _HEX_ALPHABET for character in value)
    )


def _issued_handles(issued: object, expected_count: int) -> tuple[str, ...] | None:
    if type(issued) is not tuple or len(issued) != expected_count:
        return None
    handles: list[str] = []
    namespace_ids: set[str] = set()
    for item in issued:
        try:
            handle = item.handle
            namespace_id = item.namespace_id
        except Exception:
            return None
        if (
            type(handle) is not str
            or len(handle) != len(_HANDLE_PLACEHOLDER)
            or not handle.startswith("cgr1p_")
            or any(character not in _CAPABILITY_ALPHABET for character in handle[6:])
            or not _valid_sha256(namespace_id)
        ):
            return None
        handles.append(handle)
        namespace_ids.add(namespace_id)
    if len(set(handles)) != len(handles) or len(namespace_ids) != 1:
        return None
    return tuple(handles)


def _decode_payload(value: object) -> bytes:
    if type(value) is not str or len(value) > 1_300_000 or "=" in value:
        _reject("invalid_payload")
    try:
        encoded = value.encode("ascii", errors="strict")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)
        payload = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        _reject("invalid_payload")
    if (
        len(payload) > MAX_ASSEMBLY_PAYLOAD_BYTES
        or base64.urlsafe_b64encode(payload).rstrip(b"=") != encoded
    ):
        _reject("invalid_payload")
    return payload


def _signals(value: object) -> tuple[str, ...]:
    if type(value) is not list or len(value) > 64:
        _reject("invalid_descriptor")
    if any(type(item) is not str for item in value) or len(set(value)) != len(value):
        _reject("invalid_descriptor")
    return tuple(value)  # type: ignore[arg-type]


def _source_recipe(value: object) -> dict[str, object]:
    try:
        return validate_source_recipe(value)
    except ReceiptError:
        _reject("invalid_descriptor")


def _evidence_pack_ranges(
    value: object, payload: bytes
) -> tuple[dict[str, object], ...]:
    if type(value) is not list or not value or len(value) > MAX_EVIDENCE_RANGES:
        _reject("invalid_descriptor")
    parsed: list[dict[str, object]] = []
    expected_start = 0
    for raw_range in value:
        item = _strict_keys(
            raw_range,
            frozenset(
                {
                    "caller_classification",
                    "detector_signals",
                    "end_byte",
                    "mode",
                    "source",
                    "start_byte",
                }
            ),
        )
        start = item["start_byte"]
        end = item["end_byte"]
        mode = item["mode"]
        if (
            type(start) is not int
            or type(end) is not int
            or start != expected_start
            or end <= start
            or end > len(payload)
            or type(mode) is not str
            or mode not in {"retained", "deferred"}
            or type(item["caller_classification"]) is not str
        ):
            _reject("invalid_descriptor")
        parsed.append(
            {
                "classification": item["caller_classification"],
                "end": end,
                "mode": mode,
                "payload": payload[start:end],
                "recipe": _source_recipe(item["source"]),
                "signals": _signals(item["detector_signals"]),
                "start": start,
            }
        )
        expected_start = end
    if expected_start != len(payload):
        _reject("invalid_descriptor")
    return tuple(parsed)


def _parse_document(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes:
        _reject("invalid_descriptor")
    try:
        value = parse_canonical_json_bytes(raw, limits=DESCRIPTOR_LIMITS)
    except CanonicalJSONError:
        _reject("invalid_descriptor")
    if type(value) is not dict:
        _reject("invalid_descriptor")
    return value


def _identify(
    root: object,
    recipe: dict[str, object],
    *,
    git_executable: object,
) -> dict[str, object] | None:
    selection = recipe["selection"]
    kind = selection["kind"]  # type: ignore[index]
    byte_range = None
    symbol_evidence = None
    if kind == "range":
        byte_range = (selection["start_byte"], selection["end_byte"])  # type: ignore[index]
    elif kind == "symbol":
        symbol_evidence = selection["evidence"]  # type: ignore[index]
        byte_range = (
            symbol_evidence["start_byte"],  # type: ignore[index]
            symbol_evidence["end_byte"],  # type: ignore[index]
        )
    try:
        identified = identify_source(
            root,
            recipe["relative_path"],
            byte_range=byte_range,
            symbol_evidence=symbol_evidence,
            git_executable=git_executable,
        )
    except IdentityError:
        return None
    if identified.get("disposition") not in {"exact_file", "exact_symbol"}:
        return None
    return identified


def _matches_payload(identified: dict[str, object], payload: bytes) -> bool:
    selection = identified.get("selection")
    return bool(
        type(selection) is dict
        and selection.get("byte_length") == len(payload)
        and selection.get("content_sha256") == raw_sha256(payload)
    )


def _subject_identity(identified: dict[str, object]) -> str | None:
    if identified.get("disposition") == "exact_symbol":
        symbol = identified.get("symbol")
        value = symbol.get("identity_sha256") if type(symbol) is dict else None
    else:
        selection = identified.get("selection")
        value = selection.get("identity_sha256") if type(selection) is dict else None
    return value if _valid_sha256(value) else None


def _root_bindings(identified: dict[str, object]) -> tuple[str, str]:
    repository = identified["repository"]
    return (
        repository["instance"]["identity_sha256"],  # type: ignore[index]
        repository["logical_state"]["state_sha256"],  # type: ignore[index]
    )


def _expansion_request(
    *,
    artifact_type: ArtifactType,
    payload: bytes,
    root_identity_sha256: str,
    root_state_sha256: str,
    subject_identity_sha256: str,
    revalidation: dict[str, object],
) -> ArtifactRequest | None:
    metadata = expansion_metadata(
        artifact_type=artifact_type.value,
        root_identity_sha256=root_identity_sha256,
        root_state_sha256=root_state_sha256,
        subject_identity_sha256=subject_identity_sha256,
        payload=payload,
        revalidation=revalidation,
    )
    try:
        envelope = pack_expansion_envelope(metadata, payload)
    except CanonicalJSONError:
        return None
    return ArtifactRequest(
        payload=envelope,
        root_identity_sha256=root_identity_sha256,
        subject_identity_sha256=subject_identity_sha256,
        artifact_type=artifact_type,
    )


def _fallback_decision(payload: bytes) -> tuple[RouteCosts, RouteDecision]:
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=len(payload),
        handle_bytes=0,
        blueprint_bytes=0,
        mandatory_expansion_bytes=0,
        retained_wire_bytes=0,
    )
    return costs, decide_route(costs)


def _result(
    *,
    kind: str,
    disposition: AssemblyDisposition,
    reason: str,
    input_payload: bytes,
    output_payload: bytes,
    output_form: str,
    costs: RouteCosts,
    decision: RouteDecision,
) -> AssemblyResult:
    return AssemblyResult(
        disposition=disposition,
        output_bytes=output_payload,
        receipt=assembly_receipt(
            assembly_kind=kind,
            disposition=disposition.value,
            reason=reason,
            input_payload=input_payload,
            output_payload=output_payload,
            output_form=output_form,
            costs=costs,
            decision=decision,
        ),
    )


def _pass_through(kind: str, payload: bytes, reason: str) -> AssemblyResult:
    costs, decision = _fallback_decision(payload)
    return _result(
        kind=kind,
        disposition=AssemblyDisposition.PASS_THROUGH,
        reason=reason,
        input_payload=payload,
        output_payload=payload,
        output_form="exact_payload",
        costs=costs,
        decision=decision,
    )


def _refused(kind: str, payload: bytes, reason: str) -> AssemblyResult:
    costs, decision = _fallback_decision(payload)
    return _result(
        kind=kind,
        disposition=AssemblyDisposition.REFUSED,
        reason=reason,
        input_payload=payload,
        output_payload=b"",
        output_form="none",
        costs=costs,
        decision=decision,
    )


def _protection_gate(
    kind: str, payload: bytes, classification: object, signals: object
) -> AssemblyResult | None:
    if type(classification) is not str:
        _reject("invalid_descriptor")
    try:
        decision = decide_protection(payload, classification, signals)
    except ProtectionError:
        _reject("invalid_descriptor")
    if decision.action is ProtectionAction.REFUSE:
        return _refused(kind, payload, decision.reason.value)
    if decision.action is ProtectionAction.PASS_THROUGH:
        return _pass_through(kind, payload, decision.reason.value)
    return None


def _strongest_protection(
    items: tuple[dict[str, object], ...] | list[dict[str, object]],
) -> ProtectionDecision:
    strongest: ProtectionDecision | None = None
    for item in items:
        try:
            decision = decide_protection(
                item["payload"], item["classification"], item["signals"]
            )
        except ProtectionError:
            _reject("invalid_descriptor")
        if strongest is None or _PROTECTION_PRIORITY[decision.reason] > (
            _PROTECTION_PRIORITY[strongest.reason]
        ):
            strongest = decision
    if strongest is None:
        _reject("invalid_descriptor")
    return strongest


def assemble_evidence(
    descriptor_raw: bytes,
    *,
    root: object,
    git_executable: object = None,
    store: object = None,
) -> AssemblyResult:
    document = _parse_document(descriptor_raw)
    if (
        document.get("schema_version")
        == "contextguard-receipt-evidence-pack-descriptor/v1"
    ):
        return assemble_evidence_pack(
            descriptor_raw,
            root=root,
            git_executable=git_executable,
            store=store,
        )
    descriptor = _strict_keys(
        document,
        frozenset(
            {
                "caller_classification",
                "detector_signals",
                "payload_b64u",
                "schema_version",
                "source",
            }
        ),
    )
    if descriptor["schema_version"] != "contextguard-receipt-evidence-descriptor/v1":
        _reject("invalid_descriptor")
    payload = _decode_payload(descriptor["payload_b64u"])
    recipe = _source_recipe(descriptor["source"])
    gate = _protection_gate(
        "evidence",
        payload,
        descriptor["caller_classification"],
        _signals(descriptor["detector_signals"]),
    )
    if gate is not None:
        return gate
    identified = _identify(root, recipe, git_executable=git_executable)
    if identified is None or not _matches_payload(identified, payload):
        return _pass_through("evidence", payload, "identity_mismatch")
    backend = _issuance_backend(store)
    if backend is None:
        return _pass_through("evidence", payload, "store_unavailable")

    subject_identity = _subject_identity(identified)
    if subject_identity is None:
        return _pass_through("evidence", payload, "identity_mismatch")
    placeholder = canonical_json_bytes(
        evidence_reference(
            payload=payload,
            subject_identity_sha256=subject_identity,
            capability=_HANDLE_PLACEHOLDER,
        )
    )
    handle_bytes = predicted_capability_bytes(1)
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=len(placeholder) - handle_bytes,
        handle_bytes=handle_bytes,
        blueprint_bytes=0,
        mandatory_expansion_bytes=0,
        retained_wire_bytes=0,
    )
    decision = decide_route(costs)
    if decision.disposition is not RouteDisposition.DEFER:
        return _result(
            kind="evidence",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason=decision.reason.value,
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=decision,
        )

    root_identity, root_state = _root_bindings(identified)
    request = _expansion_request(
        artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
        payload=payload,
        root_identity_sha256=root_identity,
        root_state_sha256=root_state,
        subject_identity_sha256=subject_identity,
        revalidation={"kind": "source", "source": recipe},
    )
    if request is None:
        return _pass_through("evidence", payload, "store_unavailable")
    try:
        issued = backend.issue_batch((request,))
    except Exception:
        return _pass_through("evidence", payload, "store_unavailable")
    handles = _issued_handles(issued, 1)
    if handles is None:
        return _pass_through("evidence", payload, "store_unavailable")
    artifact_bytes = canonical_json_bytes(
        evidence_reference(
            payload=payload,
            subject_identity_sha256=subject_identity,
            capability=handles[0],
        )
    )
    if len(artifact_bytes) != decision.predicted_cost_bytes:
        return _pass_through("evidence", payload, "store_unavailable")
    return _result(
        kind="evidence",
        disposition=AssemblyDisposition.DEFERRED,
        reason=decision.reason.value,
        input_payload=payload,
        output_payload=artifact_bytes,
        output_form="evidence_reference",
        costs=costs,
        decision=decision,
    )


def assemble_evidence_pack(
    descriptor_raw: bytes,
    *,
    root: object,
    git_executable: object = None,
    store: object = None,
) -> AssemblyResult:
    """Assemble an exact progressive pack without partially publishing ranges."""

    descriptor = _strict_keys(
        _parse_document(descriptor_raw),
        frozenset({"payload_b64u", "ranges", "schema_version"}),
    )
    if (
        descriptor["schema_version"]
        != "contextguard-receipt-evidence-pack-descriptor/v1"
    ):
        _reject("invalid_descriptor")
    payload = _decode_payload(descriptor["payload_b64u"])
    ranges = _evidence_pack_ranges(descriptor["ranges"], payload)

    strongest = _strongest_protection(ranges)
    if strongest.action is ProtectionAction.REFUSE:
        return _refused("evidence_pack", payload, strongest.reason.value)
    if strongest.action is ProtectionAction.PASS_THROUGH:
        return _pass_through("evidence_pack", payload, strongest.reason.value)

    placeholder_segments: list[dict[str, object]] = []
    deferred_ranges: list[dict[str, object]] = []
    for item in ranges:
        if item["mode"] == "retained":
            placeholder_segments.append(
                retained_segment(
                    start_byte=item["start"],  # type: ignore[arg-type]
                    end_byte=item["end"],  # type: ignore[arg-type]
                    payload=item["payload"],  # type: ignore[arg-type]
                )
            )
        else:
            deferred_ranges.append(item)
            placeholder_segments.append(
                deferred_segment(
                    start_byte=item["start"],  # type: ignore[arg-type]
                    end_byte=item["end"],  # type: ignore[arg-type]
                    payload=item["payload"],  # type: ignore[arg-type]
                    subject_identity_sha256="0" * 64,
                    capability=_HANDLE_PLACEHOLDER,
                )
            )
    placeholder_tuple = tuple(placeholder_segments)
    placeholder_artifact = encode_evidence_pack(
        payload=payload, segments=placeholder_tuple
    )
    handle_bytes = predicted_capability_bytes(len(deferred_ranges))
    inline_bytes = retained_wire_bytes(placeholder_tuple)
    wrapper_bytes = len(placeholder_artifact) - handle_bytes - inline_bytes
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=wrapper_bytes,
        handle_bytes=handle_bytes,
        blueprint_bytes=0,
        mandatory_expansion_bytes=0,
        retained_wire_bytes=inline_bytes,
    )
    route = decide_route(costs)
    if route.disposition is not RouteDisposition.DEFER:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason=route.reason.value,
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )

    backend = _issuance_backend(store)
    if backend is None:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )

    root_binding: tuple[str, str] | None = None
    for item in deferred_ranges:
        identified = _identify(root, item["recipe"], git_executable=git_executable)
        if identified is None or not _matches_payload(identified, item["payload"]):
            return _result(
                kind="evidence_pack",
                disposition=AssemblyDisposition.PASS_THROUGH,
                reason="identity_mismatch",
                input_payload=payload,
                output_payload=payload,
                output_form="exact_payload",
                costs=costs,
                decision=route,
            )
        binding = _root_bindings(identified)
        if root_binding is None:
            root_binding = binding
        elif binding != root_binding:
            return _result(
                kind="evidence_pack",
                disposition=AssemblyDisposition.PASS_THROUGH,
                reason="identity_mismatch",
                input_payload=payload,
                output_payload=payload,
                output_form="exact_payload",
                costs=costs,
                decision=route,
            )
        subject_identity = _subject_identity(identified)
        if subject_identity is None:
            return _result(
                kind="evidence_pack",
                disposition=AssemblyDisposition.PASS_THROUGH,
                reason="identity_mismatch",
                input_payload=payload,
                output_payload=payload,
                output_form="exact_payload",
                costs=costs,
                decision=route,
            )
        item["subject_identity_sha256"] = subject_identity
    if root_binding is None:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )

    root_identity, root_state = root_binding
    requests: list[ArtifactRequest] = []
    for item in deferred_ranges:
        item_payload = item["payload"]
        subject_identity = item["subject_identity_sha256"]
        request = _expansion_request(
            artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            payload=item_payload,
            root_identity_sha256=root_identity,
            root_state_sha256=root_state,
            subject_identity_sha256=subject_identity,
            revalidation={"kind": "source", "source": item["recipe"]},
        )
        if request is None:
            return _result(
                kind="evidence_pack",
                disposition=AssemblyDisposition.PASS_THROUGH,
                reason="store_unavailable",
                input_payload=payload,
                output_payload=payload,
                output_form="exact_payload",
                costs=costs,
                decision=route,
            )
        requests.append(request)
    try:
        issued = backend.issue_batch(tuple(requests))
    except Exception:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )
    handles = _issued_handles(issued, len(requests))
    if handles is None:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )

    actual_segments: list[dict[str, object]] = []
    deferred_index = 0
    for item in ranges:
        if item["mode"] == "retained":
            actual_segments.append(
                retained_segment(
                    start_byte=item["start"],  # type: ignore[arg-type]
                    end_byte=item["end"],  # type: ignore[arg-type]
                    payload=item["payload"],  # type: ignore[arg-type]
                )
            )
        else:
            actual_segments.append(
                deferred_segment(
                    start_byte=item["start"],  # type: ignore[arg-type]
                    end_byte=item["end"],  # type: ignore[arg-type]
                    payload=item["payload"],  # type: ignore[arg-type]
                    subject_identity_sha256=item[  # type: ignore[arg-type]
                        "subject_identity_sha256"
                    ],
                    capability=handles[deferred_index],
                )
            )
            deferred_index += 1
    artifact_bytes = encode_evidence_pack(
        payload=payload, segments=tuple(actual_segments)
    )
    if len(artifact_bytes) != route.predicted_cost_bytes:
        return _result(
            kind="evidence_pack",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=route,
        )
    return _result(
        kind="evidence_pack",
        disposition=AssemblyDisposition.DEFERRED,
        reason=route.reason.value,
        input_payload=payload,
        output_payload=artifact_bytes,
        output_form="evidence_pack",
        costs=costs,
        decision=route,
    )


def assemble_blueprint(
    descriptor_raw: bytes,
    *,
    root: object,
    git_executable: object = None,
    store: object = None,
) -> AssemblyResult:
    descriptor = _strict_keys(
        _parse_document(descriptor_raw),
        frozenset({"items", "obligations", "payload_b64u", "schema_version"}),
    )
    if descriptor["schema_version"] != "contextguard-receipt-blueprint-descriptor/v1":
        _reject("invalid_descriptor")
    payload = _decode_payload(descriptor["payload_b64u"])
    raw_items = descriptor["items"]
    raw_obligations = descriptor["obligations"]
    if (
        type(raw_items) is not list
        or not raw_items
        or len(raw_items) > MAX_BLUEPRINT_ITEMS
        or type(raw_obligations) is not list
        or len(raw_obligations) != len(raw_items)
    ):
        _reject("invalid_descriptor")

    parsed_items: list[dict[str, object]] = []
    offset = 0
    for raw_item in raw_items:
        item = _strict_keys(
            raw_item,
            frozenset(
                {
                    "caller_classification",
                    "detector_signals",
                    "payload_end_byte",
                    "payload_start_byte",
                    "source",
                }
            ),
        )
        start = item["payload_start_byte"]
        end = item["payload_end_byte"]
        if (
            type(start) is not int
            or type(end) is not int
            or start != offset
            or end <= start
            or end > len(payload)
        ):
            _reject("invalid_descriptor")
        item_payload = payload[start:end]
        parsed_items.append(
            {
                "classification": item["caller_classification"],
                "end": end,
                "payload": item_payload,
                "recipe": _source_recipe(item["source"]),
                "signals": _signals(item["detector_signals"]),
                "start": start,
            }
        )
        offset = end
    if offset != len(payload):
        _reject("invalid_descriptor")

    phases: list[str] = [""] * len(parsed_items)
    seen_indices: set[int] = set()
    for raw_obligation in raw_obligations:
        obligation = _strict_keys(raw_obligation, frozenset({"item_index", "phase"}))
        item_index = obligation["item_index"]
        phase = obligation["phase"]
        if (
            type(item_index) is not int
            or item_index < 0
            or item_index >= len(parsed_items)
            or item_index in seen_indices
            or type(phase) is not str
            or phase not in _PHASES
        ):
            _reject("invalid_descriptor")
        seen_indices.add(item_index)
        phases[item_index] = phase  # type: ignore[assignment]
    if len(seen_indices) != len(parsed_items):
        _reject("invalid_descriptor")

    strongest = _strongest_protection(parsed_items)
    if strongest.action is ProtectionAction.REFUSE:
        return _refused("blueprint", payload, strongest.reason.value)
    if strongest.action is ProtectionAction.PASS_THROUGH:
        return _pass_through("blueprint", payload, strongest.reason.value)

    root_binding: tuple[str, str] | None = None
    for item in parsed_items:
        item_payload = item["payload"]
        identified = _identify(root, item["recipe"], git_executable=git_executable)
        if identified is None or not _matches_payload(identified, item_payload):
            return _pass_through("blueprint", payload, "identity_mismatch")
        binding = _root_bindings(identified)
        if root_binding is None:
            root_binding = binding
        elif root_binding != binding:
            return _pass_through("blueprint", payload, "identity_mismatch")
        subject_identity = _subject_identity(identified)
        if subject_identity is None:
            return _pass_through("blueprint", payload, "identity_mismatch")
        item["subject_identity_sha256"] = subject_identity
    backend = _issuance_backend(store)
    if backend is None or root_binding is None:
        return _pass_through("blueprint", payload, "store_unavailable")

    aggregate = [
        {
            "end": item["end"],
            "start": item["start"],
            "subject_identity_sha256": item["subject_identity_sha256"],
        }
        for item in parsed_items
    ]
    whole_subject = framed_sha256_hex(
        "contextguard-receipt/blueprint-whole/v1",
        canonical_json_bytes(aggregate),
        payload,
    )
    placeholder_capabilities = tuple(_HANDLE_PLACEHOLDER for _item in parsed_items)
    placeholder_body = build_blueprint_body(
        whole_payload=payload,
        whole_subject_identity_sha256=whole_subject,
        whole_capability=_HANDLE_PLACEHOLDER,
        items=tuple(parsed_items),
        phases=tuple(phases),
        item_capabilities=placeholder_capabilities,
    )
    placeholder_artifact = canonical_json_bytes(typed_blueprint(placeholder_body))
    blank_body = build_blueprint_body(
        whole_payload=payload,
        whole_subject_identity_sha256=whole_subject,
        whole_capability="",
        items=tuple(parsed_items),
        phases=tuple(phases),
        item_capabilities=tuple("" for _item in parsed_items),
    )
    blueprint_bytes = len(canonical_json_bytes(blank_body)) - 1
    handle_bytes = predicted_capability_bytes(len(parsed_items) + 1)
    wrapper_bytes = len(placeholder_artifact) - blueprint_bytes - handle_bytes
    mandatory_bytes = sum(
        len(item["payload"])
        for item, phase in zip(parsed_items, phases, strict=True)
        if phase != "optional_evidence"
    )
    costs = RouteCosts(
        input_bytes=len(payload),
        wrapper_bytes=wrapper_bytes,
        handle_bytes=handle_bytes,
        blueprint_bytes=blueprint_bytes,
        mandatory_expansion_bytes=mandatory_bytes,
        retained_wire_bytes=0,
    )
    decision = decide_route(costs)
    if decision.disposition is not RouteDisposition.DEFER:
        return _result(
            kind="blueprint",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason=decision.reason.value,
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=decision,
        )

    root_identity, root_state = root_binding
    whole_revalidation = {
        "items": [
            {
                "payload_end_byte": item["end"],
                "payload_start_byte": item["start"],
                "source": item["recipe"],
                "subject_identity_sha256": item["subject_identity_sha256"],
            }
            for item in parsed_items
        ],
        "kind": "aggregate",
    }
    requests: list[ArtifactRequest] = []
    whole_request = _expansion_request(
        artifact_type=ArtifactType.BLUEPRINT_WHOLE_BYTES,
        payload=payload,
        root_identity_sha256=root_identity,
        root_state_sha256=root_state,
        subject_identity_sha256=whole_subject,
        revalidation=whole_revalidation,
    )
    if whole_request is None:
        return _result(
            kind="blueprint",
            disposition=AssemblyDisposition.PASS_THROUGH,
            reason="store_unavailable",
            input_payload=payload,
            output_payload=payload,
            output_form="exact_payload",
            costs=costs,
            decision=decision,
        )
    requests.append(whole_request)
    for item in parsed_items:
        item_payload = item["payload"]
        item_subject = item["subject_identity_sha256"]
        item_request = _expansion_request(
            artifact_type=ArtifactType.BLUEPRINT_ITEM_BYTES,
            payload=item_payload,
            root_identity_sha256=root_identity,
            root_state_sha256=root_state,
            subject_identity_sha256=item_subject,
            revalidation={"kind": "source", "source": item["recipe"]},
        )
        if item_request is None:
            return _result(
                kind="blueprint",
                disposition=AssemblyDisposition.PASS_THROUGH,
                reason="store_unavailable",
                input_payload=payload,
                output_payload=payload,
                output_form="exact_payload",
                costs=costs,
                decision=decision,
            )
        requests.append(item_request)
    try:
        issued = backend.issue_batch(tuple(requests))
    except Exception:
        return _pass_through("blueprint", payload, "store_unavailable")
    handles = _issued_handles(issued, len(requests))
    if handles is None:
        return _pass_through("blueprint", payload, "store_unavailable")
    body = build_blueprint_body(
        whole_payload=payload,
        whole_subject_identity_sha256=whole_subject,
        whole_capability=handles[0],
        items=tuple(parsed_items),
        phases=tuple(phases),
        item_capabilities=handles[1:],
    )
    artifact_bytes = canonical_json_bytes(typed_blueprint(body))
    immediate_cost = decision.predicted_cost_bytes - mandatory_bytes
    if len(artifact_bytes) != immediate_cost:
        return _pass_through("blueprint", payload, "store_unavailable")
    return _result(
        kind="blueprint",
        disposition=AssemblyDisposition.DEFERRED,
        reason=decision.reason.value,
        input_payload=payload,
        output_payload=artifact_bytes,
        output_form="typed_blueprint",
        costs=costs,
        decision=decision,
    )
