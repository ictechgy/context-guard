"""Capability-only exact expansion for source-current and historical artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from .canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .identity import IdentityError, identify_source, snapshot_repository
from .receipts import (
    EXPANSION_ENVELOPE_VERSION,
    EXPANSION_MAGIC,
    ReceiptError,
    SOURCE_CURRENT_BINDING,
    envelope_limits,
    raw_sha256,
    validate_source_recipe,
)
from .runner import validate_framed_capture
from .store import ArtifactType, StoreError, StoreErrorCode


EXPANSION_REFUSAL_VERSION = "contextguard-receipt-expansion-refusal/v1"
_CAPABILITY_PREFIX = "cgr1p_"
_CAPABILITY_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_COMMAND_CAPTURE_SUBJECT_DOMAIN = "contextguard-receipt/command-capture-subject/v1"


class ExpansionDisposition(str, Enum):
    EXACT = "exact"
    STALE = "stale"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ExpansionResult:
    disposition: ExpansionDisposition
    output_bytes: bytes = field(repr=False)
    refusal: dict[str, object] | None


class ResolutionBackend(Protocol):
    """Minimum capability required for sealed expansion lookup."""

    def resolve(
        self, handle: str, *, expected_root_identity_sha256: str
    ) -> object: ...


class _EnvelopeError(ValueError):
    pass


def _resolution_backend(value: object) -> ResolutionBackend | None:
    try:
        method = getattr(value, "resolve")
    except Exception:
        return None
    if not callable(method):
        return None
    return cast(ResolutionBackend, value)


def _valid_capability(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 49
        and value.startswith(_CAPABILITY_PREFIX)
        and all(character in _CAPABILITY_ALPHABET for character in value[6:])
    )


def _closed_refusal(status: str, reason: str) -> dict[str, object]:
    return {
        "artifact_kind": "expansion_refusal",
        "evidence_boundary": evidence_boundary(),
        "reason": reason,
        "schema_version": EXPANSION_REFUSAL_VERSION,
        "status": status,
    }


def _refused(reason: str) -> ExpansionResult:
    return ExpansionResult(
        disposition=ExpansionDisposition.REFUSED,
        output_bytes=b"",
        refusal=_closed_refusal("refused", reason),
    )


def _stale(reason: str) -> ExpansionResult:
    return ExpansionResult(
        disposition=ExpansionDisposition.STALE,
        output_bytes=b"",
        refusal=_closed_refusal("stale", reason),
    )


def _keys(value: object, expected: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected:
        raise _EnvelopeError
    return value  # type: ignore[return-value]


def _hex_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise _EnvelopeError
    return value


def _unpack_envelope(raw: object) -> tuple[dict[str, object], bytes]:
    if type(raw) is not bytes or len(raw) < len(EXPANSION_MAGIC) + 5:
        raise _EnvelopeError
    if not raw.startswith(EXPANSION_MAGIC):
        raise _EnvelopeError
    offset = len(EXPANSION_MAGIC)
    metadata_length = int.from_bytes(raw[offset : offset + 4], "big")
    metadata_start = offset + 4
    metadata_end = metadata_start + metadata_length
    if metadata_length <= 0 or metadata_end > len(raw):
        raise _EnvelopeError
    try:
        metadata = parse_canonical_json_bytes(
            raw[metadata_start:metadata_end], limits=envelope_limits()
        )
    except CanonicalJSONError:
        raise _EnvelopeError from None
    metadata = _keys(
        metadata,
        frozenset(
            {
                "artifact_kind",
                "artifact_type",
                "binding_kind",
                "evidence_boundary",
                "payload",
                "revalidation",
                "root_identity_sha256",
                "root_state_sha256",
                "schema_version",
                "subject_identity_sha256",
            }
        ),
    )
    if (
        metadata["artifact_kind"] != "expansion_envelope"
        or metadata["schema_version"] != EXPANSION_ENVELOPE_VERSION
        or metadata["binding_kind"] != SOURCE_CURRENT_BINDING
        or metadata["evidence_boundary"] != evidence_boundary()
    ):
        raise _EnvelopeError
    payload = raw[metadata_end:]
    payload_metadata = _keys(
        metadata["payload"], frozenset({"byte_length", "content_sha256"})
    )
    if (
        type(payload_metadata["byte_length"]) is not int
        or payload_metadata["byte_length"] != len(payload)
        or _hex_digest(payload_metadata["content_sha256"]) != raw_sha256(payload)
    ):
        raise _EnvelopeError
    _hex_digest(metadata["root_identity_sha256"])
    _hex_digest(metadata["root_state_sha256"])
    _hex_digest(metadata["subject_identity_sha256"])
    return metadata, payload


def _validated_source(value: object) -> dict[str, object]:
    try:
        return validate_source_recipe(value)
    except ReceiptError:
        raise _EnvelopeError from None


def _identify_recipe(
    root: object, recipe: dict[str, object], git_executable: object
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
            symbol_evidence.get("start_byte"),
            symbol_evidence.get("end_byte"),
        )
    try:
        result = identify_source(
            root,
            recipe["relative_path"],
            byte_range=byte_range,
            symbol_evidence=symbol_evidence,
            git_executable=git_executable,
        )
    except IdentityError:
        return None
    if result.get("disposition") not in {"exact_file", "exact_symbol"}:
        return None
    return result


def _current_binding(result: dict[str, object]) -> tuple[str, str]:
    repository = result["repository"]
    return (
        repository["instance"]["identity_sha256"],  # type: ignore[index]
        repository["logical_state"]["state_sha256"],  # type: ignore[index]
    )


def _selection_matches(
    identified: dict[str, object], expected_identity: str, payload: bytes
) -> bool:
    selection = identified.get("selection")
    if identified.get("disposition") == "exact_symbol":
        symbol = identified.get("symbol")
        current_identity = (
            symbol.get("identity_sha256") if type(symbol) is dict else None
        )
    else:
        current_identity = (
            selection.get("identity_sha256") if type(selection) is dict else None
        )
    return bool(
        type(selection) is dict
        and current_identity == expected_identity
        and selection.get("byte_length") == len(payload)
        and selection.get("content_sha256") == raw_sha256(payload)
    )


def _revalidate_source(
    *,
    root: object,
    git_executable: object,
    source: object,
    expected_identity: str,
    expected_root: tuple[str, str],
    payload: bytes,
) -> bool:
    recipe = _validated_source(source)
    identified = _identify_recipe(root, recipe, git_executable)
    return bool(
        identified is not None
        and _current_binding(identified) == expected_root
        and _selection_matches(identified, expected_identity, payload)
    )


def _revalidate(
    *,
    metadata: dict[str, object],
    payload: bytes,
    root: object,
    git_executable: object,
) -> bool:
    root_binding = (
        metadata["root_identity_sha256"],
        metadata["root_state_sha256"],
    )
    revalidation = metadata["revalidation"]
    if type(revalidation) is not dict:
        raise _EnvelopeError
    kind = revalidation.get("kind")
    if kind == "source":
        revalidation = _keys(revalidation, frozenset({"kind", "source"}))
        return _revalidate_source(
            root=root,
            git_executable=git_executable,
            source=revalidation["source"],
            expected_identity=metadata["subject_identity_sha256"],  # type: ignore[arg-type]
            expected_root=root_binding,  # type: ignore[arg-type]
            payload=payload,
        )
    if kind != "aggregate":
        raise _EnvelopeError
    revalidation = _keys(revalidation, frozenset({"items", "kind"}))
    raw_items = revalidation["items"]
    if type(raw_items) is not list or not raw_items or len(raw_items) > 64:
        raise _EnvelopeError
    aggregate: list[dict[str, object]] = []
    offset = 0
    for raw_item in raw_items:
        item = _keys(
            raw_item,
            frozenset(
                {
                    "payload_end_byte",
                    "payload_start_byte",
                    "source",
                    "subject_identity_sha256",
                }
            ),
        )
        start = item["payload_start_byte"]
        end = item["payload_end_byte"]
        subject = _hex_digest(item["subject_identity_sha256"])
        if (
            type(start) is not int
            or type(end) is not int
            or start != offset
            or end <= start
            or end > len(payload)
        ):
            raise _EnvelopeError
        if not _revalidate_source(
            root=root,
            git_executable=git_executable,
            source=item["source"],
            expected_identity=subject,
            expected_root=root_binding,  # type: ignore[arg-type]
            payload=payload[start:end],
        ):
            return False
        aggregate.append(
            {"end": end, "start": start, "subject_identity_sha256": subject}
        )
        offset = end
    if offset != len(payload):
        raise _EnvelopeError
    whole_subject = framed_sha256_hex(
        "contextguard-receipt/blueprint-whole/v1",
        canonical_json_bytes(aggregate),
        payload,
    )
    return whole_subject == metadata["subject_identity_sha256"]


def _validated_command_capture(stored: object, current_root_identity: str) -> bytes:
    payload = stored.payload  # type: ignore[attr-defined]
    subject_identity = stored.subject_identity_sha256  # type: ignore[attr-defined]
    if (
        stored.artifact_type is not ArtifactType.COMMAND_CAPTURE_BYTES  # type: ignore[attr-defined]
        or type(payload) is not bytes
        or type(stored.byte_length) is not int  # type: ignore[attr-defined]
        or stored.byte_length != len(payload)  # type: ignore[attr-defined]
        or stored.root_identity_sha256 != current_root_identity  # type: ignore[attr-defined]
        or type(subject_identity) is not str
    ):
        raise _EnvelopeError
    validate_framed_capture(payload)
    if framed_sha256_hex(_COMMAND_CAPTURE_SUBJECT_DOMAIN, payload) != subject_identity:
        raise _EnvelopeError
    return payload


def expand_capability(
    handle: str,
    *,
    root: object,
    store: object,
    git_executable: object = None,
) -> ExpansionResult:
    """Resolve only by capability, enforcing each artifact's sealed binding."""

    if not _valid_capability(handle):
        return _refused("capability_rejected")
    backend = _resolution_backend(store)
    if backend is None:
        return _refused("store_unavailable")

    try:
        snapshot = snapshot_repository(root, git_executable=git_executable)
        current_root_identity = snapshot["instance"]["identity_sha256"]  # type: ignore[index]
    except (IdentityError, KeyError, TypeError):
        return _stale("root_unavailable")
    try:
        stored = backend.resolve(
            handle, expected_root_identity_sha256=current_root_identity
        )
    except StoreError as error:
        if error.code == StoreErrorCode.CAPABILITY_REJECTED:
            return _refused("capability_rejected")
        return _refused("store_unavailable")
    except Exception:
        return _refused("store_unavailable")

    try:
        if stored.artifact_type is ArtifactType.COMMAND_CAPTURE_BYTES:
            payload = _validated_command_capture(stored, current_root_identity)
            try:
                final_snapshot = snapshot_repository(
                    root, git_executable=git_executable
                )
                final_root_identity = final_snapshot["instance"][  # type: ignore[index]
                    "identity_sha256"
                ]
            except Exception:
                return _stale("root_unavailable")
            if final_root_identity != current_root_identity:
                return _stale("root_unavailable")
            return ExpansionResult(
                disposition=ExpansionDisposition.EXACT,
                output_bytes=payload,
                refusal=None,
            )
        metadata, payload = _unpack_envelope(stored.payload)
        if (
            type(stored.byte_length) is not int
            or stored.byte_length != len(stored.payload)
            or stored.root_identity_sha256 != metadata["root_identity_sha256"]
            or stored.subject_identity_sha256 != metadata["subject_identity_sha256"]
            or stored.artifact_type.value != metadata["artifact_type"]
            or stored.artifact_type
            not in {
                ArtifactType.RAW_EVIDENCE_BYTES,
                ArtifactType.BLUEPRINT_WHOLE_BYTES,
                ArtifactType.BLUEPRINT_ITEM_BYTES,
            }
        ):
            raise _EnvelopeError
        current_state = snapshot["logical_state"]["state_sha256"]  # type: ignore[index]
        if current_state != metadata["root_state_sha256"]:
            return _stale("root_state_changed")
        if not _revalidate(
            metadata=metadata,
            payload=payload,
            root=root,
            git_executable=git_executable,
        ):
            return _stale("source_changed")
    except Exception:
        return _refused("artifact_invalid")
    return ExpansionResult(
        disposition=ExpansionDisposition.EXACT,
        output_bytes=payload,
        refusal=None,
    )
