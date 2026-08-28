"""Bounded, provider-free NDJSON MCP server for one pinned repository root."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO, Final, TextIO

from .assembly import (
    DESCRIPTOR_LIMITS as ASSEMBLY_DESCRIPTOR_LIMITS,
    MAX_ASSEMBLY_PAYLOAD_BYTES,
    AssemblyDisposition,
    AssemblyError,
    assemble_blueprint,
    assemble_evidence,
    assemble_evidence_pack,
)
from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .diagnostics import DiagnosticsError, analyze_diagnostics
from .execution_twin import (
    ExecutionTwin,
    ExecutionTwinError,
    parse_twin_request,
)
from .expansion import ExpansionDisposition, expand_capability
from .identity import IdentityError, snapshot_repository
from .receipts import ReceiptError, validate_source_recipe
from .store import (
    ArtifactRequest,
    ArtifactType,
    IssuedCapability,
    StoreError,
    StoreErrorCode,
    StoredArtifact,
)
from .tool_schemas import (
    DESCRIPTOR_LIMITS as TOOL_SCHEMA_DESCRIPTOR_LIMITS,
    ToolSchemaDisposition,
    ToolSchemaError,
    ToolSchemaExpansionDisposition,
    assemble_tool_schemas,
    expand_tool_schema_catalog,
    expand_tool_schema_item,
)


__all__ = [
    "InMemoryCapabilityStore",
    "MCPServer",
    "serve",
    "serve_stdio",
]


SUPPORTED_VERSIONS: Final = ("2025-11-25", "2025-06-18", "2025-03-26")
MAX_FRAME_BYTES: Final = 3 * 1024 * 1024
MAX_RESPONSE_BYTES: Final = 4 * 1024 * 1024
MAX_JSON_DEPTH: Final = 40
MAX_JSON_VALUES: Final = 65_600
MAX_OBJECT_MEMBERS: Final = 256
MAX_FRAMES: Final = 1024
MAX_TOOL_CALLS: Final = 256
MAX_ID_UTF8_BYTES: Final = 128
MAX_ARTIFACTS: Final = 256
MAX_TOTAL_ARTIFACT_BYTES: Final = 16 * 1024 * 1024
MAX_SINGLE_ARTIFACT_BYTES: Final = 1024 * 1024
CAPABILITY_TTL_SECONDS: Final = 300.0
MAX_DIRECTORY_ENTRIES: Final = 4096
MAX_ROOT_INVENTORY_ENTRIES: Final = 65_536
MAX_ROOT_INVENTORY_DEPTH: Final = 64
MAX_ROOT_INVENTORY_PATH_BYTES: Final = 4096
MAX_CONTEXT_SLICE_BYTES: Final = 64 * 1024
MAX_CONTEXT_DIAGNOSTIC_INPUT_BYTES: Final = 700_000

_RESPONSE_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=MAX_RESPONSE_BYTES,
    max_depth=MAX_JSON_DEPTH,
    max_total_values=MAX_JSON_VALUES,
    max_object_members=MAX_OBJECT_MEMBERS,
    max_string_bytes=MAX_RESPONSE_BYTES,
)

_EXTERNAL_PREFIX: Final = "cgr1m_"
_INTERNAL_PREFIX: Final = "cgr1p_"
_CAPABILITY_ALPHABET: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_TOOL_NAMES: Final = (
    "receipt_assemble",
    "receipt_context",
    "receipt_diagnose",
    "receipt_expand",
    "receipt_inspect",
    "receipt_pack",
    "receipt_tool_select",
    "receipt_twin",
)
_FROZEN_UNICODE_DATABASE: Final = unicodedata.ucd_3_2_0
_SOURCE_ARTIFACT_TYPES: Final = frozenset(
    {
        ArtifactType.BLUEPRINT_ITEM_BYTES,
        ArtifactType.BLUEPRINT_WHOLE_BYTES,
        ArtifactType.RAW_EVIDENCE_BYTES,
    }
)


class _DuplicateKey(ValueError):
    pass


class _InvalidInput(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _MemoryRecord:
    external_handle: str
    internal_handle: str
    artifact: StoredArtifact
    expires_at: float


@dataclass(frozen=True, slots=True)
class _ContextCacheEntry:
    external_handle: str
    result: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ContextLease:
    scope_hmac_sha256: str | None


@dataclass(frozen=True, slots=True)
class _ToolProfileEntry:
    descriptor_sha256: str
    capabilities: tuple[str, ...]
    result: dict[str, object]


MAX_CONTEXT_HISTORY_EVENTS: Final = 256
MAX_CONTEXT_HISTORY_RESULTS: Final = 64
MAX_TASK_SCOPE_BYTES: Final = 128


def _hash_field(digest: object, value: bytes) -> None:
    if type(value) is not bytes:
        raise _InvalidInput
    digest.update(len(value).to_bytes(8, "big"))  # type: ignore[attr-defined]
    digest.update(value)  # type: ignore[attr-defined]


def _status_fingerprint(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        stat.S_IFMT(status.st_mode),
        stat.S_IMODE(status.st_mode),
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _status_kind(status: os.stat_result) -> bytes:
    mode = status.st_mode
    if stat.S_ISDIR(mode):
        return b"directory"
    if stat.S_ISREG(mode):
        return b"regular"
    if stat.S_ISLNK(mode):
        return b"symlink"
    if stat.S_ISFIFO(mode):
        return b"fifo"
    if stat.S_ISSOCK(mode):
        return b"socket"
    if stat.S_ISCHR(mode):
        return b"character"
    if stat.S_ISBLK(mode):
        return b"block"
    return b"unknown"


def _root_metadata_digest(root_descriptor: int, *, exclude_dot_git: bool) -> str:
    """Hash bounded no-follow metadata without reading repository file contents."""

    digest = hashlib.sha256()
    _hash_field(digest, b"contextguard-receipt/mcp-root-metadata/v1")
    entry_count = 0
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )

    def record(relative_path: bytes, status: os.stat_result) -> None:
        nonlocal entry_count
        entry_count += 1
        if entry_count > MAX_ROOT_INVENTORY_ENTRIES:
            raise _InvalidInput
        fingerprint = ":".join(
            str(value) for value in _status_fingerprint(status)
        ).encode("ascii")
        _hash_field(digest, relative_path)
        _hash_field(digest, _status_kind(status))
        _hash_field(digest, fingerprint)

    def visit(
        directory_descriptor: int, relative_path: bytes, depth: int
    ) -> None:
        if depth > MAX_ROOT_INVENTORY_DEPTH:
            raise _InvalidInput
        before = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise _InvalidInput
        record(relative_path, before)
        entries: list[tuple[bytes, str, os.stat_result]] = []
        with os.scandir(directory_descriptor) as scanner:
            for index, entry in enumerate(scanner, start=1):
                if index > MAX_DIRECTORY_ENTRIES:
                    raise _InvalidInput
                raw_name = os.fsencode(entry.name)
                if not raw_name or b"/" in raw_name or b"\0" in raw_name:
                    raise _InvalidInput
                child_path = (
                    raw_name
                    if relative_path == b"."
                    else relative_path + b"/" + raw_name
                )
                if len(child_path) > MAX_ROOT_INVENTORY_PATH_BYTES:
                    raise _InvalidInput
                status = entry.stat(follow_symlinks=False)
                if (
                    depth == 0
                    and exclude_dot_git
                    and raw_name == b".git"
                    and stat.S_ISDIR(status.st_mode)
                ):
                    continue
                entries.append((raw_name, entry.name, status))
        for raw_name, name, status in sorted(entries, key=lambda item: item[0]):
            child_path = (
                raw_name
                if relative_path == b"."
                else relative_path + b"/" + raw_name
            )
            if not stat.S_ISDIR(status.st_mode):
                record(child_path, status)
                continue
            child_descriptor = os.open(
                name, directory_flags, dir_fd=directory_descriptor
            )
            try:
                if _status_fingerprint(os.fstat(child_descriptor)) != (
                    _status_fingerprint(status)
                ):
                    raise _InvalidInput
                visit(child_descriptor, child_path, depth + 1)
            finally:
                os.close(child_descriptor)
        if _status_fingerprint(os.fstat(directory_descriptor)) != (
            _status_fingerprint(before)
        ):
            raise _InvalidInput

    duplicate = -1
    try:
        duplicate = os.dup(root_descriptor)
        visit(duplicate, b".", 0)
    except (OSError, OverflowError, UnicodeError):
        raise _InvalidInput from None
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    return digest.hexdigest()


def _snapshot_bindings(snapshot: object) -> tuple[str, str, str]:
    if type(snapshot) is not dict:
        raise _InvalidInput
    instance = snapshot.get("instance")
    logical_state = snapshot.get("logical_state")
    if type(instance) is not dict or type(logical_state) is not dict:
        raise _InvalidInput
    identity = instance.get("identity_sha256")
    state = logical_state.get("state_sha256")
    kind = logical_state.get("kind")
    if (
        not _valid_digest(identity)
        or not _valid_digest(state)
        or kind not in {"git_worktree", "non_git"}
    ):
        raise _InvalidInput
    return identity, state, kind  # type: ignore[return-value]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _valid_digest(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _valid_handle(value: object, prefix: str) -> bool:
    return bool(
        type(value) is str
        and len(value) == 49
        and value.startswith(prefix)
        and all(character in _CAPABILITY_ALPHABET for character in value[6:])
    )


def _reject_capability() -> None:
    raise StoreError(StoreErrorCode.CAPABILITY_REJECTED) from None


class InMemoryCapabilityStore:
    """Atomic, process-local capability backend with monotonic expiry."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        expected_source_root_identity_sha256: str | None = None,
    ) -> None:
        if not callable(clock) or (
            expected_source_root_identity_sha256 is not None
            and not _valid_digest(expected_source_root_identity_sha256)
        ):
            raise ValueError("invalid MCP clock")
        self._clock = clock
        self._expected_source_root_identity = expected_source_root_identity_sha256
        self._source_binding_failed = False
        self._namespace_id = secrets.token_bytes(32).hex()
        self._records: dict[str, _MemoryRecord] = {}
        self._internal_to_external: dict[str, str] = {}
        self._total_bytes = 0
        self._clock_highwater: float | None = None
        self._lock = threading.RLock()

    @property
    def namespace_id(self) -> str:
        return self._namespace_id

    def _now(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or value < 0:
            raise StoreError(StoreErrorCode.UNSAFE_STATE)
        current = float(value)
        if self._clock_highwater is not None and current < self._clock_highwater:
            self._records.clear()
            self._internal_to_external.clear()
            self._total_bytes = 0
            raise StoreError(StoreErrorCode.UNSAFE_STATE)
        self._clock_highwater = current
        return current

    def _drop_expired(self, now: float) -> None:
        expired = {
            record.external_handle
            for record in self._records.values()
            if record.external_handle in self._records and now >= record.expires_at
        }
        for external in expired:
            record = self._records.pop(external)
            self._records.pop(record.internal_handle, None)
            self._internal_to_external.pop(record.internal_handle, None)
            self._total_bytes -= record.artifact.byte_length

    def _validate_request(self, request: object) -> ArtifactRequest:
        if type(request) is not ArtifactRequest:
            raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
        if (
            type(request.payload) is not bytes
            or len(request.payload) > MAX_SINGLE_ARTIFACT_BYTES
            or not _valid_digest(request.root_identity_sha256)
            or not _valid_digest(request.subject_identity_sha256)
            or type(request.artifact_type) is not ArtifactType
        ):
            raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
        if (
            request.artifact_type in _SOURCE_ARTIFACT_TYPES
            and self._expected_source_root_identity is not None
            and request.root_identity_sha256 != self._expected_source_root_identity
        ):
            with self._lock:
                self._source_binding_failed = True
            raise StoreError(StoreErrorCode.CAPABILITY_REJECTED)
        return request

    def source_binding_failed(self) -> bool:
        with self._lock:
            return self._source_binding_failed

    def issue_batch(
        self, requests: tuple[ArtifactRequest, ...]
    ) -> tuple[IssuedCapability, ...]:
        if type(requests) is not tuple or not requests:
            raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
        checked = tuple(self._validate_request(request) for request in requests)
        if len(checked) > MAX_ARTIFACTS:
            raise StoreError(StoreErrorCode.CAPABILITY_COUNT_QUOTA_EXCEEDED)
        batch_bytes = sum(len(request.payload) for request in checked)
        if batch_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise StoreError(StoreErrorCode.ARTIFACT_BYTES_QUOTA_EXCEEDED)
        with self._lock:
            now = self._now()
            self._drop_expired(now)
            current_count = len(self._records) // 2
            if current_count + len(checked) > MAX_ARTIFACTS:
                raise StoreError(StoreErrorCode.CAPABILITY_COUNT_QUOTA_EXCEEDED)
            if self._total_bytes + batch_bytes > MAX_TOTAL_ARTIFACT_BYTES:
                raise StoreError(StoreErrorCode.ARTIFACT_BYTES_QUOTA_EXCEEDED)

            pending: list[tuple[_MemoryRecord, ArtifactRequest]] = []
            reserved = set(self._records)
            for request in checked:
                for _attempt in range(16):
                    suffix = _b64u(secrets.token_bytes(32))
                    external = _EXTERNAL_PREFIX + suffix
                    internal = _INTERNAL_PREFIX + suffix
                    if external not in reserved and internal not in reserved:
                        break
                else:
                    raise StoreError(StoreErrorCode.WRITE_FAILED)
                reserved.update((external, internal))
                artifact = StoredArtifact(
                    artifact_type=request.artifact_type,
                    byte_length=len(request.payload),
                    namespace_id=self._namespace_id,
                    payload=request.payload,
                    payload_sha256=hashlib.sha256(request.payload).hexdigest(),
                    root_identity_sha256=request.root_identity_sha256,
                    subject_identity_sha256=request.subject_identity_sha256,
                    scope_hmac_sha256=request.scope_hmac_sha256,
                )
                pending.append(
                    (
                        _MemoryRecord(
                            external_handle=external,
                            internal_handle=internal,
                            artifact=artifact,
                            expires_at=now + CAPABILITY_TTL_SECONDS,
                        ),
                        request,
                    )
                )

            for record, request in pending:
                self._records[record.external_handle] = record
                self._records[record.internal_handle] = record
                self._internal_to_external[record.internal_handle] = (
                    record.external_handle
                )
                self._total_bytes += len(request.payload)
            return tuple(
                IssuedCapability(
                    handle=record.internal_handle,
                    namespace_id=self._namespace_id,
                )
                for record, _request in pending
            )

    def _get(self, handle: object) -> _MemoryRecord:
        if not (
            _valid_handle(handle, _EXTERNAL_PREFIX)
            or _valid_handle(handle, _INTERNAL_PREFIX)
        ):
            _reject_capability()
        with self._lock:
            now = self._now()
            self._drop_expired(now)
            record = self._records.get(handle)  # type: ignore[arg-type]
            if record is None or now >= record.expires_at:
                _reject_capability()
            return record

    def resolve(
        self, handle: str, *, expected_root_identity_sha256: str
    ) -> StoredArtifact:
        if not _valid_digest(expected_root_identity_sha256):
            raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
        record = self._get(handle)
        if record.artifact.root_identity_sha256 != expected_root_identity_sha256:
            _reject_capability()
        return record.artifact

    def retrieve(
        self,
        handle: str,
        *,
        expected_namespace_id: str,
        expected_root_identity_sha256: str,
        expected_subject_identity_sha256: str,
        expected_artifact_type: ArtifactType,
    ) -> StoredArtifact:
        record = self._get(handle)
        artifact = record.artifact
        if (
            expected_namespace_id != self._namespace_id
            or artifact.root_identity_sha256 != expected_root_identity_sha256
            or artifact.subject_identity_sha256 != expected_subject_identity_sha256
            or artifact.artifact_type is not expected_artifact_type
        ):
            _reject_capability()
        return artifact

    def externalize_handle(self, value: str) -> str:
        with self._lock:
            return self._internal_to_external.get(value, value)

    def internalize_handle(self, value: object) -> str:
        if not _valid_handle(value, _EXTERNAL_PREFIX):
            _reject_capability()
        record = self._get(value)
        return record.internal_handle

    def revoke_external(self, value: object) -> None:
        if not _valid_handle(value, _EXTERNAL_PREFIX):
            _reject_capability()
        with self._lock:
            now = self._now()
            self._drop_expired(now)
            record = self._records.get(value)  # type: ignore[arg-type]
            if record is None:
                _reject_capability()
            self._records.pop(record.external_handle, None)
            self._records.pop(record.internal_handle, None)
            self._internal_to_external.pop(record.internal_handle, None)
            self._total_bytes -= record.artifact.byte_length

    def inspect_counts(self) -> tuple[int, int]:
        with self._lock:
            self._drop_expired(self._now())
            return len(self._records) // 2, self._total_bytes

    def close(self) -> None:
        with self._lock:
            self._records.clear()
            self._internal_to_external.clear()
            self._total_bytes = 0


def _walk_json(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    values = 0
    while pending:
        item, depth = pending.pop()
        values += 1
        if values > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            raise _InvalidInput
        if item is None or type(item) in (bool, int):
            continue
        if type(item) is float:
            raise _InvalidInput
        if type(item) is str:
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise _InvalidInput
            item.encode("utf-8", errors="strict")
            continue
        if type(item) is list:
            if id(item) in seen:
                raise _InvalidInput
            seen.add(id(item))
            pending.extend((child, depth + 1) for child in item)
            continue
        if type(item) is dict:
            if id(item) in seen or len(item) > MAX_OBJECT_MEMBERS:
                raise _InvalidInput
            seen.add(id(item))
            for key, child in item.items():
                if type(key) is not str:
                    raise _InvalidInput
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
            continue
        raise _InvalidInput


def _valid_id(value: object) -> bool:
    if type(value) is str:
        try:
            return len(value.encode("utf-8")) <= MAX_ID_UTF8_BYTES
        except UnicodeEncodeError:
            return False
    return bool(type(value) is int and -(2**53 - 1) <= value <= 2**53 - 1)


def _canonical_text(value: dict[str, object]) -> str:
    return (
        canonical_json_bytes(value, _RESPONSE_JSON_LIMITS)
        .decode("ascii")
        .removesuffix("\n")
    )


def _payload_bytes(
    *, kind: str, disposition: str, output: bytes, receipt: object = None
) -> dict[str, object]:
    return {
        "artifact_kind": kind,
        "byte_length": len(output),
        "content_sha256": hashlib.sha256(output).hexdigest(),
        "disposition": disposition,
        "evidence_boundary": evidence_boundary(),
        "output_b64u": _b64u(output),
        "provider_claim_authority": False,
        "receipt": receipt,
        "schema_version": "contextguard-receipt-mcp-payload/v1",
    }


def _tool_error(code: str) -> dict[str, object]:
    return {
        "artifact_kind": "mcp_tool_error",
        "code": code,
        "evidence_boundary": evidence_boundary(),
        "provider_claim_authority": False,
        "schema_version": "contextguard-receipt-mcp-tool-error/v1",
    }


def _call_result(payload: dict[str, object], *, is_error: bool) -> dict[str, object]:
    return {
        "content": [{"text": _canonical_text(payload), "type": "text"}],
        "structuredContent": payload,
        "isError": is_error,
    }


def _tool_definitions() -> list[dict[str, object]]:
    closed = {"additionalProperties": False, "type": "object"}
    annotations = {
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
        "readOnlyHint": False,
    }
    return [
        {
            "annotations": annotations,
            "description": "Assemble local evidence or a blueprint beneath the pinned root.",
            "inputSchema": {
                **closed,
                "properties": {
                    "descriptor": {"type": "object"},
                    "kind": {"enum": ["blueprint", "evidence"], "type": "string"},
                },
                "required": ["descriptor", "kind"],
            },
            "name": "receipt_assemble",
        },
        {
            "annotations": annotations,
            "description": (
                "Store one explicit local file without resending its bytes, "
                "or read one bounded exact slice."
            ),
            "inputSchema": {
                "oneOf": [
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "store", "type": "string"},
                            "caller_classification": {
                                "const": "eligible",
                                "type": "string",
                            },
                            "detector_signals": {
                                "items": {
                                    "enum": [
                                        "ambiguous",
                                        "exact_required",
                                        "protected",
                                        "secret",
                                        "security_sensitive",
                                        "unknown",
                                    ],
                                    "type": "string",
                                },
                                "maxItems": 0,
                                "type": "array",
                                "uniqueItems": True,
                            },
                            "relative_path": {"maxLength": 4096, "type": "string"},
                            "task_scope": {
                                "maxLength": MAX_TASK_SCOPE_BYTES,
                                "minLength": 1,
                                "type": "string",
                            },
                        },
                        "required": [
                            "action",
                            "caller_classification",
                            "detector_signals",
                            "relative_path",
                        ],
                    },
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "read", "type": "string"},
                            "capability": {
                                "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                                "type": "string",
                            },
                            "max_bytes": {
                                "maximum": MAX_CONTEXT_SLICE_BYTES,
                                "minimum": 1,
                                "type": "integer",
                            },
                            "offset": {
                                "maximum": MAX_ASSEMBLY_PAYLOAD_BYTES,
                                "minimum": 0,
                                "type": "integer",
                            },
                            "task_scope": {
                                "maxLength": MAX_TASK_SCOPE_BYTES,
                                "minLength": 1,
                                "type": "string",
                            },
                        },
                        "required": ["action", "capability", "max_bytes", "offset"],
                    },
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "release", "type": "string"},
                            "capability": {
                                "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                                "type": "string",
                            },
                            "task_scope": {
                                "maxLength": MAX_TASK_SCOPE_BYTES,
                                "minLength": 1,
                                "type": "string",
                            },
                        },
                        "required": ["action", "capability"],
                    },
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "history", "type": "string"},
                            "limit": {
                                "maximum": MAX_CONTEXT_HISTORY_RESULTS,
                                "minimum": 1,
                                "type": "integer",
                            },
                        },
                        "required": ["action", "limit"],
                    },
                ],
                "type": "object",
            },
            "name": "receipt_context",
        },
        {
            "annotations": {**annotations, "readOnlyHint": True},
            "description": (
                "Return content-free shadow firewall, router, and scout/surgeon "
                "advice for one explicit local file."
            ),
            "inputSchema": {
                **closed,
                "properties": {
                    "caller_classification": {"const": "eligible", "type": "string"},
                    "detector_signals": {
                        "items": {"type": "string"},
                        "maxItems": 0,
                        "type": "array",
                        "uniqueItems": True,
                    },
                    "previous_capability": {
                        "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                        "type": "string",
                    },
                    "relative_path": {"maxLength": 4096, "type": "string"},
                    "task_scope": {
                        "maxLength": MAX_TASK_SCOPE_BYTES,
                        "minLength": 1,
                        "type": "string",
                    },
                },
                "required": [
                    "caller_classification",
                    "detector_signals",
                    "relative_path",
                ],
            },
            "name": "receipt_diagnose",
        },
        {
            "annotations": {**annotations, "readOnlyHint": True},
            "description": "Expand one process-local exact capability.",
            "inputSchema": {
                **closed,
                "properties": {
                    "capability": {
                        "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                        "type": "string",
                    },
                    "task_scope": {
                        "maxLength": MAX_TASK_SCOPE_BYTES,
                        "minLength": 1,
                        "type": "string",
                    },
                },
                "required": ["capability"],
            },
            "name": "receipt_expand",
        },
        {
            "annotations": {**annotations, "idempotentHint": True, "readOnlyHint": True},
            "description": "Inspect bounded process-local MCP counters.",
            "inputSchema": closed,
            "name": "receipt_inspect",
        },
        {
            "annotations": annotations,
            "description": (
                "Build one bounded multi-file evidence pack with task-scoped exact expansion."
            ),
            "inputSchema": {
                **closed,
                "properties": {
                    "sources": {
                        "items": {
                            **closed,
                            "properties": {
                                "capability": {
                                    "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                                    "type": "string",
                                },
                                "relative_path": {
                                    "maxLength": 4096,
                                    "minLength": 1,
                                    "type": "string",
                                },
                            },
                            "required": ["capability", "relative_path"],
                        },
                        "maxItems": 16,
                        "minItems": 1,
                        "type": "array",
                    },
                    "retained_budget_bytes": {
                        "maximum": MAX_ASSEMBLY_PAYLOAD_BYTES,
                        "minimum": 0,
                        "type": "integer",
                    },
                    "task_scope": {
                        "maxLength": MAX_TASK_SCOPE_BYTES,
                        "minLength": 1,
                        "type": "string",
                    },
                },
                "required": [
                    "sources",
                    "retained_budget_bytes",
                    "task_scope",
                ],
            },
            "name": "receipt_pack",
        },
        {
            "annotations": annotations,
            "description": "Select a bounded tool-schema catalog beneath the pinned root.",
            "inputSchema": {
                **closed,
                "properties": {
                    "descriptor": {"type": "object"},
                    "profile_id": {
                        "maxLength": 64,
                        "minLength": 1,
                        "pattern": "^[A-Za-z0-9._-]+$",
                        "type": "string",
                    },
                    "task_scope": {
                        "maxLength": MAX_TASK_SCOPE_BYTES,
                        "minLength": 1,
                        "type": "string",
                    },
                },
                "required": ["descriptor"],
            },
            "name": "receipt_tool_select",
        },
        {
            "annotations": annotations,
            "description": (
                "Append or inspect server-owned advisory execution-twin evidence."
            ),
            "inputSchema": {
                "oneOf": [
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "append", "type": "string"},
                            "observed_at_unix_ms": {
                                "maximum": 4_102_444_800_000,
                                "minimum": 0,
                                "type": "integer",
                            },
                            "request": {"type": "object"},
                        },
                        "required": ["action", "observed_at_unix_ms", "request"],
                    },
                    {
                        **closed,
                        "properties": {
                            "action": {"const": "inspect", "type": "string"},
                            "limit": {"maximum": 256, "minimum": 1, "type": "integer"},
                        },
                        "required": ["action", "limit"],
                    },
                ],
                "type": "object",
            },
            "name": "receipt_twin",
        },
    ]


class MCPServer:
    """One-root, one-process MCP state machine."""

    def __init__(
        self,
        root: str,
        *,
        clock: Callable[[], float] = time.monotonic,
        state_dir: str | None = None,
    ) -> None:
        if (
            type(root) is not str
            or not root
            or "\0" in root
            or not os.path.isabs(root)
            or os.path.normpath(root) != root
            or os.path.realpath(root) != root
            or not callable(clock)
            or (
                state_dir is not None
                and (
                    type(state_dir) is not str
                    or not state_dir
                    or "\0" in state_dir
                    or not os.path.isabs(state_dir)
                    or os.path.normpath(state_dir) != state_dir
                )
            )
        ):
            raise ValueError("invalid MCP root")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(root, flags)
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            os.close(descriptor)
            raise ValueError("invalid MCP root")
        try:
            snapshot = snapshot_repository(root)
            identity, state, repository_kind = _snapshot_bindings(snapshot)
            inventory = _root_metadata_digest(
                descriptor,
                exclude_dot_git=repository_kind == "git_worktree",
            )
        except (IdentityError, _InvalidInput, OSError):
            os.close(descriptor)
            raise ValueError("invalid MCP root") from None
        self._root = root
        self._root_fd = descriptor
        self._root_anchor = (status.st_dev, status.st_ino)
        self._root_identity = identity
        self._root_state = state
        self._root_inventory = inventory
        self._repository_kind = repository_kind
        self._clock = clock
        self._state_dir = state_dir
        self._context_hash_key = os.urandom(32)
        self._store = InMemoryCapabilityStore(
            clock=clock,
            expected_source_root_identity_sha256=identity,
        )
        self._state = "PRE_INIT"
        self._closed = False
        self._root_failed = False
        self._frames = 0
        self._requests = 0
        self._tool_calls = 0
        self._seen_ids: set[tuple[type, object]] = set()
        self._call_lock = threading.Lock()
        self._tool_references: dict[
            str,
            tuple[
                dict[str, object],
                dict[str, object] | None,
                str | None,
            ],
        ] = {}
        self._tool_profiles: dict[str, _ToolProfileEntry] = {}
        self._tool_profile_cache_hits = 0
        self._context_cache: dict[
            tuple[str, str, tuple[str, ...], str | None], _ContextCacheEntry
        ] = {}
        self._context_handles: dict[str, _ContextLease] = {}
        self._context_cache_hits = 0
        self._context_history: list[dict[str, object]] = []
        self._context_history_sequence = 0

    def _poison_root(self) -> None:
        self._root_failed = True
        self._store.close()

    def _revalidate_root(self) -> None:
        if self._closed or self._root_failed:
            raise _InvalidInput
        try:
            current = os.fstat(self._root_fd)
        except OSError:
            self._poison_root()
            raise _InvalidInput from None
        if (current.st_dev, current.st_ino) != self._root_anchor:
            self._poison_root()
            raise _InvalidInput
        try:
            check_fd = os.open(
                self._root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError:
            self._poison_root()
            raise _InvalidInput from None
        try:
            check = os.fstat(check_fd)
            if (check.st_dev, check.st_ino) != self._root_anchor:
                self._poison_root()
                raise _InvalidInput
        finally:
            os.close(check_fd)
        try:
            snapshot = snapshot_repository(self._root)
            identity, state, repository_kind = _snapshot_bindings(snapshot)
            inventory = _root_metadata_digest(
                self._root_fd,
                exclude_dot_git=repository_kind == "git_worktree",
            )
        except (IdentityError, _InvalidInput, OSError):
            self._poison_root()
            raise _InvalidInput from None
        if (
            identity != self._root_identity
            or state != self._root_state
            or inventory != self._root_inventory
            or repository_kind != self._repository_kind
        ):
            self._poison_root()
            raise _InvalidInput

    def _validate_relative_path(self, value: object) -> None:
        if (
            type(value) is not str
            or not value
            or "\0" in value
            or "\\" in value
            or os.path.isabs(value)
            or os.path.normpath(value) != value
            or value in (".", "..")
            or len(value.encode("utf-8")) > 4096
        ):
            raise _InvalidInput
        components = value.split("/")
        if any(
            component in ("", ".", "..")
            or _FROZEN_UNICODE_DATABASE.normalize("NFC", component) != component
            for component in components
        ) or components[0].casefold() == ".git":
            raise _InvalidInput
        parent = os.dup(self._root_fd)
        try:
            for index, component in enumerate(components):
                normalized = _FROZEN_UNICODE_DATABASE.normalize("NFC", component)
                folded = normalized.casefold()
                exact_count = 0
                alias_found = False
                entry_count = 0
                with os.scandir(parent) as entries:
                    for entry in entries:
                        entry_count += 1
                        if entry_count > MAX_DIRECTORY_ENTRIES:
                            raise _InvalidInput
                        name = os.fsdecode(entry.name)
                        normalized_name = _FROZEN_UNICODE_DATABASE.normalize(
                            "NFC", name
                        )
                        if name == component:
                            exact_count += 1
                        elif (
                            normalized_name == normalized
                            or normalized_name.casefold() == folded
                        ):
                            alias_found = True
                if alias_found or exact_count != 1:
                    raise _InvalidInput
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if index < len(components) - 1:
                    flags |= os.O_DIRECTORY
                else:
                    flags |= getattr(os, "O_NONBLOCK", 0)
                child = os.open(component, flags, dir_fd=parent)
                os.close(parent)
                parent = child
            if not stat.S_ISREG(os.fstat(parent).st_mode):
                raise _InvalidInput
        except OSError:
            raise _InvalidInput from None
        finally:
            os.close(parent)

    def _validate_descriptor_paths(self, descriptor: object) -> None:
        if type(descriptor) is not dict:
            raise _InvalidInput
        schema = descriptor.get("schema_version")
        sources: list[object]
        if schema == "contextguard-receipt-evidence-descriptor/v1":
            if set(descriptor) != {
                "caller_classification",
                "detector_signals",
                "payload_b64u",
                "schema_version",
                "source",
            }:
                raise _InvalidInput
            sources = [descriptor["source"]]
        elif schema == "contextguard-receipt-evidence-pack-descriptor/v1":
            if set(descriptor) != {"payload_b64u", "ranges", "schema_version"}:
                raise _InvalidInput
            ranges = descriptor["ranges"]
            if type(ranges) is not list or not ranges or len(ranges) > 64:
                raise _InvalidInput
            sources = []
            for item in ranges:
                if type(item) is not dict or set(item) != {
                    "caller_classification",
                    "detector_signals",
                    "end_byte",
                    "mode",
                    "source",
                    "start_byte",
                }:
                    raise _InvalidInput
                sources.append(item["source"])
        elif schema == "contextguard-receipt-blueprint-descriptor/v1":
            if set(descriptor) != {
                "items",
                "obligations",
                "payload_b64u",
                "schema_version",
            }:
                raise _InvalidInput
            items = descriptor["items"]
            if type(items) is not list or not items or len(items) > 64:
                raise _InvalidInput
            sources = []
            for item in items:
                if type(item) is not dict or set(item) != {
                    "caller_classification",
                    "detector_signals",
                    "payload_end_byte",
                    "payload_start_byte",
                    "source",
                }:
                    raise _InvalidInput
                sources.append(item["source"])
        else:
            raise _InvalidInput
        for source in sources:
            try:
                checked = validate_source_recipe(source)
            except ReceiptError:
                raise _InvalidInput from None
            self._validate_relative_path(checked["relative_path"])

    def _read_context_file(self, relative_path: object) -> bytes:
        """Read one bounded regular file through no-follow directory descriptors."""

        self._validate_relative_path(relative_path)
        components = relative_path.split("/")  # type: ignore[union-attr]
        descriptor = os.dup(self._root_fd)
        try:
            for index, component in enumerate(components):
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if index < len(components) - 1:
                    flags |= os.O_DIRECTORY
                else:
                    flags |= getattr(os, "O_NONBLOCK", 0)
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise _InvalidInput
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, MAX_ASSEMBLY_PAYLOAD_BYTES - total + 1),
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ASSEMBLY_PAYLOAD_BYTES:
                    raise _InvalidInput
                chunks.append(chunk)
            if _status_fingerprint(os.fstat(descriptor)) != _status_fingerprint(
                before
            ):
                raise _InvalidInput
            return b"".join(chunks)
        except (OSError, OverflowError, UnicodeError):
            raise _InvalidInput from None
        finally:
            os.close(descriptor)

    def _externalize_capability_field(self, value: object) -> None:
        if type(value) is not dict or set(value).isdisjoint({"capability"}):
            raise _InvalidInput
        internal = value.get("capability")
        if not _valid_handle(internal, _INTERNAL_PREFIX):
            raise _InvalidInput
        external = self._store.externalize_handle(internal)  # type: ignore[arg-type]
        if not _valid_handle(external, _EXTERNAL_PREFIX):
            raise _InvalidInput
        value["capability"] = external

    def _externalized_deferred_bytes(self, raw: bytes) -> bytes:
        try:
            parsed = parse_canonical_json_bytes(raw, limits=_RESPONSE_JSON_LIMITS)
        except CanonicalJSONError:
            raise _InvalidInput from None
        if type(parsed) is not dict:
            raise _InvalidInput
        artifact_kind = parsed.get("artifact_kind")
        if artifact_kind == "evidence_reference":
            self._externalize_capability_field(parsed)
        elif artifact_kind == "evidence_pack":
            segments = parsed.get("segments")
            if type(segments) is not list:
                raise _InvalidInput
            for segment in segments:
                if type(segment) is not dict:
                    raise _InvalidInput
                if segment.get("kind") == "deferred":
                    self._externalize_capability_field(segment)
        elif artifact_kind == "typed_blueprint":
            blueprint = parsed.get("blueprint")
            if type(blueprint) is not dict:
                raise _InvalidInput
            self._externalize_capability_field(blueprint.get("bypass"))
            obligations = blueprint.get("obligations")
            if type(obligations) is not list:
                raise _InvalidInput
            for obligation in obligations:
                self._externalize_capability_field(obligation)
        elif artifact_kind == "tool_schema_bundle":
            self._externalize_capability_field(parsed.get("catalog_reference"))
            deferred = parsed.get("deferred")
            if type(deferred) is not list:
                raise _InvalidInput
            for item in deferred:
                self._externalize_capability_field(item)
        else:
            raise _InvalidInput
        return canonical_json_bytes(parsed, _RESPONSE_JSON_LIMITS)

    def _assemble(self, arguments: object) -> dict[str, object]:
        if type(arguments) is not dict or set(arguments) != {"descriptor", "kind"}:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        kind = arguments["kind"]
        descriptor = arguments["descriptor"]
        if kind not in ("evidence", "blueprint") or type(descriptor) is not dict:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            _walk_json(descriptor)
            self._revalidate_root()
            self._validate_descriptor_paths(descriptor)
            raw = canonical_json_bytes(descriptor, ASSEMBLY_DESCRIPTOR_LIMITS)
            if kind == "blueprint":
                result = assemble_blueprint(raw, root=self._root, store=self._store)
            elif descriptor.get("schema_version") == (
                "contextguard-receipt-evidence-pack-descriptor/v1"
            ):
                result = assemble_evidence_pack(
                    raw, root=self._root, store=self._store
                )
            else:
                result = assemble_evidence(raw, root=self._root, store=self._store)
            if self._store.source_binding_failed():
                self._poison_root()
                raise _InvalidInput
            if (
                result.disposition is AssemblyDisposition.PASS_THROUGH
                and type(result.receipt) is dict
                and result.receipt.get("reason")
                in {"identity_mismatch", "store_unavailable"}
            ):
                raise _InvalidInput
            output = (
                self._externalized_deferred_bytes(result.output_bytes)
                if result.disposition is AssemblyDisposition.DEFERRED
                else result.output_bytes
            )
            receipt = result.receipt
            self._revalidate_root()
            payload = _payload_bytes(
                kind="mcp_assembly_result",
                disposition=result.disposition.value,
                output=output,
                receipt=receipt,
            )
            return _call_result(
                payload,
                is_error=result.disposition is AssemblyDisposition.REFUSED,
            )
        except (AssemblyError, CanonicalJSONError, _InvalidInput, OSError, ValueError):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _context_artifact_bytes(
        self, capability: object, task_scope: object
    ) -> bytes:
        if not self._lease_matches(capability, task_scope):
            raise _InvalidInput
        internal = self._store.internalize_handle(capability)  # type: ignore[arg-type]
        expanded = expand_capability(internal, root=self._root, store=self._store)
        if expanded.disposition is not ExpansionDisposition.EXACT:
            raise _InvalidInput
        return expanded.output_bytes

    def _pack_capabilities(self, output: bytes) -> tuple[str, ...]:
        parsed = parse_canonical_json_bytes(output, limits=_RESPONSE_JSON_LIMITS)
        if type(parsed) is not dict or parsed.get("artifact_kind") != "evidence_pack":
            raise _InvalidInput
        segments = parsed.get("segments")
        if type(segments) is not list:
            raise _InvalidInput
        capabilities: list[str] = []
        for segment in segments:
            if type(segment) is not dict or segment.get("kind") not in {
                "retained",
                "deferred",
            }:
                raise _InvalidInput
            if segment.get("kind") != "deferred":
                continue
            capability = segment.get("capability")
            if not _valid_handle(capability, _EXTERNAL_PREFIX):
                raise _InvalidInput
            capabilities.append(capability)  # type: ignore[arg-type]
        if not capabilities:
            raise _InvalidInput
        return tuple(capabilities)

    def _pack(self, arguments: object) -> dict[str, object]:
        if type(arguments) is not dict or set(arguments) != {
            "sources",
            "retained_budget_bytes",
            "task_scope",
        }:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        sources = arguments.get("sources")
        retained_budget = arguments.get("retained_budget_bytes")
        task_scope = arguments.get("task_scope")
        if (
            type(sources) is not list
            or not sources
            or len(sources) > 16
            or any(
                type(source) is not dict
                or set(source) != {"capability", "relative_path"}
                or not _valid_handle(source.get("capability"), _EXTERNAL_PREFIX)
                or type(source.get("relative_path")) is not str
                for source in sources
            )
            or len({source["capability"] for source in sources}) != len(sources)
            or len({source["relative_path"] for source in sources}) != len(sources)
            or type(retained_budget) is not int
            or not 0 <= retained_budget <= MAX_ASSEMBLY_PAYLOAD_BYTES
            or type(task_scope) is not str
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            task_scope_hmac = self._task_scope_hmac(task_scope)
            if task_scope_hmac is None:
                raise _InvalidInput
            payload_parts: list[bytes] = []
            ranges: list[dict[str, object]] = []
            offset = 0
            retained = 0
            self._revalidate_root()
            for source_request in sources:
                capability = source_request["capability"]
                relative_path = source_request["relative_path"]
                authorized = any(
                    cache_key[0] == relative_path
                    and cache_key[3] == task_scope_hmac
                    and cache_entry.external_handle == capability
                    for cache_key, cache_entry in self._context_cache.items()
                )
                if not authorized:
                    raise _InvalidInput
                capability_bytes = self._context_artifact_bytes(
                    capability, task_scope
                )
                current_bytes = self._read_context_file(relative_path)
                if (
                    not capability_bytes
                    or not hmac.compare_digest(capability_bytes, current_bytes)
                    or offset + len(capability_bytes) > MAX_ASSEMBLY_PAYLOAD_BYTES
                ):
                    raise _InvalidInput
                mode = (
                    "retained"
                    if retained + len(capability_bytes) <= retained_budget
                    else "deferred"
                )
                if mode == "retained":
                    retained += len(capability_bytes)
                end = offset + len(capability_bytes)
                ranges.append(
                    {
                        "caller_classification": "eligible",
                        "detector_signals": [],
                        "end_byte": end,
                        "mode": mode,
                        "source": {
                            "relative_path": relative_path,
                            "selection": {"kind": "file"},
                        },
                        "start_byte": offset,
                    }
                )
                payload_parts.append(capability_bytes)
                offset = end
            descriptor = {
                "payload_b64u": _b64u(b"".join(payload_parts)),
                "ranges": ranges,
                "schema_version": "contextguard-receipt-evidence-pack-descriptor/v1",
            }
            result = self._assemble({"descriptor": descriptor, "kind": "evidence"})
            structured = result.get("structuredContent")
            if (
                type(structured) is dict
                and structured.get("disposition") == "deferred"
                and type(structured.get("output_b64u")) is str
            ):
                encoded = structured["output_b64u"].encode("ascii")
                output = base64.urlsafe_b64decode(
                    encoded + b"=" * ((4 - len(encoded) % 4) % 4)
                )
                for capability in self._pack_capabilities(output):
                    self._context_handles[capability] = _ContextLease(
                        scope_hmac_sha256=task_scope_hmac
                    )
            self._revalidate_root()
            return result
        except (CanonicalJSONError, _InvalidInput, OSError, ValueError):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _diagnose(self, arguments: object) -> dict[str, object]:
        required = {
            "caller_classification",
            "detector_signals",
            "relative_path",
        }
        optional = {"previous_capability", "task_scope"}
        if (
            type(arguments) is not dict
            or not required.issubset(arguments)
            or set(arguments) - required - optional
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        classification = arguments.get("caller_classification")
        signals = arguments.get("detector_signals")
        relative_path = arguments.get("relative_path")
        if (
            classification != "eligible"
            or type(signals) is not list
            or signals
            or type(relative_path) is not str
        ):
            return _call_result(_tool_error("context_not_eligible"), is_error=True)
        try:
            self._revalidate_root()
            task_scope_hmac = self._task_scope_hmac(arguments.get("task_scope"))
            payload = self._read_context_file(relative_path)
            if len(payload) > MAX_CONTEXT_DIAGNOSTIC_INPUT_BYTES:
                return _call_result(
                    _tool_error("diagnostic_input_too_large"), is_error=True
                )
            previous_capability = arguments.get("previous_capability")
            previous_prefix: bytes | None = None
            if previous_capability is not None:
                previous = self._context_artifact_bytes(
                    previous_capability, arguments.get("task_scope")
                )
                previous_prefix = previous[:65_536]
            diagnostic_request = {
                "blueprint_b64u": "",
                "caller_classification": classification,
                "current_prefix_b64u": _b64u(payload[:65_536]),
                "detector_signals": signals,
                "handle_b64u": _b64u(b"cgr1m_" + b"0" * 43),
                "input_b64u": _b64u(payload),
                "mandatory_expansion_b64u": "",
                "previous_prefix_b64u": (
                    None if previous_prefix is None else _b64u(previous_prefix)
                ),
                "retained_wire_b64u": _b64u(b"cgr1m_" + b"0" * 43),
                "schema_version": "contextguard-receipt-diagnostics-request/v1",
                "subject_kind": "evidence",
                "wrapper_b64u": _b64u(
                    b"contextguard-receipt-mcp-context-reference/v1"
                ),
            }
            raw = canonical_json_bytes(diagnostic_request, _RESPONSE_JSON_LIMITS)
            report = analyze_diagnostics(
                raw, fingerprint_key=self._context_hash_key
            ).report()
            advisory = report.get("advisory")
            lane = advisory.get("lane") if type(advisory) is dict else "none"
            reason = advisory.get("reason") if type(advisory) is dict else "invalid"
            self._record_context_history(
                action="diagnose",
                disposition=lane if type(lane) is str else "none",
                reason=reason if type(reason) is str else "invalid",
                relative_path=relative_path,
                task_scope_hmac_sha256=task_scope_hmac,
                capability=(
                    previous_capability
                    if type(previous_capability) is str
                    else None
                ),
                byte_length=len(payload),
            )
            self._revalidate_root()
            return _call_result(report, is_error=False)
        except (
            CanonicalJSONError,
            DiagnosticsError,
            StoreError,
            _InvalidInput,
            OSError,
            UnicodeError,
            ValueError,
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _twin(self, arguments: object) -> dict[str, object]:
        if self._state_dir is None:
            return _call_result(_tool_error("twin_unavailable"), is_error=True)
        if type(arguments) is not dict:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        action = arguments.get("action")
        try:
            self._revalidate_root()
            if action == "append" and set(arguments) == {
                "action",
                "observed_at_unix_ms",
                "request",
            }:
                observed_at = arguments.get("observed_at_unix_ms")
                request = arguments.get("request")
                if type(observed_at) is not int or type(request) is not dict:
                    raise _InvalidInput
                _walk_json(request)
                parsed = parse_twin_request(
                    canonical_json_bytes(request, _RESPONSE_JSON_LIMITS)
                )
                with ExecutionTwin.open(
                    self._state_dir, self._root, create=True
                ) as twin:
                    result = twin.append(parsed, observed_at)
            elif action == "inspect" and set(arguments) == {"action", "limit"}:
                limit = arguments.get("limit")
                if type(limit) is not int or not 1 <= limit <= 256:
                    raise _InvalidInput
                with ExecutionTwin.open(
                    self._state_dir, self._root, create=False
                ) as twin:
                    result = twin.inspect(limit)
            else:
                raise _InvalidInput
            self._revalidate_root()
            return _call_result(result, is_error=False)
        except ExecutionTwinError as error:
            return _call_result(_tool_error(error.code.value), is_error=True)
        except (
            CanonicalJSONError,
            _InvalidInput,
            OSError,
            UnicodeError,
            ValueError,
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _context_hmac(self, domain: bytes, value: str | None) -> str | None:
        if value is None:
            return None
        if type(value) is not str:
            raise _InvalidInput
        encoded = value.encode("utf-8", errors="strict")
        mac = hmac.new(self._context_hash_key, digestmod=hashlib.sha256)
        mac.update(domain)
        mac.update(len(encoded).to_bytes(8, "big"))
        mac.update(encoded)
        return mac.hexdigest()

    def _task_scope_hmac(self, value: object) -> str | None:
        if value is None:
            return None
        if (
            type(value) is not str
            or not value
            or "\0" in value
            or _FROZEN_UNICODE_DATABASE.normalize("NFC", value) != value
            or len(value.encode("utf-8", errors="strict")) > MAX_TASK_SCOPE_BYTES
        ):
            raise _InvalidInput
        return self._context_hmac(b"contextguard-receipt/mcp-task-scope/v1", value)

    def _record_context_history(
        self,
        *,
        action: str,
        disposition: str,
        reason: str,
        relative_path: str | None = None,
        task_scope_hmac_sha256: str | None = None,
        capability: str | None = None,
        byte_length: int | None = None,
    ) -> None:
        self._context_history_sequence += 1
        event: dict[str, object] = {
            "action": action,
            "byte_length": byte_length,
            "capability_hmac_sha256": self._context_hmac(
                b"contextguard-receipt/mcp-capability/v1", capability
            ),
            "disposition": disposition,
            "path_hmac_sha256": self._context_hmac(
                b"contextguard-receipt/mcp-relative-path/v1", relative_path
            ),
            "reason": reason,
            "sequence": self._context_history_sequence,
            "task_scope_hmac_sha256": task_scope_hmac_sha256,
        }
        self._context_history.append(event)
        if len(self._context_history) > MAX_CONTEXT_HISTORY_EVENTS:
            del self._context_history[: len(self._context_history) - MAX_CONTEXT_HISTORY_EVENTS]

    def _lease_matches(self, capability: object, task_scope: object) -> bool:
        if not _valid_handle(capability, _EXTERNAL_PREFIX):
            return False
        lease = self._context_handles.get(capability)  # type: ignore[arg-type]
        if lease is None:
            return False
        try:
            supplied = self._task_scope_hmac(task_scope)
        except (_InvalidInput, UnicodeError):
            return False
        expected = lease.scope_hmac_sha256
        if expected is None or supplied is None:
            return expected is supplied
        return hmac.compare_digest(expected, supplied)

    def _context_history_result(self, arguments: dict[str, object]) -> dict[str, object]:
        if set(arguments) != {"action", "limit"}:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        limit = arguments.get("limit")
        if type(limit) is not int or not 1 <= limit <= MAX_CONTEXT_HISTORY_RESULTS:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        return _call_result(
            {
                "advisory_only": True,
                "applied": False,
                "events": [dict(event) for event in self._context_history[-limit:]],
                "evidence_boundary": evidence_boundary(),
                "provider_claim_authority": False,
                "schema_version": "contextguard-receipt-mcp-context-history/v1",
            },
            is_error=False,
        )

    def _context_release(self, arguments: dict[str, object]) -> dict[str, object]:
        if set(arguments) not in (
            {"action", "capability"},
            {"action", "capability", "task_scope"},
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        capability = arguments.get("capability")
        task_scope = arguments.get("task_scope")
        if not self._lease_matches(capability, task_scope):
            return _call_result(_tool_error("capability_rejected"), is_error=True)
        lease = self._context_handles[capability]  # type: ignore[index]
        try:
            self._store.revoke_external(capability)
        except StoreError:
            return _call_result(_tool_error("capability_rejected"), is_error=True)
        self._context_handles.pop(capability, None)  # type: ignore[arg-type]
        for key, entry in tuple(self._context_cache.items()):
            if entry.external_handle == capability:
                self._context_cache.pop(key, None)
        self._record_context_history(
            action="release",
            disposition="released",
            reason="explicit_release",
            task_scope_hmac_sha256=lease.scope_hmac_sha256,
            capability=capability,  # type: ignore[arg-type]
        )
        return _call_result(
            {
                "advisory_only": False,
                "evidence_boundary": evidence_boundary(),
                "provider_claim_authority": False,
                "released": True,
                "schema_version": "contextguard-receipt-mcp-context-release/v1",
            },
            is_error=False,
        )

    def _context(self, arguments: object) -> dict[str, object]:
        if type(arguments) is dict and arguments.get("action") == "history":
            return self._context_history_result(arguments)
        if type(arguments) is dict and arguments.get("action") == "release":
            return self._context_release(arguments)
        if type(arguments) is dict and arguments.get("action") == "read":
            if set(arguments) not in (
                {"action", "capability", "max_bytes", "offset"},
                {"action", "capability", "max_bytes", "offset", "task_scope"},
            ):
                return _call_result(_tool_error("invalid_arguments"), is_error=True)
            capability = arguments.get("capability")
            offset = arguments.get("offset")
            max_bytes = arguments.get("max_bytes")
            if (
                not _valid_handle(capability, _EXTERNAL_PREFIX)
                or type(offset) is not int
                or offset < 0
                or offset > MAX_ASSEMBLY_PAYLOAD_BYTES
                or type(max_bytes) is not int
                or max_bytes < 1
                or max_bytes > MAX_CONTEXT_SLICE_BYTES
            ):
                return _call_result(_tool_error("invalid_arguments"), is_error=True)
            task_scope = arguments.get("task_scope")
            try:
                supplied_scope_hmac = self._task_scope_hmac(task_scope)
            except (_InvalidInput, UnicodeError):
                return _call_result(_tool_error("invalid_arguments"), is_error=True)
            if not self._lease_matches(capability, task_scope):
                self._record_context_history(
                    action="read",
                    disposition="refused",
                    reason="capability_rejected",
                    capability=capability if type(capability) is str else None,
                    task_scope_hmac_sha256=supplied_scope_hmac,
                )
                return _call_result(
                    _tool_error("capability_rejected"), is_error=True
                )
            try:
                self._revalidate_root()
                internal = self._store.internalize_handle(capability)
                expanded = expand_capability(
                    internal, root=self._root, store=self._store
                )
                if expanded.disposition is not ExpansionDisposition.EXACT:
                    return _call_result(
                        _tool_error("capability_rejected"), is_error=True
                    )
                total = len(expanded.output_bytes)
                if offset > total:
                    return _call_result(
                        _tool_error("invalid_arguments"), is_error=True
                    )
                end = min(total, offset + max_bytes)
                output = expanded.output_bytes[offset:end]
                lease = self._context_handles[capability]  # type: ignore[index]
                self._record_context_history(
                    action="read",
                    disposition="exact",
                    reason="bounded_slice",
                    task_scope_hmac_sha256=lease.scope_hmac_sha256,
                    capability=capability,  # type: ignore[arg-type]
                    byte_length=len(output),
                )
                self._revalidate_root()
                return _call_result(
                    _payload_bytes(
                        kind="mcp_context_slice",
                        disposition="exact",
                        output=output,
                        receipt={
                            "complete": end == total,
                            "end_byte": end,
                            "start_byte": offset,
                            "total_bytes": total,
                        },
                    ),
                    is_error=False,
                )
            except (StoreError, _InvalidInput, OSError, ValueError):
                return _call_result(
                    _tool_error("capability_rejected"), is_error=True
                )
            except Exception:
                return _call_result(_tool_error("operation_failed"), is_error=True)

        expected = {
            "action",
            "caller_classification",
            "detector_signals",
            "relative_path",
        }
        expected_with_scope = expected | {"task_scope"}
        if type(arguments) is not dict or set(arguments) not in (
            expected,
            expected_with_scope,
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        if arguments.get("action") != "store":
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        signals = arguments.get("detector_signals")
        if (
            type(signals) is not list
            or len(signals) > 64
            or any(type(signal) is not str for signal in signals)
            or len(set(signals)) != len(signals)
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            self._revalidate_root()
            relative_path = arguments.get("relative_path")
            classification = arguments.get("caller_classification")
            task_scope_hmac = self._task_scope_hmac(arguments.get("task_scope"))
            if type(relative_path) is not str or type(classification) is not str:
                raise _InvalidInput
            if classification != "eligible" or signals:
                self._record_context_history(
                    action="store",
                    disposition="refused",
                    reason="context_not_eligible",
                    relative_path=relative_path,
                    task_scope_hmac_sha256=task_scope_hmac,
                )
                return _call_result(
                    _tool_error("context_not_eligible"), is_error=True
                )
            cache_key = (
                relative_path,
                classification,
                tuple(signals),
                task_scope_hmac,
            )
            cached = self._context_cache.get(cache_key)
            if cached is not None:
                try:
                    self._store.internalize_handle(cached.external_handle)
                except StoreError:
                    self._context_cache.pop(cache_key, None)
                    self._context_handles.pop(cached.external_handle, None)
                else:
                    self._context_cache_hits += 1
                    self._record_context_history(
                        action="store",
                        disposition="deferred",
                        reason="cache_hit",
                        relative_path=relative_path,
                        task_scope_hmac_sha256=task_scope_hmac,
                        capability=cached.external_handle,
                    )
                    return cached.result
            payload = self._read_context_file(arguments.get("relative_path"))
            descriptor = {
                "caller_classification": classification,
                "detector_signals": signals,
                "payload_b64u": _b64u(payload),
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {
                    "relative_path": relative_path,
                    "selection": {"kind": "file"},
                },
            }
            result = self._assemble({"descriptor": descriptor, "kind": "evidence"})
            structured = result.get("structuredContent")
            if (
                type(structured) is dict
                and structured.get("disposition") == "deferred"
                and type(structured.get("output_b64u")) is str
            ):
                encoded = structured["output_b64u"].encode("ascii")
                raw = base64.urlsafe_b64decode(
                    encoded + b"=" * ((4 - len(encoded) % 4) % 4)
                )
                reference = parse_canonical_json_bytes(raw, limits=_RESPONSE_JSON_LIMITS)
                external = (
                    reference.get("capability")
                    if type(reference) is dict
                    else None
                )
                if not _valid_handle(external, _EXTERNAL_PREFIX):
                    raise _InvalidInput
                result = _call_result(
                    {
                        "artifact_kind": "mcp_context_reference",
                        "disposition": "deferred",
                        "evidence_boundary": evidence_boundary(),
                        "provider_claim_authority": False,
                        "receipt": structured.get("receipt"),
                        "reference": reference,
                        "schema_version": (
                            "contextguard-receipt-mcp-context-reference/v1"
                        ),
                    },
                    is_error=False,
                )
                self._context_cache[cache_key] = _ContextCacheEntry(
                    external_handle=external,
                    result=result,
                )
                self._context_handles[external] = _ContextLease(
                    scope_hmac_sha256=task_scope_hmac
                )
                self._record_context_history(
                    action="store",
                    disposition="deferred",
                    reason="beneficial",
                    relative_path=relative_path,
                    task_scope_hmac_sha256=task_scope_hmac,
                    capability=external,
                    byte_length=len(payload),
                )
            else:
                structured = result.get("structuredContent")
                disposition = (
                    structured.get("disposition")
                    if type(structured) is dict
                    else "refused"
                )
                self._record_context_history(
                    action="store",
                    disposition=(
                        disposition if type(disposition) is str else "refused"
                    ),
                    reason="unchanged_fallback",
                    relative_path=relative_path,
                    task_scope_hmac_sha256=task_scope_hmac,
                    byte_length=len(payload),
                )
            return result
        except (_InvalidInput, OSError, ValueError):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _record_tool_references(
        self, output: bytes, *, scope_hmac_sha256: str | None = None
    ) -> tuple[str, ...]:
        try:
            value = parse_canonical_json_bytes(output, limits=_RESPONSE_JSON_LIMITS)
        except CanonicalJSONError:
            return ()
        if type(value) is not dict:
            return ()
        catalog = value.get("catalog_reference")
        deferred = value.get("deferred")
        if type(catalog) is not dict or type(deferred) is not list:
            return ()
        capabilities: list[str] = []
        capability = catalog.get("capability")
        if _valid_handle(capability, _EXTERNAL_PREFIX):
            self._tool_references[capability] = (  # type: ignore[index]
                catalog,
                None,
                scope_hmac_sha256,
            )
            capabilities.append(capability)  # type: ignore[arg-type]
        for item in deferred:
            if type(item) is dict and _valid_handle(item.get("capability"), _EXTERNAL_PREFIX):
                self._tool_references[item["capability"]] = (  # type: ignore[index]
                    catalog,
                    item,
                    scope_hmac_sha256,
                )
                capabilities.append(item["capability"])  # type: ignore[arg-type]
        return tuple(capabilities)

    def _tool_profile_key(self, profile_id: object, task_scope_hmac: str) -> str:
        if (
            type(profile_id) is not str
            or not 1 <= len(profile_id) <= 64
            or not profile_id.isascii()
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                for character in profile_id
            )
        ):
            raise _InvalidInput
        mac = hmac.new(self._context_hash_key, digestmod=hashlib.sha256)
        for field in (
            b"contextguard-receipt/mcp-tool-profile/v1",
            profile_id.encode("ascii"),
            task_scope_hmac.encode("ascii"),
        ):
            mac.update(len(field).to_bytes(8, "big"))
            mac.update(field)
        return mac.hexdigest()

    def _tool_select(self, arguments: object) -> dict[str, object]:
        if (
            type(arguments) is not dict
            or "descriptor" not in arguments
            or set(arguments) - {"descriptor", "profile_id", "task_scope"}
            or (("profile_id" in arguments) != ("task_scope" in arguments))
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        descriptor = arguments["descriptor"]
        if type(descriptor) is not dict:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            _walk_json(descriptor)
            self._revalidate_root()
            raw = canonical_json_bytes(descriptor, TOOL_SCHEMA_DESCRIPTOR_LIMITS)
            profile_key: str | None = None
            task_scope_hmac: str | None = None
            if "profile_id" in arguments:
                task_scope_hmac = self._task_scope_hmac(arguments.get("task_scope"))
                if task_scope_hmac is None:
                    raise _InvalidInput
                profile_key = self._tool_profile_key(
                    arguments.get("profile_id"), task_scope_hmac
                )
                existing = self._tool_profiles.get(profile_key)
                descriptor_sha256 = hashlib.sha256(raw).hexdigest()
                if existing is not None:
                    if not hmac.compare_digest(
                        existing.descriptor_sha256, descriptor_sha256
                    ):
                        return _call_result(
                            _tool_error("profile_drift"), is_error=True
                        )
                    try:
                        for capability in existing.capabilities:
                            self._store.internalize_handle(capability)
                    except StoreError:
                        return _call_result(
                            _tool_error("profile_expired"), is_error=True
                        )
                    self._tool_profile_cache_hits += 1
                    return existing.result
            result = assemble_tool_schemas(raw, store=self._store)
            output = (
                self._externalized_deferred_bytes(result.output_bytes)
                if result.disposition is ToolSchemaDisposition.DEFERRED
                else result.output_bytes
            )
            receipt = result.receipt
            capabilities = self._record_tool_references(
                output, scope_hmac_sha256=task_scope_hmac
            )
            self._revalidate_root()
            payload = _payload_bytes(
                kind="mcp_tool_selection_result",
                disposition=result.disposition.value,
                output=output,
                receipt=receipt,
            )
            response = _call_result(
                payload,
                is_error=result.disposition is ToolSchemaDisposition.REFUSED,
            )
            if profile_key is not None:
                self._tool_profiles[profile_key] = _ToolProfileEntry(
                    descriptor_sha256=hashlib.sha256(raw).hexdigest(),
                    capabilities=capabilities,
                    result=response,
                )
            return response
        except (ToolSchemaError, CanonicalJSONError, _InvalidInput, ValueError):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _internalized_reference(self, value: dict[str, object]) -> dict[str, object]:
        result = dict(value)
        result["capability"] = self._store.internalize_handle(value.get("capability"))
        return result

    @staticmethod
    def _scope_hmac_matches(expected: str | None, supplied: str | None) -> bool:
        if expected is None or supplied is None:
            return expected is supplied
        return hmac.compare_digest(expected, supplied)

    def _expand(self, arguments: object) -> dict[str, object]:
        if (
            type(arguments) is not dict
            or not set(arguments) <= {"capability", "task_scope"}
            or "capability" not in arguments
        ):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        capability = arguments["capability"]
        task_scope = arguments.get("task_scope")
        if "task_scope" in arguments and type(task_scope) is not str:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        if not _valid_handle(capability, _EXTERNAL_PREFIX):
            return _call_result(_tool_error("capability_rejected"), is_error=True)
        try:
            self._revalidate_root()
            supplied_scope_hmac = self._task_scope_hmac(task_scope)
            references = self._tool_references.get(capability)  # type: ignore[arg-type]
            if references is not None:
                catalog, item, reference_scope_hmac = references
                if not self._scope_hmac_matches(
                    reference_scope_hmac, supplied_scope_hmac
                ):
                    return _call_result(_tool_error("capability_rejected"), is_error=True)
                internal_catalog = self._internalized_reference(catalog)
                result = (
                    expand_tool_schema_catalog(internal_catalog, store=self._store)
                    if item is None
                    else expand_tool_schema_item(
                        internal_catalog,
                        self._internalized_reference(item),
                        store=self._store,
                    )
                )
                exact = result.disposition is ToolSchemaExpansionDisposition.EXACT
                output = result.output_bytes if exact else b""
                reason = None if exact else result.refusal
            else:
                internal = self._store.internalize_handle(capability)
                stored = self._store.resolve(
                    internal, expected_root_identity_sha256=self._root_identity
                )
                lease = self._context_handles.get(capability)  # type: ignore[arg-type]
                expected_scope_hmac = (
                    lease.scope_hmac_sha256
                    if lease is not None
                    else stored.scope_hmac_sha256
                )
                if not self._scope_hmac_matches(
                    expected_scope_hmac, supplied_scope_hmac
                ):
                    return _call_result(_tool_error("capability_rejected"), is_error=True)
                result = expand_capability(internal, root=self._root, store=self._store)
                exact = result.disposition is ExpansionDisposition.EXACT
                output = result.output_bytes if exact else b""
                reason = None if exact else result.refusal
            if not exact:
                return _call_result(_tool_error("capability_rejected"), is_error=True)
            self._revalidate_root()
            return _call_result(
                _payload_bytes(
                    kind="mcp_expansion_result",
                    disposition="exact",
                    output=output,
                    receipt=reason,
                ),
                is_error=False,
            )
        except (StoreError, _InvalidInput, OSError, ValueError):
            return _call_result(_tool_error("capability_rejected"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _inspect(self, arguments: object) -> dict[str, object]:
        if type(arguments) is not dict or arguments:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            self._revalidate_root()
            count, total = self._store.inspect_counts()
            self._revalidate_root()
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)
        payload = {
            "artifact_count": count,
            "artifact_limit": MAX_ARTIFACTS,
            "context_cache_hits": self._context_cache_hits,
            "evidence_boundary": evidence_boundary(),
            "network_authority": False,
            "provider_claim_authority": False,
            "schema_version": "contextguard-receipt-mcp-inspection/v1",
            "scope": "process",
            "tool_profile_cache_hits": self._tool_profile_cache_hits,
            "total_artifact_bytes": total,
            "total_artifact_bytes_limit": MAX_TOTAL_ARTIFACT_BYTES,
        }
        return _call_result(payload, is_error=False)

    @staticmethod
    def _error(request_id: object, code: int, message: str) -> dict[str, object]:
        return {
            "error": {"code": code, "message": message},
            "id": request_id,
            "jsonrpc": "2.0",
        }

    @staticmethod
    def _response(request_id: object, result: dict[str, object]) -> dict[str, object]:
        return {"id": request_id, "jsonrpc": "2.0", "result": result}

    @staticmethod
    def _initialize_params(value: object) -> bool:
        if type(value) is not dict or set(value) - {
            "_meta",
            "capabilities",
            "clientInfo",
            "protocolVersion",
        }:
            return False
        if not {"capabilities", "clientInfo", "protocolVersion"}.issubset(value):
            return False
        info = value["clientInfo"]
        return bool(
            type(value["protocolVersion"]) is str
            and type(value["capabilities"]) is dict
            and type(info) is dict
            and type(info.get("name")) is str
            and type(info.get("version")) is str
            and ("_meta" not in value or type(value["_meta"]) is dict)
        )

    def handle(self, request: object) -> dict[str, object] | None:
        self._requests += 1
        if self._requests > MAX_FRAMES:
            return self._error(None, -32600, "Request limit reached")
        try:
            _walk_json(request)
        except Exception:
            return self._error(None, -32600, "Invalid Request")
        if (
            type(request) is not dict
            or set(request) - {"id", "jsonrpc", "method", "params"}
            or request.get("jsonrpc") != "2.0"
            or type(request.get("method")) is not str
            or ("params" in request and type(request["params"]) is not dict)
        ):
            return self._error(None, -32600, "Invalid Request")
        notification = "id" not in request
        request_id = request.get("id")
        if not notification:
            if not _valid_id(request_id):
                return self._error(None, -32600, "Invalid Request")
            marker = (type(request_id), request_id)
            if marker in self._seen_ids:
                return self._error(request_id, -32600, "Duplicate request id")
            self._seen_ids.add(marker)
        method = request["method"]
        params = request.get("params")

        if method == "initialize":
            if notification:
                return None
            if self._state != "PRE_INIT":
                return self._error(request_id, -32600, "Already initialized")
            if not self._initialize_params(params):
                return self._error(request_id, -32602, "Invalid params")
            requested = (
                params.get("protocolVersion", SUPPORTED_VERSIONS[0])
                if type(params) is dict
                else SUPPORTED_VERSIONS[0]
            )
            version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
            self._state = "WAIT_INITIALIZED"
            return self._response(
                request_id,
                {
                    "capabilities": {"tools": {"listChanged": False}},
                    "protocolVersion": version,
                    "serverInfo": {
                        "name": "context-guard-receipt",
                        "version": "1.3.0",
                    },
                },
            )
        if method == "notifications/initialized":
            if not notification:
                return self._error(request_id, -32601, "Method not found")
            if params not in (None, {}) or self._state != "WAIT_INITIALIZED":
                return None
            self._state = "READY"
            return None
        if self._state != "READY":
            return None if notification else self._error(
                request_id, -32002, "Server not initialized"
            )
        if method == "tools/list":
            valid = params is None or (
                type(params) is dict
                and set(params) <= {"_meta", "cursor"}
                and params.get("cursor") is None
                and ("_meta" not in params or type(params["_meta"]) is dict)
            )
            if not valid:
                return None if notification else self._error(
                    request_id, -32602, "Invalid params"
                )
            return None if notification else self._response(
                request_id, {"tools": _tool_definitions()}
            )
        if method != "tools/call":
            return None if notification else self._error(
                request_id, -32601, "Method not found"
            )
        if (
            type(params) is not dict
            or set(params) - {"_meta", "arguments", "name"}
            or type(params.get("name")) is not str
            or type(params.get("arguments", {})) is not dict
            or ("_meta" in params and type(params["_meta"]) is not dict)
            or params["name"] not in _TOOL_NAMES
        ):
            return None if notification else self._error(
                request_id, -32602, "Invalid params"
            )
        if notification:
            return None
        self._tool_calls += 1
        if self._tool_calls > MAX_TOOL_CALLS:
            result = _call_result(_tool_error("call_limit_reached"), is_error=True)
            return self._response(request_id, result)
        if not self._call_lock.acquire(blocking=False):
            result = _call_result(_tool_error("concurrency_limit_reached"), is_error=True)
            return self._response(request_id, result)
        try:
            try:
                self._revalidate_root()
                arguments = params.get("arguments", {})
                if params["name"] == "receipt_assemble":
                    result = self._assemble(arguments)
                elif params["name"] == "receipt_context":
                    result = self._context(arguments)
                elif params["name"] == "receipt_diagnose":
                    result = self._diagnose(arguments)
                elif params["name"] == "receipt_expand":
                    result = self._expand(arguments)
                elif params["name"] == "receipt_pack":
                    result = self._pack(arguments)
                elif params["name"] == "receipt_tool_select":
                    result = self._tool_select(arguments)
                elif params["name"] == "receipt_twin":
                    result = self._twin(arguments)
                else:
                    result = self._inspect(arguments)
                self._revalidate_root()
            except Exception:
                result = _call_result(_tool_error("operation_failed"), is_error=True)
        finally:
            self._call_lock.release()
        return self._response(request_id, result)

    def serve(
        self,
        input_stream: BinaryIO | TextIO,
        output_stream: BinaryIO | TextIO,
    ) -> int:
        while self._frames < MAX_FRAMES:
            line = input_stream.readline(MAX_FRAME_BYTES + 2)  # type: ignore[call-arg]
            if line in (b"", ""):
                return 0
            self._frames += 1
            raw = line.encode("utf-8") if type(line) is str else line
            if (
                type(raw) is not bytes
                or len(raw) > MAX_FRAME_BYTES + 1
                or not raw.endswith(b"\n")
                or len(raw[:-1]) > MAX_FRAME_BYTES
                or raw.endswith(b"\r\n")
            ):
                return 1
            payload = raw[:-1]
            try:
                def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
                    result: dict[str, object] = {}
                    for key, value in items:
                        if key in result:
                            raise _DuplicateKey
                        result[key] = value
                    return result

                request = json.loads(
                    payload.decode("utf-8"),
                    object_pairs_hook=pairs,
                    parse_float=lambda _value: (_ for _ in ()).throw(_InvalidInput()),
                    parse_constant=lambda _value: (_ for _ in ()).throw(_InvalidInput()),
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = self._error(None, -32700, "Parse error")
            except Exception:
                response = self._error(None, -32600, "Invalid Request")
            else:
                response = self.handle(request)
            if response is None:
                continue
            try:
                encoded = canonical_json_bytes(response, _RESPONSE_JSON_LIMITS)
            except Exception:
                encoded = canonical_json_bytes(
                    self._error(None, -32603, "Internal error"),
                    _RESPONSE_JSON_LIMITS,
                )
            if len(encoded) > MAX_RESPONSE_BYTES:
                encoded = canonical_json_bytes(
                    self._error(response.get("id"), -32603, "Response too large"),
                    _RESPONSE_JSON_LIMITS,
                )
            try:
                try:
                    output_stream.write(encoded)  # type: ignore[arg-type]
                except TypeError:
                    output_stream.write(encoded.decode("ascii"))  # type: ignore[arg-type]
                output_stream.flush()
            except (BrokenPipeError, OSError, TypeError, UnicodeError):
                return 1
        return 1

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._context_cache.clear()
        self._context_handles.clear()
        self._context_history.clear()
        self._context_hash_key = b""
        self._state_dir = None
        self._tool_references.clear()
        self._tool_profiles.clear()
        self._store.close()
        os.close(self._root_fd)

    def __enter__(self) -> "MCPServer":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def serve(
    server: MCPServer,
    input_stream: BinaryIO | TextIO,
    output_stream: BinaryIO | TextIO,
) -> int:
    if type(server) is not MCPServer:
        raise ValueError("invalid MCP server")
    return server.serve(input_stream, output_stream)


def serve_stdio(root: str, *, state_dir: str | None = None) -> int:
    try:
        server = MCPServer(root, state_dir=state_dir)
    except Exception:
        return 70
    try:
        return server.serve(sys.stdin.buffer, sys.stdout.buffer)
    finally:
        server.close()
