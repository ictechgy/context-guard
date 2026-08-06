"""Bounded, provider-free NDJSON MCP server for one pinned repository root."""

from __future__ import annotations

import base64
import hashlib
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
    "receipt_expand",
    "receipt_inspect",
    "receipt_tool_select",
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
            "annotations": {**annotations, "readOnlyHint": True},
            "description": "Expand one process-local exact capability.",
            "inputSchema": {
                **closed,
                "properties": {
                    "capability": {
                        "pattern": "^cgr1m_[A-Za-z0-9_-]{43}$",
                        "type": "string",
                    }
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
            "description": "Select a bounded tool-schema catalog beneath the pinned root.",
            "inputSchema": {
                **closed,
                "properties": {"descriptor": {"type": "object"}},
                "required": ["descriptor"],
            },
            "name": "receipt_tool_select",
        },
    ]


class MCPServer:
    """One-root, one-process MCP state machine."""

    def __init__(
        self, root: str, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if (
            type(root) is not str
            or not root
            or "\0" in root
            or not os.path.isabs(root)
            or os.path.normpath(root) != root
            or os.path.realpath(root) != root
            or not callable(clock)
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
        self._tool_references: dict[str, tuple[dict[str, object], dict[str, object] | None]] = {}

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

    def _record_tool_references(self, output: bytes) -> None:
        try:
            value = parse_canonical_json_bytes(output, limits=_RESPONSE_JSON_LIMITS)
        except CanonicalJSONError:
            return
        if type(value) is not dict:
            return
        catalog = value.get("catalog_reference")
        deferred = value.get("deferred")
        if type(catalog) is not dict or type(deferred) is not list:
            return
        capability = catalog.get("capability")
        if _valid_handle(capability, _EXTERNAL_PREFIX):
            self._tool_references[capability] = (catalog, None)  # type: ignore[index]
        for item in deferred:
            if type(item) is dict and _valid_handle(item.get("capability"), _EXTERNAL_PREFIX):
                self._tool_references[item["capability"]] = (catalog, item)  # type: ignore[index]

    def _tool_select(self, arguments: object) -> dict[str, object]:
        if type(arguments) is not dict or set(arguments) != {"descriptor"}:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        descriptor = arguments["descriptor"]
        if type(descriptor) is not dict:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        try:
            _walk_json(descriptor)
            self._revalidate_root()
            raw = canonical_json_bytes(descriptor, TOOL_SCHEMA_DESCRIPTOR_LIMITS)
            result = assemble_tool_schemas(raw, store=self._store)
            output = (
                self._externalized_deferred_bytes(result.output_bytes)
                if result.disposition is ToolSchemaDisposition.DEFERRED
                else result.output_bytes
            )
            receipt = result.receipt
            self._record_tool_references(output)
            self._revalidate_root()
            payload = _payload_bytes(
                kind="mcp_tool_selection_result",
                disposition=result.disposition.value,
                output=output,
                receipt=receipt,
            )
            return _call_result(
                payload,
                is_error=result.disposition is ToolSchemaDisposition.REFUSED,
            )
        except (ToolSchemaError, CanonicalJSONError, _InvalidInput, ValueError):
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        except Exception:
            return _call_result(_tool_error("operation_failed"), is_error=True)

    def _internalized_reference(self, value: dict[str, object]) -> dict[str, object]:
        result = dict(value)
        result["capability"] = self._store.internalize_handle(value.get("capability"))
        return result

    def _expand(self, arguments: object) -> dict[str, object]:
        if type(arguments) is not dict or set(arguments) != {"capability"}:
            return _call_result(_tool_error("invalid_arguments"), is_error=True)
        capability = arguments["capability"]
        if not _valid_handle(capability, _EXTERNAL_PREFIX):
            return _call_result(_tool_error("capability_rejected"), is_error=True)
        try:
            self._revalidate_root()
            references = self._tool_references.get(capability)  # type: ignore[arg-type]
            if references is not None:
                catalog, item = references
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
            "evidence_boundary": evidence_boundary(),
            "network_authority": False,
            "provider_claim_authority": False,
            "schema_version": "contextguard-receipt-mcp-inspection/v1",
            "scope": "process",
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
                        "version": "1.0.0",
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
                elif params["name"] == "receipt_expand":
                    result = self._expand(arguments)
                elif params["name"] == "receipt_tool_select":
                    result = self._tool_select(arguments)
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


def serve_stdio(root: str) -> int:
    try:
        server = MCPServer(root)
    except Exception:
        return 70
    try:
        return server.serve(sys.stdin.buffer, sys.stdout.buffer)
    finally:
        server.close()
