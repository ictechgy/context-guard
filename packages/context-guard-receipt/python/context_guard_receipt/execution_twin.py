"""Provider-free, append-only revalidation evidence for a declared next action."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import logging
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Final, Iterator

from . import store as _filesystem
from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    framed_sha256_hex,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .identity import IdentityError, snapshot_repository


__all__ = [
    "ExecutionTwin",
    "ExecutionTwinError",
    "ExecutionTwinErrorCode",
    "parse_twin_request",
]


_LOGGER = logging.getLogger(__name__)

_TOP_LOCK_NAME: Final = "lock"
_AUXILIARY_NAME: Final = "auxiliary-v1"
_AUXILIARY_METADATA_NAME: Final = "metadata.json"
_DIAGNOSTICS_NAME: Final = "diagnostics-v1"
_TWIN_NAME: Final = "twin-v1"
_REFERENCE_EXPIRY_NAME: Final = "reference-expiry-v1"
_TWIN_LOCK_NAME: Final = "lock"
_KEY_NAME: Final = "key"
_METADATA_NAME: Final = "metadata.json"
_EVENTS_NAME: Final = "events.log"

_AUXILIARY_SCHEMA_VERSION: Final = "contextguard-receipt-auxiliary-metadata/v1"
_REQUEST_SCHEMA_VERSION: Final = "contextguard-receipt-twin-request/v1"
_RESULT_SCHEMA_VERSION: Final = "contextguard-receipt-twin-result/v1"
_EVENT_SCHEMA_VERSION: Final = "contextguard-receipt-twin-event/v1"
_METADATA_SCHEMA_VERSION: Final = "contextguard-receipt-twin-metadata/v1"
_SNAPSHOT_SCHEMA_VERSION: Final = "contextguard-receipt-twin-snapshot/v1"

_MAX_REQUEST_BYTES: Final = 64 * 1024
_MAX_RESULT_BYTES: Final = 64 * 1024
_MAX_EVENT_BYTES: Final = 16_384
_MAX_EVENT_COUNT: Final = 1024
_MAX_COMMITTED_LOG_BYTES: Final = 8 * 1024 * 1024
_MAX_METADATA_BYTES: Final = 4096
_MAX_FILE_BYTES: Final = 1024 * 1024
_MAX_PATH_BYTES: Final = 4096
_MAX_DIRECTORY_ENTRIES: Final = 4096
_MAX_PREDICATES: Final = 32
_LOCK_TIMEOUT_SECONDS: Final = 5.0
_MAX_UNIX_MS: Final = 4_102_444_800_000

_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_MODE_PATTERN = re.compile(r"[0-7]{4}\Z")
_AUXILIARY_TEMP_PATTERN = re.compile(r"\.auxiliary-v1\.tmp-[0-9a-f]{32}\Z")
_TWIN_TEMP_PATTERN = re.compile(r"\.twin-v1\.tmp-[0-9a-f]{32}\Z")
_METADATA_TEMP_PATTERN = re.compile(r"\.metadata\.json\.tmp-[0-9a-f]{32}\Z")
_FROZEN_UNICODE_DATABASE = unicodedata.ucd_3_2_0

_REQUEST_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_REQUEST_BYTES,
    max_depth=5,
    max_total_values=512,
    max_object_members=16,
    max_string_bytes=_MAX_PATH_BYTES,
)
_RESULT_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_RESULT_BYTES,
    max_depth=5,
    max_total_values=512,
    max_object_members=32,
    max_string_bytes=256,
)
_EVENT_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_EVENT_BYTES,
    max_depth=5,
    max_total_values=512,
    max_object_members=32,
    max_string_bytes=256,
)
_METADATA_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_METADATA_BYTES,
    max_depth=3,
    max_total_values=64,
    max_object_members=24,
    max_string_bytes=128,
)

_AUXILIARY_METADATA: Final[dict[str, object]] = {
    "evidence_boundary": evidence_boundary(),
    "schema_version": _AUXILIARY_SCHEMA_VERSION,
}

_PREDICATE_FIELDS: Final[dict[str, frozenset[str]]] = {
    "repository_instance_equals": frozenset({"expected_sha256", "kind"}),
    "git_logical_state_equals": frozenset({"expected_sha256", "kind"}),
    "regular_file_equals": frozenset(
        {
            "expected_content_sha256",
            "expected_length_bytes",
            "expected_mode",
            "kind",
            "relative_path",
        }
    ),
    "path_absent": frozenset({"kind", "relative_path"}),
}

_EVENT_FIELDS: Final = frozenset(
    {
        "declared_next_action_sha256",
        "event_hmac_sha256",
        "event_id",
        "event_sequence",
        "event_sha256",
        "matched_predicate_count",
        "namespace_id",
        "observed_at_unix_ms",
        "predicate_count",
        "predicate_results",
        "previous_event_hmac_sha256",
        "repository_instance_sha256_after",
        "repository_instance_sha256_before",
        "repository_state_sha256_after",
        "repository_state_sha256_before",
        "schema_version",
        "verified",
    }
)


class ExecutionTwinErrorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    INVALID_ARGUMENT = "invalid_argument"
    STATE_DIR_REQUIRED = "state_dir_required"
    STATE_DIR_NOT_ABSOLUTE = "state_dir_not_absolute"
    STATE_DIR_NOT_NORMALIZED = "state_dir_not_normalized"
    FILESYSTEM_UNSUPPORTED = "filesystem_unsupported"
    UNSAFE_STATE = "unsafe_state"
    LOCK_TIMEOUT = "lock_timeout"
    TWIN_UNINITIALIZED = "twin_uninitialized"
    TWIN_CORRUPT = "twin_corrupt"
    TWIN_TAMPERED = "twin_tampered"
    RECOVERY_REQUIRED = "recovery_required"
    CAS_MISMATCH = "cas_mismatch"
    COUNT_QUOTA_EXCEEDED = "count_quota_exceeded"
    BYTE_QUOTA_EXCEEDED = "byte_quota_exceeded"
    EVENT_TOO_LARGE = "event_too_large"
    WRITE_FAILED = "write_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"


class ExecutionTwinError(ValueError):
    """Stable, non-reflective execution-twin failure."""

    __slots__ = ("code",)

    def __init__(self, code: ExecutionTwinErrorCode) -> None:
        self.code = code
        super().__init__(f"execution twin rejected: {code.value}")


def _raise(code: ExecutionTwinErrorCode) -> None:
    raise ExecutionTwinError(code) from None


_STORE_ERROR_MAP: Final[dict[str, ExecutionTwinErrorCode]] = {
    "invalid_argument": ExecutionTwinErrorCode.INVALID_ARGUMENT,
    "state_dir_required": ExecutionTwinErrorCode.STATE_DIR_REQUIRED,
    "state_dir_not_absolute": ExecutionTwinErrorCode.STATE_DIR_NOT_ABSOLUTE,
    "state_dir_not_normalized": ExecutionTwinErrorCode.STATE_DIR_NOT_NORMALIZED,
    "state_dir_forbidden": ExecutionTwinErrorCode.UNSAFE_STATE,
    "filesystem_unsupported": ExecutionTwinErrorCode.FILESYSTEM_UNSUPPORTED,
    "unsafe_state": ExecutionTwinErrorCode.UNSAFE_STATE,
    "store_uninitialized": ExecutionTwinErrorCode.TWIN_UNINITIALIZED,
    "store_corrupt": ExecutionTwinErrorCode.TWIN_CORRUPT,
    "store_tampered": ExecutionTwinErrorCode.TWIN_TAMPERED,
    "recovery_required": ExecutionTwinErrorCode.RECOVERY_REQUIRED,
    "write_failed": ExecutionTwinErrorCode.WRITE_FAILED,
    "commit_uncertain": ExecutionTwinErrorCode.COMMIT_UNCERTAIN,
}


@dataclass(frozen=True, slots=True)
class _Metadata:
    namespace_id: str
    repository_instance_sha256: str
    genesis_hmac_sha256: str
    committed_event_count: int
    committed_log_bytes: int
    committed_head_hmac_sha256: str


@dataclass(frozen=True, slots=True)
class _ScannedLog:
    events: list[dict[str, object]]
    recovery_required: bool


@dataclass(frozen=True, slots=True)
class _RepositoryObservation:
    disposition: str
    logical_kind: str
    instance_sha256: str
    state_sha256: str


def _translate_store_error(error: _filesystem.StoreError) -> None:
    _raise(_STORE_ERROR_MAP.get(error.code.value, ExecutionTwinErrorCode.UNSAFE_STATE))


def _require_filesystem_features() -> None:
    try:
        _filesystem._require_filesystem_features()
    except _filesystem.StoreError as error:
        _translate_store_error(error)
    for function in (getattr(os, "pread", None), getattr(os, "pwrite", None), getattr(os, "ftruncate", None)):
        if not callable(function):
            _raise(ExecutionTwinErrorCode.FILESYSTEM_UNSUPPORTED)


def _validate_state_path(value: object) -> str:
    try:
        return _filesystem._validate_state_path(value)
    except _filesystem.StoreError as error:
        _translate_store_error(error)


def _check_disjoint(state_path: str, repository_root: object) -> tuple[int, ...]:
    try:
        return _filesystem._check_disjoint(state_path, repository_root, None)
    except _filesystem.StoreError as error:
        _translate_store_error(error)


def _open_state_directory(path: str, *, create: bool) -> int:
    try:
        return _filesystem._open_absolute_state_directory(path, create=create)
    except _filesystem.StoreError as error:
        _translate_store_error(error)


def _require_disjoint(state_fd: int, exclusion_fds: tuple[int, ...]) -> None:
    try:
        _filesystem._require_physical_disjoint(
            state_fd,
            state_complete=True,
            exclusion_descriptors=exclusion_fds,
        )
    except _filesystem.StoreError as error:
        _translate_store_error(error)


def _close_descriptors(descriptors: tuple[int, ...] | list[int]) -> None:
    _filesystem._close_directory_descriptors(descriptors)


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _file_read_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def _descriptor_status(
    descriptor: object,
    *,
    error_code: ExecutionTwinErrorCode = ExecutionTwinErrorCode.UNSAFE_STATE,
) -> os.stat_result:
    if type(descriptor) is not int or descriptor < 0:
        _raise(error_code)
    try:
        return os.fstat(descriptor)
    except OSError:
        _raise(error_code)


def _private_directory(status: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o700
    )


def _private_file(status: os.stat_result) -> bool:
    return (
        stat.S_ISREG(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o600
        and status.st_nlink == 1
    )


def _require_directory_descriptor(descriptor: object) -> int:
    checked = descriptor if type(descriptor) is int else -1
    if not stat.S_ISDIR(_descriptor_status(checked).st_mode):
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    return checked


def _require_private_file_descriptor(descriptor: object) -> int:
    checked = descriptor if type(descriptor) is int else -1
    if not _private_file(_descriptor_status(checked)):
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    return checked


def _open_directory_at(parent_fd: int, name: str) -> int:
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=_require_directory_descriptor(parent_fd))
    except OSError:
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    try:
        if not _private_directory(_descriptor_status(descriptor)):
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_private_file(
    parent_fd: int,
    name: str,
    *,
    writable: bool = False,
    missing: ExecutionTwinErrorCode = ExecutionTwinErrorCode.TWIN_CORRUPT,
) -> int:
    flags = (
        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        if writable
        else _file_read_flags()
    )
    try:
        descriptor = os.open(name, flags, dir_fd=_require_directory_descriptor(parent_fd))
    except FileNotFoundError:
        _raise(missing)
    except OSError:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
    try:
        if not _private_file(_descriptor_status(descriptor)):
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _bounded_names(
    descriptor: int,
    maximum: int,
    *,
    overflow: ExecutionTwinErrorCode = ExecutionTwinErrorCode.TWIN_CORRUPT,
) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(_require_directory_descriptor(descriptor)) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    _raise(overflow)
    except ExecutionTwinError:
        raise
    except OSError:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
    return names


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, maximum - total + 1))
        except InterruptedError:
            continue
        except OSError:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
        chunks.append(chunk)


def _read_named_file(parent_fd: int, name: str, maximum: int) -> bytes:
    descriptor = _open_private_file(parent_fd, name)
    try:
        before = _descriptor_status(descriptor, error_code=ExecutionTwinErrorCode.TWIN_CORRUPT)
        raw = _read_all(descriptor, maximum)
        after = _descriptor_status(descriptor, error_code=ExecutionTwinErrorCode.TWIN_CORRUPT)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or len(raw) != after.st_size:
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        return raw
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        try:
            written = os.write(descriptor, raw[offset:])
        except InterruptedError:
            continue
        except OSError:
            _raise(ExecutionTwinErrorCode.WRITE_FAILED)
        if written <= 0:
            _raise(ExecutionTwinErrorCode.WRITE_FAILED)
        offset += written


def _write_new_file(parent_fd: int, name: str, raw: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=_require_directory_descriptor(parent_fd),
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if not _private_file(status) or status.st_size != len(raw):
            _raise(ExecutionTwinErrorCode.WRITE_FAILED)
    except ExecutionTwinError:
        raise
    except OSError:
        _raise(ExecutionTwinErrorCode.WRITE_FAILED)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _hmac_hex(key: bytes, domain: bytes, raw: bytes) -> str:
    return hmac.new(key, domain + b"\0" + raw, hashlib.sha256).hexdigest()


def _derive_key(master_key: bytes, domain: bytes) -> bytes:
    return hmac.new(master_key, domain + b"\0", hashlib.sha256).digest()


def _valid_hash(value: object) -> bool:
    return type(value) is str and _HEX_256.fullmatch(value) is not None


def _validate_relative_path(value: object) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\0" in value or "\\" in value:
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    if len(raw) > _MAX_PATH_BYTES or _FROZEN_UNICODE_DATABASE.normalize("NFC", value) != value:
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    if any(_FROZEN_UNICODE_DATABASE.category(character) == "Cn" for character in value):
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    return value


def _validate_request_value(value: object, error_code: ExecutionTwinErrorCode) -> dict[str, object]:
    def reject() -> None:
        _raise(error_code)

    if type(value) is not dict or set(value) != {
        "declared_next_action_sha256",
        "expected_tail",
        "predicates",
        "schema_version",
    }:
        reject()
    if value.get("schema_version") != _REQUEST_SCHEMA_VERSION or not _valid_hash(
        value.get("declared_next_action_sha256")
    ):
        reject()
    expected_tail = value.get("expected_tail")
    if expected_tail is not None:
        if type(expected_tail) is not dict or set(expected_tail) != {
            "event_hmac_sha256",
            "event_sequence",
            "namespace_id",
        }:
            reject()
        if (
            not _valid_hash(expected_tail.get("event_hmac_sha256"))
            or not _valid_hash(expected_tail.get("namespace_id"))
            or type(expected_tail.get("event_sequence")) is not int
            or not 1 <= expected_tail["event_sequence"] <= _MAX_EVENT_COUNT
        ):
            reject()
        checked_tail: dict[str, object] | None = dict(expected_tail)
    else:
        checked_tail = None

    predicates = value.get("predicates")
    if type(predicates) is not list or not 1 <= len(predicates) <= _MAX_PREDICATES:
        reject()
    checked_predicates: list[dict[str, object]] = []
    for predicate in predicates:
        if type(predicate) is not dict:
            reject()
        kind = predicate.get("kind")
        expected_fields = _PREDICATE_FIELDS.get(kind) if type(kind) is str else None
        if expected_fields is None or set(predicate) != expected_fields:
            reject()
        checked = dict(predicate)
        if kind in ("repository_instance_equals", "git_logical_state_equals"):
            if not _valid_hash(predicate.get("expected_sha256")):
                reject()
        elif kind == "path_absent":
            try:
                checked["relative_path"] = _validate_relative_path(predicate.get("relative_path"))
            except ExecutionTwinError:
                reject()
        else:
            try:
                checked["relative_path"] = _validate_relative_path(predicate.get("relative_path"))
            except ExecutionTwinError:
                reject()
            if (
                not _valid_hash(predicate.get("expected_content_sha256"))
                or type(predicate.get("expected_length_bytes")) is not int
                or not 0 <= predicate["expected_length_bytes"] <= _MAX_FILE_BYTES
                or type(predicate.get("expected_mode")) is not str
                or _MODE_PATTERN.fullmatch(predicate["expected_mode"]) is None
            ):
                reject()
        checked_predicates.append(checked)
    return {
        "declared_next_action_sha256": value["declared_next_action_sha256"],
        "expected_tail": checked_tail,
        "predicates": checked_predicates,
        "schema_version": _REQUEST_SCHEMA_VERSION,
    }


def parse_twin_request(raw: bytes) -> dict[str, object]:
    """Parse the one canonical, closed, bounded twin request encoding."""

    if type(raw) is not bytes:
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    try:
        value = parse_canonical_json_bytes(raw, _REQUEST_LIMITS)
    except CanonicalJSONError:
        _raise(ExecutionTwinErrorCode.INVALID_REQUEST)
    return _validate_request_value(value, ExecutionTwinErrorCode.INVALID_REQUEST)


def _canonical_metadata(value: object) -> bytes:
    try:
        return canonical_json_bytes(value, _METADATA_LIMITS)
    except CanonicalJSONError:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)


def _metadata_document(
    metadata_key: bytes,
    *,
    namespace_id: str,
    repository_instance_sha256: str,
    genesis_hmac_sha256: str,
    committed_event_count: int = 0,
    committed_log_bytes: int = 0,
    committed_head_hmac_sha256: str | None = None,
) -> bytes:
    value: dict[str, object] = {
        "committed_event_count": committed_event_count,
        "committed_head_hmac_sha256": (
            genesis_hmac_sha256
            if committed_head_hmac_sha256 is None
            else committed_head_hmac_sha256
        ),
        "committed_log_bytes": committed_log_bytes,
        "evidence_boundary": evidence_boundary(),
        "genesis_hmac_sha256": genesis_hmac_sha256,
        "integrity_hmac_sha256": "",
        "max_committed_log_bytes": _MAX_COMMITTED_LOG_BYTES,
        "max_event_bytes": _MAX_EVENT_BYTES,
        "max_event_count": _MAX_EVENT_COUNT,
        "namespace_id": namespace_id,
        "repository_instance_sha256": repository_instance_sha256,
        "schema_version": _METADATA_SCHEMA_VERSION,
    }
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256")
    value["integrity_hmac_sha256"] = _hmac_hex(
        metadata_key,
        b"contextguard-receipt/twin-metadata-mac/v1",
        _canonical_metadata(unsigned),
    )
    return _canonical_metadata(value)


def _parse_metadata(
    raw: bytes,
    *,
    master_key: bytes,
    expected_repository_instance_sha256: str,
) -> _Metadata:
    try:
        value = parse_canonical_json_bytes(raw, _METADATA_LIMITS)
    except CanonicalJSONError:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
    expected_fields = {
        "committed_event_count",
        "committed_head_hmac_sha256",
        "committed_log_bytes",
        "evidence_boundary",
        "genesis_hmac_sha256",
        "integrity_hmac_sha256",
        "max_committed_log_bytes",
        "max_event_bytes",
        "max_event_count",
        "namespace_id",
        "repository_instance_sha256",
        "schema_version",
    }
    if type(value) is not dict or set(value) != expected_fields:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
    count = value.get("committed_event_count")
    log_bytes = value.get("committed_log_bytes")
    if (
        value.get("schema_version") != _METADATA_SCHEMA_VERSION
        or value.get("evidence_boundary") != evidence_boundary()
        or value.get("max_event_count") != _MAX_EVENT_COUNT
        or value.get("max_event_bytes") != _MAX_EVENT_BYTES
        or value.get("max_committed_log_bytes") != _MAX_COMMITTED_LOG_BYTES
        or not _valid_hash(value.get("namespace_id"))
        or not _valid_hash(value.get("repository_instance_sha256"))
        or not _valid_hash(value.get("genesis_hmac_sha256"))
        or not _valid_hash(value.get("committed_head_hmac_sha256"))
        or not _valid_hash(value.get("integrity_hmac_sha256"))
        or type(count) is not int
        or not 0 <= count <= _MAX_EVENT_COUNT
        or type(log_bytes) is not int
        or not 0 <= log_bytes <= _MAX_COMMITTED_LOG_BYTES
        or (count == 0 and log_bytes != 0)
    ):
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)

    namespace_id = value["namespace_id"]
    repository_instance = value["repository_instance_sha256"]
    expected_namespace = framed_sha256_hex(
        "contextguard-receipt/twin-namespace/v1",
        master_key,
        bytes.fromhex(repository_instance),
    )
    if not hmac.compare_digest(namespace_id, expected_namespace):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    metadata_key = _derive_key(master_key, b"contextguard-receipt/twin-metadata-key/v1")
    unsigned = dict(value)
    supplied_hmac = unsigned.pop("integrity_hmac_sha256")
    expected_hmac = _hmac_hex(
        metadata_key,
        b"contextguard-receipt/twin-metadata-mac/v1",
        _canonical_metadata(unsigned),
    )
    if not hmac.compare_digest(supplied_hmac, expected_hmac):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    genesis_value = {
        "namespace_id": namespace_id,
        "repository_instance_sha256": repository_instance,
    }
    expected_genesis = _hmac_hex(
        _derive_key(master_key, b"contextguard-receipt/twin-event-key/v1"),
        b"contextguard-receipt/twin-genesis/v1",
        canonical_json_bytes(genesis_value, _METADATA_LIMITS),
    )
    if not hmac.compare_digest(value["genesis_hmac_sha256"], expected_genesis):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    if count == 0 and value["committed_head_hmac_sha256"] != expected_genesis:
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    if repository_instance != expected_repository_instance_sha256:
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    return _Metadata(
        namespace_id=namespace_id,
        repository_instance_sha256=repository_instance,
        genesis_hmac_sha256=expected_genesis,
        committed_event_count=count,
        committed_log_bytes=log_bytes,
        committed_head_hmac_sha256=value["committed_head_hmac_sha256"],
    )


def _snapshot_observation(root: str) -> _RepositoryObservation:
    try:
        snapshot = snapshot_repository(root)
        disposition = snapshot["disposition"]
        instance = snapshot["instance"]["identity_sha256"]
        logical_state = snapshot["logical_state"]
        logical_kind = logical_state["kind"]
        state = logical_state["state_sha256"]
    except (IdentityError, KeyError, TypeError):
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    if (
        type(disposition) is not str
        or disposition not in {"captured", "pass_through"}
        or type(logical_kind) is not str
        or not logical_kind
        or not _valid_hash(instance)
        or not _valid_hash(state)
    ):
        _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
    return _RepositoryObservation(
        disposition=disposition,
        logical_kind=logical_kind,
        instance_sha256=instance,
        state_sha256=state,
    )


def _snapshot_hashes(root: str) -> tuple[str, str]:
    observation = _snapshot_observation(root)
    return observation.instance_sha256, observation.state_sha256


def _event_hash(event_without_hashes: dict[str, object]) -> str:
    return framed_sha256_hex(
        "contextguard-receipt/twin-event-sha256/v1",
        canonical_json_bytes(event_without_hashes, _EVENT_LIMITS),
    )


def _event_hmac(event_key: bytes, event_without_hmac: dict[str, object]) -> str:
    return _hmac_hex(
        event_key,
        b"contextguard-receipt/twin-event-mac/v1",
        canonical_json_bytes(event_without_hmac, _EVENT_LIMITS),
    )


def _validate_loaded_event(
    value: object,
    *,
    event_key: bytes,
    metadata: _Metadata,
    expected_sequence: int,
    expected_previous_hmac: str | None,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != _EVENT_FIELDS:
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    predicate_results = value.get("predicate_results")
    predicate_count = value.get("predicate_count")
    matched_count = value.get("matched_predicate_count")
    if (
        value.get("schema_version") != _EVENT_SCHEMA_VERSION
        or value.get("namespace_id") != metadata.namespace_id
        or value.get("event_sequence") != expected_sequence
        or value.get("previous_event_hmac_sha256") != expected_previous_hmac
        or not _valid_hash(value.get("event_id"))
        or not _valid_hash(value.get("event_sha256"))
        or not _valid_hash(value.get("event_hmac_sha256"))
        or not _valid_hash(value.get("declared_next_action_sha256"))
        or not _valid_hash(value.get("repository_instance_sha256_before"))
        or not _valid_hash(value.get("repository_instance_sha256_after"))
        or not _valid_hash(value.get("repository_state_sha256_before"))
        or not _valid_hash(value.get("repository_state_sha256_after"))
        or value.get("repository_instance_sha256_before") != metadata.repository_instance_sha256
        or value.get("repository_instance_sha256_after") != metadata.repository_instance_sha256
        or type(value.get("observed_at_unix_ms")) is not int
        or not 0 <= value["observed_at_unix_ms"] <= _MAX_UNIX_MS
        or type(predicate_count) is not int
        or not 1 <= predicate_count <= _MAX_PREDICATES
        or type(matched_count) is not int
        or not 0 <= matched_count <= predicate_count
        or type(value.get("verified")) is not bool
        or type(predicate_results) is not list
        or len(predicate_results) != predicate_count
    ):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    observed_matched = 0
    for ordinal, result in enumerate(predicate_results):
        if (
            type(result) is not dict
            or set(result) != {
                "kind",
                "matched",
                "observation_hmac_sha256",
                "ordinal",
            }
            or result.get("kind") not in _PREDICATE_FIELDS
            or type(result.get("matched")) is not bool
            or not _valid_hash(result.get("observation_hmac_sha256"))
            or result.get("ordinal") != ordinal
        ):
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        observed_matched += int(result["matched"])
    if observed_matched != matched_count or (value["verified"] and matched_count != predicate_count):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    unsigned_hash = dict(value)
    supplied_hmac = unsigned_hash.pop("event_hmac_sha256")
    supplied_sha = unsigned_hash.pop("event_sha256")
    expected_sha = _event_hash(unsigned_hash)
    if not hmac.compare_digest(supplied_sha, expected_sha):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    unsigned_hmac = dict(value)
    unsigned_hmac.pop("event_hmac_sha256")
    expected_hmac = _event_hmac(event_key, unsigned_hmac)
    if not hmac.compare_digest(supplied_hmac, expected_hmac):
        _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
    return dict(value)


def _result_from_event(event: dict[str, object]) -> dict[str, object]:
    result = {
        "advisory_only": True,
        "applied": False,
        "declared_next_action_sha256": event["declared_next_action_sha256"],
        "event_hmac_sha256": event["event_hmac_sha256"],
        "event_id": event["event_id"],
        "event_sequence": event["event_sequence"],
        "evidence_boundary": evidence_boundary(),
        "execution_authority": False,
        "global_completeness_authority": False,
        "matched_predicate_count": event["matched_predicate_count"],
        "namespace_id": event["namespace_id"],
        "predicate_count": event["predicate_count"],
        "predicate_results": [dict(item) for item in event["predicate_results"]],
        "previous_event_hmac_sha256": event["previous_event_hmac_sha256"],
        "provider_claim_authority": False,
        "result_kind": "revalidated_declared_next_action_delta",
        "schema_version": _RESULT_SCHEMA_VERSION,
        "verified": event["verified"],
    }
    try:
        canonical_json_bytes(result, _RESULT_LIMITS)
    except CanonicalJSONError:
        _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
    return result


class _PathObserver:
    def __init__(self, root_fd: int) -> None:
        self._root_fd = root_fd

    @staticmethod
    def _status_identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def _entry_outcome(self, directory_fd: int, component: str) -> str:
        normalized = _FROZEN_UNICODE_DATABASE.normalize("NFC", component)
        folded = normalized.casefold()
        exact = 0
        alias = False
        count = 0
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    count += 1
                    if count > _MAX_DIRECTORY_ENTRIES:
                        return "directory_too_large"
                    name = os.fsdecode(entry.name)
                    normalized_name = _FROZEN_UNICODE_DATABASE.normalize("NFC", name)
                    if name == component:
                        exact += 1
                    elif normalized_name == normalized or normalized_name.casefold() == folded:
                        alias = True
        except OSError:
            return "io_error"
        if exact != 1:
            return "alias" if alias or exact > 1 else "absent"
        return "alias" if alias else "exact"

    def _stable_entry_outcome(self, directory_fd: int, component: str) -> str:
        try:
            before = os.fstat(directory_fd)
            first = self._entry_outcome(directory_fd, component)
            middle = os.fstat(directory_fd)
            second = self._entry_outcome(directory_fd, component)
            after = os.fstat(directory_fd)
        except OSError:
            return "io_error"
        if (
            self._status_identity(before) != self._status_identity(middle)
            or self._status_identity(middle) != self._status_identity(after)
            or first != second
        ):
            return "race"
        return first

    def observe(self, relative_path: str, *, read_file: bool) -> dict[str, object]:
        current = os.dup(self._root_fd)
        try:
            components = relative_path.split("/")
            for component in components[:-1]:
                outcome = self._stable_entry_outcome(current, component)
                if outcome != "exact":
                    return {"outcome": outcome}
                try:
                    before = os.stat(component, dir_fd=current, follow_symlinks=False)
                except OSError:
                    return {"outcome": "race"}
                if stat.S_ISLNK(before.st_mode):
                    return {"outcome": "symlink"}
                if not stat.S_ISDIR(before.st_mode):
                    return {"outcome": "not_directory"}
                try:
                    next_fd = os.open(component, _directory_flags(), dir_fd=current)
                    after = os.fstat(next_fd)
                except OSError:
                    return {"outcome": "race"}
                if self._status_identity(before) != self._status_identity(after):
                    os.close(next_fd)
                    return {"outcome": "race"}
                os.close(current)
                current = next_fd

            final = components[-1]
            outcome = self._stable_entry_outcome(current, final)
            if outcome != "exact":
                return {"outcome": outcome}
            try:
                path_status = os.stat(final, dir_fd=current, follow_symlinks=False)
            except OSError:
                return {"outcome": "race"}
            if stat.S_ISLNK(path_status.st_mode):
                return {"outcome": "symlink"}
            if not read_file:
                return {"outcome": "present"}
            if not stat.S_ISREG(path_status.st_mode):
                return {"outcome": "not_regular"}
            if path_status.st_nlink != 1:
                return {"outcome": "multiple_links"}
            if path_status.st_size > _MAX_FILE_BYTES:
                return {"outcome": "file_too_large"}
            descriptor: int | None = None
            try:
                descriptor = os.open(final, _file_read_flags(), dir_fd=current)
                before = os.fstat(descriptor)
                if (
                    self._status_identity(before) != self._status_identity(path_status)
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size > _MAX_FILE_BYTES
                ):
                    return {"outcome": "race"}
                payload = _read_observed_file(descriptor)
                after = os.fstat(descriptor)
                try:
                    final_status = os.stat(final, dir_fd=current, follow_symlinks=False)
                except OSError:
                    return {"outcome": "race"}
                if (
                    self._status_identity(before) != self._status_identity(after)
                    or self._status_identity(after) != self._status_identity(final_status)
                    or len(payload) != after.st_size
                ):
                    return {"outcome": "race"}
                return {
                    "content_sha256": hashlib.sha256(payload).hexdigest(),
                    "length_bytes": len(payload),
                    "mode": f"{stat.S_IMODE(after.st_mode):04o}",
                    "outcome": "regular_file",
                }
            except OSError:
                return {"outcome": "io_error"}
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        finally:
            os.close(current)


def _read_observed_file(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, _MAX_FILE_BYTES - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > _MAX_FILE_BYTES:
            return b"".join(chunks) + chunk
        chunks.append(chunk)


def _observation_hmac_sha256(
    observation_key: bytes,
    *,
    namespace_id: str,
    event_sequence: int,
    ordinal: int,
    predicate: dict[str, object],
    observation: dict[str, object],
) -> str:
    return _hmac_hex(
        observation_key,
        b"contextguard-receipt/twin-predicate-observation-mac/v1",
        canonical_json_bytes(
            {
                "event_sequence": event_sequence,
                "namespace_id": namespace_id,
                "observation": observation,
                "ordinal": ordinal,
                "predicate": predicate,
            },
            _REQUEST_LIMITS,
        ),
    )


class ExecutionTwin:
    """A private durable event log for local, advisory revalidation evidence."""

    def __init__(self) -> None:
        self._closed = True
        self._close_requested = False
        self._active_operations = 0
        self._exclusion_fds: tuple[int, ...] = ()
        self._opener_pid = os.getpid()
        self._thread_lock = threading.RLock()

    @classmethod
    def open(
        cls,
        state_dir: str,
        repository_root: object,
        create: bool = False,
    ) -> "ExecutionTwin":
        _require_filesystem_features()
        checked_state = _validate_state_path(state_dir)
        if type(create) is not bool:
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
        if isinstance(repository_root, bytes):
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
        try:
            root_path = os.fspath(repository_root)
        except TypeError:
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
        if (
            type(root_path) is not str
            or not root_path
            or "\0" in root_path
            or not os.path.isabs(root_path)
            or os.path.normpath(root_path) != root_path
        ):
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)

        exclusion_fds = _check_disjoint(checked_state, root_path)
        state_fd: int | None = None
        root_fd: int | None = None
        try:
            state_fd = _open_state_directory(checked_state, create=create)
            _require_disjoint(state_fd, exclusion_fds)
            try:
                root_fd = os.open(root_path, _directory_flags())
            except OSError:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            root_status = os.fstat(root_fd)
            if not stat.S_ISDIR(root_status.st_mode):
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            instance = cls()
            instance._state_path = checked_state
            instance._repository_root = root_path
            instance._state_fd = state_fd
            instance._root_fd = root_fd
            instance._root_anchor = (root_status.st_dev, root_status.st_ino)
            instance._exclusion_fds = exclusion_fds
            state_fd = None
            root_fd = None
            exclusion_fds = ()
        except Exception:
            if root_fd is not None:
                os.close(root_fd)
            if state_fd is not None:
                os.close(state_fd)
            _close_descriptors(exclusion_fds)
            raise

        try:
            instance._top_lock_fd, top_lock_created = instance._open_lock_at(
                instance._state_fd,
                _TOP_LOCK_NAME,
                create=create,
                missing=ExecutionTwinErrorCode.TWIN_UNINITIALIZED,
            )
            with instance._locked_descriptor(instance._top_lock_fd, exclusive=True):
                repository_instance, _state = _snapshot_hashes(root_path)
                instance._ensure_initialized(
                    create=create,
                    top_lock_created=top_lock_created,
                    repository_instance_sha256=repository_instance,
                )
                instance._open_axis(repository_instance)
            instance._closed = False
            return instance
        except Exception:
            instance._close_descriptors()
            raise

    def _revalidate_state_disjoint(self) -> None:
        if type(self._exclusion_fds) is not tuple or not self._exclusion_fds:
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        _require_disjoint(_require_directory_descriptor(self._state_fd), self._exclusion_fds)

    def _open_lock_at(
        self,
        parent_fd: int,
        name: str,
        *,
        create: bool,
        missing: ExecutionTwinErrorCode,
    ) -> tuple[int, bool]:
        self._revalidate_state_disjoint()
        descriptor: int | None = None
        created = False
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if not create:
                _raise(missing)
            try:
                descriptor = os.open(
                    name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_fd,
                )
                created = True
            except OSError:
                _raise(ExecutionTwinErrorCode.WRITE_FAILED)
            try:
                os.fchmod(descriptor, 0o600)
            except OSError:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                descriptor = None
                _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
        except OSError:
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        if descriptor is None:
            _raise(ExecutionTwinErrorCode.WRITE_FAILED)
        try:
            if not _private_file(_descriptor_status(descriptor)):
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            if created:
                try:
                    os.fsync(descriptor)
                    os.fsync(parent_fd)
                except OSError:
                    _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
            return descriptor, created
        except Exception:
            os.close(descriptor)
            raise

    @contextmanager
    def _locked_descriptor(self, descriptor: int, *, exclusive: bool) -> Iterator[None]:
        self._require_opener_process()
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        if not self._thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            _raise(ExecutionTwinErrorCode.LOCK_TIMEOUT)
        acquired = False
        checked = -1
        try:
            checked = _require_private_file_descriptor(descriptor)
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            while True:
                try:
                    fcntl.flock(checked, operation | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        _raise(ExecutionTwinErrorCode.LOCK_TIMEOUT)
                    time.sleep(0.01)
                except OSError:
                    _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            yield
        finally:
            if acquired:
                try:
                    fcntl.flock(checked, fcntl.LOCK_UN)
                except OSError:
                    pass
            self._thread_lock.release()

    def _root_names(self) -> set[str]:
        names = set(
            _bounded_names(
                self._state_fd,
                4,
                overflow=ExecutionTwinErrorCode.RECOVERY_REQUIRED,
            )
        )
        unknown = names - {_TOP_LOCK_NAME, "store-v1", _AUXILIARY_NAME}
        if unknown:
            _raise(ExecutionTwinErrorCode.RECOVERY_REQUIRED)
        return names

    @staticmethod
    def _validate_auxiliary_metadata(auxiliary_fd: int) -> None:
        raw = _read_named_file(auxiliary_fd, _AUXILIARY_METADATA_NAME, _MAX_METADATA_BYTES)
        try:
            value = parse_canonical_json_bytes(raw, _METADATA_LIMITS)
        except CanonicalJSONError:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
        if value != _AUXILIARY_METADATA:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)

    def _create_twin_tree(
        self,
        parent_fd: int,
        name: str,
        repository_instance_sha256: str,
    ) -> None:
        twin_fd: int | None = None
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            twin_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
            os.fchmod(twin_fd, 0o700)
            master_key = secrets.token_bytes(32)
            namespace_id = framed_sha256_hex(
                "contextguard-receipt/twin-namespace/v1",
                master_key,
                bytes.fromhex(repository_instance_sha256),
            )
            event_key = _derive_key(master_key, b"contextguard-receipt/twin-event-key/v1")
            genesis = _hmac_hex(
                event_key,
                b"contextguard-receipt/twin-genesis/v1",
                canonical_json_bytes(
                    {
                        "namespace_id": namespace_id,
                        "repository_instance_sha256": repository_instance_sha256,
                    },
                    _METADATA_LIMITS,
                ),
            )
            metadata_key = _derive_key(master_key, b"contextguard-receipt/twin-metadata-key/v1")
            _write_new_file(twin_fd, _TWIN_LOCK_NAME, b"")
            _write_new_file(twin_fd, _KEY_NAME, master_key)
            _write_new_file(
                twin_fd,
                _METADATA_NAME,
                _metadata_document(
                    metadata_key,
                    namespace_id=namespace_id,
                    repository_instance_sha256=repository_instance_sha256,
                    genesis_hmac_sha256=genesis,
                ),
            )
            _write_new_file(twin_fd, _EVENTS_NAME, b"")
            os.fsync(twin_fd)
        except ExecutionTwinError:
            raise
        except OSError:
            _raise(ExecutionTwinErrorCode.WRITE_FAILED)
        finally:
            if twin_fd is not None:
                os.close(twin_fd)

    def _ensure_existing_auxiliary(
        self,
        *,
        create: bool,
        repository_instance_sha256: str,
    ) -> None:
        auxiliary_fd = _open_directory_at(self._state_fd, _AUXILIARY_NAME)
        try:
            self._validate_auxiliary_metadata(auxiliary_fd)
            names = set(
                _bounded_names(
                    auxiliary_fd,
                    5,
                    overflow=ExecutionTwinErrorCode.RECOVERY_REQUIRED,
                )
            )
            unknown = names - {
                _AUXILIARY_METADATA_NAME,
                _DIAGNOSTICS_NAME,
                _TWIN_NAME,
                _REFERENCE_EXPIRY_NAME,
            }
            if unknown:
                if all(_TWIN_TEMP_PATTERN.fullmatch(name) for name in unknown):
                    _raise(ExecutionTwinErrorCode.RECOVERY_REQUIRED)
                _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
            if _DIAGNOSTICS_NAME in names:
                descriptor = _open_directory_at(auxiliary_fd, _DIAGNOSTICS_NAME)
                os.close(descriptor)
            if _REFERENCE_EXPIRY_NAME in names:
                descriptor = _open_directory_at(
                    auxiliary_fd, _REFERENCE_EXPIRY_NAME
                )
                os.close(descriptor)
            if _TWIN_NAME in names:
                descriptor = _open_directory_at(auxiliary_fd, _TWIN_NAME)
                os.close(descriptor)
                return
            if not create:
                _raise(ExecutionTwinErrorCode.TWIN_UNINITIALIZED)
            temporary_name = ".twin-v1.tmp-" + secrets.token_bytes(16).hex()
            published = False
            try:
                self._create_twin_tree(auxiliary_fd, temporary_name, repository_instance_sha256)
                os.rename(
                    temporary_name,
                    _TWIN_NAME,
                    src_dir_fd=auxiliary_fd,
                    dst_dir_fd=auxiliary_fd,
                )
                published = True
                os.fsync(auxiliary_fd)
            except ExecutionTwinError:
                raise
            except OSError:
                _raise(
                    ExecutionTwinErrorCode.COMMIT_UNCERTAIN
                    if published
                    else ExecutionTwinErrorCode.WRITE_FAILED
                )
        finally:
            os.close(auxiliary_fd)

    def _ensure_initialized(
        self,
        *,
        create: bool,
        top_lock_created: bool,
        repository_instance_sha256: str,
    ) -> None:
        self._revalidate_state_disjoint()
        names = self._root_names()
        if top_lock_created and names != {_TOP_LOCK_NAME}:
            _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
        if "store-v1" in names:
            descriptor = _open_directory_at(self._state_fd, "store-v1")
            os.close(descriptor)
        if _AUXILIARY_NAME in names:
            self._ensure_existing_auxiliary(
                create=create,
                repository_instance_sha256=repository_instance_sha256,
            )
            return
        if not create:
            _raise(ExecutionTwinErrorCode.TWIN_UNINITIALIZED)

        temporary_name = ".auxiliary-v1.tmp-" + secrets.token_bytes(16).hex()
        auxiliary_fd: int | None = None
        published = False
        try:
            os.mkdir(temporary_name, 0o700, dir_fd=self._state_fd)
            auxiliary_fd = os.open(temporary_name, _directory_flags(), dir_fd=self._state_fd)
            os.fchmod(auxiliary_fd, 0o700)
            _write_new_file(
                auxiliary_fd,
                _AUXILIARY_METADATA_NAME,
                canonical_json_bytes(_AUXILIARY_METADATA, _METADATA_LIMITS),
            )
            self._create_twin_tree(auxiliary_fd, _TWIN_NAME, repository_instance_sha256)
            os.fsync(auxiliary_fd)
            os.close(auxiliary_fd)
            auxiliary_fd = None
            os.rename(
                temporary_name,
                _AUXILIARY_NAME,
                src_dir_fd=self._state_fd,
                dst_dir_fd=self._state_fd,
            )
            published = True
            os.fsync(self._state_fd)
        except ExecutionTwinError:
            raise
        except OSError:
            _raise(
                ExecutionTwinErrorCode.COMMIT_UNCERTAIN
                if published
                else ExecutionTwinErrorCode.WRITE_FAILED
            )
        finally:
            if auxiliary_fd is not None:
                os.close(auxiliary_fd)

    def _open_axis(self, repository_instance_sha256: str) -> None:
        self._revalidate_state_disjoint()
        self._auxiliary_fd = _open_directory_at(self._state_fd, _AUXILIARY_NAME)
        self._validate_auxiliary_metadata(self._auxiliary_fd)
        self._twin_fd = _open_directory_at(self._auxiliary_fd, _TWIN_NAME)
        if set(_bounded_names(self._twin_fd, 4)) != {
            _EVENTS_NAME,
            _KEY_NAME,
            _METADATA_NAME,
            _TWIN_LOCK_NAME,
        }:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
        self._twin_lock_fd, _created = self._open_lock_at(
            self._twin_fd,
            _TWIN_LOCK_NAME,
            create=False,
            missing=ExecutionTwinErrorCode.TWIN_CORRUPT,
        )
        master_key = _read_named_file(self._twin_fd, _KEY_NAME, 33)
        if len(master_key) != 32:
            _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
        self._master_key = master_key
        self._event_key = _derive_key(master_key, b"contextguard-receipt/twin-event-key/v1")
        self._metadata_key = _derive_key(master_key, b"contextguard-receipt/twin-metadata-key/v1")
        self._observation_key = _derive_key(
            master_key,
            b"contextguard-receipt/twin-predicate-observation-key/v1",
        )
        metadata = _parse_metadata(
            _read_named_file(self._twin_fd, _METADATA_NAME, _MAX_METADATA_BYTES),
            master_key=master_key,
            expected_repository_instance_sha256=repository_instance_sha256,
        )
        self._namespace_id = metadata.namespace_id
        self._repository_instance_sha256 = metadata.repository_instance_sha256
        self._genesis_hmac_sha256 = metadata.genesis_hmac_sha256
        self._events_fd = _open_private_file(self._twin_fd, _EVENTS_NAME, writable=True)

        self._state_anchor = self._descriptor_identity(self._state_fd)
        self._top_lock_anchor = self._descriptor_identity(self._top_lock_fd)
        self._auxiliary_anchor = self._descriptor_identity(self._auxiliary_fd)
        self._twin_anchor = self._descriptor_identity(self._twin_fd)
        self._twin_lock_anchor = self._descriptor_identity(self._twin_lock_fd)
        key_fd = _open_private_file(self._twin_fd, _KEY_NAME)
        try:
            self._key_anchor = self._descriptor_identity(key_fd)
        finally:
            os.close(key_fd)
        self._events_anchor = self._descriptor_identity(self._events_fd)
        self._revalidate_anchors(check_repository=False)

    @staticmethod
    def _descriptor_identity(descriptor: int) -> tuple[int, int]:
        status = _descriptor_status(descriptor)
        return status.st_dev, status.st_ino

    def _revalidate_anchors(self, *, check_repository: bool = True) -> None:
        self._revalidate_state_disjoint()
        opened: list[int] = []
        try:
            state_fd = _open_state_directory(self._state_path, create=False)
            opened.append(state_fd)
            if self._descriptor_identity(state_fd) != self._state_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            root_fd = os.open(self._repository_root, _directory_flags())
            opened.append(root_fd)
            if self._descriptor_identity(root_fd) != self._root_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            names = self._root_names()
            if names not in (
                {_TOP_LOCK_NAME, _AUXILIARY_NAME},
                {_TOP_LOCK_NAME, "store-v1", _AUXILIARY_NAME},
            ):
                _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
            if "store-v1" in names:
                opened.append(_open_directory_at(state_fd, "store-v1"))
            top_lock_fd = _open_private_file(state_fd, _TOP_LOCK_NAME, writable=True)
            opened.append(top_lock_fd)
            if self._descriptor_identity(top_lock_fd) != self._top_lock_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            auxiliary_fd = _open_directory_at(state_fd, _AUXILIARY_NAME)
            opened.append(auxiliary_fd)
            if self._descriptor_identity(auxiliary_fd) != self._auxiliary_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            auxiliary_names = set(_bounded_names(auxiliary_fd, 4))
            if (
                _TWIN_NAME not in auxiliary_names
                or auxiliary_names
                - {
                    _AUXILIARY_METADATA_NAME,
                    _DIAGNOSTICS_NAME,
                    _TWIN_NAME,
                    _REFERENCE_EXPIRY_NAME,
                }
            ):
                _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
            self._validate_auxiliary_metadata(auxiliary_fd)
            if _DIAGNOSTICS_NAME in auxiliary_names:
                opened.append(_open_directory_at(auxiliary_fd, _DIAGNOSTICS_NAME))
            if _REFERENCE_EXPIRY_NAME in auxiliary_names:
                opened.append(
                    _open_directory_at(auxiliary_fd, _REFERENCE_EXPIRY_NAME)
                )
            twin_fd = _open_directory_at(auxiliary_fd, _TWIN_NAME)
            opened.append(twin_fd)
            if self._descriptor_identity(twin_fd) != self._twin_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            twin_names = set(
                _bounded_names(
                    twin_fd,
                    5,
                    overflow=ExecutionTwinErrorCode.RECOVERY_REQUIRED,
                )
            )
            if twin_names != {_EVENTS_NAME, _KEY_NAME, _METADATA_NAME, _TWIN_LOCK_NAME}:
                if any(_METADATA_TEMP_PATTERN.fullmatch(name) for name in twin_names):
                    _raise(ExecutionTwinErrorCode.RECOVERY_REQUIRED)
                _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
            lock_fd = _open_private_file(twin_fd, _TWIN_LOCK_NAME, writable=True)
            opened.append(lock_fd)
            if self._descriptor_identity(lock_fd) != self._twin_lock_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            key_fd = _open_private_file(twin_fd, _KEY_NAME)
            opened.append(key_fd)
            if self._descriptor_identity(key_fd) != self._key_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            if not hmac.compare_digest(_read_all(key_fd, 33), self._master_key):
                _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
            events_fd = _open_private_file(twin_fd, _EVENTS_NAME, writable=True)
            opened.append(events_fd)
            if self._descriptor_identity(events_fd) != self._events_anchor:
                _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
            if check_repository:
                repository_instance, _repository_state = _snapshot_hashes(self._repository_root)
                if repository_instance != self._repository_instance_sha256:
                    _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        except OSError:
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        finally:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @contextmanager
    def _operation(self) -> Iterator[None]:
        self._require_opener_process()
        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
            for name in ("_state_fd", "_root_fd", "_auxiliary_fd", "_twin_fd"):
                _require_directory_descriptor(getattr(self, name, None))
            for name in ("_top_lock_fd", "_twin_lock_fd", "_events_fd"):
                _require_private_file_descriptor(getattr(self, name, None))
            self._active_operations += 1
        try:
            yield
        finally:
            with self._thread_lock:
                self._active_operations -= 1
                if self._active_operations == 0 and self._close_requested:
                    self._close_descriptors()
                    self._closed = True
                    self._close_requested = False

    def _require_opener_process(self) -> None:
        if os.getpid() != self._opener_pid:
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)

    def _read_metadata_state(self) -> _Metadata:
        return _parse_metadata(
            _read_named_file(self._twin_fd, _METADATA_NAME, _MAX_METADATA_BYTES),
            master_key=self._master_key,
            expected_repository_instance_sha256=self._repository_instance_sha256,
        )

    @staticmethod
    def _pread_exact(descriptor: int, length: int, offset: int) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while total < length:
            try:
                chunk = os.pread(descriptor, length - total, offset + total)
            except InterruptedError:
                continue
            except OSError:
                _raise(ExecutionTwinErrorCode.TWIN_CORRUPT)
            if not chunk:
                _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def _has_authenticated_event_suffix(
        self,
        metadata: _Metadata,
        *,
        log_size: int,
    ) -> bool:
        """Return true when bytes beyond metadata begin with a valid next event."""

        remaining = log_size - metadata.committed_log_bytes
        if remaining < 8:
            return False
        frame_offset = metadata.committed_log_bytes
        header = self._pread_exact(self._events_fd, 8, frame_offset)
        event_length = int.from_bytes(header, "big", signed=False)
        if (
            event_length <= 0
            or event_length > _MAX_EVENT_BYTES
            or remaining < 8 + event_length
        ):
            return False
        event_raw = self._pread_exact(self._events_fd, event_length, frame_offset + 8)
        try:
            value = parse_canonical_json_bytes(event_raw, _EVENT_LIMITS)
            _validate_loaded_event(
                value,
                event_key=self._event_key,
                metadata=metadata,
                expected_sequence=metadata.committed_event_count + 1,
                expected_previous_hmac=(
                    None
                    if metadata.committed_event_count == 0
                    else metadata.committed_head_hmac_sha256
                ),
            )
        except (CanonicalJSONError, ExecutionTwinError):
            return False
        return True

    def _scan_committed(self, metadata: _Metadata) -> _ScannedLog:
        status = _descriptor_status(self._events_fd, error_code=ExecutionTwinErrorCode.TWIN_CORRUPT)
        if not _private_file(status):
            _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
        if status.st_size < metadata.committed_log_bytes:
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        raw = self._pread_exact(self._events_fd, metadata.committed_log_bytes, 0) if metadata.committed_log_bytes else b""
        status_after_read = _descriptor_status(
            self._events_fd,
            error_code=ExecutionTwinErrorCode.TWIN_CORRUPT,
        )
        status_identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if status_identity(status) != status_identity(status_after_read):
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        events: list[dict[str, object]] = []
        offset = 0
        previous_hmac: str | None = None
        for sequence in range(1, metadata.committed_event_count + 1):
            if offset + 8 > len(raw):
                _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
            event_length = int.from_bytes(raw[offset : offset + 8], "big", signed=False)
            offset += 8
            if event_length <= 0 or event_length > _MAX_EVENT_BYTES or offset + event_length > len(raw):
                _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
            event_raw = raw[offset : offset + event_length]
            offset += event_length
            try:
                value = parse_canonical_json_bytes(event_raw, _EVENT_LIMITS)
            except CanonicalJSONError:
                _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
            event = _validate_loaded_event(
                value,
                event_key=self._event_key,
                metadata=metadata,
                expected_sequence=sequence,
                expected_previous_hmac=previous_hmac,
            )
            previous_hmac = event["event_hmac_sha256"]
            events.append(event)
        if offset != len(raw):
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        expected_head = metadata.genesis_hmac_sha256 if not events else events[-1]["event_hmac_sha256"]
        if not hmac.compare_digest(metadata.committed_head_hmac_sha256, expected_head):
            _raise(ExecutionTwinErrorCode.TWIN_TAMPERED)
        recovery_required = status.st_size > metadata.committed_log_bytes
        if recovery_required:
            if self._has_authenticated_event_suffix(metadata, log_size=status.st_size):
                _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
            status_before_truncate = _descriptor_status(
                self._events_fd,
                error_code=ExecutionTwinErrorCode.TWIN_CORRUPT,
            )
            if status_identity(status) != status_identity(status_before_truncate):
                _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
            try:
                os.ftruncate(self._events_fd, metadata.committed_log_bytes)
                os.fsync(self._events_fd)
            except OSError:
                _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
            _LOGGER.debug("execution twin recovered an uncommitted log tail")
        return _ScannedLog(events=events, recovery_required=recovery_required)

    def _evaluate_predicates(
        self,
        predicates: list[dict[str, object]],
        *,
        event_sequence: int,
        repository: _RepositoryObservation,
    ) -> list[dict[str, object]]:
        observer = _PathObserver(self._root_fd)
        results: list[dict[str, object]] = []
        for ordinal, predicate in enumerate(predicates):
            kind = predicate["kind"]
            if kind == "repository_instance_equals":
                observation = {
                    "observed_sha256": repository.instance_sha256,
                    "outcome": "repository_instance",
                }
                matched = predicate["expected_sha256"] == repository.instance_sha256
            elif kind == "git_logical_state_equals":
                available = (
                    repository.disposition == "captured"
                    and repository.logical_kind in {"git_bare", "git_worktree"}
                )
                observation = (
                    {
                        "observed_sha256": repository.state_sha256,
                        "outcome": "git_logical_state",
                    }
                    if available
                    else {"outcome": "git_logical_state_unavailable"}
                )
                matched = available and predicate["expected_sha256"] == repository.state_sha256
            elif kind == "path_absent":
                observation = observer.observe(predicate["relative_path"], read_file=False)
                matched = observation["outcome"] == "absent"
            else:
                observation = observer.observe(predicate["relative_path"], read_file=True)
                matched = observation == {
                    "content_sha256": predicate["expected_content_sha256"],
                    "length_bytes": predicate["expected_length_bytes"],
                    "mode": predicate["expected_mode"],
                    "outcome": "regular_file",
                }
            results.append(
                {
                    "kind": kind,
                    "matched": matched,
                    "observation_hmac_sha256": _observation_hmac_sha256(
                        self._observation_key,
                        namespace_id=self._namespace_id,
                        event_sequence=event_sequence,
                        ordinal=ordinal,
                        predicate=predicate,
                        observation=observation,
                    ),
                    "ordinal": ordinal,
                }
            )
        return results

    @staticmethod
    def _pwrite_all(descriptor: int, raw: bytes, offset: int) -> None:
        written_total = 0
        while written_total < len(raw):
            try:
                written = os.pwrite(descriptor, raw[written_total:], offset + written_total)
            except InterruptedError:
                continue
            except OSError:
                _raise(
                    ExecutionTwinErrorCode.WRITE_FAILED
                    if written_total == 0
                    else ExecutionTwinErrorCode.COMMIT_UNCERTAIN
                )
            if written <= 0:
                _raise(
                    ExecutionTwinErrorCode.WRITE_FAILED
                    if written_total == 0
                    else ExecutionTwinErrorCode.COMMIT_UNCERTAIN
                )
            written_total += written

    def _publish_metadata(self, raw: bytes) -> None:
        temporary_name = ".metadata.json.tmp-" + secrets.token_bytes(16).hex()
        published = False
        try:
            _write_new_file(self._twin_fd, temporary_name, raw)
            os.rename(
                temporary_name,
                _METADATA_NAME,
                src_dir_fd=self._twin_fd,
                dst_dir_fd=self._twin_fd,
            )
            published = True
            os.fsync(self._twin_fd)
        except ExecutionTwinError:
            if not published:
                try:
                    os.unlink(temporary_name, dir_fd=self._twin_fd)
                except OSError:
                    pass
            raise
        except OSError:
            if not published:
                try:
                    os.unlink(temporary_name, dir_fd=self._twin_fd)
                except OSError:
                    pass
            _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)

    def append(
        self,
        parsed_request: dict[str, object],
        observed_at_unix_ms: int,
    ) -> dict[str, object]:
        request = _validate_request_value(parsed_request, ExecutionTwinErrorCode.INVALID_ARGUMENT)
        if type(observed_at_unix_ms) is not int or not 0 <= observed_at_unix_ms <= _MAX_UNIX_MS:
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
        with self._operation():
            with self._locked_descriptor(self._twin_lock_fd, exclusive=True):
                self._revalidate_anchors()
                metadata = self._read_metadata_state()
                scanned = self._scan_committed(metadata)
                expected_tail = request["expected_tail"]
                if metadata.committed_event_count == 0:
                    if expected_tail is not None:
                        _raise(ExecutionTwinErrorCode.CAS_MISMATCH)
                elif expected_tail != {
                    "event_hmac_sha256": metadata.committed_head_hmac_sha256,
                    "event_sequence": metadata.committed_event_count,
                    "namespace_id": metadata.namespace_id,
                }:
                    _raise(ExecutionTwinErrorCode.CAS_MISMATCH)
                if metadata.committed_event_count >= _MAX_EVENT_COUNT:
                    _raise(ExecutionTwinErrorCode.COUNT_QUOTA_EXCEEDED)

                sequence = metadata.committed_event_count + 1
                repository_before = _snapshot_observation(self._repository_root)
                if repository_before.instance_sha256 != metadata.repository_instance_sha256:
                    _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
                predicate_results_before = self._evaluate_predicates(
                    request["predicates"],
                    event_sequence=sequence,
                    repository=repository_before,
                )
                repository_after = _snapshot_observation(self._repository_root)
                if repository_after.instance_sha256 != metadata.repository_instance_sha256:
                    _raise(ExecutionTwinErrorCode.UNSAFE_STATE)
                predicate_results = self._evaluate_predicates(
                    request["predicates"],
                    event_sequence=sequence,
                    repository=repository_after,
                )
                matched_count = sum(int(item["matched"]) for item in predicate_results)
                verified = (
                    matched_count == len(predicate_results)
                    and predicate_results_before == predicate_results
                    and repository_before.instance_sha256
                    == repository_after.instance_sha256
                    and repository_before.state_sha256 == repository_after.state_sha256
                )
                previous_hmac = None if sequence == 1 else metadata.committed_head_hmac_sha256
                event: dict[str, object] = {
                    "declared_next_action_sha256": request["declared_next_action_sha256"],
                    "event_hmac_sha256": "",
                    "event_id": secrets.token_bytes(32).hex(),
                    "event_sequence": sequence,
                    "event_sha256": "",
                    "matched_predicate_count": matched_count,
                    "namespace_id": metadata.namespace_id,
                    "observed_at_unix_ms": observed_at_unix_ms,
                    "predicate_count": len(predicate_results),
                    "predicate_results": predicate_results,
                    "previous_event_hmac_sha256": previous_hmac,
                    "repository_instance_sha256_after": repository_after.instance_sha256,
                    "repository_instance_sha256_before": repository_before.instance_sha256,
                    "repository_state_sha256_after": repository_after.state_sha256,
                    "repository_state_sha256_before": repository_before.state_sha256,
                    "schema_version": _EVENT_SCHEMA_VERSION,
                    "verified": verified,
                }
                unsigned_hash = dict(event)
                unsigned_hash.pop("event_hmac_sha256")
                unsigned_hash.pop("event_sha256")
                event["event_sha256"] = _event_hash(unsigned_hash)
                unsigned_hmac = dict(event)
                unsigned_hmac.pop("event_hmac_sha256")
                event["event_hmac_sha256"] = _event_hmac(self._event_key, unsigned_hmac)
                try:
                    event_raw = canonical_json_bytes(event, _EVENT_LIMITS)
                except CanonicalJSONError:
                    _raise(ExecutionTwinErrorCode.EVENT_TOO_LARGE)
                if len(event_raw) > _MAX_EVENT_BYTES:
                    _raise(ExecutionTwinErrorCode.EVENT_TOO_LARGE)
                frame = len(event_raw).to_bytes(8, "big", signed=False) + event_raw
                new_log_bytes = metadata.committed_log_bytes + len(frame)
                if new_log_bytes > _MAX_COMMITTED_LOG_BYTES:
                    _raise(ExecutionTwinErrorCode.BYTE_QUOTA_EXCEEDED)

                log_write_completed = False
                try:
                    self._pwrite_all(self._events_fd, frame, metadata.committed_log_bytes)
                    log_write_completed = True
                    os.fsync(self._events_fd)
                    metadata_raw = _metadata_document(
                        self._metadata_key,
                        namespace_id=metadata.namespace_id,
                        repository_instance_sha256=metadata.repository_instance_sha256,
                        genesis_hmac_sha256=metadata.genesis_hmac_sha256,
                        committed_event_count=sequence,
                        committed_log_bytes=new_log_bytes,
                        committed_head_hmac_sha256=event["event_hmac_sha256"],
                    )
                    self._publish_metadata(metadata_raw)
                    final_metadata = self._read_metadata_state()
                    final_scanned = self._scan_committed(final_metadata)
                    if (
                        final_scanned.recovery_required
                        or final_metadata.committed_event_count != sequence
                        or len(final_scanned.events) != sequence
                        or final_scanned.events[-1]["event_hmac_sha256"] != event["event_hmac_sha256"]
                    ):
                        _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
                    self._revalidate_anchors()
                except ExecutionTwinError as error:
                    if log_write_completed and error.code is not ExecutionTwinErrorCode.COMMIT_UNCERTAIN:
                        _raise(ExecutionTwinErrorCode.COMMIT_UNCERTAIN)
                    raise
                except OSError:
                    _raise(
                        ExecutionTwinErrorCode.COMMIT_UNCERTAIN
                        if log_write_completed
                        else ExecutionTwinErrorCode.WRITE_FAILED
                    )
                return _result_from_event(event)

    def inspect(self, limit: int = 256) -> dict[str, object]:
        if type(limit) is not int or not 1 <= limit <= 256:
            _raise(ExecutionTwinErrorCode.INVALID_ARGUMENT)
        with self._operation():
            with self._locked_descriptor(self._twin_lock_fd, exclusive=True):
                self._revalidate_anchors()
                metadata = self._read_metadata_state()
                scanned = self._scan_committed(metadata)
                self._revalidate_anchors()
        return {
            "advisory_only": True,
            "applied": False,
            "committed_event_count": metadata.committed_event_count,
            "committed_head_hmac_sha256": (
                None
                if metadata.committed_event_count == 0
                else metadata.committed_head_hmac_sha256
            ),
            "committed_log_bytes": metadata.committed_log_bytes,
            "evidence_boundary": evidence_boundary(),
            "execution_authority": False,
            "global_completeness_authority": False,
            "latest_events": [dict(event) for event in scanned.events[-limit:]],
            "namespace_id": metadata.namespace_id,
            "provider_claim_authority": False,
            "recovery_required": scanned.recovery_required,
            "schema_version": _SNAPSHOT_SCHEMA_VERSION,
        }

    def _close_descriptors(self) -> None:
        for name in (
            "_events_fd",
            "_twin_lock_fd",
            "_twin_fd",
            "_auxiliary_fd",
            "_top_lock_fd",
            "_root_fd",
            "_state_fd",
        ):
            descriptor = getattr(self, name, None)
            if isinstance(descriptor, int):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)
        _close_descriptors(self._exclusion_fds)
        self._exclusion_fds = ()
        for name in ("_master_key", "_event_key", "_metadata_key", "_observation_key"):
            if hasattr(self, name):
                setattr(self, name, b"")

    def close(self) -> None:
        if os.getpid() != self._opener_pid:
            self._close_descriptors()
            self._closed = True
            self._close_requested = False
            return
        with self._thread_lock:
            if not self._closed:
                if self._active_operations:
                    self._close_requested = True
                else:
                    self._close_descriptors()
                    self._closed = True
                    self._close_requested = False

    def __enter__(self) -> "ExecutionTwin":
        with self._operation():
            return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "ExecutionTwin(<private>)"
