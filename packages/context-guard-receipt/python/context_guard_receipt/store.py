"""Private, capability-only durable storage for exact local receipt artifacts."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Callable, Final, Iterator

from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .identity import IdentityError, _repository_exclusion_snapshot


__all__ = [
    "ArtifactRequest",
    "ArtifactType",
    "CapabilityStore",
    "IssuedCapability",
    "StoreError",
    "StoreErrorCode",
    "StoreLimits",
    "StoreSummary",
    "StoredArtifact",
    "predicted_capability_bytes",
]


_STORE_DIRECTORY: Final = "store-v1"
_LOCK_NAME: Final = "lock"
_AUXILIARY_DIRECTORY: Final = "auxiliary-v1"
_AUXILIARY_METADATA_NAME: Final = "metadata.json"
_DIAGNOSTICS_DIRECTORY: Final = "diagnostics-v1"
_TWIN_DIRECTORY: Final = "twin-v1"
_REFERENCE_EXPIRY_DIRECTORY: Final = "reference-expiry-v1"
_KEY_NAME: Final = "integrity-key"
_METADATA_NAME: Final = "metadata.json"
_COMMITS_NAME: Final = "commits"
_TEMP_NAME: Final = "tmp"
_PAYLOAD_NAME: Final = "payload.bin"
_RECORD_NAME: Final = "record.json"
_COMMIT_MANIFEST_NAME: Final = "manifest.json"

_STORE_SCHEMA_VERSION: Final = "contextguard-receipt-store-metadata/v1"
_RECORD_SCHEMA_VERSION: Final = "contextguard-receipt-capability-record/v1"
_COMMIT_SCHEMA_VERSION: Final = "contextguard-receipt-store-commit/v1"
_CAPABILITY_PREFIX: Final = "cgr1p_"
_CAPABILITY_RAW_BYTES: Final = 32
_CAPABILITY_TEXT_BYTES: Final = 49
_LOCK_TIMEOUT_SECONDS: Final = 5.0
_COMMIT_DOCUMENT_BYTES: Final = 128 * 1024
_COMMIT_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=_COMMIT_DOCUMENT_BYTES,
    max_depth=8,
    max_total_values=2048,
    max_object_members=32,
    max_string_bytes=256,
)
_AUXILIARY_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=4096,
    max_depth=4,
    max_total_values=64,
    max_object_members=16,
    max_string_bytes=128,
)
_AUXILIARY_SCHEMA_VERSION: Final = "contextguard-receipt-auxiliary-metadata/v1"
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_CAPABILITY_PATTERN = re.compile(r"cgr1p_[A-Za-z0-9_-]{43}\Z")

_HARD_MAX_ARTIFACTS: Final = 1024
_HARD_MAX_TOTAL_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
_HARD_MAX_CAPABILITIES: Final = 1024
_HARD_MAX_SINGLE_ARTIFACT_BYTES: Final = 10_000_000
_DEFAULT_MAX_SINGLE_ARTIFACT_BYTES: Final = 1024 * 1024


class StoreErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    STATE_DIR_REQUIRED = "state_dir_required"
    STATE_DIR_NOT_ABSOLUTE = "state_dir_not_absolute"
    STATE_DIR_NOT_NORMALIZED = "state_dir_not_normalized"
    STATE_DIR_FORBIDDEN = "state_dir_forbidden"
    FILESYSTEM_UNSUPPORTED = "filesystem_unsupported"
    UNSAFE_STATE = "unsafe_state"
    LOCK_TIMEOUT = "lock_timeout"
    STORE_UNINITIALIZED = "store_uninitialized"
    STORE_CORRUPT = "store_corrupt"
    STORE_TAMPERED = "store_tampered"
    RECOVERY_REQUIRED = "recovery_required"
    ARTIFACT_TOO_LARGE = "artifact_too_large"
    ARTIFACT_COUNT_QUOTA_EXCEEDED = "artifact_count_quota_exceeded"
    ARTIFACT_BYTES_QUOTA_EXCEEDED = "artifact_bytes_quota_exceeded"
    CAPABILITY_COUNT_QUOTA_EXCEEDED = "capability_count_quota_exceeded"
    CAPABILITY_REJECTED = "capability_rejected"
    WRITE_FAILED = "write_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"


class StoreError(ValueError):
    """Stable non-reflective capability-store failure."""

    __slots__ = ("code",)

    def __init__(self, code: StoreErrorCode) -> None:
        self.code = code
        super().__init__(f"capability store rejected: {code.value}")


class ArtifactType(str, Enum):
    RAW_EVIDENCE_BYTES = "raw_evidence_bytes"
    BLUEPRINT_WHOLE_BYTES = "blueprint_whole_bytes"
    BLUEPRINT_ITEM_BYTES = "blueprint_item_bytes"
    TOOL_SCHEMA_SET_BYTES = "tool_schema_set_bytes"
    TOOL_SCHEMA_BYTES = "tool_schema_bytes"
    COMMAND_CAPTURE_BYTES = "command_capture_bytes"


@dataclass(frozen=True, slots=True)
class StoreLimits:
    max_artifacts: int = _HARD_MAX_ARTIFACTS
    max_total_artifact_bytes: int = _HARD_MAX_TOTAL_ARTIFACT_BYTES
    max_capabilities: int = _HARD_MAX_CAPABILITIES
    max_single_artifact_bytes: int = _DEFAULT_MAX_SINGLE_ARTIFACT_BYTES

    def __post_init__(self) -> None:
        maximums = {
            "max_artifacts": _HARD_MAX_ARTIFACTS,
            "max_total_artifact_bytes": _HARD_MAX_TOTAL_ARTIFACT_BYTES,
            "max_capabilities": _HARD_MAX_CAPABILITIES,
            "max_single_artifact_bytes": _HARD_MAX_SINGLE_ARTIFACT_BYTES,
        }
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value <= 0 or value > maximums[item.name]:
                raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
        if self.max_single_artifact_bytes > self.max_total_artifact_bytes:
            raise StoreError(StoreErrorCode.INVALID_ARGUMENT)


_DEFAULT_STORE_LIMITS: Final = StoreLimits()
_MERGED_CAPTURE_STORE_LIMITS: Final = StoreLimits(
    max_single_artifact_bytes=_HARD_MAX_SINGLE_ARTIFACT_BYTES
)


@dataclass(frozen=True, slots=True)
class ArtifactRequest:
    payload: bytes = field(repr=False)
    root_identity_sha256: str
    subject_identity_sha256: str
    artifact_type: ArtifactType
    scope_hmac_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class IssuedCapability:
    handle: str = field(repr=False)
    namespace_id: str


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    artifact_type: ArtifactType
    byte_length: int
    namespace_id: str
    payload: bytes = field(repr=False)
    payload_sha256: str
    root_identity_sha256: str
    subject_identity_sha256: str
    scope_hmac_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class StoreSummary:
    artifact_count: int
    capability_count: int
    total_artifact_bytes: int
    namespace_id: str
    recovery_required: bool


@dataclass(frozen=True, slots=True)
class _Usage:
    artifacts: int
    capabilities: int
    payload_bytes: int
    lookup_ids: frozenset[str]
    selected: StoredArtifact | None = None


def predicted_capability_bytes(count: int) -> int:
    """Return the exact UTF-8 bytes occupied by ``count`` external handles."""

    if type(count) is not int or count < 0 or count > _HARD_MAX_CAPABILITIES:
        raise StoreError(StoreErrorCode.INVALID_ARGUMENT)
    return count * _CAPABILITY_TEXT_BYTES


def _raise(code: StoreErrorCode) -> None:
    raise StoreError(code) from None


def _descriptor_status(
    descriptor: object,
    *,
    error_code: StoreErrorCode = StoreErrorCode.UNSAFE_STATE,
) -> os.stat_result:
    if type(descriptor) is not int or descriptor < 0:
        _raise(error_code)
    try:
        return os.fstat(descriptor)
    except OSError:
        _raise(error_code)


def _require_directory_descriptor(descriptor: object) -> int:
    status = _descriptor_status(descriptor)
    if not stat.S_ISDIR(status.st_mode):
        _raise(StoreErrorCode.UNSAFE_STATE)
    return descriptor


def _require_private_file_descriptor(descriptor: object) -> int:
    status = _descriptor_status(descriptor)
    if not _private_file(status):
        _raise(StoreErrorCode.UNSAFE_STATE)
    return descriptor


def _bounded_names(
    descriptor: int, maximum: int, *, overflow: StoreErrorCode = StoreErrorCode.STORE_CORRUPT
) -> list[str]:
    checked_descriptor = _require_directory_descriptor(descriptor)
    names: list[str] = []
    try:
        with os.scandir(checked_descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    _raise(overflow)
    except StoreError:
        raise
    except OSError:
        _raise(StoreErrorCode.STORE_CORRUPT)
    return names


def _require_filesystem_features() -> None:
    required_flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")
    if any(not getattr(os, name, 0) for name in required_flags):
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    if os.rename not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    effective_uid = getattr(os, "geteuid", None)
    if not callable(effective_uid) or not hasattr(stat, "S_ISVTX"):
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    try:
        observed_uid = effective_uid()
    except OSError:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    if type(observed_uid) is not int or observed_uid < 0:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)


def _validate_state_path(value: object) -> str:
    if type(value) is not str or not value or "\0" in value:
        _raise(StoreErrorCode.STATE_DIR_REQUIRED)
    if not os.path.isabs(value):
        _raise(StoreErrorCode.STATE_DIR_NOT_ABSOLUTE)
    if value == os.sep or os.path.normpath(value) != value or "//" in value:
        _raise(StoreErrorCode.STATE_DIR_NOT_NORMALIZED)
    if any(component in ("", ".", "..") for component in value.split(os.sep)[1:]):
        _raise(StoreErrorCode.STATE_DIR_NOT_NORMALIZED)
    return value


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


def _trusted_ancestry_directory(status: os.stat_result) -> bool:
    effective_uid = getattr(os, "geteuid", None)
    if not callable(effective_uid):
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    try:
        observed_uid = effective_uid()
    except OSError:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    if type(observed_uid) is not int or observed_uid < 0:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    writable_by_other_principal = bool(
        status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid in (0, observed_uid)
        and (
            not writable_by_other_principal
            or bool(status.st_mode & stat.S_ISVTX)
        )
    )


def _adopt_open_descriptor(
    descriptor: int,
    *,
    validator: Callable[[os.stat_result], bool],
    error_code: StoreErrorCode,
) -> tuple[int, os.stat_result]:
    try:
        status = os.fstat(descriptor)
        valid = validator(status)
    except StoreError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    except OSError:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _raise(error_code)
    if not valid:
        try:
            os.close(descriptor)
        except OSError:
            pass
        _raise(error_code)
    return descriptor, status


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _file_read_flags() -> int:
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def _open_directory_at(parent_fd: int, name: str) -> int:
    checked_parent = _require_directory_descriptor(parent_fd)
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=checked_parent)
    except OSError:
        _raise(StoreErrorCode.UNSAFE_STATE)
    descriptor, _status = _adopt_open_descriptor(
        descriptor,
        validator=_private_directory,
        error_code=StoreErrorCode.UNSAFE_STATE,
    )
    return descriptor


def _open_absolute_state_directory(path: str, *, create: bool) -> int:
    try:
        current = os.open(os.sep, _directory_flags())
    except OSError:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    components = path.split(os.sep)[1:]
    try:
        for index, component in enumerate(components):
            last = index == len(components) - 1
            try:
                next_descriptor = os.open(component, _directory_flags(), dir_fd=current)
            except FileNotFoundError:
                if not (last and create):
                    _raise(StoreErrorCode.STORE_UNINITIALIZED)
                next_descriptor = None
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    next_descriptor = os.open(component, _directory_flags(), dir_fd=current)
                    os.fchmod(next_descriptor, 0o700)
                    os.fsync(current)
                except OSError:
                    if next_descriptor is not None:
                        try:
                            os.close(next_descriptor)
                        except OSError:
                            pass
                    _raise(StoreErrorCode.WRITE_FAILED)
            except OSError:
                _raise(StoreErrorCode.UNSAFE_STATE)
            os.close(current)
            current = next_descriptor
        if not _private_directory(_descriptor_status(current)):
            _raise(StoreErrorCode.UNSAFE_STATE)
        return current
    except Exception:
        os.close(current)
        raise


def _open_existing_absolute_ancestor(path: str) -> tuple[int, bool]:
    try:
        current = os.open(os.sep, _directory_flags())
    except OSError:
        _raise(StoreErrorCode.FILESYSTEM_UNSUPPORTED)
    try:
        for component in path.split(os.sep)[1:]:
            try:
                next_descriptor = os.open(
                    component, _directory_flags(), dir_fd=current
                )
            except FileNotFoundError:
                return current, False
            except OSError:
                _raise(StoreErrorCode.UNSAFE_STATE)
            os.close(current)
            current = next_descriptor
        return current, True
    except Exception:
        os.close(current)
        raise


def _open_existing_absolute_directory(path: str) -> int:
    descriptor, complete = _open_existing_absolute_ancestor(path)
    if not complete:
        os.close(descriptor)
        _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
    return descriptor


def _physical_directory_ancestry(descriptor: int) -> frozenset[tuple[int, int]]:
    checked_descriptor = _require_directory_descriptor(descriptor)
    try:
        opened = os.open(".", _directory_flags(), dir_fd=checked_descriptor)
    except OSError:
        _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
    current, current_status = _adopt_open_descriptor(
        opened,
        validator=_trusted_ancestry_directory,
        error_code=StoreErrorCode.STATE_DIR_FORBIDDEN,
    )
    identities: set[tuple[int, int]] = set()
    try:
        for _depth in range(4096):
            identity = current_status.st_dev, current_status.st_ino
            identities.add(identity)
            opened_parent = os.open("..", _directory_flags(), dir_fd=current)
            parent, parent_status = _adopt_open_descriptor(
                opened_parent,
                validator=_trusted_ancestry_directory,
                error_code=StoreErrorCode.STATE_DIR_FORBIDDEN,
            )
            parent_identity = parent_status.st_dev, parent_status.st_ino
            if parent_identity == identity:
                os.close(parent)
                return frozenset(identities)
            os.close(current)
            current = parent
            current_status = parent_status
    except OSError:
        _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
    finally:
        os.close(current)
    _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)


def _require_physical_disjoint(
    state_descriptor: int,
    *,
    state_complete: bool,
    exclusion_descriptors: tuple[int, ...],
) -> None:
    try:
        state_status = os.fstat(state_descriptor)
        state_identity = state_status.st_dev, state_status.st_ino
        state_ancestry = _physical_directory_ancestry(state_descriptor)
        for excluded_descriptor in exclusion_descriptors:
            excluded_status = os.fstat(excluded_descriptor)
            excluded_identity = excluded_status.st_dev, excluded_status.st_ino
            excluded_ancestry = _physical_directory_ancestry(excluded_descriptor)
            if excluded_identity in state_ancestry or (
                state_complete and state_identity in excluded_ancestry
            ):
                _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
    except StoreError:
        raise
    except OSError:
        _raise(StoreErrorCode.UNSAFE_STATE)


def _close_directory_descriptors(descriptors: tuple[int, ...] | list[int]) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _check_disjoint(
    state_path: str, repository_root: object, git_executable: object
) -> tuple[int, ...]:
    try:
        exclusions = _repository_exclusion_snapshot(
            repository_root, git_executable=git_executable
        )
    except IdentityError:
        _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
    exclusion_descriptors: list[int] = []
    try:
        for excluded, expected_identity in exclusions:
            excluded_descriptor = _open_existing_absolute_directory(str(excluded))
            exclusion_descriptors.append(excluded_descriptor)
            excluded_status = _descriptor_status(
                excluded_descriptor,
                error_code=StoreErrorCode.STATE_DIR_FORBIDDEN,
            )
            observed_identity = excluded_status.st_dev, excluded_status.st_ino
            if observed_identity != expected_identity:
                _raise(StoreErrorCode.STATE_DIR_FORBIDDEN)
        state_descriptor, state_complete = _open_existing_absolute_ancestor(state_path)
        try:
            _require_physical_disjoint(
                state_descriptor,
                state_complete=state_complete,
                exclusion_descriptors=tuple(exclusion_descriptors),
            )
        finally:
            os.close(state_descriptor)
        return tuple(exclusion_descriptors)
    except Exception:
        _close_directory_descriptors(exclusion_descriptors)
        raise


def _open_private_file(parent_fd: int, name: str) -> int:
    checked_parent = _require_directory_descriptor(parent_fd)
    try:
        descriptor = os.open(name, _file_read_flags(), dir_fd=checked_parent)
    except OSError:
        _raise(StoreErrorCode.STORE_CORRUPT)
    descriptor, _status = _adopt_open_descriptor(
        descriptor,
        validator=_private_file,
        error_code=StoreErrorCode.UNSAFE_STATE,
    )
    return descriptor


def _read_all(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, min(64 * 1024, maximum - total + 1))
        except InterruptedError:
            continue
        except OSError:
            _raise(StoreErrorCode.STORE_CORRUPT)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            _raise(StoreErrorCode.STORE_CORRUPT)
        chunks.append(chunk)
    return b"".join(chunks)


def _read_named_file(parent_fd: int, name: str, maximum: int) -> bytes:
    descriptor = _open_private_file(parent_fd, name)
    try:
        before = _descriptor_status(
            descriptor, error_code=StoreErrorCode.STORE_CORRUPT
        )
        raw = _read_all(descriptor, maximum)
        after = _descriptor_status(
            descriptor, error_code=StoreErrorCode.STORE_CORRUPT
        )
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(raw) != after.st_size:
            _raise(StoreErrorCode.STORE_TAMPERED)
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
            _raise(StoreErrorCode.WRITE_FAILED)
        if written <= 0:
            _raise(StoreErrorCode.WRITE_FAILED)
        offset += written


def _write_new_file(parent_fd: int, name: str, raw: bytes) -> None:
    checked_parent = _require_directory_descriptor(parent_fd)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=checked_parent)
    except OSError:
        _raise(StoreErrorCode.WRITE_FAILED)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if not _private_file(status) or status.st_size != len(raw):
            _raise(StoreErrorCode.WRITE_FAILED)
    except StoreError:
        raise
    except OSError:
        _raise(StoreErrorCode.WRITE_FAILED)
    finally:
        os.close(descriptor)


def _source_fingerprint(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _private_source_status(
    source_fd: object, byte_length: object, maximum: int
) -> os.stat_result:
    if (
        type(source_fd) is not int
        or source_fd < 0
        or type(byte_length) is not int
        or byte_length < 0
        or byte_length > maximum
        or not hasattr(os, "pread")
    ):
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    status = _descriptor_status(source_fd, error_code=StoreErrorCode.INVALID_ARGUMENT)
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != os.geteuid()
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_nlink not in {0, 1}
        or status.st_size != byte_length
    ):
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    return status


def _source_matches_payload(
    source_fd: int,
    byte_length: int,
    before: os.stat_result,
    payload: bytes,
) -> bool:
    if len(payload) != byte_length:
        return False
    offset = 0
    while offset < byte_length:
        try:
            chunk = os.pread(source_fd, min(64 * 1024, byte_length - offset), offset)
        except InterruptedError:
            continue
        except OSError:
            _raise(StoreErrorCode.WRITE_FAILED)
        if not chunk or not hmac.compare_digest(
            chunk, payload[offset : offset + len(chunk)]
        ):
            return False
        offset += len(chunk)
    after = _descriptor_status(source_fd, error_code=StoreErrorCode.WRITE_FAILED)
    return _source_fingerprint(before) == _source_fingerprint(after)


def _payload_sha256(payload: bytes) -> str:
    """Hash one already size-checked store payload with the frozen framing."""

    digest = hashlib.sha256()
    digest.update(b"contextguard-receipt/store-payload/v1\0")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def _write_new_stream_file(
    parent_fd: int,
    name: str,
    *,
    source_fd: int,
    byte_length: int,
    source_status: os.stat_result,
    subject_identity_domain: str,
) -> tuple[str, str]:
    checked_parent = _require_directory_descriptor(parent_fd)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=checked_parent)
    except OSError:
        _raise(StoreErrorCode.WRITE_FAILED)
    digest = hashlib.sha256()
    digest.update(b"contextguard-receipt/store-payload/v1\0")
    digest.update(byte_length.to_bytes(8, "big"))
    subject_digest = hashlib.sha256()
    subject_digest.update(subject_identity_domain.encode("ascii"))
    subject_digest.update(b"\0")
    subject_digest.update(byte_length.to_bytes(8, "big"))
    offset = 0
    try:
        os.fchmod(descriptor, 0o600)
        while offset < byte_length:
            try:
                chunk = os.pread(
                    source_fd, min(64 * 1024, byte_length - offset), offset
                )
            except InterruptedError:
                continue
            if not chunk:
                _raise(StoreErrorCode.WRITE_FAILED)
            _write_all(descriptor, chunk)
            digest.update(chunk)
            subject_digest.update(chunk)
            offset += len(chunk)
        os.fsync(descriptor)
        destination_status = os.fstat(descriptor)
        final_source_status = os.fstat(source_fd)
        if (
            not _private_file(destination_status)
            or destination_status.st_size != byte_length
            or _source_fingerprint(source_status)
            != _source_fingerprint(final_source_status)
        ):
            _raise(StoreErrorCode.WRITE_FAILED)
    except StoreError:
        raise
    except OSError:
        _raise(StoreErrorCode.WRITE_FAILED)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), subject_digest.hexdigest()


def _hmac_hex(key: bytes, domain: bytes, raw: bytes) -> str:
    return hmac.new(key, domain + b"\0" + raw, hashlib.sha256).hexdigest()


def _canonical_document(value: object, limits: JSONLimits | None) -> bytes:
    return canonical_json_bytes(value) if limits is None else canonical_json_bytes(value, limits)


def _mac_document(
    key: bytes,
    domain: bytes,
    value: dict[str, object],
    *,
    limits: JSONLimits | None = None,
) -> bytes:
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256", None)
    value["integrity_hmac_sha256"] = _hmac_hex(
        key, domain, _canonical_document(unsigned, limits)
    )
    return _canonical_document(value, limits)


def _verify_document_mac(
    key: bytes,
    domain: bytes,
    value: object,
    *,
    expected_keys: frozenset[str],
    limits: JSONLimits | None = None,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected_keys:
        _raise(StoreErrorCode.STORE_CORRUPT)
    result = value
    supplied = result.get("integrity_hmac_sha256")
    if type(supplied) is not str or _HEX_256.fullmatch(supplied) is None:
        _raise(StoreErrorCode.STORE_CORRUPT)
    unsigned = dict(result)
    unsigned.pop("integrity_hmac_sha256")
    expected = _hmac_hex(key, domain, _canonical_document(unsigned, limits))
    if not hmac.compare_digest(supplied, expected):
        _raise(StoreErrorCode.STORE_TAMPERED)
    return result


def _parse_document(raw: bytes, limits: JSONLimits | None = None) -> object:
    try:
        return (
            parse_canonical_json_bytes(raw)
            if limits is None
            else parse_canonical_json_bytes(raw, limits)
        )
    except CanonicalJSONError:
        _raise(StoreErrorCode.STORE_CORRUPT)


def _validate_auxiliary_compartment(state_fd: int, top_names: set[str]) -> None:
    """Validate only the removable axis boundary, never its private internals."""

    if _AUXILIARY_DIRECTORY not in top_names:
        return
    auxiliary_fd = _open_directory_at(state_fd, _AUXILIARY_DIRECTORY)
    diagnostics_fd: int | None = None
    twin_fd: int | None = None
    reference_expiry_fd: int | None = None
    try:
        names = set(
            _bounded_names(
                auxiliary_fd, 4, overflow=StoreErrorCode.RECOVERY_REQUIRED
            )
        )
        allowed = {
            _AUXILIARY_METADATA_NAME,
            _DIAGNOSTICS_DIRECTORY,
            _TWIN_DIRECTORY,
            _REFERENCE_EXPIRY_DIRECTORY,
        }
        if _AUXILIARY_METADATA_NAME not in names or names - allowed:
            _raise(StoreErrorCode.RECOVERY_REQUIRED)
        metadata = _parse_document(
            _read_named_file(auxiliary_fd, _AUXILIARY_METADATA_NAME, 4096),
            _AUXILIARY_JSON_LIMITS,
        )
        if metadata != {
            "evidence_boundary": evidence_boundary(),
            "schema_version": _AUXILIARY_SCHEMA_VERSION,
        }:
            _raise(StoreErrorCode.STORE_CORRUPT)
        if _DIAGNOSTICS_DIRECTORY in names:
            diagnostics_fd = _open_directory_at(
                auxiliary_fd, _DIAGNOSTICS_DIRECTORY
            )
        if _TWIN_DIRECTORY in names:
            twin_fd = _open_directory_at(auxiliary_fd, _TWIN_DIRECTORY)
        if _REFERENCE_EXPIRY_DIRECTORY in names:
            reference_expiry_fd = _open_directory_at(
                auxiliary_fd, _REFERENCE_EXPIRY_DIRECTORY
            )
    finally:
        if reference_expiry_fd is not None:
            os.close(reference_expiry_fd)
        if twin_fd is not None:
            os.close(twin_fd)
        if diagnostics_fd is not None:
            os.close(diagnostics_fd)
        os.close(auxiliary_fd)


def _limits_object(limits: StoreLimits) -> dict[str, int]:
    return {item.name: getattr(limits, item.name) for item in fields(limits)}


def _limits_from_object(value: object) -> StoreLimits:
    expected = {item.name for item in fields(StoreLimits)}
    if type(value) is not dict or set(value) != expected:
        _raise(StoreErrorCode.STORE_CORRUPT)
    try:
        return StoreLimits(**value)
    except (StoreError, TypeError):
        _raise(StoreErrorCode.STORE_CORRUPT)


def _store_metadata_bytes(
    key: bytes, namespace_id: str, limits: StoreLimits
) -> bytes:
    return _mac_document(
        key,
        b"contextguard-receipt/store-metadata-mac/v1",
        {
            "evidence_boundary": evidence_boundary(),
            "integrity_hmac_sha256": "",
            "limits": _limits_object(limits),
            "namespace_id": namespace_id,
            "schema_version": _STORE_SCHEMA_VERSION,
        },
    )


def _external_capability(raw: bytes) -> str:
    return _CAPABILITY_PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _capability_bytes(handle: object) -> bytes:
    if type(handle) is not str or _CAPABILITY_PATTERN.fullmatch(handle) is None:
        _raise(StoreErrorCode.CAPABILITY_REJECTED)
    suffix = handle[len(_CAPABILITY_PREFIX) :]
    try:
        raw = base64.b64decode(
            (suffix + "=").encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error):
        _raise(StoreErrorCode.CAPABILITY_REJECTED)
    if len(raw) != _CAPABILITY_RAW_BYTES or _external_capability(raw) != handle:
        _raise(StoreErrorCode.CAPABILITY_REJECTED)
    return raw


def _lookup_id(key: bytes, namespace_id: str, capability: bytes) -> str:
    namespace = bytes.fromhex(namespace_id)
    framed = (
        len(namespace).to_bytes(8, "big")
        + namespace
        + len(capability).to_bytes(8, "big")
        + capability
    )
    return _hmac_hex(key, b"contextguard-receipt/capability-lookup/v1", framed)


def _idempotent_capability(
    key: bytes, namespace_id: str, idempotency_key: str
) -> bytes:
    if type(idempotency_key) is not str or _HEX_256.fullmatch(idempotency_key) is None:
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    framed = bytes.fromhex(namespace_id) + bytes.fromhex(idempotency_key)
    return hmac.new(
        key,
        b"contextguard-receipt/idempotent-capability/v1\0" + framed,
        hashlib.sha256,
    ).digest()


def _validate_hash(value: object) -> str:
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    return value


def _validate_request(request: object, limits: StoreLimits) -> ArtifactRequest:
    if type(request) is not ArtifactRequest:
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    if type(request.payload) is not bytes:
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    if len(request.payload) > limits.max_single_artifact_bytes:
        _raise(StoreErrorCode.ARTIFACT_TOO_LARGE)
    _validate_hash(request.root_identity_sha256)
    _validate_hash(request.subject_identity_sha256)
    if type(request.artifact_type) is not ArtifactType:
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    if request.scope_hmac_sha256 is not None:
        # The durable record format does not persist this field (see
        # issue_batch below), so a scoped request would silently resolve as
        # unscoped after a read-back. Refuse it here rather than let scope
        # binding silently disappear until durable persistence is added.
        _raise(StoreErrorCode.INVALID_ARGUMENT)
    return request


class CapabilityStore:
    """An explicit private store; no path or content identifier grants retrieval."""

    def __init__(self) -> None:
        self._closed = True
        self._descriptor_boundary_retained = False
        self._close_requested = False
        self._active_operations = 0
        self._exclusion_fds: tuple[int, ...] = ()
        self._opener_pid = os.getpid()
        self._thread_lock = threading.RLock()

    @classmethod
    def open(
        cls,
        *,
        state_dir: str,
        repository_root: object,
        git_executable: object = None,
        create: bool = False,
        limits: StoreLimits | None = None,
        allow_default_limit_upgrade: bool = False,
    ) -> "CapabilityStore":
        _require_filesystem_features()
        checked_path = _validate_state_path(state_dir)
        if (
            type(create) is not bool
            or type(allow_default_limit_upgrade) is not bool
            or (limits is not None and type(limits) is not StoreLimits)
            or (
                allow_default_limit_upgrade
                and limits != _MERGED_CAPTURE_STORE_LIMITS
            )
        ):
            _raise(StoreErrorCode.INVALID_ARGUMENT)
        exclusion_descriptors = _check_disjoint(
            checked_path, repository_root, git_executable
        )
        state_fd: int | None = None
        try:
            state_fd = _open_absolute_state_directory(checked_path, create=create)
            _require_physical_disjoint(
                state_fd,
                state_complete=True,
                exclusion_descriptors=exclusion_descriptors,
            )
            instance = cls()
            instance._state_path = checked_path
            instance._state_fd = state_fd
            instance._exclusion_fds = exclusion_descriptors
            state_fd = None
            exclusion_descriptors = ()
        except Exception:
            if state_fd is not None:
                os.close(state_fd)
            _close_directory_descriptors(exclusion_descriptors)
            raise
        try:
            instance._lock_fd = instance._open_lock(create=create)
            with instance._locked(exclusive=True):
                instance._ensure_initialized(create=create, limits=limits)
                instance._open_store()
                if limits is not None and limits != instance._limits:
                    if allow_default_limit_upgrade:
                        instance._upgrade_default_limits(limits)
                    if limits != instance._limits:
                        _raise(StoreErrorCode.INVALID_ARGUMENT)
            instance._closed = False
            return instance
        except Exception:
            instance._close_descriptors()
            raise

    def _revalidate_state_disjoint(self) -> None:
        exclusion_fds = self._exclusion_fds
        if type(exclusion_fds) is not tuple or not exclusion_fds:
            _raise(StoreErrorCode.UNSAFE_STATE)
        state_fd = _require_directory_descriptor(self._state_fd)
        checked_exclusions = tuple(
            _require_directory_descriptor(descriptor)
            for descriptor in exclusion_fds
        )
        _require_physical_disjoint(
            state_fd,
            state_complete=True,
            exclusion_descriptors=checked_exclusions,
        )

    def _open_lock(self, *, create: bool) -> int:
        self._revalidate_state_disjoint()
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        created = False
        descriptor: int | None = None
        try:
            descriptor = os.open(_LOCK_NAME, flags, dir_fd=self._state_fd)
        except FileNotFoundError:
            if not create:
                _raise(StoreErrorCode.STORE_UNINITIALIZED)
            try:
                descriptor = os.open(
                    _LOCK_NAME,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=self._state_fd,
                )
                os.fchmod(descriptor, 0o600)
                created = True
            except OSError:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                _raise(StoreErrorCode.WRITE_FAILED)
        except OSError:
            _raise(StoreErrorCode.UNSAFE_STATE)
        if descriptor is None:
            _raise(StoreErrorCode.WRITE_FAILED)
        descriptor, _status = _adopt_open_descriptor(
            descriptor,
            validator=_private_file,
            error_code=StoreErrorCode.UNSAFE_STATE,
        )
        if created:
            try:
                os.fsync(descriptor)
                os.fsync(self._state_fd)
            except OSError:
                os.close(descriptor)
                _raise(StoreErrorCode.COMMIT_UNCERTAIN)
        return descriptor

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        self._require_opener_process()
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        if not self._thread_lock.acquire(
            timeout=max(0.0, deadline - time.monotonic())
        ):
            _raise(StoreErrorCode.LOCK_TIMEOUT)
        flock_acquired = False
        try:
            lock_fd = _require_private_file_descriptor(self._lock_fd)
            while True:
                try:
                    fcntl.flock(lock_fd, operation | fcntl.LOCK_NB)
                    flock_acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        _raise(StoreErrorCode.LOCK_TIMEOUT)
                    time.sleep(0.01)
                except OSError:
                    _raise(StoreErrorCode.UNSAFE_STATE)
            yield
        finally:
            if flock_acquired:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            self._thread_lock.release()

    def _ensure_initialized(self, *, create: bool, limits: StoreLimits | None) -> None:
        self._revalidate_state_disjoint()
        names = set(
            _bounded_names(
                self._state_fd, 3, overflow=StoreErrorCode.RECOVERY_REQUIRED
            )
        )
        allowed = {_LOCK_NAME, _STORE_DIRECTORY, _AUXILIARY_DIRECTORY}
        if any(name not in allowed for name in names):
            _raise(StoreErrorCode.RECOVERY_REQUIRED)
        _validate_auxiliary_compartment(self._state_fd, names)
        if _STORE_DIRECTORY in names:
            return
        if not create:
            _raise(StoreErrorCode.STORE_UNINITIALIZED)
        effective_limits = _DEFAULT_STORE_LIMITS if limits is None else limits
        key = secrets.token_bytes(32)
        namespace_id = secrets.token_bytes(32).hex()
        temporary_name = ".store-v1.tmp-" + secrets.token_bytes(16).hex()
        temporary_fd: int | None = None
        try:
            os.mkdir(temporary_name, 0o700, dir_fd=self._state_fd)
            temporary_fd = os.open(temporary_name, _directory_flags(), dir_fd=self._state_fd)
            os.fchmod(temporary_fd, 0o700)
            _write_new_file(temporary_fd, _KEY_NAME, key)
            _write_new_file(
                temporary_fd,
                _METADATA_NAME,
                _store_metadata_bytes(key, namespace_id, effective_limits),
            )
            for child in (_COMMITS_NAME, _TEMP_NAME):
                os.mkdir(child, 0o700, dir_fd=temporary_fd)
                child_fd = os.open(child, _directory_flags(), dir_fd=temporary_fd)
                try:
                    os.fchmod(child_fd, 0o700)
                    os.fsync(child_fd)
                finally:
                    os.close(child_fd)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.rename(
                temporary_name,
                _STORE_DIRECTORY,
                src_dir_fd=self._state_fd,
                dst_dir_fd=self._state_fd,
            )
            try:
                os.fsync(self._state_fd)
            except OSError:
                _raise(StoreErrorCode.COMMIT_UNCERTAIN)
        except StoreError:
            raise
        except OSError:
            _raise(StoreErrorCode.WRITE_FAILED)
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass

    def _open_store(self) -> None:
        self._revalidate_state_disjoint()
        self._store_fd = _open_directory_at(self._state_fd, _STORE_DIRECTORY)
        key = _read_named_file(self._store_fd, _KEY_NAME, 33)
        if len(key) != 32:
            _raise(StoreErrorCode.STORE_CORRUPT)
        self._key = key
        namespace_id, limits = self._read_authenticated_metadata()
        self._namespace_id = namespace_id
        self._limits = limits
        self._commits_fd = _open_directory_at(self._store_fd, _COMMITS_NAME)
        self._temp_fd = _open_directory_at(self._store_fd, _TEMP_NAME)
        if set(_bounded_names(self._store_fd, 4)) != {
            _KEY_NAME,
            _METADATA_NAME,
            _COMMITS_NAME,
            _TEMP_NAME,
        }:
            _raise(StoreErrorCode.STORE_CORRUPT)
        self._state_anchor = self._descriptor_identity(self._state_fd)
        self._lock_anchor = self._descriptor_identity(self._lock_fd)
        self._store_anchor = self._descriptor_identity(self._store_fd)
        self._commits_anchor = self._descriptor_identity(self._commits_fd)
        self._temp_anchor = self._descriptor_identity(self._temp_fd)
        self._revalidate_anchors()

    def _read_authenticated_metadata(self) -> tuple[str, StoreLimits]:
        metadata_raw = _read_named_file(self._store_fd, _METADATA_NAME, 64 * 1024)
        metadata = _verify_document_mac(
            self._key,
            b"contextguard-receipt/store-metadata-mac/v1",
            _parse_document(metadata_raw),
            expected_keys=frozenset(
                {
                    "evidence_boundary",
                    "integrity_hmac_sha256",
                    "limits",
                    "namespace_id",
                    "schema_version",
                }
            ),
        )
        if (
            metadata.get("schema_version") != _STORE_SCHEMA_VERSION
            or metadata.get("evidence_boundary") != evidence_boundary()
        ):
            _raise(StoreErrorCode.STORE_CORRUPT)
        namespace_id = metadata.get("namespace_id")
        if type(namespace_id) is not str or _HEX_256.fullmatch(namespace_id) is None:
            _raise(StoreErrorCode.STORE_CORRUPT)
        return namespace_id, _limits_from_object(metadata.get("limits"))

    def _refresh_limits(self) -> None:
        namespace_id, persisted_limits = self._read_authenticated_metadata()
        if namespace_id != self._namespace_id:
            _raise(StoreErrorCode.STORE_CORRUPT)
        if persisted_limits == self._limits:
            return
        if (
            self._limits == _DEFAULT_STORE_LIMITS
            and persisted_limits == _MERGED_CAPTURE_STORE_LIMITS
        ):
            self._limits = persisted_limits
            return
        _raise(StoreErrorCode.STORE_CORRUPT)

    def _upgrade_default_limits(self, requested_limits: StoreLimits) -> None:
        if (
            self._limits != _DEFAULT_STORE_LIMITS
            or requested_limits != _MERGED_CAPTURE_STORE_LIMITS
        ):
            _raise(StoreErrorCode.INVALID_ARGUMENT)
        self._revalidate_anchors()
        temp_fd = _require_directory_descriptor(self._temp_fd)
        if _bounded_names(
            temp_fd, 1, overflow=StoreErrorCode.RECOVERY_REQUIRED
        ):
            _raise(StoreErrorCode.RECOVERY_REQUIRED)
        self._scan()

        temporary_name = ".metadata.tmp-" + secrets.token_bytes(16).hex()
        metadata_raw = _store_metadata_bytes(
            self._key, self._namespace_id, requested_limits
        )
        mutation_started = False
        try:
            mutation_started = True
            _write_new_file(temp_fd, temporary_name, metadata_raw)
            os.rename(
                temporary_name,
                _METADATA_NAME,
                src_dir_fd=temp_fd,
                dst_dir_fd=self._store_fd,
            )
            os.fsync(self._store_fd)
            os.fsync(temp_fd)
            namespace_id, persisted_limits = self._read_authenticated_metadata()
            if (
                namespace_id != self._namespace_id
                or persisted_limits != requested_limits
            ):
                _raise(StoreErrorCode.COMMIT_UNCERTAIN)
            self._limits = persisted_limits
            self._scan()
            self._revalidate_anchors()
        except StoreError:
            if mutation_started:
                _raise(StoreErrorCode.COMMIT_UNCERTAIN)
            raise
        except OSError:
            _raise(
                StoreErrorCode.COMMIT_UNCERTAIN
                if mutation_started
                else StoreErrorCode.WRITE_FAILED
            )

    @staticmethod
    def _descriptor_identity(descriptor: int) -> tuple[int, int]:
        status = _descriptor_status(descriptor)
        return status.st_dev, status.st_ino

    def _revalidate_anchors(self) -> None:
        self._revalidate_state_disjoint()
        if self._descriptor_boundary_retained:
            retained = (
                (self._state_fd, self._state_anchor),
                (self._lock_fd, self._lock_anchor),
                (self._store_fd, self._store_anchor),
                (self._commits_fd, self._commits_anchor),
                (self._temp_fd, self._temp_anchor),
            )
            if any(
                self._descriptor_identity(descriptor) != anchor
                for descriptor, anchor in retained
            ):
                _raise(StoreErrorCode.UNSAFE_STATE)
            return
        opened: list[int] = []
        try:
            state_fd = _open_absolute_state_directory(self._state_path, create=False)
            opened.append(state_fd)
            if self._descriptor_identity(state_fd) != self._state_anchor:
                _raise(StoreErrorCode.UNSAFE_STATE)
            names = set(
                _bounded_names(
                    state_fd, 3, overflow=StoreErrorCode.RECOVERY_REQUIRED
                )
            )
            if names not in (
                {_LOCK_NAME, _STORE_DIRECTORY},
                {_LOCK_NAME, _STORE_DIRECTORY, _AUXILIARY_DIRECTORY},
            ):
                _raise(StoreErrorCode.RECOVERY_REQUIRED)
            _validate_auxiliary_compartment(state_fd, names)
            lock_fd = _open_private_file(state_fd, _LOCK_NAME)
            opened.append(lock_fd)
            if self._descriptor_identity(lock_fd) != self._lock_anchor:
                _raise(StoreErrorCode.UNSAFE_STATE)
            store_fd = _open_directory_at(state_fd, _STORE_DIRECTORY)
            opened.append(store_fd)
            if self._descriptor_identity(store_fd) != self._store_anchor:
                _raise(StoreErrorCode.UNSAFE_STATE)
            commits_fd = _open_directory_at(store_fd, _COMMITS_NAME)
            opened.append(commits_fd)
            if self._descriptor_identity(commits_fd) != self._commits_anchor:
                _raise(StoreErrorCode.UNSAFE_STATE)
            temp_fd = _open_directory_at(store_fd, _TEMP_NAME)
            opened.append(temp_fd)
            if self._descriptor_identity(temp_fd) != self._temp_anchor:
                _raise(StoreErrorCode.UNSAFE_STATE)
        except StoreError:
            _raise(StoreErrorCode.UNSAFE_STATE)
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    def _retain_descriptor_boundary(self) -> None:
        """Stop reopening the state pathname after one final full validation."""

        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(StoreErrorCode.INVALID_ARGUMENT)
            self._revalidate_anchors()
            self._descriptor_boundary_retained = True

    @property
    def namespace_id(self) -> str:
        with self._operation():
            return self._namespace_id

    @property
    def limits(self) -> StoreLimits:
        with self._operation():
            with self._locked(exclusive=False):
                self._revalidate_anchors()
                self._refresh_limits()
                self._revalidate_anchors()
            return self._limits

    @contextmanager
    def _operation(self) -> Iterator[None]:
        self._require_opener_process()
        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(StoreErrorCode.INVALID_ARGUMENT)
            for name in ("_state_fd", "_store_fd", "_commits_fd", "_temp_fd"):
                _require_directory_descriptor(getattr(self, name, None))
            _require_private_file_descriptor(getattr(self, "_lock_fd", None))
            self._active_operations += 1
            try:
                yield
            finally:
                self._active_operations -= 1
                if self._active_operations == 0 and self._close_requested:
                    self._close_descriptors()
                    self._closed = True
                    self._close_requested = False

    def _require_open(self) -> None:
        self._require_opener_process()
        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(StoreErrorCode.INVALID_ARGUMENT)

    def _require_opener_process(self) -> None:
        if os.getpid() != self._opener_pid:
            _raise(StoreErrorCode.UNSAFE_STATE)

    def issue(
        self,
        *,
        payload: bytes,
        root_identity_sha256: str,
        subject_identity_sha256: str,
        artifact_type: ArtifactType,
    ) -> IssuedCapability:
        request = ArtifactRequest(
            payload=payload,
            root_identity_sha256=root_identity_sha256,
            subject_identity_sha256=subject_identity_sha256,
            artifact_type=artifact_type,
        )
        return self.issue_batch((request,))[0]

    def issue_batch(self, requests: tuple[ArtifactRequest, ...]) -> tuple[IssuedCapability, ...]:
        with self._operation():
            return self._issue_batch(requests)

    def ensure_issued(
        self,
        *,
        payload: bytes,
        root_identity_sha256: str,
        subject_identity_sha256: str,
        artifact_type: ArtifactType,
        idempotency_key: str,
    ) -> IssuedCapability:
        """Issue once for one opaque idempotency key, or validate the exact prior issue."""

        request = ArtifactRequest(
            payload=payload,
            root_identity_sha256=root_identity_sha256,
            subject_identity_sha256=subject_identity_sha256,
            artifact_type=artifact_type,
        )
        with self._operation():
            capability_raw = _idempotent_capability(
                self._key, self._namespace_id, idempotency_key
            )
            return self._issue_batch(
                (request,), deterministic_capability_raw=capability_raw
            )[0]

    def ensure_issued_file(
        self,
        *,
        source_fd: int,
        byte_length: int,
        root_identity_sha256: str,
        subject_identity_sha256: str,
        subject_identity_domain: str,
        artifact_type: ArtifactType,
        idempotency_key: str,
    ) -> IssuedCapability:
        """Stream one private regular file into deterministic durable authority."""

        with self._operation():
            _validate_hash(root_identity_sha256)
            _validate_hash(subject_identity_sha256)
            try:
                encoded_domain = subject_identity_domain.encode("ascii")
            except (AttributeError, UnicodeEncodeError):
                _raise(StoreErrorCode.INVALID_ARGUMENT)
            if (
                type(subject_identity_domain) is not str
                or not subject_identity_domain
                or "\0" in subject_identity_domain
                or len(encoded_domain) > 128
                or type(artifact_type) is not ArtifactType
            ):
                _raise(StoreErrorCode.INVALID_ARGUMENT)
            capability_raw = _idempotent_capability(
                self._key, self._namespace_id, idempotency_key
            )
            lookup_id = _lookup_id(
                self._key, self._namespace_id, capability_raw
            )
            with self._locked(exclusive=True):
                self._revalidate_anchors()
                self._refresh_limits()
                source_status = _private_source_status(
                    source_fd,
                    byte_length,
                    self._limits.max_single_artifact_bytes,
                )
                temp_fd = _require_directory_descriptor(self._temp_fd)
                commits_fd = _require_directory_descriptor(self._commits_fd)
                if _bounded_names(
                    temp_fd, 1, overflow=StoreErrorCode.RECOVERY_REQUIRED
                ):
                    _raise(StoreErrorCode.RECOVERY_REQUIRED)
                usage = self._scan(return_payload_for=lookup_id)
                if usage.selected is not None:
                    stored = usage.selected
                    if not (
                        stored.artifact_type is artifact_type
                        and stored.byte_length == byte_length
                        and stored.root_identity_sha256
                        == root_identity_sha256
                        and stored.subject_identity_sha256
                        == subject_identity_sha256
                        and _source_matches_payload(
                            source_fd,
                            byte_length,
                            source_status,
                            stored.payload,
                        )
                    ):
                        _raise(StoreErrorCode.CAPABILITY_REJECTED)
                    return IssuedCapability(
                        handle=_external_capability(capability_raw),
                        namespace_id=self._namespace_id,
                    )
                if usage.artifacts + 1 > self._limits.max_artifacts:
                    _raise(StoreErrorCode.ARTIFACT_COUNT_QUOTA_EXCEEDED)
                if usage.capabilities + 1 > self._limits.max_capabilities:
                    _raise(StoreErrorCode.CAPABILITY_COUNT_QUOTA_EXCEEDED)
                if (
                    usage.payload_bytes + byte_length
                    > self._limits.max_total_artifact_bytes
                ):
                    _raise(StoreErrorCode.ARTIFACT_BYTES_QUOTA_EXCEEDED)

                commit_id = secrets.token_bytes(32).hex()
                temporary_id = secrets.token_bytes(16).hex()
                batch_fd: int | None = None
                entry_fd: int | None = None
                published = False
                try:
                    os.mkdir(temporary_id, 0o700, dir_fd=temp_fd)
                    batch_fd = os.open(
                        temporary_id, _directory_flags(), dir_fd=temp_fd
                    )
                    os.fchmod(batch_fd, 0o700)
                    os.mkdir(lookup_id, 0o700, dir_fd=batch_fd)
                    entry_fd = os.open(
                        lookup_id, _directory_flags(), dir_fd=batch_fd
                    )
                    os.fchmod(entry_fd, 0o700)
                    payload_sha256, streamed_subject = _write_new_stream_file(
                        entry_fd,
                        _PAYLOAD_NAME,
                        source_fd=source_fd,
                        byte_length=byte_length,
                        source_status=source_status,
                        subject_identity_domain=subject_identity_domain,
                    )
                    if not hmac.compare_digest(
                        streamed_subject, subject_identity_sha256
                    ):
                        _raise(StoreErrorCode.CAPABILITY_REJECTED)
                    record = {
                        "artifact_type": artifact_type.value,
                        "byte_length": byte_length,
                        "capability_lookup_sha256": lookup_id,
                        "evidence_boundary": evidence_boundary(),
                        "integrity_hmac_sha256": "",
                        "namespace_id": self._namespace_id,
                        "payload_sha256": payload_sha256,
                        "root_identity_sha256": root_identity_sha256,
                        "schema_version": _RECORD_SCHEMA_VERSION,
                        "subject_identity_sha256": subject_identity_sha256,
                    }
                    _write_new_file(
                        entry_fd,
                        _RECORD_NAME,
                        _mac_document(
                            self._key,
                            b"contextguard-receipt/capability-record-mac/v1",
                            record,
                        ),
                    )
                    os.fsync(entry_fd)
                    os.close(entry_fd)
                    entry_fd = None
                    manifest = {
                        "capability_lookup_sha256": [lookup_id],
                        "evidence_boundary": evidence_boundary(),
                        "integrity_hmac_sha256": "",
                        "schema_version": _COMMIT_SCHEMA_VERSION,
                    }
                    _write_new_file(
                        batch_fd,
                        _COMMIT_MANIFEST_NAME,
                        _mac_document(
                            self._key,
                            b"contextguard-receipt/store-commit-mac/v1",
                            manifest,
                            limits=_COMMIT_JSON_LIMITS,
                        ),
                    )
                    os.fsync(batch_fd)
                    os.close(batch_fd)
                    batch_fd = None
                    os.rename(
                        temporary_id,
                        commit_id,
                        src_dir_fd=temp_fd,
                        dst_dir_fd=commits_fd,
                    )
                    published = True
                    parent_sync_failed = False
                    for parent_fd in (temp_fd, commits_fd):
                        try:
                            os.fsync(parent_fd)
                        except OSError:
                            parent_sync_failed = True
                    if parent_sync_failed:
                        _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                    final_usage = self._scan()
                    if lookup_id not in final_usage.lookup_ids:
                        _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                    self._revalidate_anchors()
                except StoreError:
                    if published:
                        _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                    raise
                except OSError:
                    if published:
                        _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                    _raise(StoreErrorCode.WRITE_FAILED)
                finally:
                    for descriptor in (entry_fd, batch_fd):
                        if descriptor is not None:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass
                return IssuedCapability(
                    handle=_external_capability(capability_raw),
                    namespace_id=self._namespace_id,
                )

    def idempotent_handle(self, idempotency_key: str) -> str:
        """Re-derive authority for explicit transaction-scoped recovery."""

        with self._operation():
            return _external_capability(
                _idempotent_capability(
                    self._key, self._namespace_id, idempotency_key
                )
            )

    def _issue_batch(
        self,
        requests: tuple[ArtifactRequest, ...],
        *,
        deterministic_capability_raw: bytes | None = None,
    ) -> tuple[IssuedCapability, ...]:
        if type(requests) is not tuple or not requests:
            _raise(StoreErrorCode.INVALID_ARGUMENT)
        if deterministic_capability_raw is not None and (
            len(requests) != 1
            or type(deterministic_capability_raw) is not bytes
            or len(deterministic_capability_raw) != _CAPABILITY_RAW_BYTES
        ):
            _raise(StoreErrorCode.INVALID_ARGUMENT)
        with self._locked(exclusive=True):
            self._revalidate_anchors()
            self._refresh_limits()
            if len(requests) > self._limits.max_capabilities:
                _raise(StoreErrorCode.CAPABILITY_COUNT_QUOTA_EXCEEDED)
            if len(requests) > self._limits.max_artifacts:
                _raise(StoreErrorCode.ARTIFACT_COUNT_QUOTA_EXCEEDED)
            checked = tuple(
                _validate_request(request, self._limits) for request in requests
            )
            temp_fd = _require_directory_descriptor(self._temp_fd)
            commits_fd = _require_directory_descriptor(self._commits_fd)
            if _bounded_names(
                temp_fd, 1, overflow=StoreErrorCode.RECOVERY_REQUIRED
            ):
                _raise(StoreErrorCode.RECOVERY_REQUIRED)
            deterministic_lookup = (
                _lookup_id(
                    self._key,
                    self._namespace_id,
                    deterministic_capability_raw,
                )
                if deterministic_capability_raw is not None
                else None
            )
            usage = self._scan(return_payload_for=deterministic_lookup)
            if deterministic_capability_raw is not None and usage.selected is not None:
                request = checked[0]
                stored = usage.selected
                if not (
                    stored.artifact_type is request.artifact_type
                    and stored.byte_length == len(request.payload)
                    and stored.root_identity_sha256 == request.root_identity_sha256
                    and stored.subject_identity_sha256
                    == request.subject_identity_sha256
                    and hmac.compare_digest(stored.payload, request.payload)
                ):
                    _raise(StoreErrorCode.CAPABILITY_REJECTED)
                return (
                    IssuedCapability(
                        handle=_external_capability(deterministic_capability_raw),
                        namespace_id=self._namespace_id,
                    ),
                )
            next_count = usage.artifacts + len(checked)
            next_capabilities = usage.capabilities + len(checked)
            next_bytes = usage.payload_bytes + sum(len(item.payload) for item in checked)
            if next_count > self._limits.max_artifacts:
                _raise(StoreErrorCode.ARTIFACT_COUNT_QUOTA_EXCEEDED)
            if next_bytes > self._limits.max_total_artifact_bytes:
                _raise(StoreErrorCode.ARTIFACT_BYTES_QUOTA_EXCEEDED)
            if next_capabilities > self._limits.max_capabilities:
                _raise(StoreErrorCode.CAPABILITY_COUNT_QUOTA_EXCEEDED)

            issued: list[IssuedCapability] = []
            records: list[tuple[str, ArtifactRequest, dict[str, object], bytes]] = []
            reserved = set(usage.lookup_ids)
            for index, request in enumerate(checked):
                if deterministic_capability_raw is not None and index == 0:
                    capability_raw = deterministic_capability_raw
                    lookup_id = _lookup_id(
                        self._key, self._namespace_id, capability_raw
                    )
                    if lookup_id in reserved:
                        _raise(StoreErrorCode.CAPABILITY_REJECTED)
                else:
                    for _attempt in range(8):
                        capability_raw = secrets.token_bytes(_CAPABILITY_RAW_BYTES)
                        lookup_id = _lookup_id(
                            self._key, self._namespace_id, capability_raw
                        )
                        if lookup_id not in reserved:
                            break
                    else:
                        _raise(StoreErrorCode.WRITE_FAILED)
                reserved.add(lookup_id)
                handle = _external_capability(capability_raw)
                payload_sha256 = _payload_sha256(request.payload)
                record = {
                    "artifact_type": request.artifact_type.value,
                    "byte_length": len(request.payload),
                    "capability_lookup_sha256": lookup_id,
                    "evidence_boundary": evidence_boundary(),
                    "integrity_hmac_sha256": "",
                    "namespace_id": self._namespace_id,
                    "payload_sha256": payload_sha256,
                    "root_identity_sha256": request.root_identity_sha256,
                    "schema_version": _RECORD_SCHEMA_VERSION,
                    "subject_identity_sha256": request.subject_identity_sha256,
                }
                record_raw = _mac_document(
                    self._key,
                    b"contextguard-receipt/capability-record-mac/v1",
                    record,
                )
                records.append((lookup_id, request, record, record_raw))
                issued.append(IssuedCapability(handle=handle, namespace_id=self._namespace_id))

            commit_id = secrets.token_bytes(32).hex()
            temporary_id = secrets.token_bytes(16).hex()
            batch_fd: int | None = None
            published = False
            try:
                os.mkdir(temporary_id, 0o700, dir_fd=temp_fd)
                batch_fd = os.open(temporary_id, _directory_flags(), dir_fd=temp_fd)
                os.fchmod(batch_fd, 0o700)
                lookup_ids: list[str] = []
                for lookup_id, request, _record, record_raw in records:
                    os.mkdir(lookup_id, 0o700, dir_fd=batch_fd)
                    entry_fd = os.open(lookup_id, _directory_flags(), dir_fd=batch_fd)
                    try:
                        os.fchmod(entry_fd, 0o700)
                        _write_new_file(entry_fd, _PAYLOAD_NAME, request.payload)
                        _write_new_file(entry_fd, _RECORD_NAME, record_raw)
                        os.fsync(entry_fd)
                    finally:
                        os.close(entry_fd)
                    lookup_ids.append(lookup_id)
                manifest = {
                    "capability_lookup_sha256": sorted(lookup_ids),
                    "evidence_boundary": evidence_boundary(),
                    "integrity_hmac_sha256": "",
                    "schema_version": _COMMIT_SCHEMA_VERSION,
                }
                _write_new_file(
                    batch_fd,
                    _COMMIT_MANIFEST_NAME,
                    _mac_document(
                        self._key,
                        b"contextguard-receipt/store-commit-mac/v1",
                        manifest,
                        limits=_COMMIT_JSON_LIMITS,
                    ),
                )
                os.fsync(batch_fd)
                os.close(batch_fd)
                batch_fd = None
                os.rename(
                    temporary_id,
                    commit_id,
                    src_dir_fd=temp_fd,
                    dst_dir_fd=commits_fd,
                )
                published = True
                parent_sync_failed = False
                for parent_fd in (temp_fd, commits_fd):
                    try:
                        os.fsync(parent_fd)
                    except OSError:
                        parent_sync_failed = True
                if parent_sync_failed:
                    _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                final_usage = self._scan()
                if not set(lookup_ids).issubset(final_usage.lookup_ids):
                    _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                self._revalidate_anchors()
            except StoreError:
                if published:
                    _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                raise
            except OSError:
                if published:
                    _raise(StoreErrorCode.COMMIT_UNCERTAIN)
                _raise(StoreErrorCode.WRITE_FAILED)
            finally:
                if batch_fd is not None:
                    try:
                        os.close(batch_fd)
                    except OSError:
                        pass
            return tuple(issued)

    def resolve(
        self,
        handle: str,
        *,
        expected_root_identity_sha256: str,
    ) -> StoredArtifact:
        """Open a sealed artifact using only its capability and exact root binding."""

        with self._operation():
            return self._resolve(
                handle,
                expected_root_identity_sha256=expected_root_identity_sha256,
            )

    def _resolve(
        self,
        handle: str,
        *,
        expected_root_identity_sha256: str,
    ) -> StoredArtifact:
        _validate_hash(expected_root_identity_sha256)
        artifact = self._resolve_capability_record(handle)
        if artifact.root_identity_sha256 != expected_root_identity_sha256:
            _raise(StoreErrorCode.CAPABILITY_REJECTED)
        return artifact

    def _resolve_for_auxiliary_control(self, handle: str) -> StoredArtifact:
        """Resolve existing authority for a same-package denial-only overlay."""

        with self._operation():
            return self._resolve_capability_record(handle)

    def _resolve_capability_record(self, handle: str) -> StoredArtifact:
        capability_raw = _capability_bytes(handle)
        lookup_id = _lookup_id(self._key, self._namespace_id, capability_raw)
        with self._locked(exclusive=False):
            self._revalidate_anchors()
            records = self._scan(return_payload_for=lookup_id)
            self._revalidate_anchors()
        artifact = records.selected
        if artifact is None:
            _raise(StoreErrorCode.CAPABILITY_REJECTED)
        return artifact

    def retrieve(
        self,
        handle: str,
        *,
        expected_namespace_id: str,
        expected_root_identity_sha256: str,
        expected_subject_identity_sha256: str,
        expected_artifact_type: ArtifactType,
    ) -> StoredArtifact:
        with self._operation():
            return self._retrieve(
                handle,
                expected_namespace_id=expected_namespace_id,
                expected_root_identity_sha256=expected_root_identity_sha256,
                expected_subject_identity_sha256=expected_subject_identity_sha256,
                expected_artifact_type=expected_artifact_type,
            )

    def _retrieve(
        self,
        handle: str,
        *,
        expected_namespace_id: str,
        expected_root_identity_sha256: str,
        expected_subject_identity_sha256: str,
        expected_artifact_type: ArtifactType,
    ) -> StoredArtifact:
        _capability_bytes(handle)
        for value in (
            expected_namespace_id,
            expected_root_identity_sha256,
            expected_subject_identity_sha256,
        ):
            _validate_hash(value)
        if type(expected_artifact_type) is not ArtifactType:
            _raise(StoreErrorCode.INVALID_ARGUMENT)
        artifact = self._resolve(
            handle,
            expected_root_identity_sha256=expected_root_identity_sha256,
        )
        if (
            artifact.namespace_id != expected_namespace_id
            or artifact.subject_identity_sha256 != expected_subject_identity_sha256
            or artifact.artifact_type is not expected_artifact_type
        ):
            _raise(StoreErrorCode.CAPABILITY_REJECTED)
        return artifact

    def _scan(self, *, return_payload_for: str | None = None) -> _Usage:
        self._refresh_limits()
        commit_names = sorted(
            _bounded_names(self._commits_fd, self._limits.max_artifacts)
        )
        artifacts = 0
        payload_bytes = 0
        lookup_ids: set[str] = set()
        selected: StoredArtifact | None = None
        for commit_name in commit_names:
            if _HEX_256.fullmatch(commit_name) is None:
                _raise(StoreErrorCode.STORE_CORRUPT)
            commit_fd = _open_directory_at(self._commits_fd, commit_name)
            try:
                manifest_raw = _read_named_file(
                    commit_fd, _COMMIT_MANIFEST_NAME, _COMMIT_DOCUMENT_BYTES
                )
                manifest = _verify_document_mac(
                    self._key,
                    b"contextguard-receipt/store-commit-mac/v1",
                    _parse_document(manifest_raw, _COMMIT_JSON_LIMITS),
                    expected_keys=frozenset(
                        {
                            "capability_lookup_sha256",
                            "evidence_boundary",
                            "integrity_hmac_sha256",
                            "schema_version",
                        }
                    ),
                    limits=_COMMIT_JSON_LIMITS,
                )
                declared = manifest.get("capability_lookup_sha256")
                if (
                    manifest.get("schema_version") != _COMMIT_SCHEMA_VERSION
                    or manifest.get("evidence_boundary") != evidence_boundary()
                    or type(declared) is not list
                    or not declared
                    or any(
                        type(item) is not str or _HEX_256.fullmatch(item) is None
                        for item in declared
                    )
                    or declared != sorted(declared)
                    or len(declared) != len(set(declared))
                    or set(
                        _bounded_names(
                            commit_fd, self._limits.max_capabilities + 1
                        )
                    )
                    != set(declared) | {_COMMIT_MANIFEST_NAME}
                ):
                    _raise(StoreErrorCode.STORE_CORRUPT)
                for lookup_id in declared:
                    if lookup_id in lookup_ids:
                        _raise(StoreErrorCode.STORE_TAMPERED)
                    entry_fd = _open_directory_at(commit_fd, lookup_id)
                    try:
                        if set(_bounded_names(entry_fd, 2)) != {
                            _PAYLOAD_NAME,
                            _RECORD_NAME,
                        }:
                            _raise(StoreErrorCode.STORE_CORRUPT)
                        record_raw = _read_named_file(entry_fd, _RECORD_NAME, 64 * 1024)
                        record = _verify_document_mac(
                            self._key,
                            b"contextguard-receipt/capability-record-mac/v1",
                            _parse_document(record_raw),
                            expected_keys=frozenset(
                                {
                                    "artifact_type",
                                    "byte_length",
                                    "capability_lookup_sha256",
                                    "evidence_boundary",
                                    "integrity_hmac_sha256",
                                    "namespace_id",
                                    "payload_sha256",
                                    "root_identity_sha256",
                                    "schema_version",
                                    "subject_identity_sha256",
                                }
                            ),
                        )
                        payload = _read_named_file(
                            entry_fd,
                            _PAYLOAD_NAME,
                            self._limits.max_single_artifact_bytes,
                        )
                    finally:
                        os.close(entry_fd)
                    try:
                        artifact_type = ArtifactType(record.get("artifact_type"))
                    except (TypeError, ValueError):
                        _raise(StoreErrorCode.STORE_CORRUPT)
                    byte_length = record.get("byte_length")
                    payload_sha256 = record.get("payload_sha256")
                    if (
                        record.get("schema_version") != _RECORD_SCHEMA_VERSION
                        or record.get("evidence_boundary") != evidence_boundary()
                        or record.get("capability_lookup_sha256") != lookup_id
                        or record.get("namespace_id") != self._namespace_id
                        or type(byte_length) is not int
                        or byte_length < 0
                        or byte_length > self._limits.max_single_artifact_bytes
                        or len(payload) > self._limits.max_single_artifact_bytes
                        or byte_length != len(payload)
                        or type(payload_sha256) is not str
                        or _HEX_256.fullmatch(payload_sha256) is None
                        or type(record.get("root_identity_sha256")) is not str
                        or _HEX_256.fullmatch(record["root_identity_sha256"]) is None
                        or type(record.get("subject_identity_sha256")) is not str
                        or _HEX_256.fullmatch(record["subject_identity_sha256"]) is None
                    ):
                        _raise(StoreErrorCode.STORE_CORRUPT)
                    observed_digest = _payload_sha256(payload)
                    if not hmac.compare_digest(payload_sha256, observed_digest):
                        _raise(StoreErrorCode.STORE_TAMPERED)
                    artifacts += 1
                    payload_bytes += len(payload)
                    lookup_ids.add(lookup_id)
                    if lookup_id == return_payload_for:
                        selected = StoredArtifact(
                            artifact_type=artifact_type,
                            byte_length=byte_length,
                            namespace_id=self._namespace_id,
                            payload=payload,
                            payload_sha256=payload_sha256,
                            root_identity_sha256=record["root_identity_sha256"],
                            subject_identity_sha256=record["subject_identity_sha256"],
                        )
            finally:
                os.close(commit_fd)
        capabilities = len(lookup_ids)
        if (
            artifacts > self._limits.max_artifacts
            or capabilities > self._limits.max_capabilities
            or payload_bytes > self._limits.max_total_artifact_bytes
        ):
            _raise(StoreErrorCode.STORE_CORRUPT)
        usage = _Usage(
            artifacts=artifacts,
            capabilities=capabilities,
            payload_bytes=payload_bytes,
            lookup_ids=frozenset(lookup_ids),
            selected=selected,
        )
        return usage

    def inspect_counts(self) -> StoreSummary:
        with self._operation():
            return self._inspect_counts()

    def _inspect_counts(self) -> StoreSummary:
        with self._locked(exclusive=False):
            self._revalidate_anchors()
            usage = self._scan()
            recovery_required = bool(
                _bounded_names(
                    self._temp_fd, 1, overflow=StoreErrorCode.RECOVERY_REQUIRED
                )
            )
            self._revalidate_anchors()
        return StoreSummary(
            artifact_count=usage.artifacts,
            capability_count=usage.capabilities,
            total_artifact_bytes=usage.payload_bytes,
            namespace_id=self._namespace_id,
            recovery_required=recovery_required,
        )

    def _close_descriptors(self) -> None:
        for name in ("_temp_fd", "_commits_fd", "_store_fd", "_lock_fd", "_state_fd"):
            descriptor = getattr(self, name, None)
            if isinstance(descriptor, int):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, None)
        exclusion_fds = getattr(self, "_exclusion_fds", ())
        if type(exclusion_fds) is tuple:
            _close_directory_descriptors(exclusion_fds)
        self._exclusion_fds = ()

    def close(self) -> None:
        if os.getpid() != self._opener_pid:
            self._close_descriptors()
            self._closed = True
            self._close_requested = False
            return
        with self._thread_lock:
            if not self._closed:
                if self._active_operations > 0:
                    self._close_requested = True
                else:
                    self._close_descriptors()
                    self._closed = True
                    self._close_requested = False

    def __enter__(self) -> "CapabilityStore":
        self._require_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()
