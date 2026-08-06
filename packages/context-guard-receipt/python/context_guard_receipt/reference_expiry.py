"""Explicit, removable expiry for local capability references only."""

from __future__ import annotations

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
from dataclasses import dataclass, fields
from enum import Enum
from typing import Final, Iterator

from . import store as _filesystem
from .canonical import (
    CanonicalJSONError,
    JSONLimits,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from .contracts import evidence_boundary
from .expansion import ExpansionDisposition, expand_capability
from .identity import IdentityError, snapshot_repository
from .receipts import EXPANSION_MAGIC


__all__ = [
    "ReferenceExpiryError",
    "ReferenceExpiryErrorCode",
    "ReferenceExpiryLimits",
    "ReferenceExpiryRegistry",
    "parse_reference_expiry_request",
]


_TOP_LOCK_NAME: Final = "lock"
_STORE_NAME: Final = "store-v1"
_AUXILIARY_NAME: Final = "auxiliary-v1"
_AUXILIARY_METADATA_NAME: Final = "metadata.json"
_DIAGNOSTICS_NAME: Final = "diagnostics-v1"
_TWIN_NAME: Final = "twin-v1"
_REGISTRY_NAME: Final = "reference-expiry-v1"
_KEY_NAME: Final = "key"
_METADATA_NAME: Final = "metadata.json"
_RECORDS_NAME: Final = "records"
_TEMP_NAME: Final = "tmp"

_AUXILIARY_SCHEMA_VERSION: Final = "contextguard-receipt-auxiliary-metadata/v1"
_REQUEST_SCHEMA_VERSION: Final = "contextguard-receipt-reference-expiry-request/v1"
_RECORD_SCHEMA_VERSION: Final = "contextguard-receipt-reference-expiry-record/v1"
_METADATA_SCHEMA_VERSION: Final = "contextguard-receipt-reference-expiry-metadata/v1"
_RESULT_SCHEMA_VERSION: Final = "contextguard-receipt-reference-expiry-result/v1"
_INSPECTION_SCHEMA_VERSION: Final = "contextguard-receipt-reference-expiry-inspection/v1"

_MAX_UNIX_MS: Final = 4_102_444_800_000
_HARD_MAX_REFERENCES: Final = 1024
_HARD_MAX_TOTAL_RECORD_BYTES: Final = 4 * 1024 * 1024
_HARD_MAX_RECORD_BYTES: Final = 4096
_MAX_METADATA_BYTES: Final = 8192
_MAX_REQUEST_BYTES: Final = 4096
_LOCK_TIMEOUT_SECONDS: Final = 5.0

_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_REGISTRY_TEMP_PATTERN = re.compile(r"\.reference-expiry-v1\.tmp-[0-9a-f]{32}\Z")
_RECORD_TEMP_PATTERN = re.compile(r"\.record\.tmp-[0-9a-f]{32}\Z")
_METADATA_TEMP_PATTERN = re.compile(r"\.metadata\.tmp-[0-9a-f]{32}\Z")

_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_METADATA_BYTES,
    max_depth=6,
    max_total_values=512,
    max_object_members=32,
    max_string_bytes=256,
)
_REQUEST_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_REQUEST_BYTES,
    max_depth=3,
    max_total_values=32,
    max_object_members=8,
    max_string_bytes=128,
)
_AUXILIARY_METADATA: Final[dict[str, object]] = {
    "evidence_boundary": evidence_boundary(),
    "schema_version": _AUXILIARY_SCHEMA_VERSION,
}
_STATE_LOCATION: Final[dict[str, str]] = {
    "compartment": "auxiliary-v1/reference-expiry-v1",
    "scope": "explicit_state_dir",
}


class ReferenceExpiryErrorCode(str, Enum):
    INVALID_REQUEST = "invalid_request"
    INVALID_ARGUMENT = "invalid_argument"
    STATE_DIR_REQUIRED = "state_dir_required"
    STATE_DIR_NOT_ABSOLUTE = "state_dir_not_absolute"
    STATE_DIR_NOT_NORMALIZED = "state_dir_not_normalized"
    FILESYSTEM_UNSUPPORTED = "filesystem_unsupported"
    UNSAFE_STATE = "unsafe_state"
    LOCK_TIMEOUT = "lock_timeout"
    REGISTRY_UNINITIALIZED = "registry_uninitialized"
    REGISTRY_CORRUPT = "registry_corrupt"
    REGISTRY_TAMPERED = "registry_tampered"
    STORE_NAMESPACE_MISMATCH = "store_namespace_mismatch"
    REFERENCE_ALREADY_REGISTERED = "reference_already_registered"
    REFERENCE_NOT_REGISTERED = "reference_not_registered"
    REFERENCE_INACCESSIBLE = "reference_inaccessible"
    CAS_MISMATCH = "cas_mismatch"
    REFERENCE_COUNT_QUOTA_EXCEEDED = "reference_count_quota_exceeded"
    RECORD_BYTES_QUOTA_EXCEEDED = "record_bytes_quota_exceeded"
    WRITE_FAILED = "write_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"
    RECOVERY_REQUIRED = "recovery_required"


class ReferenceExpiryError(ValueError):
    """Stable non-reflective reference-expiry failure."""

    __slots__ = ("code",)

    def __init__(self, code: ReferenceExpiryErrorCode) -> None:
        self.code = code
        super().__init__(f"reference expiry rejected: {code.value}")


def _raise(code: ReferenceExpiryErrorCode) -> None:
    raise ReferenceExpiryError(code) from None


_STORE_ERROR_MAP: Final[dict[str, ReferenceExpiryErrorCode]] = {
    "invalid_argument": ReferenceExpiryErrorCode.INVALID_ARGUMENT,
    "state_dir_required": ReferenceExpiryErrorCode.STATE_DIR_REQUIRED,
    "state_dir_not_absolute": ReferenceExpiryErrorCode.STATE_DIR_NOT_ABSOLUTE,
    "state_dir_not_normalized": ReferenceExpiryErrorCode.STATE_DIR_NOT_NORMALIZED,
    "state_dir_forbidden": ReferenceExpiryErrorCode.UNSAFE_STATE,
    "filesystem_unsupported": ReferenceExpiryErrorCode.FILESYSTEM_UNSUPPORTED,
    "unsafe_state": ReferenceExpiryErrorCode.UNSAFE_STATE,
    "store_uninitialized": ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED,
    "store_corrupt": ReferenceExpiryErrorCode.REGISTRY_CORRUPT,
    "store_tampered": ReferenceExpiryErrorCode.REGISTRY_TAMPERED,
    "recovery_required": ReferenceExpiryErrorCode.RECOVERY_REQUIRED,
    "write_failed": ReferenceExpiryErrorCode.WRITE_FAILED,
    "commit_uncertain": ReferenceExpiryErrorCode.COMMIT_UNCERTAIN,
}


@dataclass(frozen=True, slots=True)
class ReferenceExpiryLimits:
    max_references: int = _HARD_MAX_REFERENCES
    max_total_record_bytes: int = _HARD_MAX_TOTAL_RECORD_BYTES
    max_record_bytes: int = _HARD_MAX_RECORD_BYTES

    def __post_init__(self) -> None:
        maximums = {
            "max_references": _HARD_MAX_REFERENCES,
            "max_total_record_bytes": _HARD_MAX_TOTAL_RECORD_BYTES,
            "max_record_bytes": _HARD_MAX_RECORD_BYTES,
        }
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) is not int or value <= 0 or value > maximums[item.name]:
                _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        if self.max_record_bytes > self.max_total_record_bytes:
            _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)


@dataclass(frozen=True, slots=True)
class _Metadata:
    registry_namespace_id: str
    store_namespace_id: str
    limits: ReferenceExpiryLimits
    reference_count: int
    total_record_bytes: int
    registry_state_hmac_sha256: str


@dataclass(frozen=True, slots=True)
class _Scan:
    records: dict[str, dict[str, object]]
    raw_sizes: dict[str, int]
    total_record_bytes: int
    state_hmac_sha256: str


def _translate_store_error(error: _filesystem.StoreError) -> None:
    _raise(_STORE_ERROR_MAP.get(error.code.value, ReferenceExpiryErrorCode.UNSAFE_STATE))


def _call_filesystem(operation):
    try:
        return operation()
    except _filesystem.StoreError as error:
        _translate_store_error(error)


def _validate_time(value: object, *, request: bool = False) -> int:
    if type(value) is not int or value < 0 or value > _MAX_UNIX_MS:
        _raise(
            ReferenceExpiryErrorCode.INVALID_REQUEST
            if request
            else ReferenceExpiryErrorCode.INVALID_ARGUMENT
        )
    return value


def _validate_generation(value: object, *, request: bool = False) -> int:
    if type(value) is not int or value <= 0 or value > 2**31 - 1:
        _raise(
            ReferenceExpiryErrorCode.INVALID_REQUEST
            if request
            else ReferenceExpiryErrorCode.INVALID_ARGUMENT
        )
    return value


def _capability_bytes(value: object, *, request: bool = False) -> bytes:
    try:
        return _filesystem._capability_bytes(value)
    except _filesystem.StoreError:
        _raise(
            ReferenceExpiryErrorCode.INVALID_REQUEST
            if request
            else ReferenceExpiryErrorCode.INVALID_ARGUMENT
        )


def _valid_tool_schema_artifact(stored: object) -> bool:
    try:
        from . import tool_schemas

        artifact_type = stored.artifact_type
        if artifact_type not in {
            _filesystem.ArtifactType.TOOL_SCHEMA_SET_BYTES,
            _filesystem.ArtifactType.TOOL_SCHEMA_BYTES,
        }:
            return False
        raw = stored.payload
        if type(raw) is not bytes or not raw.startswith(tool_schemas.TOOL_SCHEMA_MAGIC):
            return False
        metadata, payload = tool_schemas._unpack_envelope(raw, artifact_type)
        if (
            stored.byte_length != len(raw)
            or stored.root_identity_sha256 != metadata["catalog_identity_sha256"]
            or stored.subject_identity_sha256
            != metadata["subject_identity_sha256"]
        ):
            return False
        catalog_identity = metadata["catalog_identity_sha256"]
        catalog_format = metadata["catalog_format"]
        if artifact_type is _filesystem.ArtifactType.TOOL_SCHEMA_SET_BYTES:
            tool_schemas._parse_catalog(payload)
            return bool(
                tool_schemas._catalog_identity(catalog_format, payload)
                == catalog_identity
                and tool_schemas._catalog_subject(catalog_identity, payload)
                == metadata["subject_identity_sha256"]
            )
        raw_range = metadata["raw_range"]
        start = raw_range["start_byte"]
        end = raw_range["end_byte"]
        if end - start != len(payload):
            return False
        item = parse_canonical_json_bytes(
            payload + b"\n", limits=tool_schemas.CATALOG_LIMITS
        )
        if type(item) is not dict:
            return False
        name = tool_schemas._native_name(catalog_format, item)
        if name is None:
            return False
        name_sha256 = tool_schemas._name_digest(name)
        subject = tool_schemas._item_subject(
            catalog_identity=catalog_identity,
            index=metadata["input_index"],
            start=start,
            end=end,
            name_sha256=name_sha256,
            payload=payload,
        )
        return bool(
            metadata["normalized_name_sha256"] == name_sha256
            and metadata["subject_identity_sha256"] == subject
        )
    except Exception:
        return False


def parse_reference_expiry_request(raw: object) -> dict[str, object]:
    """Parse one canonical, closed administrative request."""

    if type(raw) is not bytes:
        _raise(ReferenceExpiryErrorCode.INVALID_REQUEST)
    try:
        value = parse_canonical_json_bytes(raw, _REQUEST_LIMITS)
    except CanonicalJSONError:
        _raise(ReferenceExpiryErrorCode.INVALID_REQUEST)
    if type(value) is not dict:
        _raise(ReferenceExpiryErrorCode.INVALID_REQUEST)
    operation = value.get("operation")
    expected = (
        {"capability", "expires_at_unix_ms", "operation", "schema_version"}
        if operation == "register"
        else {"capability", "expected_generation", "operation", "schema_version"}
        if operation == "revoke"
        else set()
    )
    if set(value) != expected or value.get("schema_version") != _REQUEST_SCHEMA_VERSION:
        _raise(ReferenceExpiryErrorCode.INVALID_REQUEST)
    _capability_bytes(value.get("capability"), request=True)
    if operation == "register":
        _validate_time(value.get("expires_at_unix_ms"), request=True)
    else:
        _validate_generation(value.get("expected_generation"), request=True)
    return value


def _hmac_hex(key: bytes, domain: bytes, raw: bytes) -> str:
    return hmac.new(key, domain + b"\0" + raw, hashlib.sha256).hexdigest()


def _mac_document(key: bytes, domain: bytes, value: dict[str, object]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256", None)
    value["integrity_hmac_sha256"] = _hmac_hex(
        key, domain, canonical_json_bytes(unsigned, _JSON_LIMITS)
    )
    return canonical_json_bytes(value, _JSON_LIMITS)


def _parse_document(raw: bytes) -> object:
    try:
        return parse_canonical_json_bytes(raw, _JSON_LIMITS)
    except CanonicalJSONError:
        _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)


def _verify_document(
    key: bytes,
    domain: bytes,
    value: object,
    expected_keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected_keys:
        _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
    supplied = value.get("integrity_hmac_sha256")
    if type(supplied) is not str or _HEX_256.fullmatch(supplied) is None:
        _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256")
    expected = _hmac_hex(key, domain, canonical_json_bytes(unsigned, _JSON_LIMITS))
    if not hmac.compare_digest(supplied, expected):
        _raise(ReferenceExpiryErrorCode.REGISTRY_TAMPERED)
    return value


def _limits_object(limits: ReferenceExpiryLimits) -> dict[str, int]:
    return {item.name: getattr(limits, item.name) for item in fields(limits)}


def _limits_from_object(value: object) -> ReferenceExpiryLimits:
    expected = {item.name for item in fields(ReferenceExpiryLimits)}
    if type(value) is not dict or set(value) != expected:
        _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
    try:
        return ReferenceExpiryLimits(**value)
    except (ReferenceExpiryError, TypeError):
        _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)


def _state_digest(key: bytes, records: dict[str, dict[str, object]]) -> str:
    summary = [
        {
            "integrity_hmac_sha256": records[name]["integrity_hmac_sha256"],
            "reference_hmac_sha256": name,
        }
        for name in sorted(records)
    ]
    return _hmac_hex(
        key,
        b"contextguard-receipt/reference-expiry-state/v1",
        canonical_json_bytes(summary, _JSON_LIMITS),
    )


def _selector(key: bytes, store_namespace_id: str, capability: bytes) -> str:
    namespace = bytes.fromhex(store_namespace_id)
    framed = (
        len(namespace).to_bytes(8, "big")
        + namespace
        + len(capability).to_bytes(8, "big")
        + capability
    )
    return _hmac_hex(
        key, b"contextguard-receipt/reference-expiry-selector/v1", framed
    )


def _validate_root(value: object) -> str:
    if isinstance(value, bytes):
        _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
    try:
        root = os.fspath(value)
    except TypeError:
        _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
    if (
        type(root) is not str
        or not root
        or "\0" in root
        or not os.path.isabs(root)
        or os.path.normpath(root) != root
        or "//" in root
    ):
        _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
    return root


def _private_directory(status: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o700
    )


class ReferenceExpiryRegistry:
    """A compact capability-denial overlay that never owns artifact bytes."""

    def __init__(self) -> None:
        self._closed = True
        self._close_requested = False
        self._active_operations = 0
        self._opener_pid = os.getpid()
        self._thread_lock = threading.RLock()
        self._exclusion_fds: tuple[int, ...] = ()

    @classmethod
    def open(
        cls,
        *,
        state_dir: str,
        repository_root: object,
        store_namespace_id: str,
        create: bool = False,
        limits: ReferenceExpiryLimits | None = None,
    ) -> "ReferenceExpiryRegistry":
        try:
            _filesystem._require_filesystem_features()
            checked_state = _filesystem._validate_state_path(state_dir)
        except _filesystem.StoreError as error:
            _translate_store_error(error)
        root = _validate_root(repository_root)
        if (
            type(store_namespace_id) is not str
            or _HEX_256.fullmatch(store_namespace_id) is None
            or type(create) is not bool
            or (limits is not None and type(limits) is not ReferenceExpiryLimits)
        ):
            _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        exclusion_fds: tuple[int, ...] = ()
        state_fd = -1
        try:
            with _filesystem.CapabilityStore.open(
                state_dir=checked_state,
                repository_root=root,
                create=False,
            ) as store:
                actual_store_namespace_id = store.namespace_id
            if actual_store_namespace_id != store_namespace_id:
                _raise(ReferenceExpiryErrorCode.STORE_NAMESPACE_MISMATCH)
            exclusion_fds = _filesystem._check_disjoint(checked_state, root, None)
            state_fd = _filesystem._open_absolute_state_directory(checked_state, create=False)
            _filesystem._require_physical_disjoint(
                state_fd,
                state_complete=True,
                exclusion_descriptors=exclusion_fds,
            )
        except _filesystem.StoreError as error:
            if state_fd >= 0:
                os.close(state_fd)
            _filesystem._close_directory_descriptors(exclusion_fds)
            _translate_store_error(error)
        except Exception:
            if state_fd >= 0:
                os.close(state_fd)
            _filesystem._close_directory_descriptors(exclusion_fds)
            raise
        root_fd: int | None = None
        try:
            root_fd = os.open(root, _filesystem._directory_flags())
            root_status = os.fstat(root_fd)
            if not stat.S_ISDIR(root_status.st_mode):
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            instance = cls()
            instance._state_path = checked_state
            instance._repository_root = root
            instance._store_namespace_id = store_namespace_id
            instance._state_fd = state_fd
            instance._root_fd = root_fd
            instance._root_anchor = (root_status.st_dev, root_status.st_ino)
            instance._exclusion_fds = exclusion_fds
            state_fd = -1
            root_fd = None
            exclusion_fds = ()
        except OSError:
            if root_fd is not None:
                os.close(root_fd)
            if state_fd >= 0:
                os.close(state_fd)
            _filesystem._close_directory_descriptors(exclusion_fds)
            _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
        except Exception:
            if root_fd is not None:
                os.close(root_fd)
            if state_fd >= 0:
                os.close(state_fd)
            _filesystem._close_directory_descriptors(exclusion_fds)
            raise
        try:
            instance._top_lock_fd = _call_filesystem(
                lambda: _filesystem._open_private_file(
                    instance._state_fd, _TOP_LOCK_NAME
                )
            )
            with instance._locked(exclusive=True):
                instance._ensure_initialized(create=create, limits=limits)
                instance._open_axis()
                if limits is not None and limits != instance._limits:
                    _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
            instance._closed = False
            return instance
        except Exception:
            instance._close_descriptors()
            raise

    @contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        self._require_opener_process()
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        if not self._thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            _raise(ReferenceExpiryErrorCode.LOCK_TIMEOUT)
        acquired = False
        try:
            operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            while True:
                try:
                    fcntl.flock(self._top_lock_fd, operation | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        _raise(ReferenceExpiryErrorCode.LOCK_TIMEOUT)
                    time.sleep(0.01)
                except OSError:
                    _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            yield
        finally:
            if acquired:
                try:
                    fcntl.flock(self._top_lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            self._thread_lock.release()

    def _validate_auxiliary_metadata(self, auxiliary_fd: int) -> None:
        raw = _call_filesystem(
            lambda: _filesystem._read_named_file(
                auxiliary_fd, _AUXILIARY_METADATA_NAME, _MAX_METADATA_BYTES
            )
        )
        try:
            value = parse_canonical_json_bytes(raw, _JSON_LIMITS)
        except CanonicalJSONError:
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
        if value != _AUXILIARY_METADATA:
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)

    def _create_axis(self, parent_fd: int, name: str, limits: ReferenceExpiryLimits) -> None:
        axis_fd: int | None = None
        created = False
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
            axis_fd = os.open(name, _filesystem._directory_flags(), dir_fd=parent_fd)
            os.fchmod(axis_fd, 0o700)
            key = secrets.token_bytes(32)
            registry_namespace_id = secrets.token_bytes(32).hex()
            empty_digest = _state_digest(key, {})
            _filesystem._write_new_file(axis_fd, _KEY_NAME, key)
            metadata = {
                "evidence_boundary": evidence_boundary(),
                "integrity_hmac_sha256": "",
                "limits": _limits_object(limits),
                "reference_count": 0,
                "registry_namespace_id": registry_namespace_id,
                "registry_state_hmac_sha256": empty_digest,
                "schema_version": _METADATA_SCHEMA_VERSION,
                "store_namespace_id": self._store_namespace_id,
                "total_record_bytes": 0,
            }
            _filesystem._write_new_file(
                axis_fd,
                _METADATA_NAME,
                _mac_document(
                    key,
                    b"contextguard-receipt/reference-expiry-metadata-mac/v1",
                    metadata,
                ),
            )
            for child in (_RECORDS_NAME, _TEMP_NAME):
                os.mkdir(child, 0o700, dir_fd=axis_fd)
                child_fd = os.open(
                    child, _filesystem._directory_flags(), dir_fd=axis_fd
                )
                try:
                    os.fchmod(child_fd, 0o700)
                    os.fsync(child_fd)
                finally:
                    os.close(child_fd)
            os.fsync(axis_fd)
        except ReferenceExpiryError:
            raise
        except _filesystem.StoreError as error:
            if created:
                _raise(ReferenceExpiryErrorCode.COMMIT_UNCERTAIN)
            _translate_store_error(error)
        except OSError:
            _raise(
                ReferenceExpiryErrorCode.COMMIT_UNCERTAIN
                if created
                else ReferenceExpiryErrorCode.WRITE_FAILED
            )
        finally:
            if axis_fd is not None:
                os.close(axis_fd)

    def _ensure_initialized(
        self, *, create: bool, limits: ReferenceExpiryLimits | None
    ) -> None:
        names = set(
            _call_filesystem(
                lambda: _filesystem._bounded_names(self._state_fd, 4)
            )
        )
        if names - {_TOP_LOCK_NAME, _STORE_NAME, _AUXILIARY_NAME}:
            _raise(ReferenceExpiryErrorCode.RECOVERY_REQUIRED)
        if _STORE_NAME not in names:
            _raise(ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED)
        store_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._state_fd, _STORE_NAME)
        )
        os.close(store_fd)
        effective_limits = ReferenceExpiryLimits() if limits is None else limits
        if _AUXILIARY_NAME not in names:
            if not create:
                _raise(ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED)
            temporary_name = ".auxiliary-v1.tmp-" + secrets.token_bytes(16).hex()
            auxiliary_fd: int | None = None
            created = False
            published = False
            try:
                os.mkdir(temporary_name, 0o700, dir_fd=self._state_fd)
                created = True
                auxiliary_fd = os.open(
                    temporary_name,
                    _filesystem._directory_flags(),
                    dir_fd=self._state_fd,
                )
                os.fchmod(auxiliary_fd, 0o700)
                _filesystem._write_new_file(
                    auxiliary_fd,
                    _AUXILIARY_METADATA_NAME,
                    canonical_json_bytes(_AUXILIARY_METADATA, _JSON_LIMITS),
                )
                self._create_axis(auxiliary_fd, _REGISTRY_NAME, effective_limits)
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
            except ReferenceExpiryError:
                raise
            except _filesystem.StoreError as error:
                if created:
                    _raise(ReferenceExpiryErrorCode.COMMIT_UNCERTAIN)
                _translate_store_error(error)
            except OSError:
                _raise(
                    ReferenceExpiryErrorCode.COMMIT_UNCERTAIN
                    if created or published
                    else ReferenceExpiryErrorCode.WRITE_FAILED
                )
            finally:
                if auxiliary_fd is not None:
                    os.close(auxiliary_fd)
            return

        auxiliary_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._state_fd, _AUXILIARY_NAME)
        )
        try:
            self._validate_auxiliary_metadata(auxiliary_fd)
            auxiliary_names = set(
                _call_filesystem(
                    lambda: _filesystem._bounded_names(auxiliary_fd, 5)
                )
            )
            unknown = auxiliary_names - {
                _AUXILIARY_METADATA_NAME,
                _DIAGNOSTICS_NAME,
                _TWIN_NAME,
                _REGISTRY_NAME,
            }
            if unknown:
                _raise(
                    ReferenceExpiryErrorCode.RECOVERY_REQUIRED
                    if all(_REGISTRY_TEMP_PATTERN.fullmatch(name) for name in unknown)
                    else ReferenceExpiryErrorCode.REGISTRY_CORRUPT
                )
            for sibling in (_DIAGNOSTICS_NAME, _TWIN_NAME):
                if sibling in auxiliary_names:
                    descriptor = _call_filesystem(
                        lambda sibling=sibling: _filesystem._open_directory_at(
                            auxiliary_fd, sibling
                        )
                    )
                    os.close(descriptor)
            if _REGISTRY_NAME in auxiliary_names:
                return
            if not create:
                _raise(ReferenceExpiryErrorCode.REGISTRY_UNINITIALIZED)
            temporary_name = ".reference-expiry-v1.tmp-" + secrets.token_bytes(16).hex()
            created = False
            published = False
            try:
                self._create_axis(auxiliary_fd, temporary_name, effective_limits)
                created = True
                os.rename(
                    temporary_name,
                    _REGISTRY_NAME,
                    src_dir_fd=auxiliary_fd,
                    dst_dir_fd=auxiliary_fd,
                )
                published = True
                os.fsync(auxiliary_fd)
            except ReferenceExpiryError:
                raise
            except OSError:
                _raise(
                    ReferenceExpiryErrorCode.COMMIT_UNCERTAIN
                    if created or published
                    else ReferenceExpiryErrorCode.WRITE_FAILED
                )
        finally:
            os.close(auxiliary_fd)

    def _open_axis(self) -> None:
        self._store_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._state_fd, _STORE_NAME)
        )
        self._auxiliary_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._state_fd, _AUXILIARY_NAME)
        )
        self._validate_auxiliary_metadata(self._auxiliary_fd)
        self._axis_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._auxiliary_fd, _REGISTRY_NAME)
        )
        names = set(
            _call_filesystem(lambda: _filesystem._bounded_names(self._axis_fd, 5))
        )
        if names != {_KEY_NAME, _METADATA_NAME, _RECORDS_NAME, _TEMP_NAME}:
            _raise(
                ReferenceExpiryErrorCode.RECOVERY_REQUIRED
                if any(_METADATA_TEMP_PATTERN.fullmatch(name) for name in names)
                else ReferenceExpiryErrorCode.REGISTRY_CORRUPT
            )
        key = _call_filesystem(
            lambda: _filesystem._read_named_file(self._axis_fd, _KEY_NAME, 33)
        )
        if len(key) != 32:
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
        self._key = key
        self._records_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._axis_fd, _RECORDS_NAME)
        )
        self._temp_fd = _call_filesystem(
            lambda: _filesystem._open_directory_at(self._axis_fd, _TEMP_NAME)
        )
        if _call_filesystem(lambda: _filesystem._bounded_names(self._temp_fd, 1)):
            _raise(ReferenceExpiryErrorCode.RECOVERY_REQUIRED)
        metadata = self._read_metadata()
        if metadata.store_namespace_id != self._store_namespace_id:
            _raise(ReferenceExpiryErrorCode.STORE_NAMESPACE_MISMATCH)
        self._metadata = metadata
        self._limits = metadata.limits
        scan = self._scan()
        self._verify_scan(metadata, scan)
        self._state_anchor = self._identity(self._state_fd)
        self._top_lock_anchor = self._identity(self._top_lock_fd)
        self._store_anchor = self._identity(self._store_fd)
        self._auxiliary_anchor = self._identity(self._auxiliary_fd)
        self._axis_anchor = self._identity(self._axis_fd)
        self._records_anchor = self._identity(self._records_fd)
        self._temp_anchor = self._identity(self._temp_fd)
        self._closed = False

    def _read_metadata(self) -> _Metadata:
        raw = _call_filesystem(
            lambda: _filesystem._read_named_file(
                self._axis_fd, _METADATA_NAME, _MAX_METADATA_BYTES
            )
        )
        value = _verify_document(
            self._key,
            b"contextguard-receipt/reference-expiry-metadata-mac/v1",
            _parse_document(raw),
            frozenset(
                {
                    "evidence_boundary",
                    "integrity_hmac_sha256",
                    "limits",
                    "reference_count",
                    "registry_namespace_id",
                    "registry_state_hmac_sha256",
                    "schema_version",
                    "store_namespace_id",
                    "total_record_bytes",
                }
            ),
        )
        if (
            value.get("schema_version") != _METADATA_SCHEMA_VERSION
            or value.get("evidence_boundary") != evidence_boundary()
        ):
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
        registry_namespace_id = value.get("registry_namespace_id")
        store_namespace_id = value.get("store_namespace_id")
        state_digest = value.get("registry_state_hmac_sha256")
        count = value.get("reference_count")
        total = value.get("total_record_bytes")
        if (
            type(registry_namespace_id) is not str
            or _HEX_256.fullmatch(registry_namespace_id) is None
            or type(store_namespace_id) is not str
            or _HEX_256.fullmatch(store_namespace_id) is None
            or type(state_digest) is not str
            or _HEX_256.fullmatch(state_digest) is None
            or type(count) is not int
            or count < 0
            or type(total) is not int
            or total < 0
        ):
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
        limits = _limits_from_object(value.get("limits"))
        if count > limits.max_references or total > limits.max_total_record_bytes:
            _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
        return _Metadata(
            registry_namespace_id=registry_namespace_id,
            store_namespace_id=store_namespace_id,
            limits=limits,
            reference_count=count,
            total_record_bytes=total,
            registry_state_hmac_sha256=state_digest,
        )

    def _scan(self) -> _Scan:
        names = sorted(
            _call_filesystem(
                lambda: _filesystem._bounded_names(
                    self._records_fd, self._limits.max_references + 1
                )
            )
        )
        records: dict[str, dict[str, object]] = {}
        sizes: dict[str, int] = {}
        total = 0
        for name in names:
            if _HEX_256.fullmatch(name) is None:
                _raise(
                    ReferenceExpiryErrorCode.RECOVERY_REQUIRED
                    if _RECORD_TEMP_PATTERN.fullmatch(name)
                    else ReferenceExpiryErrorCode.REGISTRY_CORRUPT
                )
            raw = _call_filesystem(
                lambda name=name: _filesystem._read_named_file(
                    self._records_fd, name, self._limits.max_record_bytes
                )
            )
            record = _verify_document(
                self._key,
                b"contextguard-receipt/reference-expiry-record-mac/v1",
                _parse_document(raw),
                frozenset(
                    {
                        "evidence_boundary",
                        "expires_at_unix_ms",
                        "generation",
                        "integrity_hmac_sha256",
                        "reference_hmac_sha256",
                        "registered_at_unix_ms",
                        "schema_version",
                        "status",
                        "updated_at_unix_ms",
                    }
                ),
            )
            if not self._valid_record(record, expected_reference=name):
                _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
            records[name] = record
            sizes[name] = len(raw)
            total += len(raw)
        return _Scan(
            records=records,
            raw_sizes=sizes,
            total_record_bytes=total,
            state_hmac_sha256=_state_digest(self._key, records),
        )

    @staticmethod
    def _valid_record(record: dict[str, object], *, expected_reference: str) -> bool:
        registered = record.get("registered_at_unix_ms")
        updated = record.get("updated_at_unix_ms")
        expires = record.get("expires_at_unix_ms")
        generation = record.get("generation")
        status_value = record.get("status")
        return (
            record.get("schema_version") == _RECORD_SCHEMA_VERSION
            and record.get("evidence_boundary") == evidence_boundary()
            and record.get("reference_hmac_sha256") == expected_reference
            and type(registered) is int
            and 0 <= registered <= _MAX_UNIX_MS
            and type(updated) is int
            and registered <= updated <= _MAX_UNIX_MS
            and type(expires) is int
            and 0 <= expires <= _MAX_UNIX_MS
            and type(generation) is int
            and 1 <= generation <= 2**31 - 1
            and status_value in {"active", "expired", "revoked"}
            and (generation == 1 if status_value == "active" else generation >= 1)
        )

    @staticmethod
    def _verify_scan(metadata: _Metadata, scan: _Scan) -> None:
        if (
            len(scan.records) != metadata.reference_count
            or scan.total_record_bytes != metadata.total_record_bytes
            or not hmac.compare_digest(
                scan.state_hmac_sha256, metadata.registry_state_hmac_sha256
            )
        ):
            _raise(ReferenceExpiryErrorCode.COMMIT_UNCERTAIN)

    @staticmethod
    def _identity(descriptor: int) -> tuple[int, int]:
        try:
            status = os.fstat(descriptor)
        except OSError:
            _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
        return status.st_dev, status.st_ino

    def _revalidate_anchors(self) -> None:
        opened: list[int] = []
        try:
            state_fd = _call_filesystem(
                lambda: _filesystem._open_absolute_state_directory(
                    self._state_path, create=False
                )
            )
            opened.append(state_fd)
            if self._identity(state_fd) != self._state_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            root_fd = os.open(self._repository_root, _filesystem._directory_flags())
            opened.append(root_fd)
            if self._identity(root_fd) != self._root_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            top_lock_fd = _call_filesystem(
                lambda: _filesystem._open_private_file(state_fd, _TOP_LOCK_NAME)
            )
            opened.append(top_lock_fd)
            if self._identity(top_lock_fd) != self._top_lock_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            names = set(
                _call_filesystem(lambda: _filesystem._bounded_names(state_fd, 4))
            )
            if names != {_TOP_LOCK_NAME, _STORE_NAME, _AUXILIARY_NAME}:
                _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
            store_fd = _call_filesystem(
                lambda: _filesystem._open_directory_at(state_fd, _STORE_NAME)
            )
            opened.append(store_fd)
            if self._identity(store_fd) != self._store_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            auxiliary_fd = _call_filesystem(
                lambda: _filesystem._open_directory_at(state_fd, _AUXILIARY_NAME)
            )
            opened.append(auxiliary_fd)
            if self._identity(auxiliary_fd) != self._auxiliary_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            self._validate_auxiliary_metadata(auxiliary_fd)
            allowed_auxiliary = {
                _AUXILIARY_METADATA_NAME,
                _DIAGNOSTICS_NAME,
                _TWIN_NAME,
                _REGISTRY_NAME,
            }
            auxiliary_names = set(
                _call_filesystem(
                    lambda: _filesystem._bounded_names(auxiliary_fd, 4)
                )
            )
            if _REGISTRY_NAME not in auxiliary_names or auxiliary_names - allowed_auxiliary:
                _raise(ReferenceExpiryErrorCode.REGISTRY_CORRUPT)
            for sibling in (_DIAGNOSTICS_NAME, _TWIN_NAME):
                if sibling in auxiliary_names:
                    sibling_fd = _call_filesystem(
                        lambda sibling=sibling: _filesystem._open_directory_at(
                            auxiliary_fd, sibling
                        )
                    )
                    opened.append(sibling_fd)
            axis_fd = _call_filesystem(
                lambda: _filesystem._open_directory_at(auxiliary_fd, _REGISTRY_NAME)
            )
            opened.append(axis_fd)
            if self._identity(axis_fd) != self._axis_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            axis_names = set(
                _call_filesystem(lambda: _filesystem._bounded_names(axis_fd, 4))
            )
            if axis_names != {_KEY_NAME, _METADATA_NAME, _RECORDS_NAME, _TEMP_NAME}:
                _raise(ReferenceExpiryErrorCode.RECOVERY_REQUIRED)
            key = _call_filesystem(
                lambda: _filesystem._read_named_file(axis_fd, _KEY_NAME, 33)
            )
            if not hmac.compare_digest(key, self._key):
                _raise(ReferenceExpiryErrorCode.REGISTRY_TAMPERED)
            records_fd = _call_filesystem(
                lambda: _filesystem._open_directory_at(axis_fd, _RECORDS_NAME)
            )
            opened.append(records_fd)
            if self._identity(records_fd) != self._records_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            temp_fd = _call_filesystem(
                lambda: _filesystem._open_directory_at(axis_fd, _TEMP_NAME)
            )
            opened.append(temp_fd)
            if self._identity(temp_fd) != self._temp_anchor:
                _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
            if _call_filesystem(lambda: _filesystem._bounded_names(temp_fd, 1)):
                _raise(ReferenceExpiryErrorCode.RECOVERY_REQUIRED)
        except OSError:
            _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)
        finally:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _metadata_bytes(self, scan: _Scan) -> bytes:
        document = {
            "evidence_boundary": evidence_boundary(),
            "integrity_hmac_sha256": "",
            "limits": _limits_object(self._limits),
            "reference_count": len(scan.records),
            "registry_namespace_id": self._metadata.registry_namespace_id,
            "registry_state_hmac_sha256": scan.state_hmac_sha256,
            "schema_version": _METADATA_SCHEMA_VERSION,
            "store_namespace_id": self._store_namespace_id,
            "total_record_bytes": scan.total_record_bytes,
        }
        return _mac_document(
            self._key,
            b"contextguard-receipt/reference-expiry-metadata-mac/v1",
            document,
        )

    def _publish_record(
        self,
        reference_id: str,
        record: dict[str, object],
        scan: _Scan,
    ) -> _Scan:
        return self._publish_records({reference_id: record}, scan)

    def _publish_records(
        self,
        updates: dict[str, dict[str, object]],
        scan: _Scan,
    ) -> _Scan:
        if not updates:
            return scan
        next_records = dict(scan.records)
        next_sizes = dict(scan.raw_sizes)
        new_total = scan.total_record_bytes
        encoded: dict[str, bytes] = {}
        for reference_id in sorted(updates):
            record = dict(updates[reference_id])
            raw = _mac_document(
                self._key,
                b"contextguard-receipt/reference-expiry-record-mac/v1",
                record,
            )
            if len(raw) > self._limits.max_record_bytes:
                _raise(ReferenceExpiryErrorCode.RECORD_BYTES_QUOTA_EXCEEDED)
            new_total -= next_sizes.get(reference_id, 0)
            new_total += len(raw)
            encoded[reference_id] = raw
            next_records[reference_id] = record
            next_sizes[reference_id] = len(raw)
        if new_total > self._limits.max_total_record_bytes:
            _raise(ReferenceExpiryErrorCode.RECORD_BYTES_QUOTA_EXCEEDED)
        next_scan = _Scan(
            records=next_records,
            raw_sizes=next_sizes,
            total_record_bytes=new_total,
            state_hmac_sha256=_state_digest(self._key, next_records),
        )
        record_temps = {
            reference_id: ".record.tmp-" + secrets.token_bytes(16).hex()
            for reference_id in sorted(encoded)
        }
        metadata_temp = ".metadata.tmp-" + secrets.token_bytes(16).hex()
        mutation_started = False
        try:
            mutation_started = True
            for reference_id in sorted(encoded):
                _filesystem._write_new_file(
                    self._temp_fd,
                    record_temps[reference_id],
                    encoded[reference_id],
                )
            for reference_id in sorted(encoded):
                os.rename(
                    record_temps[reference_id],
                    reference_id,
                    src_dir_fd=self._temp_fd,
                    dst_dir_fd=self._records_fd,
                )
            os.fsync(self._temp_fd)
            os.fsync(self._records_fd)
            metadata_raw = self._metadata_bytes(next_scan)
            _filesystem._write_new_file(self._temp_fd, metadata_temp, metadata_raw)
            os.rename(
                metadata_temp,
                _METADATA_NAME,
                src_dir_fd=self._temp_fd,
                dst_dir_fd=self._axis_fd,
            )
            os.fsync(self._temp_fd)
            os.fsync(self._axis_fd)
        except ReferenceExpiryError:
            if mutation_started:
                _raise(ReferenceExpiryErrorCode.COMMIT_UNCERTAIN)
            raise
        except _filesystem.StoreError as error:
            if mutation_started:
                _raise(ReferenceExpiryErrorCode.COMMIT_UNCERTAIN)
            _translate_store_error(error)
        except OSError:
            _raise(
                ReferenceExpiryErrorCode.COMMIT_UNCERTAIN
                if mutation_started
                else ReferenceExpiryErrorCode.WRITE_FAILED
            )
        metadata = self._read_metadata()
        final_scan = self._scan()
        self._verify_scan(metadata, final_scan)
        self._metadata = metadata
        return final_scan

    def _read_consistent(self) -> _Scan:
        self._revalidate_anchors()
        metadata = self._read_metadata()
        if metadata.store_namespace_id != self._store_namespace_id:
            _raise(ReferenceExpiryErrorCode.STORE_NAMESPACE_MISMATCH)
        scan = self._scan()
        self._verify_scan(metadata, scan)
        self._metadata = metadata
        self._revalidate_anchors()
        return scan

    @staticmethod
    def _result(operation: str, record: dict[str, object]) -> dict[str, object]:
        return {
            "artifact_cleanup_performed": False,
            "evidence_boundary": evidence_boundary(),
            "expires_at_unix_ms": record["expires_at_unix_ms"],
            "generation": record["generation"],
            "operation": operation,
            "reference_hmac_sha256": record["reference_hmac_sha256"],
            "retained_artifacts": True,
            "schema_version": _RESULT_SCHEMA_VERSION,
            "state_location": dict(_STATE_LOCATION),
            "status": record["status"],
        }

    def _validate_store_membership(self, capability: str) -> None:
        try:
            with _filesystem.CapabilityStore.open(
                state_dir=self._state_path,
                repository_root=self._repository_root,
                create=False,
            ) as store:
                if store.namespace_id != self._store_namespace_id:
                    _raise(ReferenceExpiryErrorCode.STORE_NAMESPACE_MISMATCH)
                stored = store._resolve_for_auxiliary_control(capability)
                if stored.artifact_type in {
                    _filesystem.ArtifactType.TOOL_SCHEMA_SET_BYTES,
                    _filesystem.ArtifactType.TOOL_SCHEMA_BYTES,
                }:
                    if not _valid_tool_schema_artifact(stored):
                        _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
                    return
                snapshot = snapshot_repository(self._repository_root)
                root_identity = snapshot["instance"]["identity_sha256"]
                if type(root_identity) is not str:
                    _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
                store.resolve(
                    capability,
                    expected_root_identity_sha256=root_identity,
                )
                requires_exact_expansion = bool(
                    stored.artifact_type
                    is _filesystem.ArtifactType.COMMAND_CAPTURE_BYTES
                    or (
                        stored.artifact_type
                        in {
                            _filesystem.ArtifactType.RAW_EVIDENCE_BYTES,
                            _filesystem.ArtifactType.BLUEPRINT_WHOLE_BYTES,
                            _filesystem.ArtifactType.BLUEPRINT_ITEM_BYTES,
                        }
                        and stored.payload.startswith(EXPANSION_MAGIC)
                    )
                )
                if requires_exact_expansion:
                    validation = expand_capability(
                        capability,
                        root=self._repository_root,
                        store=store,
                    )
                    if validation.disposition is not ExpansionDisposition.EXACT:
                        _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        except IdentityError:
            _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        except _filesystem.StoreError as error:
            if error.code is _filesystem.StoreErrorCode.CAPABILITY_REJECTED:
                _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
            _translate_store_error(error)

    def register(
        self,
        capability: str,
        *,
        expires_at_unix_ms: int,
        observed_at_unix_ms: int,
    ) -> dict[str, object]:
        capability_raw = _capability_bytes(capability)
        expires = _validate_time(expires_at_unix_ms)
        observed = _validate_time(observed_at_unix_ms)
        with self._operation():
            self._validate_store_membership(capability)
            with self._locked(exclusive=True):
                scan = self._read_consistent()
                reference_id = _selector(
                    self._key, self._store_namespace_id, capability_raw
                )
                if reference_id in scan.records:
                    _raise(ReferenceExpiryErrorCode.REFERENCE_ALREADY_REGISTERED)
                if len(scan.records) >= self._limits.max_references:
                    _raise(ReferenceExpiryErrorCode.REFERENCE_COUNT_QUOTA_EXCEEDED)
                record = {
                    "evidence_boundary": evidence_boundary(),
                    "expires_at_unix_ms": expires,
                    "generation": 1,
                    "integrity_hmac_sha256": "",
                    "reference_hmac_sha256": reference_id,
                    "registered_at_unix_ms": observed,
                    "schema_version": _RECORD_SCHEMA_VERSION,
                    "status": "expired" if observed >= expires else "active",
                    "updated_at_unix_ms": observed,
                }
                self._publish_record(reference_id, record, scan)
                return self._result("register", record)

    def revoke(
        self,
        capability: str,
        *,
        expected_generation: int,
        observed_at_unix_ms: int,
    ) -> dict[str, object]:
        capability_raw = _capability_bytes(capability)
        expected = _validate_generation(expected_generation)
        observed = _validate_time(observed_at_unix_ms)
        with self._operation(), self._locked(exclusive=True):
            scan = self._read_consistent()
            reference_id = _selector(
                self._key, self._store_namespace_id, capability_raw
            )
            current = scan.records.get(reference_id)
            if current is None:
                _raise(ReferenceExpiryErrorCode.REFERENCE_NOT_REGISTERED)
            if current["generation"] != expected:
                _raise(ReferenceExpiryErrorCode.CAS_MISMATCH)
            if current["status"] != "active":
                _raise(ReferenceExpiryErrorCode.REFERENCE_INACCESSIBLE)
            record = dict(current)
            record.update(
                {
                    "generation": expected + 1,
                    "integrity_hmac_sha256": "",
                    "status": "revoked",
                    "updated_at_unix_ms": max(
                        observed, int(current["updated_at_unix_ms"])
                    ),
                }
            )
            self._publish_record(reference_id, record, scan)
            return self._result("revoke", record)

    def is_inaccessible(
        self, capability: str, *, observed_at_unix_ms: int
    ) -> bool:
        capability_raw = _capability_bytes(capability)
        observed = _validate_time(observed_at_unix_ms)
        with self._operation(), self._locked(exclusive=True):
            scan = self._read_consistent()
            reference_id = _selector(
                self._key, self._store_namespace_id, capability_raw
            )
            current = scan.records.get(reference_id)
            if current is None:
                return False
            if current["status"] != "active":
                return True
            previous_observed = int(current["updated_at_unix_ms"])
            clock_rolled_back = observed < previous_observed
            effective_observed = max(observed, previous_observed)
            record = dict(current)
            if clock_rolled_back or effective_observed >= current["expires_at_unix_ms"]:
                record.update(
                    {
                        "generation": int(current["generation"]) + 1,
                        "integrity_hmac_sha256": "",
                        "status": "expired",
                        "updated_at_unix_ms": effective_observed,
                    }
                )
                self._publish_record(reference_id, record, scan)
                return True
            if effective_observed > current["updated_at_unix_ms"]:
                record.update(
                    {
                        "integrity_hmac_sha256": "",
                        "updated_at_unix_ms": effective_observed,
                    }
                )
                self._publish_record(reference_id, record, scan)
            return False

    def inspect(
        self, *, observed_at_unix_ms: int, limit: int = 256
    ) -> dict[str, object]:
        observed = _validate_time(observed_at_unix_ms)
        if type(limit) is not int or limit <= 0 or limit > 256:
            _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        with self._operation(), self._locked(exclusive=True):
            scan = self._read_consistent()
            updates: dict[str, dict[str, object]] = {}
            for reference_id in sorted(scan.records):
                current = scan.records[reference_id]
                if current["status"] == "active":
                    previous_observed = int(current["updated_at_unix_ms"])
                    clock_rolled_back = observed < previous_observed
                    effective_observed = max(observed, previous_observed)
                    if not clock_rolled_back and effective_observed == previous_observed:
                        continue
                    record = dict(current)
                    record["integrity_hmac_sha256"] = ""
                    record["updated_at_unix_ms"] = effective_observed
                    if (
                        clock_rolled_back
                        or effective_observed >= current["expires_at_unix_ms"]
                    ):
                        record["generation"] = int(current["generation"]) + 1
                        record["status"] = "expired"
                    updates[reference_id] = record
            if updates:
                scan = self._publish_records(updates, scan)
            counts = {"active": 0, "expired": 0, "revoked": 0}
            summaries: list[dict[str, object]] = []
            for reference_id in sorted(scan.records):
                record = scan.records[reference_id]
                status_value = str(record["status"])
                counts[status_value] += 1
                summaries.append(
                    {
                        "expires_at_unix_ms": record["expires_at_unix_ms"],
                        "generation": record["generation"],
                        "reference_hmac_sha256": reference_id,
                        "status": status_value,
                        "updated_at_unix_ms": record["updated_at_unix_ms"],
                    }
                )
            return {
                "active_reference_count": counts["active"],
                "artifact_cleanup_performed": False,
                "evidence_boundary": evidence_boundary(),
                "expired_reference_count": counts["expired"],
                "reference_summaries": summaries[-limit:],
                "registered_reference_count": len(scan.records),
                "registry_state_hmac_sha256": scan.state_hmac_sha256,
                "retained_artifacts": True,
                "revoked_reference_count": counts["revoked"],
                "schema_version": _INSPECTION_SCHEMA_VERSION,
                "state_location": dict(_STATE_LOCATION),
                "total_record_bytes": scan.total_record_bytes,
            }

    @contextmanager
    def _operation(self) -> Iterator[None]:
        self._require_opener_process()
        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
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
            _raise(ReferenceExpiryErrorCode.UNSAFE_STATE)

    def _close_descriptors(self) -> None:
        for name in (
            "_temp_fd",
            "_records_fd",
            "_axis_fd",
            "_auxiliary_fd",
            "_top_lock_fd",
            "_root_fd",
            "_store_fd",
            "_state_fd",
        ):
            descriptor = getattr(self, name, None)
            if type(descriptor) is int and descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, name, -1)
        _filesystem._close_directory_descriptors(self._exclusion_fds)
        self._exclusion_fds = ()

    def close(self) -> None:
        if os.getpid() != self._opener_pid:
            self._close_descriptors()
            self._closed = True
            self._close_requested = False
            return
        with self._thread_lock:
            if self._closed:
                return
            if self._active_operations:
                self._close_requested = True
            else:
                self._close_descriptors()
                self._closed = True

    def __enter__(self) -> "ReferenceExpiryRegistry":
        self._require_opener_process()
        if self._closed:
            _raise(ReferenceExpiryErrorCode.INVALID_ARGUMENT)
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
