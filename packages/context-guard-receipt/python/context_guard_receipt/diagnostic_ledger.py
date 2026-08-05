"""Private, bounded, append-only durable storage for advisory diagnostics."""

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
from dataclasses import dataclass
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
from .diagnostics import DIAGNOSTICS_POLICY_SHA256
from .router import RouteCosts, decide_route


__all__ = [
    "DiagnosticLedger",
    "DiagnosticLedgerError",
    "DiagnosticLedgerErrorCode",
    "LedgerError",
    "LedgerErrorCode",
]


_TOP_LOCK_NAME: Final = "lock"
_AUXILIARY_NAME: Final = "auxiliary-v1"
_AUXILIARY_METADATA_NAME: Final = "metadata.json"
_DIAGNOSTICS_NAME: Final = "diagnostics-v1"
_TWIN_NAME: Final = "twin-v1"
_REFERENCE_EXPIRY_NAME: Final = "reference-expiry-v1"
_DIAGNOSTIC_LOCK_NAME: Final = "lock"
_KEY_NAME: Final = "key"
_METADATA_NAME: Final = "metadata.json"
_ENTRIES_NAME: Final = "entries"
_TEMP_NAME: Final = "tmp"

_AUXILIARY_SCHEMA_VERSION: Final = "contextguard-receipt-auxiliary-metadata/v1"
_METADATA_SCHEMA_VERSION: Final = "contextguard-receipt-diagnostic-ledger-metadata/v1"
_ENTRY_SCHEMA_VERSION: Final = "contextguard-receipt-diagnostic-ledger-entry/v1"
_INSPECTION_SCHEMA_VERSION: Final = "contextguard-receipt-diagnostic-ledger-inspection/v1"

_MAX_ENTRIES: Final = 1024
_MAX_ENTRY_BYTES: Final = 4096
_MAX_TOTAL_BYTES: Final = 4 * 1024 * 1024
_LOCK_TIMEOUT_SECONDS: Final = 5.0
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_ENTRY_NAME = re.compile(r"[0-9]{16}\.json\Z")
_TEMP_ENTRY_NAME = re.compile(r"[0-9a-f]{32}\.json\Z")
_AUXILIARY_TEMP_NAME = re.compile(r"\.auxiliary-v1\.tmp-[0-9a-f]{32}\Z")
_DIAGNOSTICS_TEMP_NAME = re.compile(r"\.diagnostics-v1\.tmp-[0-9a-f]{32}\Z")

_ENTRY_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_ENTRY_BYTES,
    max_depth=2,
    max_total_values=96,
    max_object_members=64,
    max_string_bytes=128,
)
_METADATA_JSON_LIMITS: Final = JSONLimits(
    max_document_bytes=4096,
    max_depth=4,
    max_total_values=64,
    max_object_members=16,
    max_string_bytes=128,
)

_ADVISORY_LANES: Final = frozenset({"none", "scout", "surgeon"})
_ADVISORY_REASONS: Final = frozenset(
    {
        "protection_refused",
        "exact_path_required",
        "input_too_small",
        "savings_too_small",
        "savings_ratio_too_small",
        "mandatory_expansion_cost",
        "prefix_evidence_empty",
        "prior_prefix_missing",
        "rolling_sample_partial",
        "prefix_churn_high",
        "bounded_stable_benefit",
    }
)
_ADVISORY_REASONS_BY_LANE: Final[dict[str, frozenset[str]]] = {
    "none": frozenset({"protection_refused", "exact_path_required"}),
    "scout": frozenset(
        {
            "input_too_small",
            "savings_too_small",
            "savings_ratio_too_small",
            "mandatory_expansion_cost",
            "prefix_evidence_empty",
            "prior_prefix_missing",
            "rolling_sample_partial",
            "prefix_churn_high",
        }
    ),
    "surgeon": frozenset({"bounded_stable_benefit"}),
}
_FIREWALL_REASONS_BY_ADVISORY_REASON: Final[dict[str, frozenset[str]]] = {
    "protection_refused": frozenset({"secret", "refuse"}),
    "exact_path_required": frozenset(
        {"exact_required", "protected", "unknown", "ambiguous", "security_sensitive"}
    ),
    "input_too_small": frozenset({"input_too_small"}),
    "savings_too_small": frozenset({"savings_too_small"}),
    "savings_ratio_too_small": frozenset({"savings_ratio_too_small"}),
    "mandatory_expansion_cost": frozenset({"mandatory_expansion_cost"}),
    "prefix_evidence_empty": frozenset({"beneficial"}),
    "prior_prefix_missing": frozenset({"beneficial"}),
    "rolling_sample_partial": frozenset({"beneficial"}),
    "prefix_churn_high": frozenset({"beneficial"}),
    "bounded_stable_benefit": frozenset({"beneficial"}),
}
_FIREWALL_REASONS: Final = frozenset(
    {
        "beneficial",
        "input_too_small",
        "savings_too_small",
        "savings_ratio_too_small",
        "mandatory_expansion_cost",
        "exact_required",
        "protected",
        "unknown",
        "ambiguous",
        "security_sensitive",
        "secret",
        "refuse",
    }
)
_ROLLING_STATUSES: Final = frozenset({"unavailable", "partial", "complete"})
_SUBJECT_KINDS: Final = frozenset(
    {"evidence", "evidence_pack", "blueprint", "tool_schema_catalog", "command_capture"}
)

_BOOLEAN_FIELDS: Final = frozenset(
    {
        "advisory_only",
        "applied",
        "current_truncated",
        "efficacy_claim_authority",
        "live_observation_authority",
        "previous_prefix_present",
        "previous_truncated",
        "provider_claim_authority",
        "provider_routing_authority",
        "would_block",
    }
)
_HASH_FIELDS: Final = frozenset(
    {
        "current_prefix_hmac_sha256",
        "evidence_hmac_sha256",
        "policy_sha256",
        "previous_prefix_hmac_sha256",
    }
)
_UNSIGNED_BYTE_FIELDS: Final = frozenset(
    {
        "blueprint_bytes",
        "current_prefix_bytes",
        "handle_bytes",
        "input_bytes",
        "mandatory_expansion_bytes",
        "previous_prefix_bytes",
        "retained_wire_bytes",
        "wrapper_bytes",
    }
)
_SIGNED_BYTE_FIELDS: Final = frozenset(
    {"prefix_delta_bytes", "predicted_savings_bytes"}
)
_SAMPLE_BYTE_FIELDS: Final = frozenset(
    {"current_sample_bytes", "previous_sample_bytes"}
)
_WINDOW_FIELDS: Final = frozenset(
    {"current_window_count", "matched_window_count", "previous_window_count"}
)
_BASIS_POINT_FIELDS: Final = frozenset(
    {"current_reuse_basis_points", "previous_retention_basis_points"}
)
_ENUM_FIELDS: Final[dict[str, frozenset[str]]] = {
    "advisory_lane": _ADVISORY_LANES,
    "advisory_reason": _ADVISORY_REASONS,
    "firewall_reason": _FIREWALL_REASONS,
    "rolling_status": _ROLLING_STATUSES,
    "subject_kind": _SUBJECT_KINDS,
}
_FLAT_FIELD_NAMES: Final = frozenset(
    _BOOLEAN_FIELDS
    | _HASH_FIELDS
    | _UNSIGNED_BYTE_FIELDS
    | _SIGNED_BYTE_FIELDS
    | _SAMPLE_BYTE_FIELDS
    | _WINDOW_FIELDS
    | _BASIS_POINT_FIELDS
    | frozenset(_ENUM_FIELDS)
    | {"predicted_cost_bytes", "savings_basis_points"}
)
_LEDGER_FIELD_NAMES: Final = frozenset(
    {
        "entry_hmac_sha256",
        "observed_at_unix_ms",
        "previous_entry_hmac_sha256",
        "schema_version",
        "sequence",
        "state_scope",
    }
)
_ENTRY_FIELD_NAMES: Final = _FLAT_FIELD_NAMES | _LEDGER_FIELD_NAMES

_AUXILIARY_METADATA: Final[dict[str, object]] = {
    "evidence_boundary": evidence_boundary(),
    "schema_version": _AUXILIARY_SCHEMA_VERSION,
}


@dataclass(frozen=True, slots=True)
class _LedgerMetadata:
    genesis_hmac_sha256: str
    committed_entry_count: int
    committed_head_hmac_sha256: str
    committed_total_canonical_bytes: int


@dataclass(frozen=True, slots=True)
class _ScannedLedger:
    rows: list[dict[str, object]]
    cumulative_bytes: list[int]


class DiagnosticLedgerErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    STATE_DIR_REQUIRED = "state_dir_required"
    STATE_DIR_NOT_ABSOLUTE = "state_dir_not_absolute"
    STATE_DIR_NOT_NORMALIZED = "state_dir_not_normalized"
    STATE_DIR_FORBIDDEN = "state_dir_forbidden"
    FILESYSTEM_UNSUPPORTED = "filesystem_unsupported"
    UNSAFE_STATE = "unsafe_state"
    LOCK_TIMEOUT = "lock_timeout"
    LEDGER_UNINITIALIZED = "ledger_uninitialized"
    LEDGER_CORRUPT = "ledger_corrupt"
    LEDGER_TAMPERED = "ledger_tampered"
    RECOVERY_REQUIRED = "recovery_required"
    ENTRY_COUNT_QUOTA_EXCEEDED = "entry_count_quota_exceeded"
    ENTRY_BYTES_QUOTA_EXCEEDED = "entry_bytes_quota_exceeded"
    ENTRY_TOO_LARGE = "entry_too_large"
    WRITE_FAILED = "write_failed"
    COMMIT_UNCERTAIN = "commit_uncertain"


class DiagnosticLedgerError(ValueError):
    """Stable non-reflective diagnostic-ledger failure."""

    __slots__ = ("code",)

    def __init__(self, code: DiagnosticLedgerErrorCode) -> None:
        self.code = code
        super().__init__(f"diagnostic ledger rejected: {code.value}")


LedgerErrorCode = DiagnosticLedgerErrorCode
LedgerError = DiagnosticLedgerError


def _raise(code: DiagnosticLedgerErrorCode) -> None:
    raise DiagnosticLedgerError(code) from None


_STORE_ERROR_MAP: Final[dict[str, DiagnosticLedgerErrorCode]] = {
    "invalid_argument": DiagnosticLedgerErrorCode.INVALID_ARGUMENT,
    "state_dir_required": DiagnosticLedgerErrorCode.STATE_DIR_REQUIRED,
    "state_dir_not_absolute": DiagnosticLedgerErrorCode.STATE_DIR_NOT_ABSOLUTE,
    "state_dir_not_normalized": DiagnosticLedgerErrorCode.STATE_DIR_NOT_NORMALIZED,
    "state_dir_forbidden": DiagnosticLedgerErrorCode.STATE_DIR_FORBIDDEN,
    "filesystem_unsupported": DiagnosticLedgerErrorCode.FILESYSTEM_UNSUPPORTED,
    "unsafe_state": DiagnosticLedgerErrorCode.UNSAFE_STATE,
    "store_uninitialized": DiagnosticLedgerErrorCode.LEDGER_UNINITIALIZED,
    "store_corrupt": DiagnosticLedgerErrorCode.LEDGER_CORRUPT,
    "store_tampered": DiagnosticLedgerErrorCode.LEDGER_TAMPERED,
    "recovery_required": DiagnosticLedgerErrorCode.RECOVERY_REQUIRED,
    "write_failed": DiagnosticLedgerErrorCode.WRITE_FAILED,
    "commit_uncertain": DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN,
}


def _translate_store_error(error: _filesystem.StoreError) -> None:
    _raise(_STORE_ERROR_MAP.get(error.code.value, DiagnosticLedgerErrorCode.UNSAFE_STATE))


def _require_filesystem_features() -> None:
    try:
        _filesystem._require_filesystem_features()
    except _filesystem.StoreError as error:
        _translate_store_error(error)


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


def _require_disjoint(
    state_fd: int, exclusion_fds: tuple[int, ...]
) -> None:
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
    error_code: DiagnosticLedgerErrorCode = DiagnosticLedgerErrorCode.UNSAFE_STATE,
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
    status = _descriptor_status(descriptor)
    if not stat.S_ISDIR(status.st_mode):
        _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
    return descriptor


def _require_private_file_descriptor(descriptor: object) -> int:
    status = _descriptor_status(descriptor)
    if not _private_file(status):
        _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
    return descriptor


def _open_directory_at(parent_fd: int, name: str) -> int:
    parent = _require_directory_descriptor(parent_fd)
    try:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent)
    except OSError:
        _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
    try:
        if not _private_directory(_descriptor_status(descriptor)):
            _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_private_file(
    parent_fd: int,
    name: str,
    *,
    missing: DiagnosticLedgerErrorCode = DiagnosticLedgerErrorCode.LEDGER_CORRUPT,
) -> int:
    parent = _require_directory_descriptor(parent_fd)
    try:
        descriptor = os.open(name, _file_read_flags(), dir_fd=parent)
    except FileNotFoundError:
        _raise(missing)
    except OSError:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    try:
        if not _private_file(_descriptor_status(descriptor)):
            _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _bounded_names(
    descriptor: int,
    maximum: int,
    *,
    overflow: DiagnosticLedgerErrorCode = DiagnosticLedgerErrorCode.LEDGER_CORRUPT,
) -> list[str]:
    checked = _require_directory_descriptor(descriptor)
    names: list[str] = []
    try:
        with os.scandir(checked) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    _raise(overflow)
    except DiagnosticLedgerError:
        raise
    except OSError:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
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
            _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > maximum:
            _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
        chunks.append(chunk)


def _read_named_file(parent_fd: int, name: str, maximum: int) -> bytes:
    descriptor = _open_private_file(parent_fd, name)
    try:
        before = _descriptor_status(
            descriptor, error_code=DiagnosticLedgerErrorCode.LEDGER_CORRUPT
        )
        raw = _read_all(descriptor, maximum)
        after = _descriptor_status(
            descriptor, error_code=DiagnosticLedgerErrorCode.LEDGER_CORRUPT
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
            _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
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
            _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
        if written <= 0:
            _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
        offset += written


def _write_new_file(parent_fd: int, name: str, raw: bytes) -> None:
    parent = _require_directory_descriptor(parent_fd)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        status = os.fstat(descriptor)
        if not _private_file(status) or status.st_size != len(raw):
            _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
    except DiagnosticLedgerError:
        raise
    except OSError:
        _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _parse_document(raw: bytes, limits: JSONLimits) -> object:
    try:
        return parse_canonical_json_bytes(raw, limits)
    except CanonicalJSONError:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)


def _canonical_document(value: object, limits: JSONLimits) -> bytes:
    try:
        return canonical_json_bytes(value, limits)
    except CanonicalJSONError:
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)


def _hmac_hex(key: bytes, domain: bytes, raw: bytes) -> str:
    return hmac.new(key, domain + b"\0" + raw, hashlib.sha256).hexdigest()


def _derive_key(master_key: bytes, domain: bytes) -> bytes:
    return hmac.new(master_key, domain + b"\0", hashlib.sha256).digest()


def _metadata_document(
    ledger_key: bytes,
    genesis_hmac: str,
    *,
    committed_entry_count: int = 0,
    committed_head_hmac_sha256: str | None = None,
    committed_total_canonical_bytes: int = 0,
) -> bytes:
    committed_head = (
        genesis_hmac
        if committed_head_hmac_sha256 is None
        else committed_head_hmac_sha256
    )
    value: dict[str, object] = {
        "committed_entry_count": committed_entry_count,
        "committed_head_hmac_sha256": committed_head,
        "committed_total_canonical_bytes": committed_total_canonical_bytes,
        "evidence_boundary": evidence_boundary(),
        "genesis_hmac_sha256": genesis_hmac,
        "integrity_hmac_sha256": "",
        "schema_version": _METADATA_SCHEMA_VERSION,
    }
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256")
    value["integrity_hmac_sha256"] = _hmac_hex(
        ledger_key,
        b"contextguard-receipt/diagnostic-ledger-metadata-mac/v1",
        canonical_json_bytes(unsigned, _METADATA_JSON_LIMITS),
    )
    return canonical_json_bytes(value, _METADATA_JSON_LIMITS)


def _validate_metadata(raw: bytes, ledger_key: bytes) -> _LedgerMetadata:
    value = _parse_document(raw, _METADATA_JSON_LIMITS)
    expected_keys = {
        "committed_entry_count",
        "committed_head_hmac_sha256",
        "committed_total_canonical_bytes",
        "evidence_boundary",
        "genesis_hmac_sha256",
        "integrity_hmac_sha256",
        "schema_version",
    }
    if type(value) is not dict or set(value) != expected_keys:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    genesis = value.get("genesis_hmac_sha256")
    committed_count = value.get("committed_entry_count")
    committed_head = value.get("committed_head_hmac_sha256")
    committed_bytes = value.get("committed_total_canonical_bytes")
    supplied = value.get("integrity_hmac_sha256")
    if (
        value.get("schema_version") != _METADATA_SCHEMA_VERSION
        or value.get("evidence_boundary") != evidence_boundary()
        or type(genesis) is not str
        or _HEX_256.fullmatch(genesis) is None
        or type(committed_count) is not int
        or committed_count < 0
        or committed_count > _MAX_ENTRIES
        or type(committed_head) is not str
        or _HEX_256.fullmatch(committed_head) is None
        or type(committed_bytes) is not int
        or committed_bytes < 0
        or committed_bytes > _MAX_TOTAL_BYTES
        or type(supplied) is not str
        or _HEX_256.fullmatch(supplied) is None
    ):
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256")
    expected = _hmac_hex(
        ledger_key,
        b"contextguard-receipt/diagnostic-ledger-metadata-mac/v1",
        canonical_json_bytes(unsigned, _METADATA_JSON_LIMITS),
    )
    if not hmac.compare_digest(supplied, expected):
        _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
    if committed_count == 0 and (
        committed_head != genesis or committed_bytes != 0
    ):
        _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
    return _LedgerMetadata(
        genesis_hmac_sha256=genesis,
        committed_entry_count=committed_count,
        committed_head_hmac_sha256=committed_head,
        committed_total_canonical_bytes=committed_bytes,
    )


def _validate_auxiliary_metadata(raw: bytes) -> None:
    value = _parse_document(raw, _METADATA_JSON_LIMITS)
    if value != _AUXILIARY_METADATA:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)


def _require_integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    return value


def _validate_flat_fields(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != _FLAT_FIELD_NAMES:
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    result = dict(value)
    for name in _BOOLEAN_FIELDS:
        if type(result[name]) is not bool:
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    if (
        result["applied"] is not False
        or result["advisory_only"] is not True
        or any(
            result[name] is not False
            for name in (
                "efficacy_claim_authority",
                "live_observation_authority",
                "provider_claim_authority",
                "provider_routing_authority",
            )
        )
    ):
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    for name, choices in _ENUM_FIELDS.items():
        if type(result[name]) is not str or result[name] not in choices:
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    for name in _HASH_FIELDS:
        if type(result[name]) is not str or _HEX_256.fullmatch(result[name]) is None:
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    for name in _UNSIGNED_BYTE_FIELDS | {"predicted_cost_bytes"}:
        _require_integer(result[name], 0, 900_000)
    for name in _SIGNED_BYTE_FIELDS:
        _require_integer(result[name], -900_000, 900_000)
    for name in _SAMPLE_BYTE_FIELDS:
        _require_integer(result[name], 0, 65_536)
    for name in _WINDOW_FIELDS:
        _require_integer(result[name], 0, 1024)
    for name in _BASIS_POINT_FIELDS:
        _require_integer(result[name], 0, 10_000)
    _require_integer(result["savings_basis_points"], -9_000_000_000, 10_000)

    current_prefix = result["current_prefix_bytes"]
    previous_prefix = result["previous_prefix_bytes"]
    current_sample = result["current_sample_bytes"]
    previous_sample = result["previous_sample_bytes"]
    current_windows = result["current_window_count"]
    previous_windows = result["previous_window_count"]
    matched_windows = result["matched_window_count"]
    previous_present = result["previous_prefix_present"]
    if (
        current_sample != min(current_prefix, 65_536)
        or result["current_truncated"] is not (current_prefix > 65_536)
        or current_windows != (current_sample + 63) // 64
        or matched_windows > current_windows
    ):
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    if previous_present:
        if (
            previous_sample != min(previous_prefix, 65_536)
            or result["previous_truncated"] is not (previous_prefix > 65_536)
            or previous_windows != (previous_sample + 63) // 64
            or matched_windows > previous_windows
            or result["prefix_delta_bytes"] != current_prefix - previous_prefix
            or result["rolling_status"]
            != ("partial" if result["current_truncated"] or result["previous_truncated"] else "complete")
        ):
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    elif (
        previous_prefix != 0
        or previous_sample != 0
        or previous_windows != 0
        or result["previous_truncated"] is not False
        or matched_windows != 0
        or result["current_reuse_basis_points"] != 0
        or result["previous_retention_basis_points"] != 0
        or result["prefix_delta_bytes"] != 0
        or result["rolling_status"] != "unavailable"
    ):
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    expected_current_reuse = (
        matched_windows * 10_000 // current_windows if current_windows else 0
    )
    expected_previous_retention = (
        matched_windows * 10_000 // previous_windows if previous_windows else 0
    )
    if (
        result["current_reuse_basis_points"] != expected_current_reuse
        or result["previous_retention_basis_points"] != expected_previous_retention
        or result["predicted_savings_bytes"]
        != result["input_bytes"] - result["predicted_cost_bytes"]
    ):
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    route = decide_route(
        RouteCosts(
            input_bytes=result["input_bytes"],
            wrapper_bytes=result["wrapper_bytes"],
            handle_bytes=result["handle_bytes"],
            blueprint_bytes=result["blueprint_bytes"],
            mandatory_expansion_bytes=result["mandatory_expansion_bytes"],
            retained_wire_bytes=result["retained_wire_bytes"],
        )
    )
    advisory_lane = result["advisory_lane"]
    advisory_reason = result["advisory_reason"]
    if (
        result["predicted_cost_bytes"] != route.predicted_cost_bytes
        or result["predicted_savings_bytes"] != route.predicted_savings_bytes
        or result["savings_basis_points"] != route.savings_basis_points
        or result["policy_sha256"] != DIAGNOSTICS_POLICY_SHA256
        or result["would_block"] is not (result["firewall_reason"] != "beneficial")
        or advisory_reason not in _ADVISORY_REASONS_BY_LANE[advisory_lane]
        or result["firewall_reason"]
        not in _FIREWALL_REASONS_BY_ADVISORY_REASON[advisory_reason]
    ):
        _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    if advisory_lane != "none":
        if route.reason.value != "beneficial":
            expected_advisory = ("scout", route.reason.value)
        elif current_prefix == 0:
            expected_advisory = ("scout", "prefix_evidence_empty")
        elif not previous_present:
            expected_advisory = ("scout", "prior_prefix_missing")
        elif result["current_truncated"] or result["previous_truncated"]:
            expected_advisory = ("scout", "rolling_sample_partial")
        elif (
            current_sample < 64
            or previous_sample < 64
            or result["current_reuse_basis_points"] < 9_000
            or result["previous_retention_basis_points"] < 9_000
        ):
            expected_advisory = ("scout", "prefix_churn_high")
        else:
            expected_advisory = ("surgeon", "bounded_stable_benefit")
        if (advisory_lane, advisory_reason) != expected_advisory:
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
    return result


def _validate_loaded_entry(value: object, expected_sequence: int) -> dict[str, object]:
    if type(value) is not dict or set(value) != _ENTRY_FIELD_NAMES:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    try:
        _validate_flat_fields({name: value[name] for name in _FLAT_FIELD_NAMES})
        _require_integer(value.get("sequence"), 1, _MAX_ENTRIES)
        _require_integer(value.get("observed_at_unix_ms"), 0, 4_102_444_800_000)
    except DiagnosticLedgerError:
        _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    for name in ("entry_hmac_sha256", "previous_entry_hmac_sha256"):
        field_value = value.get(name)
        if type(field_value) is not str or _HEX_256.fullmatch(field_value) is None:
            _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
    if (
        value.get("schema_version") != _ENTRY_SCHEMA_VERSION
        or value.get("state_scope") != "durable"
        or value.get("sequence") != expected_sequence
    ):
        _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
    return dict(value)


class DiagnosticLedger:
    """An independent append-only advisory ledger with no provider authority."""

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
        *,
        state_dir: str,
        repository_root: object,
        create: bool = False,
    ) -> "DiagnosticLedger":
        _require_filesystem_features()
        checked_path = _validate_state_path(state_dir)
        if type(create) is not bool:
            _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
        exclusion_fds = _check_disjoint(checked_path, repository_root)
        state_fd: int | None = None
        try:
            state_fd = _open_state_directory(checked_path, create=create)
            _require_disjoint(state_fd, exclusion_fds)
            if create:
                existing_names = set(
                    _bounded_names(
                        state_fd,
                        4,
                        overflow=DiagnosticLedgerErrorCode.RECOVERY_REQUIRED,
                    )
                )
                if existing_names and _TOP_LOCK_NAME not in existing_names:
                    _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
            instance = cls()
            instance._state_path = checked_path
            instance._state_fd = state_fd
            instance._exclusion_fds = exclusion_fds
            state_fd = None
            exclusion_fds = ()
        except Exception:
            if state_fd is not None:
                os.close(state_fd)
            _close_descriptors(exclusion_fds)
            raise
        try:
            instance._top_lock_fd, top_lock_created = instance._open_lock_at(
                instance._state_fd, _TOP_LOCK_NAME, create=create
            )
            with instance._locked_descriptor(instance._top_lock_fd, exclusive=True):
                instance._ensure_initialized(
                    create=create,
                    top_lock_created=top_lock_created,
                )
                instance._open_axis()
            instance._closed = False
            return instance
        except Exception:
            instance._close_descriptors()
            raise

    def _revalidate_state_disjoint(self) -> None:
        if type(self._exclusion_fds) is not tuple or not self._exclusion_fds:
            _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
        state_fd = _require_directory_descriptor(self._state_fd)
        for descriptor in self._exclusion_fds:
            _require_directory_descriptor(descriptor)
        _require_disjoint(state_fd, self._exclusion_fds)

    def _open_lock_at(
        self, parent_fd: int, name: str, *, create: bool
    ) -> tuple[int, bool]:
        self._revalidate_state_disjoint()
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            if not create:
                _raise(DiagnosticLedgerErrorCode.LEDGER_UNINITIALIZED)
            try:
                descriptor = os.open(
                    name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_fd,
                )
                os.fchmod(descriptor, 0o600)
                created = True
            except OSError:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
        except OSError:
            _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
        if descriptor is None:
            _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
        try:
            if not _private_file(_descriptor_status(descriptor)):
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            if created:
                try:
                    os.fsync(descriptor)
                    os.fsync(parent_fd)
                except OSError:
                    _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
            return descriptor, created
        except Exception:
            os.close(descriptor)
            raise

    @contextmanager
    def _locked_descriptor(self, descriptor: int, *, exclusive: bool) -> Iterator[None]:
        self._require_opener_process()
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        if not self._thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            _raise(DiagnosticLedgerErrorCode.LOCK_TIMEOUT)
        acquired = False
        checked = -1
        try:
            checked = _require_private_file_descriptor(descriptor)
            while True:
                try:
                    fcntl.flock(checked, operation | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        _raise(DiagnosticLedgerErrorCode.LOCK_TIMEOUT)
                    time.sleep(0.01)
                except OSError:
                    _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
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
                overflow=DiagnosticLedgerErrorCode.RECOVERY_REQUIRED,
            )
        )
        allowed = {_TOP_LOCK_NAME, "store-v1", _AUXILIARY_NAME}
        unknown = names - allowed
        if unknown:
            if all(_AUXILIARY_TEMP_NAME.fullmatch(name) for name in unknown):
                _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
            _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
        return names

    def _create_diagnostics_tree(self, parent_fd: int, name: str) -> None:
        diagnostics_fd: int | None = None
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            diagnostics_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
            os.fchmod(diagnostics_fd, 0o700)
            master_key = secrets.token_bytes(32)
            ledger_key = _derive_key(
                master_key, b"contextguard-receipt/diagnostic-ledger-mac-key/v1"
            )
            genesis_hmac = _hmac_hex(
                ledger_key,
                b"contextguard-receipt/diagnostic-ledger-genesis/v1",
                canonical_json_bytes(_AUXILIARY_METADATA, _METADATA_JSON_LIMITS),
            )
            _write_new_file(diagnostics_fd, _DIAGNOSTIC_LOCK_NAME, b"")
            _write_new_file(diagnostics_fd, _KEY_NAME, master_key)
            _write_new_file(
                diagnostics_fd,
                _METADATA_NAME,
                _metadata_document(ledger_key, genesis_hmac),
            )
            for child in (_ENTRIES_NAME, _TEMP_NAME):
                os.mkdir(child, 0o700, dir_fd=diagnostics_fd)
                child_fd = os.open(child, _directory_flags(), dir_fd=diagnostics_fd)
                try:
                    os.fchmod(child_fd, 0o700)
                    os.fsync(child_fd)
                finally:
                    os.close(child_fd)
            os.fsync(diagnostics_fd)
        except DiagnosticLedgerError:
            raise
        except OSError:
            _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
        finally:
            if diagnostics_fd is not None:
                try:
                    os.close(diagnostics_fd)
                except OSError:
                    pass

    def _validate_diagnostics_topology(self, auxiliary_fd: int) -> None:
        diagnostics_fd = _open_directory_at(auxiliary_fd, _DIAGNOSTICS_NAME)
        try:
            if set(_bounded_names(diagnostics_fd, 5)) != {
                _DIAGNOSTIC_LOCK_NAME,
                _KEY_NAME,
                _METADATA_NAME,
                _ENTRIES_NAME,
                _TEMP_NAME,
            }:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
        finally:
            os.close(diagnostics_fd)

    def _ensure_existing_auxiliary(self, *, create: bool) -> None:
        auxiliary_fd = _open_directory_at(self._state_fd, _AUXILIARY_NAME)
        try:
            _validate_auxiliary_metadata(
                _read_named_file(auxiliary_fd, _AUXILIARY_METADATA_NAME, 4096)
            )
            names = set(
                _bounded_names(
                    auxiliary_fd,
                    5,
                    overflow=DiagnosticLedgerErrorCode.RECOVERY_REQUIRED,
                )
            )
            unknown = names - {
                _AUXILIARY_METADATA_NAME,
                _DIAGNOSTICS_NAME,
                _TWIN_NAME,
                _REFERENCE_EXPIRY_NAME,
            }
            temporary_names = {
                name for name in unknown if _DIAGNOSTICS_TEMP_NAME.fullmatch(name)
            }
            if unknown - temporary_names:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if temporary_names:
                _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
            if _TWIN_NAME in names:
                twin_fd = _open_directory_at(auxiliary_fd, _TWIN_NAME)
                os.close(twin_fd)
            if _REFERENCE_EXPIRY_NAME in names:
                expiry_fd = _open_directory_at(auxiliary_fd, _REFERENCE_EXPIRY_NAME)
                os.close(expiry_fd)
            if _DIAGNOSTICS_NAME in names:
                if names - {
                    _AUXILIARY_METADATA_NAME,
                    _DIAGNOSTICS_NAME,
                    _TWIN_NAME,
                    _REFERENCE_EXPIRY_NAME,
                }:
                    _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
                self._validate_diagnostics_topology(auxiliary_fd)
                return
            if names - {
                _AUXILIARY_METADATA_NAME,
                _TWIN_NAME,
                _REFERENCE_EXPIRY_NAME,
            }:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if not create:
                _raise(DiagnosticLedgerErrorCode.LEDGER_UNINITIALIZED)

            temporary_name = ".diagnostics-v1.tmp-" + secrets.token_bytes(16).hex()
            published = False
            try:
                self._create_diagnostics_tree(auxiliary_fd, temporary_name)
                os.rename(
                    temporary_name,
                    _DIAGNOSTICS_NAME,
                    src_dir_fd=auxiliary_fd,
                    dst_dir_fd=auxiliary_fd,
                )
                published = True
                os.fsync(auxiliary_fd)
            except DiagnosticLedgerError:
                raise
            except OSError:
                _raise(
                    DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN
                    if published
                    else DiagnosticLedgerErrorCode.WRITE_FAILED
                )
        finally:
            os.close(auxiliary_fd)

    def _ensure_initialized(
        self,
        *,
        create: bool,
        top_lock_created: bool = False,
    ) -> None:
        self._revalidate_state_disjoint()
        try:
            names = self._root_names()
        except DiagnosticLedgerError:
            if top_lock_created:
                # POSIX has no portable conditional unlink-by-inode. Preserve
                # every name if topology changed after preflight rather than
                # risk deleting a concurrent replacement.
                _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
            raise
        if "store-v1" in names:
            descriptor = _open_directory_at(self._state_fd, "store-v1")
            os.close(descriptor)
        if _AUXILIARY_NAME in names:
            self._ensure_existing_auxiliary(create=create)
            return
        if not create:
            _raise(DiagnosticLedgerErrorCode.LEDGER_UNINITIALIZED)

        temporary_name = ".auxiliary-v1.tmp-" + secrets.token_bytes(16).hex()
        temporary_fd: int | None = None
        published = False
        try:
            os.mkdir(temporary_name, 0o700, dir_fd=self._state_fd)
            temporary_fd = os.open(temporary_name, _directory_flags(), dir_fd=self._state_fd)
            os.fchmod(temporary_fd, 0o700)
            _write_new_file(
                temporary_fd,
                _AUXILIARY_METADATA_NAME,
                canonical_json_bytes(_AUXILIARY_METADATA, _METADATA_JSON_LIMITS),
            )
            self._create_diagnostics_tree(temporary_fd, _DIAGNOSTICS_NAME)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = None
            os.rename(
                temporary_name,
                _AUXILIARY_NAME,
                src_dir_fd=self._state_fd,
                dst_dir_fd=self._state_fd,
            )
            published = True
            os.fsync(self._state_fd)
        except DiagnosticLedgerError:
            raise
        except OSError:
            _raise(
                DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN
                if published
                else DiagnosticLedgerErrorCode.WRITE_FAILED
            )
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass

    def _open_axis(self) -> None:
        self._revalidate_state_disjoint()
        self._auxiliary_fd = _open_directory_at(self._state_fd, _AUXILIARY_NAME)
        _validate_auxiliary_metadata(
            _read_named_file(self._auxiliary_fd, _AUXILIARY_METADATA_NAME, 4096)
        )
        self._diagnostics_fd = _open_directory_at(
            self._auxiliary_fd, _DIAGNOSTICS_NAME
        )
        self._diagnostic_lock_fd, _created = self._open_lock_at(
            self._diagnostics_fd, _DIAGNOSTIC_LOCK_NAME, create=False
        )
        master_key = _read_named_file(self._diagnostics_fd, _KEY_NAME, 33)
        if len(master_key) != 32:
            _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
        self._fingerprint_key = _derive_key(
            master_key, b"contextguard-receipt/diagnostic-fingerprint-key/v1"
        )
        self._ledger_key = _derive_key(
            master_key, b"contextguard-receipt/diagnostic-ledger-mac-key/v1"
        )
        metadata_raw = _read_named_file(
            self._diagnostics_fd, _METADATA_NAME, 4096
        )
        metadata = _validate_metadata(metadata_raw, self._ledger_key)
        self._genesis_hmac = metadata.genesis_hmac_sha256
        self._entries_fd = _open_directory_at(self._diagnostics_fd, _ENTRIES_NAME)
        self._temp_fd = _open_directory_at(self._diagnostics_fd, _TEMP_NAME)
        self._state_anchor = self._descriptor_identity(self._state_fd)
        self._top_lock_anchor = self._descriptor_identity(self._top_lock_fd)
        self._auxiliary_anchor = self._descriptor_identity(self._auxiliary_fd)
        self._diagnostics_anchor = self._descriptor_identity(self._diagnostics_fd)
        self._diagnostic_lock_anchor = self._descriptor_identity(
            self._diagnostic_lock_fd
        )
        self._entries_anchor = self._descriptor_identity(self._entries_fd)
        self._temp_anchor = self._descriptor_identity(self._temp_fd)
        self._revalidate_anchors()

    @staticmethod
    def _descriptor_identity(descriptor: int) -> tuple[int, int]:
        status = _descriptor_status(descriptor)
        return status.st_dev, status.st_ino

    def _revalidate_anchors(self) -> None:
        self._revalidate_state_disjoint()
        opened: list[int] = []
        try:
            state_fd = _open_state_directory(self._state_path, create=False)
            opened.append(state_fd)
            if self._descriptor_identity(state_fd) != self._state_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            names = self._root_names()
            if names not in (
                {_TOP_LOCK_NAME, _AUXILIARY_NAME},
                {_TOP_LOCK_NAME, "store-v1", _AUXILIARY_NAME},
            ):
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if "store-v1" in names:
                store_fd = _open_directory_at(state_fd, "store-v1")
                opened.append(store_fd)
            top_lock_fd = _open_private_file(state_fd, _TOP_LOCK_NAME)
            opened.append(top_lock_fd)
            if self._descriptor_identity(top_lock_fd) != self._top_lock_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            auxiliary_fd = _open_directory_at(state_fd, _AUXILIARY_NAME)
            opened.append(auxiliary_fd)
            if self._descriptor_identity(auxiliary_fd) != self._auxiliary_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            auxiliary_names = set(_bounded_names(auxiliary_fd, 4))
            if (
                _DIAGNOSTICS_NAME not in auxiliary_names
                or auxiliary_names
                - {
                    _AUXILIARY_METADATA_NAME,
                    _DIAGNOSTICS_NAME,
                    _TWIN_NAME,
                    _REFERENCE_EXPIRY_NAME,
                }
            ):
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            _validate_auxiliary_metadata(
                _read_named_file(auxiliary_fd, _AUXILIARY_METADATA_NAME, 4096)
            )
            if _TWIN_NAME in auxiliary_names:
                twin_fd = _open_directory_at(auxiliary_fd, _TWIN_NAME)
                opened.append(twin_fd)
            if _REFERENCE_EXPIRY_NAME in auxiliary_names:
                expiry_fd = _open_directory_at(
                    auxiliary_fd, _REFERENCE_EXPIRY_NAME
                )
                opened.append(expiry_fd)
            diagnostics_fd = _open_directory_at(auxiliary_fd, _DIAGNOSTICS_NAME)
            opened.append(diagnostics_fd)
            if self._descriptor_identity(diagnostics_fd) != self._diagnostics_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            if set(_bounded_names(diagnostics_fd, 5)) != {
                _DIAGNOSTIC_LOCK_NAME,
                _KEY_NAME,
                _METADATA_NAME,
                _ENTRIES_NAME,
                _TEMP_NAME,
            }:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            lock_fd = _open_private_file(diagnostics_fd, _DIAGNOSTIC_LOCK_NAME)
            opened.append(lock_fd)
            if self._descriptor_identity(lock_fd) != self._diagnostic_lock_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            key = _read_named_file(diagnostics_fd, _KEY_NAME, 33)
            if len(key) != 32:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if not hmac.compare_digest(
                _derive_key(key, b"contextguard-receipt/diagnostic-ledger-mac-key/v1"),
                self._ledger_key,
            ):
                _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
            metadata = _validate_metadata(
                _read_named_file(diagnostics_fd, _METADATA_NAME, 4096),
                self._ledger_key,
            )
            if metadata.genesis_hmac_sha256 != self._genesis_hmac:
                _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
            entries_fd = _open_directory_at(diagnostics_fd, _ENTRIES_NAME)
            opened.append(entries_fd)
            if self._descriptor_identity(entries_fd) != self._entries_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
            temp_fd = _open_directory_at(diagnostics_fd, _TEMP_NAME)
            opened.append(temp_fd)
            if self._descriptor_identity(temp_fd) != self._temp_anchor:
                _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)
        finally:
            for descriptor in reversed(opened):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    @property
    def fingerprint_key(self) -> bytes:
        with self._operation():
            return self._fingerprint_key

    @contextmanager
    def _operation(self) -> Iterator[None]:
        self._require_opener_process()
        with self._thread_lock:
            if self._closed or self._close_requested:
                _raise(DiagnosticLedgerErrorCode.INVALID_ARGUMENT)
            for name in (
                "_state_fd",
                "_auxiliary_fd",
                "_diagnostics_fd",
                "_entries_fd",
                "_temp_fd",
            ):
                _require_directory_descriptor(getattr(self, name, None))
            for name in ("_top_lock_fd", "_diagnostic_lock_fd"):
                _require_private_file_descriptor(getattr(self, name, None))
            self._active_operations += 1
            try:
                yield
            finally:
                self._active_operations -= 1
                if self._active_operations == 0 and self._close_requested:
                    self._close_descriptors()
                    self._closed = True
                    self._close_requested = False

    def _require_opener_process(self) -> None:
        if os.getpid() != self._opener_pid:
            _raise(DiagnosticLedgerErrorCode.UNSAFE_STATE)

    def _read_metadata_state(self) -> _LedgerMetadata:
        metadata = _validate_metadata(
            _read_named_file(self._diagnostics_fd, _METADATA_NAME, 4096),
            self._ledger_key,
        )
        if metadata.genesis_hmac_sha256 != self._genesis_hmac:
            _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
        return metadata

    def _scan(self) -> _ScannedLedger:
        names = sorted(_bounded_names(self._entries_fd, _MAX_ENTRIES))
        rows: list[dict[str, object]] = []
        cumulative_bytes: list[int] = []
        total_bytes = 0
        previous_hmac = self._genesis_hmac
        for expected_sequence, name in enumerate(names, start=1):
            if _ENTRY_NAME.fullmatch(name) is None:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if name != f"{expected_sequence:016d}.json":
                _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
            raw = _read_named_file(self._entries_fd, name, _MAX_ENTRY_BYTES)
            total_bytes += len(raw)
            if total_bytes > _MAX_TOTAL_BYTES:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            parsed = _parse_document(raw, _ENTRY_JSON_LIMITS)
            if type(parsed) is not dict or set(parsed) != _ENTRY_FIELD_NAMES:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            supplied = parsed.get("entry_hmac_sha256")
            supplied_previous = parsed.get("previous_entry_hmac_sha256")
            if (
                type(supplied) is not str
                or _HEX_256.fullmatch(supplied) is None
                or type(supplied_previous) is not str
                or _HEX_256.fullmatch(supplied_previous) is None
            ):
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            if supplied_previous != previous_hmac:
                _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
            unsigned = dict(parsed)
            unsigned.pop("entry_hmac_sha256")
            expected_hmac = _hmac_hex(
                self._ledger_key,
                b"contextguard-receipt/diagnostic-ledger-entry-mac/v1",
                canonical_json_bytes(unsigned, _ENTRY_JSON_LIMITS),
            )
            if not hmac.compare_digest(supplied, expected_hmac):
                _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
            row = _validate_loaded_entry(parsed, expected_sequence)
            previous_hmac = supplied
            rows.append(row)
            cumulative_bytes.append(total_bytes)
        return _ScannedLedger(rows=rows, cumulative_bytes=cumulative_bytes)

    def _committed_view(
        self,
        metadata: _LedgerMetadata,
        scanned: _ScannedLedger,
    ) -> tuple[list[dict[str, object]], bool]:
        committed_count = metadata.committed_entry_count
        if len(scanned.rows) < committed_count:
            _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
        committed_head = (
            scanned.rows[committed_count - 1]["entry_hmac_sha256"]
            if committed_count
            else self._genesis_hmac
        )
        committed_bytes = (
            scanned.cumulative_bytes[committed_count - 1]
            if committed_count
            else 0
        )
        if (
            committed_head != metadata.committed_head_hmac_sha256
            or committed_bytes != metadata.committed_total_canonical_bytes
        ):
            _raise(DiagnosticLedgerErrorCode.LEDGER_TAMPERED)
        return scanned.rows[:committed_count], len(scanned.rows) > committed_count

    def _temp_recovery_required(self) -> bool:
        names = _bounded_names(
            self._temp_fd,
            1,
            overflow=DiagnosticLedgerErrorCode.RECOVERY_REQUIRED,
        )
        for name in names:
            if _TEMP_ENTRY_NAME.fullmatch(name) is None:
                _raise(DiagnosticLedgerErrorCode.LEDGER_CORRUPT)
            descriptor = _open_private_file(self._temp_fd, name)
            os.close(descriptor)
        return bool(names)

    def append(
        self,
        flat_fields: dict[str, object],
        observed_at_unix_ms: int,
    ) -> dict[str, object]:
        checked_fields = _validate_flat_fields(flat_fields)
        _require_integer(observed_at_unix_ms, 0, 4_102_444_800_000)
        with self._operation():
            with self._locked_descriptor(self._diagnostic_lock_fd, exclusive=True):
                self._revalidate_anchors()
                if self._temp_recovery_required():
                    _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
                metadata = self._read_metadata_state()
                scanned = self._scan()
                _rows, row_ahead = self._committed_view(metadata, scanned)
                if row_ahead:
                    _raise(DiagnosticLedgerErrorCode.RECOVERY_REQUIRED)
                if metadata.committed_entry_count >= _MAX_ENTRIES:
                    _raise(DiagnosticLedgerErrorCode.ENTRY_COUNT_QUOTA_EXCEEDED)
                sequence = metadata.committed_entry_count + 1
                previous_hmac = metadata.committed_head_hmac_sha256
                row = {
                    **checked_fields,
                    "entry_hmac_sha256": "",
                    "observed_at_unix_ms": observed_at_unix_ms,
                    "previous_entry_hmac_sha256": previous_hmac,
                    "schema_version": _ENTRY_SCHEMA_VERSION,
                    "sequence": sequence,
                    "state_scope": "durable",
                }
                unsigned = dict(row)
                unsigned.pop("entry_hmac_sha256")
                row["entry_hmac_sha256"] = _hmac_hex(
                    self._ledger_key,
                    b"contextguard-receipt/diagnostic-ledger-entry-mac/v1",
                    canonical_json_bytes(unsigned, _ENTRY_JSON_LIMITS),
                )
                raw = _canonical_document(row, _ENTRY_JSON_LIMITS)
                if len(raw) > _MAX_ENTRY_BYTES:
                    _raise(DiagnosticLedgerErrorCode.ENTRY_TOO_LARGE)
                new_total_bytes = metadata.committed_total_canonical_bytes + len(raw)
                if new_total_bytes > _MAX_TOTAL_BYTES:
                    _raise(DiagnosticLedgerErrorCode.ENTRY_BYTES_QUOTA_EXCEEDED)

                temporary_name = secrets.token_bytes(16).hex() + ".json"
                final_name = f"{sequence:016d}.json"
                published = False
                try:
                    _write_new_file(self._temp_fd, temporary_name, raw)
                    os.rename(
                        temporary_name,
                        final_name,
                        src_dir_fd=self._temp_fd,
                        dst_dir_fd=self._entries_fd,
                    )
                    published = True
                    for parent_fd in (self._temp_fd, self._entries_fd):
                        try:
                            os.fsync(parent_fd)
                        except OSError:
                            _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
                    metadata_raw = _metadata_document(
                        self._ledger_key,
                        self._genesis_hmac,
                        committed_entry_count=sequence,
                        committed_head_hmac_sha256=row["entry_hmac_sha256"],
                        committed_total_canonical_bytes=new_total_bytes,
                    )
                    metadata_temporary_name = secrets.token_bytes(16).hex() + ".json"
                    _write_new_file(
                        self._temp_fd, metadata_temporary_name, metadata_raw
                    )
                    os.rename(
                        metadata_temporary_name,
                        _METADATA_NAME,
                        src_dir_fd=self._temp_fd,
                        dst_dir_fd=self._diagnostics_fd,
                    )
                    parent_sync_failed = False
                    for parent_fd in (self._temp_fd, self._diagnostics_fd):
                        try:
                            os.fsync(parent_fd)
                        except OSError:
                            parent_sync_failed = True
                    final_metadata = self._read_metadata_state()
                    final_scanned = self._scan()
                    final_rows, recovery_required = self._committed_view(
                        final_metadata, final_scanned
                    )
                    if (
                        recovery_required
                        or final_metadata.committed_entry_count != sequence
                        or len(final_rows) != sequence
                        or final_rows[-1]["entry_hmac_sha256"]
                        != row["entry_hmac_sha256"]
                    ):
                        _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
                    self._revalidate_anchors()
                    if parent_sync_failed:
                        _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
                except DiagnosticLedgerError:
                    if published:
                        _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
                    raise
                except OSError:
                    if published:
                        _raise(DiagnosticLedgerErrorCode.COMMIT_UNCERTAIN)
                    _raise(DiagnosticLedgerErrorCode.WRITE_FAILED)
                return dict(row)

    def inspect(self, limit: int) -> dict[str, object]:
        _require_integer(limit, 1, 256)
        with self._operation():
            with self._locked_descriptor(self._diagnostic_lock_fd, exclusive=False):
                self._revalidate_anchors()
                metadata = self._read_metadata_state()
                scanned = self._scan()
                rows, row_ahead = self._committed_view(metadata, scanned)
                recovery_required = row_ahead or self._temp_recovery_required()
                self._revalidate_anchors()
        return {
            "entries": rows[-limit:],
            "entry_count": metadata.committed_entry_count,
            "evidence_boundary": evidence_boundary(),
            "recovery_required": recovery_required,
            "schema_version": _INSPECTION_SCHEMA_VERSION,
            "state_scope": "durable",
            "total_canonical_bytes": metadata.committed_total_canonical_bytes,
        }

    def _close_descriptors(self) -> None:
        for name in (
            "_temp_fd",
            "_entries_fd",
            "_diagnostic_lock_fd",
            "_diagnostics_fd",
            "_auxiliary_fd",
            "_top_lock_fd",
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
        for name in ("_fingerprint_key", "_ledger_key"):
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

    def __enter__(self) -> "DiagnosticLedger":
        with self._operation():
            return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "DiagnosticLedger(<private>)"
