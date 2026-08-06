"""Transactional import of completed canonical merged sanitized UTF-8 spools."""

from __future__ import annotations

import codecs
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import stat
import time
import unicodedata
from contextlib import contextmanager
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
from .identity import IdentityError, snapshot_repository
from .reference_expiry import ReferenceExpiryError, ReferenceExpiryRegistry
from .store import (
    ArtifactType,
    CapabilityStore,
    StoreError,
    StoreErrorCode,
    StoreLimits,
)


__all__ = [
    "MERGED_CAPTURE_SUBJECT_DOMAIN",
    "MergedCaptureError",
    "MergedCaptureErrorCode",
    "PROTOCOL_MAX_SPOOL_BYTES",
    "inspect",
    "is_registered_reference",
    "merged_capture_subject_sha256",
    "prepare_broker",
    "publish",
    "recover",
    "valid_merged_artifact",
]


MERGED_CAPTURE_SUBJECT_DOMAIN: Final = (
    "contextguard-receipt/command-capture-merged-sanitized/v1"
)
PROTOCOL_TTL_MS: Final = 604_800_000
PROTOCOL_MAX_SPOOL_BYTES: Final = 10_000_000
_MERGED_STORE_LIMITS: Final = StoreLimits(
    max_single_artifact_bytes=PROTOCOL_MAX_SPOOL_BYTES
)

_MAX_UNIX_MS: Final = 4_102_444_800_000
_MAX_PENDING_TRANSACTIONS: Final = 32
_MAX_PENDING_ARTIFACT_BYTES: Final = 32 * 1024 * 1024
_MAX_TRANSACTION_RECORDS: Final = 1024
_MAX_RECORD_BYTES: Final = 4096
_JOURNAL_NAME: Final = "import-transactions-v1"
_LOCK_NAME: Final = "lock"
_RECORDS_NAME: Final = "records"
_TEMP_NAME: Final = "tmp"
_REGISTRY_KEY_NAME: Final = "key"
_SCHEMA_VERSION: Final = "contextguard-receipt-merged-capture-import/v1"
_RECORD_SCHEMA_VERSION: Final = (
    "contextguard-receipt-merged-capture-transaction/v1"
)
_INSPECTION_SCHEMA_VERSION: Final = (
    "contextguard-receipt-merged-capture-inspection/v1"
)
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
_TEMP_PATTERN = re.compile(r"\.record\.tmp-[0-9a-f]{32}\Z")
_PENDING_STATES: Final = frozenset({"prepared", "issued", "validated"})
_STATES: Final = frozenset((*_PENDING_STATES, "registered", "abandoned"))
_STATE_ORDER: Final = {
    "prepared": 0,
    "issued": 1,
    "validated": 2,
    "registered": 3,
}
_RECORD_LIMITS: Final = JSONLimits(
    max_document_bytes=_MAX_RECORD_BYTES,
    max_depth=5,
    max_total_values=64,
    max_object_members=16,
    max_string_bytes=128,
)
_RECORD_KEYS: Final = frozenset(
    {
        "byte_length",
        "evidence_boundary",
        "expires_at_unix_ms",
        "integrity_hmac_sha256",
        "issued_at_unix_ms",
        "schema_version",
        "state",
        "transaction_id",
        "updated_at_unix_ms",
    }
)


class MergedCaptureErrorCode(str, Enum):
    INVALID_ARGUMENT = "invalid_argument"
    DEADLINE_OVERFLOW = "deadline_overflow"
    UNSAFE_SPOOL = "unsafe_spool"
    SPOOL_TOO_LARGE = "spool_too_large"
    NONCANONICAL_SPOOL = "noncanonical_spool"
    TRANSACTION_NOT_FOUND = "transaction_not_found"
    TRANSACTION_ABANDONED = "transaction_abandoned"
    TRANSACTION_CONFLICT = "transaction_conflict"
    TRANSACTION_QUOTA_EXCEEDED = "transaction_quota_exceeded"
    PENDING_QUOTA_EXCEEDED = "pending_quota_exceeded"
    PENDING_BYTES_QUOTA_EXCEEDED = "pending_bytes_quota_exceeded"
    ARTIFACT_MISSING = "artifact_missing"
    ARTIFACT_INVALID = "artifact_invalid"
    REFERENCE_INACCESSIBLE = "reference_inaccessible"
    STATE_CORRUPT = "state_corrupt"
    STATE_UNAVAILABLE = "state_unavailable"
    COMMIT_UNCERTAIN = "commit_uncertain"


class MergedCaptureError(ValueError):
    """Stable non-reflective merged-capture failure."""

    __slots__ = ("code",)

    def __init__(self, code: MergedCaptureErrorCode) -> None:
        self.code = code
        super().__init__(f"merged capture import rejected: {code.value}")


def _raise(code: MergedCaptureErrorCode) -> None:
    raise MergedCaptureError(code) from None


def _transaction_id(value: object) -> str:
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
    return value


def _absolute_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\0" in value
        or not os.path.isabs(value)
        or os.path.normpath(value) != value
        or "//" in value
    ):
        _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
    return value


def _deadline(observed_at: int) -> int:
    if type(observed_at) is not int or observed_at < 0:
        _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
    if observed_at > _MAX_UNIX_MS - PROTOCOL_TTL_MS:
        _raise(MergedCaptureErrorCode.DEADLINE_OVERFLOW)
    return observed_at + PROTOCOL_TTL_MS


def _spool_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    if not no_follow or not close_on_exec:
        _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
    return (
        os.O_RDONLY
        | no_follow
        | close_on_exec
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )


def _safe_spool_status(status: os.stat_result) -> bool:
    return bool(
        stat.S_ISREG(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o600
        and status.st_nlink == 1
    )


def _fingerprint(status: os.stat_result) -> tuple[int, ...]:
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


def _validate_text_chunk(text: str, *, first: bool) -> bool:
    for index, character in enumerate(text):
        if first and index == 0 and character == "\ufeff":
            return False
        if character in {"\r", "\n", "\t"}:
            continue
        if unicodedata.category(character) in {"Cc", "Cs"}:
            return False
    return True


def _inspect_spool(path: str) -> tuple[int, int, str]:
    descriptor = -1
    try:
        descriptor = os.open(path, _spool_flags())
        before = os.fstat(descriptor)
        if not _safe_spool_status(before):
            _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
        if before.st_size > PROTOCOL_MAX_SPOOL_BYTES:
            _raise(MergedCaptureErrorCode.SPOOL_TOO_LARGE)
        digest = hashlib.sha256()
        digest.update(MERGED_CAPTURE_SUBJECT_DOMAIN.encode("ascii"))
        digest.update(b"\0")
        digest.update(before.st_size.to_bytes(8, "big"))
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        total = 0
        first = True
        while True:
            raw = os.read(descriptor, min(64 * 1024, before.st_size + 1 - total))
            if not raw:
                break
            total += len(raw)
            if total > before.st_size or total > PROTOCOL_MAX_SPOOL_BYTES:
                _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
            digest.update(raw)
            try:
                text = decoder.decode(raw, final=False)
            except UnicodeDecodeError:
                _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
            if not _validate_text_chunk(text, first=first):
                _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
            if text:
                first = False
        try:
            tail = decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
        if not _validate_text_chunk(tail, first=first):
            _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
        after = os.fstat(descriptor)
    except MergedCaptureError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
    if total != before.st_size or _fingerprint(before) != _fingerprint(after):
        os.close(descriptor)
        _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
    return descriptor, total, digest.hexdigest()


def _anonymous_capture_identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
    )


def _safe_anonymous_capture(status: os.stat_result) -> bool:
    return bool(
        stat.S_ISREG(status.st_mode)
        and status.st_uid == os.geteuid()
        and stat.S_IMODE(status.st_mode) == 0o600
        and status.st_nlink == 0
    )


def _inspect_anonymous_capture(
    descriptor: int, expected_identity: tuple[int, ...]
) -> tuple[int, str]:
    """Inspect immutable descriptor identity and canonical bytes with pread."""

    try:
        before = os.fstat(descriptor)
        if (
            not _safe_anonymous_capture(before)
            or _anonymous_capture_identity(before) != expected_identity
        ):
            _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
        if before.st_size > PROTOCOL_MAX_SPOOL_BYTES:
            _raise(MergedCaptureErrorCode.SPOOL_TOO_LARGE)
        digest = hashlib.sha256()
        digest.update(MERGED_CAPTURE_SUBJECT_DOMAIN.encode("ascii"))
        digest.update(b"\0")
        digest.update(before.st_size.to_bytes(8, "big"))
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        offset = 0
        first = True
        while offset < before.st_size:
            raw = os.pread(
                descriptor, min(64 * 1024, before.st_size - offset), offset
            )
            if not raw:
                _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
            offset += len(raw)
            digest.update(raw)
            try:
                text = decoder.decode(raw, final=False)
            except UnicodeDecodeError:
                _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
            if not _validate_text_chunk(text, first=first):
                _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
            if text:
                first = False
        try:
            tail = decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
        if not _validate_text_chunk(tail, first=first):
            _raise(MergedCaptureErrorCode.NONCANONICAL_SPOOL)
        after = os.fstat(descriptor)
    except MergedCaptureError:
        raise
    except (AttributeError, OSError):
        _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
    if (
        after.st_size != before.st_size
        or _anonymous_capture_identity(after) != expected_identity
    ):
        _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
    return before.st_size, digest.hexdigest()


def _valid_merged_payload(payload: object) -> bool:
    if type(payload) is not bytes or len(payload) > PROTOCOL_MAX_SPOOL_BYTES:
        return False
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    first = True
    try:
        for offset in range(0, len(payload), 64 * 1024):
            text = decoder.decode(payload[offset : offset + 64 * 1024], final=False)
            if not _validate_text_chunk(text, first=first):
                return False
            if text:
                first = False
        tail = decoder.decode(b"", final=True)
    except UnicodeDecodeError:
        return False
    return _validate_text_chunk(tail, first=first)


def merged_capture_subject_sha256(payload: bytes) -> str:
    """Hash one size-bounded merged spool with the frozen subject framing."""

    if type(payload) is not bytes or len(payload) > PROTOCOL_MAX_SPOOL_BYTES:
        _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
    digest = hashlib.sha256()
    digest.update(MERGED_CAPTURE_SUBJECT_DOMAIN.encode("ascii"))
    digest.update(b"\0")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


def valid_merged_artifact(stored: object) -> bool:
    """Validate a sealed merged artifact without accepting legacy CGRF bytes."""

    try:
        payload = stored.payload
        return bool(
            stored.artifact_type is ArtifactType.COMMAND_CAPTURE_BYTES
            and type(payload) is bytes
            and stored.byte_length == len(payload)
            and _valid_merged_payload(payload)
            and hmac.compare_digest(
                stored.subject_identity_sha256,
                merged_capture_subject_sha256(payload),
            )
        )
    except (AttributeError, MergedCaptureError, TypeError):
        return False


def _record_mac(key: bytes, record: dict[str, object]) -> bytes:
    unsigned = dict(record)
    unsigned.pop("integrity_hmac_sha256", None)
    record["integrity_hmac_sha256"] = hmac.new(
        key,
        b"contextguard-receipt/merged-capture-transaction-mac/v1\0"
        + canonical_json_bytes(unsigned, _RECORD_LIMITS),
        hashlib.sha256,
    ).hexdigest()
    return canonical_json_bytes(record, _RECORD_LIMITS)


def _validated_record(key: bytes, raw: bytes, expected_id: str) -> dict[str, object]:
    try:
        value = parse_canonical_json_bytes(raw, _RECORD_LIMITS)
    except CanonicalJSONError:
        _raise(MergedCaptureErrorCode.STATE_CORRUPT)
    if type(value) is not dict or frozenset(value) != _RECORD_KEYS:
        _raise(MergedCaptureErrorCode.STATE_CORRUPT)
    supplied = value.get("integrity_hmac_sha256")
    unsigned = dict(value)
    unsigned.pop("integrity_hmac_sha256", None)
    if type(supplied) is not str or _HEX_256.fullmatch(supplied) is None:
        _raise(MergedCaptureErrorCode.STATE_CORRUPT)
    expected = hmac.new(
        key,
        b"contextguard-receipt/merged-capture-transaction-mac/v1\0"
        + canonical_json_bytes(unsigned, _RECORD_LIMITS),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        _raise(MergedCaptureErrorCode.STATE_CORRUPT)
    byte_length = value.get("byte_length")
    expires = value.get("expires_at_unix_ms")
    issued = value.get("issued_at_unix_ms")
    updated = value.get("updated_at_unix_ms")
    if (
        value.get("schema_version") != _RECORD_SCHEMA_VERSION
        or value.get("evidence_boundary") != evidence_boundary()
        or value.get("transaction_id") != expected_id
        or value.get("state") not in _STATES
        or type(byte_length) is not int
        or byte_length < 0
        or byte_length > PROTOCOL_MAX_SPOOL_BYTES
        or type(expires) is not int
        or expires < 0
        or expires > _MAX_UNIX_MS
        or type(issued) is not int
        or issued < 0
        or issued > _MAX_UNIX_MS
        or type(updated) is not int
        or updated < issued
        or updated > _MAX_UNIX_MS
    ):
        _raise(MergedCaptureErrorCode.STATE_CORRUPT)
    return value


@contextmanager
def _locked(descriptor: int) -> Iterator[None]:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except OSError:
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass


class _Journal:
    def __init__(self, *, state_dir: str, create: bool) -> None:
        self._descriptors: list[int] = []
        try:
            state_fd = _filesystem._open_absolute_state_directory(
                state_dir, create=False
            )
            self._descriptors.append(state_fd)
            top_lock_fd = _filesystem._open_private_file(state_fd, "lock")
            self._descriptors.append(top_lock_fd)
            with _locked(top_lock_fd):
                auxiliary_fd = _filesystem._open_directory_at(
                    state_fd, "auxiliary-v1"
                )
                self._descriptors.append(auxiliary_fd)
                registry_fd = _filesystem._open_directory_at(
                    auxiliary_fd, "reference-expiry-v1"
                )
                self._descriptors.append(registry_fd)
                key = _filesystem._read_named_file(
                    registry_fd, _REGISTRY_KEY_NAME, 33
                )
                if len(key) != 32:
                    _raise(MergedCaptureErrorCode.STATE_CORRUPT)
                self._key = key
                names = set(_filesystem._bounded_names(registry_fd, 5))
                if _JOURNAL_NAME not in names:
                    if not create:
                        _raise(MergedCaptureErrorCode.TRANSACTION_NOT_FOUND)
                    self._create(registry_fd)
                journal_fd = _filesystem._open_directory_at(
                    registry_fd, _JOURNAL_NAME
                )
                self._descriptors.append(journal_fd)
                if set(_filesystem._bounded_names(journal_fd, 3)) != {
                    _LOCK_NAME,
                    _RECORDS_NAME,
                    _TEMP_NAME,
                }:
                    _raise(MergedCaptureErrorCode.STATE_CORRUPT)
                self._journal_fd = journal_fd
                self._lock_fd = _filesystem._open_private_file(
                    journal_fd, _LOCK_NAME
                )
                self._descriptors.append(self._lock_fd)
                self._records_fd = _filesystem._open_directory_at(
                    journal_fd, _RECORDS_NAME
                )
                self._descriptors.append(self._records_fd)
                self._temp_fd = _filesystem._open_directory_at(
                    journal_fd, _TEMP_NAME
                )
                self._descriptors.append(self._temp_fd)
        except MergedCaptureError:
            self.close()
            raise
        except StoreError as error:
            self.close()
            if error.code is StoreErrorCode.RECOVERY_REQUIRED:
                _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
        except OSError:
            self.close()
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)

    @staticmethod
    def _create(registry_fd: int) -> None:
        try:
            os.mkdir(_JOURNAL_NAME, 0o700, dir_fd=registry_fd)
        except FileExistsError:
            return
        journal_fd = -1
        try:
            journal_fd = os.open(
                _JOURNAL_NAME,
                _filesystem._directory_flags(),
                dir_fd=registry_fd,
            )
            os.fchmod(journal_fd, 0o700)
            _filesystem._write_new_file(journal_fd, _LOCK_NAME, b"")
            for name in (_RECORDS_NAME, _TEMP_NAME):
                os.mkdir(name, 0o700, dir_fd=journal_fd)
                child_fd = os.open(
                    name, _filesystem._directory_flags(), dir_fd=journal_fd
                )
                try:
                    os.fchmod(child_fd, 0o700)
                    os.fsync(child_fd)
                finally:
                    os.close(child_fd)
            os.fsync(journal_fd)
            os.fsync(registry_fd)
        except (OSError, StoreError):
            _raise(MergedCaptureErrorCode.COMMIT_UNCERTAIN)
        finally:
            if journal_fd >= 0:
                os.close(journal_fd)

    def close(self) -> None:
        for descriptor in reversed(getattr(self, "_descriptors", [])):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._descriptors = []

    def __enter__(self) -> "_Journal":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _clean_temps(self) -> None:
        names = _filesystem._bounded_names(
            self._temp_fd, _MAX_TRANSACTION_RECORDS + 1
        )
        if any(_TEMP_PATTERN.fullmatch(name) is None for name in names):
            _raise(MergedCaptureErrorCode.STATE_CORRUPT)
        for name in names:
            try:
                status = os.stat(
                    name, dir_fd=self._temp_fd, follow_symlinks=False
                )
                if not _filesystem._private_file(status):
                    _raise(MergedCaptureErrorCode.STATE_CORRUPT)
                os.unlink(name, dir_fd=self._temp_fd)
            except MergedCaptureError:
                raise
            except OSError:
                _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)

    def _scan(self) -> dict[str, dict[str, object]]:
        self._clean_temps()
        names = sorted(
            _filesystem._bounded_names(
                self._records_fd, _MAX_TRANSACTION_RECORDS + 1
            )
        )
        if len(names) > _MAX_TRANSACTION_RECORDS:
            _raise(MergedCaptureErrorCode.STATE_CORRUPT)
        records: dict[str, dict[str, object]] = {}
        pending_count = 0
        pending_bytes = 0
        for name in names:
            if _HEX_256.fullmatch(name) is None:
                _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            raw = _filesystem._read_named_file(
                self._records_fd, name, _MAX_RECORD_BYTES
            )
            record = _validated_record(self._key, raw, name)
            records[name] = record
            if record["state"] in _PENDING_STATES:
                pending_count += 1
                pending_bytes += int(record["byte_length"])
        if (
            pending_count > _MAX_PENDING_TRANSACTIONS
            or pending_bytes > _MAX_PENDING_ARTIFACT_BYTES
        ):
            _raise(MergedCaptureErrorCode.STATE_CORRUPT)
        return records

    def _write(self, transaction_id: str, record: dict[str, object]) -> None:
        temporary = ".record.tmp-" + secrets.token_bytes(16).hex()
        try:
            _filesystem._write_new_file(
                self._temp_fd, temporary, _record_mac(self._key, record)
            )
            os.rename(
                temporary,
                transaction_id,
                src_dir_fd=self._temp_fd,
                dst_dir_fd=self._records_fd,
            )
            os.fsync(self._temp_fd)
            os.fsync(self._records_fd)
        except MergedCaptureError:
            raise
        except (OSError, StoreError):
            _raise(MergedCaptureErrorCode.COMMIT_UNCERTAIN)

    def prepare(
        self,
        *,
        transaction_id: str,
        byte_length: int,
        issued_at_unix_ms: int,
        expires_at_unix_ms: int,
    ) -> dict[str, object]:
        with _locked(self._lock_fd):
            records = self._scan()
            current = records.get(transaction_id)
            if current is not None:
                if current["state"] == "abandoned":
                    _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
                if current["byte_length"] != byte_length:
                    _raise(MergedCaptureErrorCode.TRANSACTION_CONFLICT)
                return current
            if len(records) >= _MAX_TRANSACTION_RECORDS:
                _raise(MergedCaptureErrorCode.TRANSACTION_QUOTA_EXCEEDED)
            pending = [
                record
                for record in records.values()
                if record["state"] in _PENDING_STATES
            ]
            if len(pending) >= _MAX_PENDING_TRANSACTIONS:
                _raise(MergedCaptureErrorCode.PENDING_QUOTA_EXCEEDED)
            pending_bytes = sum(int(record["byte_length"]) for record in pending)
            if pending_bytes + byte_length > _MAX_PENDING_ARTIFACT_BYTES:
                _raise(MergedCaptureErrorCode.PENDING_BYTES_QUOTA_EXCEEDED)
            record = {
                "byte_length": byte_length,
                "evidence_boundary": evidence_boundary(),
                "expires_at_unix_ms": expires_at_unix_ms,
                "integrity_hmac_sha256": "",
                "issued_at_unix_ms": issued_at_unix_ms,
                "schema_version": _RECORD_SCHEMA_VERSION,
                "state": "prepared",
                "transaction_id": transaction_id,
                "updated_at_unix_ms": issued_at_unix_ms,
            }
            self._write(transaction_id, record)
            return record

    def read(self, transaction_id: str) -> dict[str, object]:
        with _locked(self._lock_fd):
            current = self._scan().get(transaction_id)
            if current is None:
                _raise(MergedCaptureErrorCode.TRANSACTION_NOT_FOUND)
            return current

    def advance(
        self, transaction_id: str, state: str, *, observed_at_unix_ms: int
    ) -> dict[str, object]:
        if state not in _STATES:
            _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
        with _locked(self._lock_fd):
            records = self._scan()
            current = records.get(transaction_id)
            if current is None:
                _raise(MergedCaptureErrorCode.TRANSACTION_NOT_FOUND)
            current_state = str(current["state"])
            if current_state == "abandoned":
                if state == "abandoned":
                    return current
                _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
            if state == "abandoned":
                if current_state != "prepared":
                    _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            elif _STATE_ORDER[state] <= _STATE_ORDER[current_state]:
                return current
            elif _STATE_ORDER[state] != _STATE_ORDER[current_state] + 1:
                _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            updated = dict(current)
            updated["integrity_hmac_sha256"] = ""
            updated["state"] = state
            updated["updated_at_unix_ms"] = max(
                observed_at_unix_ms, int(current["updated_at_unix_ms"])
            )
            self._write(transaction_id, updated)
            return updated

    def aggregate(self) -> dict[str, object]:
        with _locked(self._lock_fd):
            records = self._scan()
        counts = {
            "abandoned": 0,
            "pending": 0,
            "registered": 0,
        }
        pending_bytes = 0
        for record in records.values():
            state = str(record["state"])
            if state in _PENDING_STATES:
                counts["pending"] += 1
                pending_bytes += int(record["byte_length"])
            else:
                counts[state] += 1
        return {
            "abandoned_transaction_count": counts["abandoned"],
            "evidence_boundary": evidence_boundary(),
            "pending_artifact_bytes": pending_bytes,
            "pending_transaction_count": counts["pending"],
            "registered_transaction_count": counts["registered"],
            "schema_version": _INSPECTION_SCHEMA_VERSION,
            "status": "ok",
            "transaction_count": len(records),
        }

    def registered_record_for_handle(
        self, *, store: CapabilityStore, handle: str
    ) -> dict[str, object] | None:
        """Return the HMAC-authenticated registered transaction for one handle."""

        with _locked(self._lock_fd):
            records = self._scan()
        matched: dict[str, object] | None = None
        for transaction_id, record in records.items():
            if record["state"] != "registered" or not hmac.compare_digest(
                store.idempotent_handle(transaction_id), handle
            ):
                continue
            if matched is not None:
                _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            matched = record
        return matched


def _snapshot_root(repository_root: str) -> str:
    try:
        snapshot = snapshot_repository(repository_root)
        value = snapshot["instance"]["identity_sha256"]
    except (IdentityError, KeyError, TypeError):
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    return value


def _initialize_axes(state_dir: str, repository_root: str) -> str:
    try:
        try:
            opened_store = CapabilityStore.open(
                state_dir=state_dir,
                repository_root=repository_root,
                create=True,
                limits=_MERGED_STORE_LIMITS,
            )
        except StoreError as error:
            if error.code is not StoreErrorCode.WRITE_FAILED:
                raise
            opened_store = CapabilityStore.open(
                state_dir=state_dir,
                repository_root=repository_root,
                create=False,
            )
        with opened_store as store:
            namespace = store.namespace_id
        with ReferenceExpiryRegistry.open(
            state_dir=state_dir,
            repository_root=repository_root,
            store_namespace_id=namespace,
            create=True,
        ):
            pass
        return namespace
    except (StoreError, ReferenceExpiryError):
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)


def _existing_axes(state_dir: str, repository_root: str) -> str:
    try:
        with CapabilityStore.open(
            state_dir=state_dir, repository_root=repository_root, create=False
        ) as store:
            namespace = store.namespace_id
        with ReferenceExpiryRegistry.open(
            state_dir=state_dir,
            repository_root=repository_root,
            store_namespace_id=namespace,
            create=False,
        ):
            pass
        return namespace
    except (StoreError, ReferenceExpiryError):
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)


def _read_back(
    *, state_dir: str, repository_root: str, root_identity: str, transaction_id: str
) -> tuple[str, object]:
    try:
        with CapabilityStore.open(
            state_dir=state_dir, repository_root=repository_root, create=False
        ) as store:
            handle = store.idempotent_handle(transaction_id)
            stored = store.resolve(
                handle, expected_root_identity_sha256=root_identity
            )
    except StoreError as error:
        if error.code is StoreErrorCode.CAPABILITY_REJECTED:
            _raise(MergedCaptureErrorCode.ARTIFACT_MISSING)
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    if not valid_merged_artifact(stored):
        _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
    return handle, stored


def is_registered_reference(
    *,
    handle: str,
    repository_root: str,
    state_dir: str,
    observed_at_unix_ms: int,
) -> bool:
    """Require store, merged journal, and expiry registry agreement."""

    try:
        checked_root = _absolute_path(repository_root)
        checked_state = _absolute_path(state_dir)
        observed = observed_at_unix_ms
        if type(handle) is not str or type(observed) is not int or observed < 0:
            return False
        namespace = _existing_axes(checked_state, checked_root)
        root_identity = _snapshot_root(checked_root)
        with CapabilityStore.open(
            state_dir=checked_state,
            repository_root=checked_root,
            create=False,
        ) as store:
            if store.namespace_id != namespace:
                return False
            stored = store.resolve(
                handle,
                expected_root_identity_sha256=root_identity,
            )
            with _Journal(state_dir=checked_state, create=False) as journal:
                record = journal.registered_record_for_handle(
                    store=store, handle=handle
                )
            if (
                record is None
                or stored.byte_length != record["byte_length"]
                or not valid_merged_artifact(stored)
            ):
                return False
        with ReferenceExpiryRegistry.open(
            state_dir=checked_state,
            repository_root=checked_root,
            store_namespace_id=namespace,
            create=False,
        ) as registry:
            return registry.is_registered_and_accessible(
                handle, observed_at_unix_ms=observed
            )
    except (MergedCaptureError, ReferenceExpiryError, StoreError):
        return False


def _registered_result(
    *,
    transaction_id: str,
    handle: str,
    record: dict[str, object],
    registry_status: str,
) -> dict[str, object]:
    if registry_status != "active":
        _raise(MergedCaptureErrorCode.REFERENCE_INACCESSIBLE)
    return {
        "actionable": True,
        "evidence_boundary": evidence_boundary(),
        "expires_at_unix_ms": record["expires_at_unix_ms"],
        "operation": "import_merged_capture",
        "reason": None,
        "reference": handle,
        "schema_version": _SCHEMA_VERSION,
        "status": "registered" if registry_status == "active" else registry_status,
        "transaction_id": transaction_id,
    }


class PreparedMergedCaptureBroker:
    """One prevalidated, descriptor-retained merged-capture transaction."""

    def __init__(
        self,
        *,
        capture_fd: int,
        transaction_id: str,
        repository_root: str,
        state_dir: str,
        disclosure_days: int,
    ) -> None:
        self._closed = True
        self._capture_fd = -1
        self._store: CapabilityStore | None = None
        self._registry: ReferenceExpiryRegistry | None = None
        self._journal: _Journal | None = None
        checked_transaction = _transaction_id(transaction_id)
        checked_root = _absolute_path(repository_root)
        checked_state = _absolute_path(state_dir)
        if type(disclosure_days) is not int or disclosure_days != 7:
            _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
        if type(capture_fd) is not int or capture_fd < 0:
            _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
        try:
            owned_capture = os.dup(capture_fd)
            self._capture_fd = owned_capture
            os.set_inheritable(owned_capture, False)
            capture_status = os.fstat(owned_capture)
            if not _safe_anonymous_capture(capture_status) or capture_status.st_size != 0:
                _raise(MergedCaptureErrorCode.UNSAFE_SPOOL)
            self._capture_identity = _anonymous_capture_identity(capture_status)
            self._transaction_id = checked_transaction
            self._repository_root = checked_root
            self._state_dir = checked_state
            self._root_identity = _snapshot_root(checked_root)
            namespace = _initialize_axes(checked_state, checked_root)
            store = CapabilityStore.open(
                state_dir=checked_state,
                repository_root=checked_root,
                create=False,
            )
            self._store = store
            if store.namespace_id != namespace:
                _raise(MergedCaptureErrorCode.STATE_CORRUPT)
            registry = ReferenceExpiryRegistry.open(
                state_dir=checked_state,
                repository_root=checked_root,
                store_namespace_id=namespace,
                create=False,
            )
            self._registry = registry
            journal = _Journal(state_dir=checked_state, create=True)
            self._journal = journal
            store._retain_descriptor_boundary()
            registry._retain_descriptor_boundary()
            self._closed = False
        except MergedCaptureError:
            self.close()
            raise
        except (StoreError, ReferenceExpiryError, OSError):
            self.close()
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)

    def _require_open(
        self,
    ) -> tuple[CapabilityStore, ReferenceExpiryRegistry, _Journal]:
        if (
            self._closed
            or self._store is None
            or self._registry is None
            or self._journal is None
        ):
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
        return self._store, self._registry, self._journal

    def _register(
        self,
        *,
        handle: str,
        record: dict[str, object],
        observed: int,
    ) -> tuple[dict[str, object], dict[str, object]]:
        store, registry, journal = self._require_open()
        try:
            registered = registry._ensure_registered_prevalidated_merged_capture(
                handle,
                expires_at_unix_ms=int(record["expires_at_unix_ms"]),
                observed_at_unix_ms=observed,
                store=store,
                expected_root_identity_sha256=self._root_identity,
                artifact_validator=valid_merged_artifact,
            )
        except ReferenceExpiryError as error:
            if getattr(error.code, "value", None) == "commit_uncertain":
                _raise(MergedCaptureErrorCode.COMMIT_UNCERTAIN)
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
        if record["state"] == "validated":
            record = journal.advance(
                self._transaction_id,
                "registered",
                observed_at_unix_ms=observed,
            )
        accessible = registry.is_registered_and_accessible(
            handle, observed_at_unix_ms=observed
        )
        registry_status = str(registered["status"])
        if not accessible and registry_status == "active":
            registry_status = "expired"
        return record, {"status": registry_status}

    def _recover(self, *, observed: int) -> dict[str, object]:
        store, _registry, journal = self._require_open()
        record = journal.read(self._transaction_id)
        if record["state"] == "abandoned":
            _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
        handle = store.idempotent_handle(self._transaction_id)
        try:
            stored = store.resolve(
                handle,
                expected_root_identity_sha256=self._root_identity,
            )
        except StoreError as error:
            if (
                record["state"] == "prepared"
                and error.code is StoreErrorCode.CAPABILITY_REJECTED
            ):
                journal.advance(
                    self._transaction_id,
                    "abandoned",
                    observed_at_unix_ms=observed,
                )
                _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
            if error.code is StoreErrorCode.CAPABILITY_REJECTED:
                _raise(MergedCaptureErrorCode.ARTIFACT_MISSING)
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
        if not valid_merged_artifact(stored) or stored.byte_length != record["byte_length"]:
            _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
        if record["state"] == "prepared":
            record = journal.advance(
                self._transaction_id, "issued", observed_at_unix_ms=observed
            )
        if record["state"] == "issued":
            record = journal.advance(
                self._transaction_id, "validated", observed_at_unix_ms=observed
            )
        record, registered = self._register(
            handle=handle, record=record, observed=observed
        )
        return _registered_result(
            transaction_id=self._transaction_id,
            handle=handle,
            record=record,
            registry_status=str(registered["status"]),
        )

    def _commit_once(self, *, observed: int) -> dict[str, object]:
        store, _registry, journal = self._require_open()
        expires = _deadline(observed)
        byte_length, subject_identity = _inspect_anonymous_capture(
            self._capture_fd, self._capture_identity
        )
        record = journal.prepare(
            transaction_id=self._transaction_id,
            byte_length=byte_length,
            issued_at_unix_ms=observed,
            expires_at_unix_ms=expires,
        )
        try:
            issued = store.ensure_issued_file(
                source_fd=self._capture_fd,
                byte_length=byte_length,
                root_identity_sha256=self._root_identity,
                subject_identity_sha256=subject_identity,
                subject_identity_domain=MERGED_CAPTURE_SUBJECT_DOMAIN,
                artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                idempotency_key=self._transaction_id,
            )
        except StoreError as error:
            if error.code is StoreErrorCode.CAPABILITY_REJECTED:
                _raise(MergedCaptureErrorCode.TRANSACTION_CONFLICT)
            if error.code is StoreErrorCode.COMMIT_UNCERTAIN:
                _raise(MergedCaptureErrorCode.COMMIT_UNCERTAIN)
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
        record = journal.advance(
            self._transaction_id, "issued", observed_at_unix_ms=observed
        )
        stored = store.resolve(
            issued.handle,
            expected_root_identity_sha256=self._root_identity,
        )
        if (
            not valid_merged_artifact(stored)
            or stored.byte_length != byte_length
            or stored.subject_identity_sha256 != subject_identity
        ):
            _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
        record = journal.advance(
            self._transaction_id, "validated", observed_at_unix_ms=observed
        )
        record, registered = self._register(
            handle=issued.handle, record=record, observed=observed
        )
        return _registered_result(
            transaction_id=self._transaction_id,
            handle=issued.handle,
            record=record,
            registry_status=str(registered["status"]),
        )

    def commit(self) -> dict[str, object]:
        observed = time.time_ns() // 1_000_000
        try:
            return self._commit_once(observed=observed)
        except MergedCaptureError as error:
            if error.code not in {
                MergedCaptureErrorCode.COMMIT_UNCERTAIN,
                MergedCaptureErrorCode.STATE_CORRUPT,
            }:
                raise
            return self._recover(observed=observed)

    def close(self) -> None:
        journal = self._journal
        registry = self._registry
        store = self._store
        self._journal = None
        self._registry = None
        self._store = None
        for resource in (journal, registry, store):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        if self._capture_fd >= 0:
            try:
                os.close(self._capture_fd)
            except OSError:
                pass
            self._capture_fd = -1
        self._closed = True

    def __enter__(self) -> "PreparedMergedCaptureBroker":
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def prepare_broker(
    *,
    capture_fd: int,
    transaction_id: str,
    repository_root: str,
    state_dir: str,
    disclosure_days: int = 7,
) -> PreparedMergedCaptureBroker:
    """Prepare all executable/path boundaries before the caller emits READY."""

    return PreparedMergedCaptureBroker(
        capture_fd=capture_fd,
        transaction_id=transaction_id,
        repository_root=repository_root,
        state_dir=state_dir,
        disclosure_days=disclosure_days,
    )


def publish(
    *,
    spool_path: str,
    transaction_id: str,
    repository_root: str,
    state_dir: str,
    disclosure_days: int = 7,
) -> dict[str, object]:
    """Import one completed spool and disclose authority only after registration."""

    checked_transaction = _transaction_id(transaction_id)
    checked_spool = _absolute_path(spool_path)
    checked_root = _absolute_path(repository_root)
    checked_state = _absolute_path(state_dir)
    if type(disclosure_days) is not int or disclosure_days != 7:
        _raise(MergedCaptureErrorCode.INVALID_ARGUMENT)
    observed = time.time_ns() // 1_000_000
    expires = _deadline(observed)
    spool_fd, byte_length, subject_identity = _inspect_spool(checked_spool)
    try:
        root_identity = _snapshot_root(checked_root)
        namespace = _initialize_axes(checked_state, checked_root)

        with _Journal(state_dir=checked_state, create=True) as journal:
            record = journal.prepare(
                transaction_id=checked_transaction,
                byte_length=byte_length,
                issued_at_unix_ms=observed,
                expires_at_unix_ms=expires,
            )
        expires = int(record["expires_at_unix_ms"])
        try:
            with CapabilityStore.open(
                state_dir=checked_state,
                repository_root=checked_root,
                create=False,
            ) as store:
                if store.namespace_id != namespace:
                    _raise(MergedCaptureErrorCode.STATE_CORRUPT)
                try:
                    issued = store.ensure_issued_file(
                        source_fd=spool_fd,
                        byte_length=byte_length,
                        root_identity_sha256=root_identity,
                        subject_identity_sha256=subject_identity,
                        subject_identity_domain=MERGED_CAPTURE_SUBJECT_DOMAIN,
                        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                        idempotency_key=checked_transaction,
                    )
                except StoreError as error:
                    if error.code is not StoreErrorCode.COMMIT_UNCERTAIN:
                        raise
                    issued = store.ensure_issued_file(
                        source_fd=spool_fd,
                        byte_length=byte_length,
                        root_identity_sha256=root_identity,
                        subject_identity_sha256=subject_identity,
                        subject_identity_domain=MERGED_CAPTURE_SUBJECT_DOMAIN,
                        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                        idempotency_key=checked_transaction,
                    )
        except MergedCaptureError:
            raise
        except StoreError as error:
            if error.code is StoreErrorCode.CAPABILITY_REJECTED:
                _raise(MergedCaptureErrorCode.TRANSACTION_CONFLICT)
            if error.code is StoreErrorCode.COMMIT_UNCERTAIN:
                _raise(MergedCaptureErrorCode.COMMIT_UNCERTAIN)
            _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    finally:
        os.close(spool_fd)
    with _Journal(state_dir=checked_state, create=False) as journal:
        journal.advance(
            checked_transaction, "issued", observed_at_unix_ms=observed
        )

    handle, stored = _read_back(
        state_dir=checked_state,
        repository_root=checked_root,
        root_identity=root_identity,
        transaction_id=checked_transaction,
    )
    if (
        handle != issued.handle
        or stored.byte_length != byte_length
        or stored.subject_identity_sha256 != subject_identity
    ):
        _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
    with _Journal(state_dir=checked_state, create=False) as journal:
        journal.advance(
            checked_transaction, "validated", observed_at_unix_ms=observed
        )
    try:
        with ReferenceExpiryRegistry.open(
            state_dir=checked_state,
            repository_root=checked_root,
            store_namespace_id=namespace,
            create=False,
        ) as registry:
            registered = registry.ensure_registered(
                handle,
                expires_at_unix_ms=expires,
                observed_at_unix_ms=observed,
            )
    except ReferenceExpiryError:
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    with _Journal(state_dir=checked_state, create=False) as journal:
        record = journal.advance(
            checked_transaction, "registered", observed_at_unix_ms=observed
        )
    return _registered_result(
        transaction_id=checked_transaction,
        handle=handle,
        record=record,
        registry_status=str(registered["status"]),
    )


def recover(
    *, transaction_id: str, repository_root: str, state_dir: str
) -> dict[str, object]:
    """Recover exactly one explicitly named transaction without minting an artifact."""

    checked_transaction = _transaction_id(transaction_id)
    checked_root = _absolute_path(repository_root)
    checked_state = _absolute_path(state_dir)
    observed = time.time_ns() // 1_000_000
    namespace = _existing_axes(checked_state, checked_root)
    root_identity = _snapshot_root(checked_root)
    with _Journal(state_dir=checked_state, create=False) as journal:
        record = journal.read(checked_transaction)
    if record["state"] == "abandoned":
        _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
    try:
        handle, stored = _read_back(
            state_dir=checked_state,
            repository_root=checked_root,
            root_identity=root_identity,
            transaction_id=checked_transaction,
        )
    except MergedCaptureError as error:
        if (
            record["state"] == "prepared"
            and error.code is MergedCaptureErrorCode.ARTIFACT_MISSING
        ):
            with _Journal(state_dir=checked_state, create=False) as journal:
                journal.advance(
                    checked_transaction,
                    "abandoned",
                    observed_at_unix_ms=observed,
                )
            _raise(MergedCaptureErrorCode.TRANSACTION_ABANDONED)
        raise
    if stored.byte_length != record["byte_length"]:
        _raise(MergedCaptureErrorCode.ARTIFACT_INVALID)
    if record["state"] == "prepared":
        with _Journal(state_dir=checked_state, create=False) as journal:
            record = journal.advance(
                checked_transaction, "issued", observed_at_unix_ms=observed
            )
    if record["state"] == "issued":
        with _Journal(state_dir=checked_state, create=False) as journal:
            record = journal.advance(
                checked_transaction, "validated", observed_at_unix_ms=observed
            )
    try:
        with ReferenceExpiryRegistry.open(
            state_dir=checked_state,
            repository_root=checked_root,
            store_namespace_id=namespace,
            create=False,
        ) as registry:
            registered = registry.ensure_registered(
                handle,
                expires_at_unix_ms=int(record["expires_at_unix_ms"]),
                observed_at_unix_ms=observed,
            )
            accessible = registry.is_registered_and_accessible(
                handle, observed_at_unix_ms=observed
            )
            registry_status = str(registered["status"])
            if not accessible and registry_status == "active":
                registry_status = "expired"
    except ReferenceExpiryError:
        _raise(MergedCaptureErrorCode.STATE_UNAVAILABLE)
    if record["state"] == "validated":
        with _Journal(state_dir=checked_state, create=False) as journal:
            record = journal.advance(
                checked_transaction, "registered", observed_at_unix_ms=observed
            )
    return _registered_result(
        transaction_id=checked_transaction,
        handle=handle,
        record=record,
        registry_status=registry_status,
    )


def inspect(*, repository_root: str, state_dir: str) -> dict[str, object]:
    """Return aggregate-only journal state without transaction-derived values."""

    checked_root = _absolute_path(repository_root)
    checked_state = _absolute_path(state_dir)
    _existing_axes(checked_state, checked_root)
    with _Journal(state_dir=checked_state, create=False) as journal:
        return journal.aggregate()
