"""Fail-closed, one-use authorization boundary for external provider work."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Callable, TypeVar


APPROVAL_SCHEMA = "contextguard.external-approval/v1"
DIAGNOSTIC_SCHEMA = "contextguard.external-approval-diagnostic/v1"
STATE_SCHEMA = "contextguard.external-approval-state/v1"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}$")
_HOST = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,9})?$")
_SECRET_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "credential_value",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_TOP_KEYS = frozenset(
    {
        "credential",
        "destinations",
        "limits",
        "network_policy",
        "observer",
        "operation",
        "output",
        "provider",
        "retention",
        "runtime",
        "source_candidate",
    }
)
_MAX_APPROVAL_LIFETIME_SECONDS = 31_536_000
_MAX_UNIX_SECONDS = 4_102_444_800
_MAX_STATE_BYTES = 4 * 1024 * 1024
_MAX_STATE_ENTRIES = 65_536
_PROCESS_STATE_LOCK = threading.Lock()
_ENVELOPE_KEYS = frozenset(
    {
        "authentication_hmac_sha256",
        "expires_at",
        "issued_at",
        "nonce",
        "revocation_handle",
        "schema_version",
        "scope",
    }
)
T = TypeVar("T")


class ApprovalError(RuntimeError):
    """A public, value-free refusal from the approval boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _refuse(code: str) -> None:
    raise ApprovalError(code)


def _object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _refuse("malformed")
    if any(not isinstance(key, str) or key.lower() in _SECRET_KEYS for key in value):
        _refuse("malformed")
    return value


def _frozen_copy(value: T) -> T:
    try:
        return copy.deepcopy(value)
    except Exception:
        _refuse("malformed")


def _identity(value: object) -> str:
    if not isinstance(value, str) or _IDENTITY.fullmatch(value) is None:
        _refuse("malformed")
    return value


def _sha256(value: object) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _refuse("malformed")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        _refuse("malformed")
    return value


def _positive_int(value: object, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _refuse("malformed")
    if maximum is not None and value > maximum:
        _refuse("malformed")
    return value


def _validate_scope(value: object) -> dict[str, object]:
    scope = _object(value, _TOP_KEYS)

    candidate = _object(
        scope["source_candidate"],
        frozenset({"artifact_ids", "checksums_sha256", "commit_sha", "manifest_sha256"}),
    )
    _git_sha(candidate["commit_sha"])
    _sha256(candidate["manifest_sha256"])
    _sha256(candidate["checksums_sha256"])
    artifacts = candidate["artifact_ids"]
    if (
        type(artifacts) is not list
        or not artifacts
        or len(artifacts) > 16
        or len(set(artifacts)) != len(artifacts)
    ):
        _refuse("malformed")
    for artifact in artifacts:
        _identity(artifact)

    provider = _object(scope["provider"], frozenset({"model_id", "provider_id"}))
    _identity(provider["provider_id"])
    _identity(provider["model_id"])

    observer = _object(
        scope["observer"],
        frozenset({"observer_id", "phase", "receipt_schema", "surface_id"}),
    )
    _identity(observer["observer_id"])
    _identity(observer["surface_id"])
    _identity(observer["receipt_schema"])
    if observer["phase"] not in {"P2", "P3", "P4", "P5", "P6"}:
        _refuse("malformed")

    operation = _object(
        scope["operation"],
        frozenset({"receipt_schema", "surface_id", "version"}),
    )
    _identity(operation["receipt_schema"])
    _identity(operation["surface_id"])
    _identity(operation["version"])
    if operation["receipt_schema"] != observer["receipt_schema"]:
        _refuse("malformed")

    runtime = _object(
        scope["runtime"],
        frozenset(
            {
                "argv_sha256",
                "environment_sha256",
                "executable_sha256",
                "identity",
                "version",
            }
        ),
    )
    _identity(runtime["identity"])
    _identity(runtime["version"])
    _sha256(runtime["executable_sha256"])
    _sha256(runtime["argv_sha256"])
    _sha256(runtime["environment_sha256"])

    credential = _object(
        scope["credential"], frozenset({"consumer_id", "scope_allowlist"})
    )
    _identity(credential["consumer_id"])
    scopes = credential["scope_allowlist"]
    if (
        type(scopes) is not list
        or not scopes
        or len(scopes) > 32
        or len(set(scopes)) != len(scopes)
    ):
        _refuse("malformed")
    for item in scopes:
        _identity(item)

    destinations = scope["destinations"]
    if type(destinations) is not list or not destinations or len(destinations) > 16:
        _refuse("malformed")
    seen_destinations: set[tuple[str, str, int]] = set()
    for item in destinations:
        destination = _object(item, frozenset({"host", "port", "scheme"}))
        if destination["scheme"] != "https":
            _refuse("malformed")
        host = destination["host"]
        if not isinstance(host, str) or _HOST.fullmatch(host) is None:
            _refuse("malformed")
        port = _positive_int(destination["port"], maximum=65535)
        key = ("https", host.lower(), port)
        if key in seen_destinations:
            _refuse("malformed")
        seen_destinations.add(key)

    network_policy = _object(
        scope["network_policy"],
        frozenset({"proxies_allowed", "redirects_allowed"}),
    )
    if network_policy != {"proxies_allowed": False, "redirects_allowed": False}:
        _refuse("malformed")

    limits = _object(
        scope["limits"],
        frozenset({"call_cap", "currency", "spend_cap", "timeout_seconds"}),
    )
    _positive_int(limits["call_cap"], maximum=240)
    _positive_int(limits["timeout_seconds"], maximum=86_400)
    spend = limits["spend_cap"]
    if not isinstance(spend, str) or _DECIMAL.fullmatch(spend) is None:
        _refuse("malformed")
    try:
        parsed_spend = Decimal(spend)
    except InvalidOperation:
        _refuse("malformed")
    if not parsed_spend.is_finite() or parsed_spend <= 0:
        _refuse("malformed")
    currency = limits["currency"]
    if not isinstance(currency, str) or _CURRENCY.fullmatch(currency) is None:
        _refuse("malformed")

    output = _object(scope["output"], frozenset({"mode", "root"}))
    if output["mode"] != "owner_private":
        _refuse("malformed")
    root = output["root"]
    if (
        not isinstance(root, str)
        or not root.startswith("/")
        or "\x00" in root
        or "/../" in f"{root}/"
        or os.path.normpath(root) != root
        or len(root) > 4096
    ):
        _refuse("malformed")

    retention = _object(scope["retention"], frozenset({"seconds"}))
    _positive_int(retention["seconds"], maximum=31_536_000)
    return scope


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _refuse("malformed")


def _unsigned(approval: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in approval.items() if key != "authentication_hmac_sha256"}


def create_approval(
    *,
    scope: dict[str, object],
    issued_at: int,
    expires_at: int,
    nonce: str,
    revocation_handle: str,
    signing_key: bytes,
) -> dict[str, object]:
    """Create an authenticated envelope without embedding or retaining its key."""

    frozen_scope = _frozen_copy(scope)
    _validate_scope(frozen_scope)
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or issued_at < 0
        or expires_at > _MAX_UNIX_SECONDS
        or expires_at - issued_at > _MAX_APPROVAL_LIFETIME_SECONDS
    ):
        _refuse("malformed")
    _sha256(nonce)
    _sha256(revocation_handle)
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        _refuse("malformed")
    envelope: dict[str, object] = {
        "expires_at": expires_at,
        "issued_at": issued_at,
        "nonce": nonce,
        "revocation_handle": revocation_handle,
        "schema_version": APPROVAL_SCHEMA,
        "scope": frozen_scope,
    }
    envelope["authentication_hmac_sha256"] = hmac.new(
        signing_key,
        b"contextguard/external-approval/v1\0" + _canonical(envelope),
        hashlib.sha256,
    ).hexdigest()
    return envelope


def _validate_approval(
    approval: object, requested_scope: object, verification_key: bytes
) -> dict[str, object]:
    envelope = _object(_frozen_copy(approval), _ENVELOPE_KEYS)
    if envelope["schema_version"] != APPROVAL_SCHEMA:
        _refuse("malformed")
    scope = _validate_scope(envelope["scope"])
    requested = _validate_scope(_frozen_copy(requested_scope))
    if not hmac.compare_digest(_canonical(scope), _canonical(requested)):
        _refuse("scope-expanded")
    issued_at = envelope["issued_at"]
    expires_at = envelope["expires_at"]
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or issued_at < 0
        or expires_at > _MAX_UNIX_SECONDS
        or expires_at - issued_at > _MAX_APPROVAL_LIFETIME_SECONDS
    ):
        _refuse("malformed")
    _sha256(envelope["nonce"])
    _sha256(envelope["revocation_handle"])
    supplied = envelope["authentication_hmac_sha256"]
    if not isinstance(supplied, str) or _HASH.fullmatch(supplied) is None:
        _refuse("malformed")
    if not isinstance(verification_key, bytes) or len(verification_key) < 32:
        _refuse("unapproved")
    expected = hmac.new(
        verification_key,
        b"contextguard/external-approval/v1\0" + _canonical(_unsigned(envelope)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        _refuse("unapproved")
    return envelope


def _validate_time(envelope: dict[str, object], now: int) -> None:
    if now < envelope["issued_at"]:
        _refuse("not-yet-valid")
    if now >= envelope["expires_at"]:
        _refuse("expired")


def _private_state_root(state_root: Path) -> int:
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        _refuse("state-unavailable")
    try:
        descriptor = os.open(
            state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
    except OSError:
        _refuse("state-unavailable")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        try:
            os.close(descriptor)
        except OSError:
            pass
        _refuse("state-unavailable")
    return descriptor


def _state_hmac(state: dict[str, object], key: bytes) -> str:
    unsigned = {name: value for name, value in state.items() if name != "integrity_hmac_sha256"}
    return hmac.new(
        key,
        b"contextguard/external-approval-state/v1\0" + _canonical(unsigned),
        hashlib.sha256,
    ).hexdigest()


def _load_state(root_descriptor: int, key: bytes) -> dict[str, object]:
    try:
        descriptor = os.open(
            "registry.json",
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=root_descriptor,
        )
    except FileNotFoundError:
        value: dict[str, object] = {
            "consumed_nonce_sha256": [],
            "integrity_hmac_sha256": "",
            "revoked_handle_sha256": [],
            "schema_version": STATE_SCHEMA,
        }
        value["integrity_hmac_sha256"] = _state_hmac(value, key)
        return value
    except OSError:
        _refuse("state-unavailable")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_STATE_BYTES
        ):
            _refuse("state-unavailable")
        raw = os.read(descriptor, _MAX_STATE_BYTES + 1)
        if len(raw) != metadata.st_size:
            _refuse("state-unavailable")
    except OSError:
        _refuse("state-unavailable")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _refuse("state-unavailable")
    expected = {
        "consumed_nonce_sha256",
        "integrity_hmac_sha256",
        "revoked_handle_sha256",
        "schema_version",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema_version"] != STATE_SCHEMA:
        _refuse("state-unavailable")
    for field_name in ("consumed_nonce_sha256", "revoked_handle_sha256"):
        entries = value[field_name]
        if (
            type(entries) is not list
            or len(entries) > _MAX_STATE_ENTRIES
            or any(
                _HASH.fullmatch(item) is None
                for item in entries
                if isinstance(item, str)
            )
        ):
            _refuse("state-unavailable")
        if (
            any(not isinstance(item, str) for item in entries)
            or len(entries) != len(set(entries))
            or entries != sorted(entries)
        ):
            _refuse("state-unavailable")
    integrity = value["integrity_hmac_sha256"]
    if (
        not isinstance(integrity, str)
        or _HASH.fullmatch(integrity) is None
        or not hmac.compare_digest(integrity, _state_hmac(value, key))
    ):
        _refuse("state-unavailable")
    return value


def _write_state(root_descriptor: int, value: dict[str, object]) -> None:
    temporary = "registry.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_descriptor,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(
            temporary,
            "registry.json",
            src_dir_fd=root_descriptor,
            dst_dir_fd=root_descriptor,
        )
        os.fsync(root_descriptor)
    except OSError:
        try:
            os.unlink(temporary, dir_fd=root_descriptor)
        except OSError:
            pass
        _refuse("state-unavailable")


def _with_locked_state_unthreaded(
    state_root: Path, registry_key: bytes, update: Callable[[dict[str, object]], T]
) -> T:
    if not isinstance(registry_key, bytes) or len(registry_key) < 32:
        _refuse("state-unavailable")
    root_descriptor = _private_state_root(state_root)
    try:
        descriptor = os.open(
            "registry.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=root_descriptor,
        )
    except OSError:
        os.close(root_descriptor)
        _refuse("state-unavailable")
    try:
        lock_metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        os.close(root_descriptor)
        _refuse("state-unavailable")
    if (
        not stat.S_ISREG(lock_metadata.st_mode)
        or lock_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(lock_metadata.st_mode) != 0o600
        or lock_metadata.st_nlink != 1
    ):
        os.close(descriptor)
        os.close(root_descriptor)
        _refuse("state-unavailable")
    try:
        lock = os.fdopen(descriptor, "r+b")
    except OSError:
        os.close(descriptor)
        os.close(root_descriptor)
        _refuse("state-unavailable")
    try:
        with lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                state = _load_state(root_descriptor, registry_key)
                result = update(state)
                state["integrity_hmac_sha256"] = _state_hmac(state, registry_key)
                _write_state(root_descriptor, state)
                return result
            except ApprovalError:
                raise
            except OSError:
                _refuse("state-unavailable")
    finally:
        try:
            os.close(root_descriptor)
        except OSError:
            pass


def _with_locked_state(
    state_root: Path, registry_key: bytes, update: Callable[[dict[str, object]], T]
) -> T:
    # BSD flock locks are process-associated, so they do not serialize threads
    # in the same interpreter. Keep the process lock in addition to the durable
    # cross-process lock.
    with _PROCESS_STATE_LOCK:
        return _with_locked_state_unthreaded(state_root, registry_key, update)


def revoke(
    *,
    state_root: Path,
    revocation_handle: str,
    registry_key: bytes,
) -> None:
    """Revoke by opaque handle while persisting only its one-way digest."""

    _sha256(revocation_handle)
    handle_hash = hashlib.sha256(revocation_handle.encode("ascii")).hexdigest()

    def update(state: dict[str, object]) -> None:
        revoked = state["revoked_handle_sha256"]
        if handle_hash not in revoked:
            revoked.append(handle_hash)
            revoked.sort()

    _with_locked_state(state_root, registry_key, update)


def authorize_and_consume(
    *,
    approval: object,
    requested_scope: object,
    verification_key: bytes,
    registry_key: bytes,
    state_root: Path,
    materialize: Callable[[dict[str, object]], T],
) -> T:
    """Validate and atomically consume approval before invoking external work."""

    if not callable(materialize):
        _refuse("malformed")
    if (
        not isinstance(registry_key, bytes)
        or len(registry_key) < 32
        or not isinstance(verification_key, bytes)
        or hmac.compare_digest(registry_key, verification_key)
    ):
        _refuse("state-unavailable")
    envelope = _validate_approval(approval, requested_scope, verification_key)
    nonce_hash = hashlib.sha256(envelope["nonce"].encode("ascii")).hexdigest()
    handle_hash = hashlib.sha256(envelope["revocation_handle"].encode("ascii")).hexdigest()

    def consume(state: dict[str, object]) -> None:
        _validate_time(envelope, int(time.time()))
        if handle_hash in state["revoked_handle_sha256"]:
            _refuse("revoked")
        if nonce_hash in state["consumed_nonce_sha256"]:
            _refuse("replayed")
        state["consumed_nonce_sha256"].append(nonce_hash)
        state["consumed_nonce_sha256"].sort()

    _with_locked_state(state_root, registry_key, consume)
    return materialize(copy.deepcopy(envelope["scope"]))


def diagnostic(error: ApprovalError) -> dict[str, object]:
    """Return a bounded refusal without echoing attacker-controlled values."""

    allowed = {
        "expired",
        "malformed",
        "not-yet-valid",
        "replayed",
        "revoked",
        "scope-expanded",
        "state-unavailable",
        "unapproved",
    }
    reason = error.code if error.code in allowed else "unapproved"
    return {
        "approval_authorized": False,
        "reason": reason,
        "schema_version": DIAGNOSTIC_SCHEMA,
    }
