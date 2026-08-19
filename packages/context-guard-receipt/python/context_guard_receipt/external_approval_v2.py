"""Versioned external approval adapter for truthful manual evidence retention."""

from __future__ import annotations

import copy
import hashlib
import hmac
from pathlib import Path
from typing import Callable, TypeVar

try:
    _V1  # type: ignore[name-defined]
except NameError:
    from . import external_approval as _V1


APPROVAL_SCHEMA = "contextguard.external-approval/v2"
DIAGNOSTIC_SCHEMA = "contextguard.external-approval-diagnostic/v2"
ApprovalError = _V1.ApprovalError
T = TypeVar("T")
_RETENTION_KEYS = frozenset({"mode", "maximum_seconds"})
_MANUAL_RETENTION = {
    "mode": "manual_owner_cleanup",
    "maximum_seconds": None,
}


def _refuse(code: str) -> None:
    raise ApprovalError(code)


def _validate_scope(value: object) -> dict[str, object]:
    scope = _V1._object(_V1._frozen_copy(value), _V1._TOP_KEYS)
    retention = _V1._object(scope["retention"], _RETENTION_KEYS)
    if retention != _MANUAL_RETENTION:
        _refuse("malformed")
    projected = copy.deepcopy(scope)
    projected["retention"] = {"seconds": 1}
    _V1._validate_scope(projected)
    return scope


def _legacy_scope(scope: dict[str, object]) -> dict[str, object]:
    projected = copy.deepcopy(scope)
    projected["retention"] = {"seconds": 1}
    return projected


def create_approval(
    *,
    scope: dict[str, object],
    issued_at: int,
    expires_at: int,
    nonce: str,
    revocation_handle: str,
    signing_key: bytes,
) -> dict[str, object]:
    frozen_scope = _validate_scope(scope)
    legacy = _V1.create_approval(
        scope=_legacy_scope(frozen_scope),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        revocation_handle=revocation_handle,
        signing_key=signing_key,
    )
    envelope = copy.deepcopy(legacy)
    envelope["schema_version"] = APPROVAL_SCHEMA
    envelope["scope"] = frozen_scope
    envelope["authentication_hmac_sha256"] = hmac.new(
        signing_key,
        b"contextguard/external-approval/v2\0"
        + _V1._canonical(_V1._unsigned(envelope)),
        hashlib.sha256,
    ).hexdigest()
    return envelope


def _validate_approval(
    approval: object, requested_scope: object, verification_key: bytes
) -> dict[str, object]:
    envelope = _V1._object(
        _V1._frozen_copy(approval), _V1._ENVELOPE_KEYS
    )
    if envelope["schema_version"] != APPROVAL_SCHEMA:
        _refuse("malformed")
    scope = _validate_scope(envelope["scope"])
    requested = _validate_scope(requested_scope)
    if not hmac.compare_digest(
        _V1._canonical(scope), _V1._canonical(requested)
    ):
        _refuse("scope-expanded")
    if not isinstance(verification_key, bytes) or len(verification_key) < 32:
        _refuse("unapproved")
    supplied = envelope["authentication_hmac_sha256"]
    if not isinstance(supplied, str) or _V1._HASH.fullmatch(supplied) is None:
        _refuse("malformed")
    expected = hmac.new(
        verification_key,
        b"contextguard/external-approval/v2\0"
        + _V1._canonical(_V1._unsigned(envelope)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        _refuse("unapproved")

    legacy = copy.deepcopy(envelope)
    legacy["schema_version"] = _V1.APPROVAL_SCHEMA
    legacy["scope"] = _legacy_scope(scope)
    legacy["authentication_hmac_sha256"] = hmac.new(
        verification_key,
        b"contextguard/external-approval/v1\0"
        + _V1._canonical(_V1._unsigned(legacy)),
        hashlib.sha256,
    ).hexdigest()
    _V1._validate_approval(
        legacy, _legacy_scope(requested), verification_key
    )
    return envelope


def authorize_and_consume(
    *,
    approval: object,
    requested_scope: object,
    verification_key: bytes,
    registry_key: bytes,
    state_root: Path,
    materialize: Callable[[dict[str, object]], T],
) -> T:
    if not callable(materialize):
        _refuse("malformed")
    if (
        not isinstance(registry_key, bytes)
        or len(registry_key) < 32
        or not isinstance(verification_key, bytes)
        or hmac.compare_digest(registry_key, verification_key)
    ):
        _refuse("state-unavailable")
    envelope = _validate_approval(
        approval, requested_scope, verification_key
    )
    nonce_hash = hashlib.sha256(
        envelope["nonce"].encode("ascii")
    ).hexdigest()
    handle_hash = hashlib.sha256(
        envelope["revocation_handle"].encode("ascii")
    ).hexdigest()

    def consume(state: dict[str, object]) -> None:
        _V1._validate_time(envelope, int(_V1.time.time()))
        if handle_hash in state["revoked_handle_sha256"]:
            _refuse("revoked")
        if nonce_hash in state["consumed_nonce_sha256"]:
            _refuse("replayed")
        state["consumed_nonce_sha256"].append(nonce_hash)
        state["consumed_nonce_sha256"].sort()

    _V1._with_locked_state(state_root, registry_key, consume)
    return materialize(copy.deepcopy(envelope["scope"]))


def revoke(
    *, state_root: Path, revocation_handle: str, registry_key: bytes
) -> None:
    _V1.revoke(
        state_root=state_root,
        revocation_handle=revocation_handle,
        registry_key=registry_key,
    )


def diagnostic(error: ApprovalError) -> dict[str, object]:
    result = _V1.diagnostic(error)
    result["schema_version"] = DIAGNOSTIC_SCHEMA
    return result
