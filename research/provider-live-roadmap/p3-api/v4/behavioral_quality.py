#!/usr/bin/env python3
"""Deterministic, provider-free behavioral quality evaluation for V4.

The frozen contract and its independently supplied digest are scorer-private.
Only aggregate criteria and the secondary historical-patch diagnostic leave the
scoring phase.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping


CONTRACT_SCHEMA = "contextguard.behavioral-quality-contract/v1"
EVIDENCE_SCHEMA = "contextguard.behavioral-quality-evidence/v1"
RESULT_SCHEMA = "contextguard.behavioral-quality-result/v1"
KINDS = frozenset({"hidden_check", "build", "typecheck", "test"})
HEX64 = re.compile(r"[0-9a-f]{64}")


class QualityError(ValueError):
    """The quality evidence cannot be trusted or evaluated."""


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise QualityError(f"invalid {label} fields")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QualityError(f"invalid {label}")
    return value


def _safe_path(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise QualityError("unsafe path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {"", ".", ".."} for part in path.parts):
        raise QualityError("unsafe path")
    return value


def _validate_contract(contract: object, expected_sha256: str) -> dict[str, Any]:
    value = _closed(
        contract,
        {"allowed_paths", "limits", "required_evidence", "schema_version", "task_id"},
        "contract",
    )
    if (
        type(expected_sha256) is not str
        or not HEX64.fullmatch(expected_sha256)
        or sha256(canonical(value)) != expected_sha256
    ):
        raise QualityError("contract identity mismatch")
    if value["schema_version"] != CONTRACT_SCHEMA or type(value["task_id"]) is not str or not value["task_id"]:
        raise QualityError("invalid contract identity")
    paths = value["allowed_paths"]
    if type(paths) is not list or not paths or len(paths) != len(set(paths)):
        raise QualityError("invalid allowed paths")
    for path in paths:
        _safe_path(path)
    limits = _closed(
        value["limits"],
        {"max_added_lines", "max_changed_paths", "max_corrections", "max_deleted_lines", "max_patch_bytes"},
        "limits",
    )
    for name, limit in limits.items():
        _nonnegative_int(limit, name)
    if limits["max_changed_paths"] < 1 or limits["max_patch_bytes"] < 1:
        raise QualityError("invalid limits")
    required = value["required_evidence"]
    if type(required) is not list or not required:
        raise QualityError("invalid required evidence")
    identities: set[tuple[str, str]] = set()
    kinds: set[str] = set()
    for item in required:
        item = _closed(item, {"check_sha256", "id", "kind"}, "required evidence")
        identity = (item["kind"], item["id"])
        if (
            item["kind"] not in KINDS
            or type(item["id"]) is not str
            or not item["id"]
            or not HEX64.fullmatch(str(item["check_sha256"]))
            or identity in identities
        ):
            raise QualityError("invalid required evidence")
        identities.add(identity)
        kinds.add(item["kind"])
    if kinds != KINDS:
        raise QualityError("missing required evidence kind")
    return value


def evaluate(
    contract: Mapping[str, object],
    evidence: Mapping[str, object],
    *,
    expected_contract_sha256: str,
    expected_evidence_sha256: str,
) -> dict[str, object]:
    """Evaluate authenticated private evidence and return a public aggregate."""

    frozen = _validate_contract(contract, expected_contract_sha256)
    observed = _closed(
        evidence,
        {
            "changed_paths", "correction_count", "correction_receipts", "observations",
            "patch", "schema_version", "task_id",
        },
        "evidence",
    )
    if (
        type(expected_evidence_sha256) is not str
        or not HEX64.fullmatch(expected_evidence_sha256)
        or sha256(canonical(observed)) != expected_evidence_sha256
    ):
        raise QualityError("evidence identity mismatch")
    if observed["schema_version"] != EVIDENCE_SCHEMA or observed["task_id"] != frozen["task_id"]:
        raise QualityError("evidence identity mismatch")

    expected = {
        (item["kind"], item["id"]): item["check_sha256"]
        for item in frozen["required_evidence"]
    }
    observations = observed["observations"]
    if type(observations) is not list:
        raise QualityError("evidence set mismatch")
    actual: dict[tuple[str, str], dict[str, Any]] = {}
    for item in observations:
        item = _closed(item, {"check_sha256", "id", "kind", "payload"}, "observation")
        identity = (item["kind"], item["id"])
        if identity in actual:
            raise QualityError("evidence set mismatch")
        payload = _closed(item["payload"], {"exit_code", "passed", "test_count"}, "payload")
        _nonnegative_int(payload["exit_code"], "exit code")
        _nonnegative_int(payload["test_count"], "test count")
        if type(payload["passed"]) is not bool:
            raise QualityError("invalid pass result")
        if payload["passed"] != (payload["exit_code"] == 0):
            raise QualityError("forged checker result")
        if not HEX64.fullmatch(str(item["check_sha256"])):
            raise QualityError("invalid check identity")
        actual[identity] = {"check_sha256": item["check_sha256"], "payload": payload}
    if set(actual) != set(expected):
        raise QualityError("evidence set mismatch")
    if any(actual[key]["check_sha256"] != expected[key] for key in expected):
        raise QualityError("frozen check identity mismatch")

    changed_paths = observed["changed_paths"]
    if type(changed_paths) is not list or len(changed_paths) != len(set(changed_paths)):
        raise QualityError("invalid changed paths")
    for path in changed_paths:
        _safe_path(path)
    allowed_paths_ok = set(changed_paths).issubset(frozen["allowed_paths"]) and bool(changed_paths)

    correction_count = _nonnegative_int(observed["correction_count"], "correction count")
    receipts = observed["correction_receipts"]
    if type(receipts) is not list or len(receipts) != correction_count:
        raise QualityError("correction count mismatch")
    if len(receipts) != len(set(receipts)) or any(not HEX64.fullmatch(str(item)) for item in receipts):
        raise QualityError("invalid correction receipt")

    patch = _closed(
        observed["patch"],
        {"added_lines", "bytes", "deleted_lines", "historical_patch_sha256", "sha256"},
        "patch",
    )
    for field in ("added_lines", "bytes", "deleted_lines"):
        _nonnegative_int(patch[field], f"patch {field}")
    if patch["bytes"] < 1 or any(
        not HEX64.fullmatch(str(patch[field])) for field in ("historical_patch_sha256", "sha256")
    ):
        raise QualityError("invalid patch identity")

    limits = frozen["limits"]
    criteria = {
        "allowed_paths": allowed_paths_ok,
        "build": all(item["payload"]["passed"] for key, item in actual.items() if key[0] == "build"),
        "correction_burden": correction_count <= limits["max_corrections"],
        "hidden_checks": all(item["payload"]["passed"] for key, item in actual.items() if key[0] == "hidden_check"),
        "patch_locality": (
            len(changed_paths) <= limits["max_changed_paths"]
            and patch["bytes"] <= limits["max_patch_bytes"]
            and patch["added_lines"] <= limits["max_added_lines"]
            and patch["deleted_lines"] <= limits["max_deleted_lines"]
        ),
        "test": all(item["payload"]["passed"] for key, item in actual.items() if key[0] == "test"),
        "typecheck": all(item["payload"]["passed"] for key, item in actual.items() if key[0] == "typecheck"),
    }
    return {
        "contract_sha256": expected_contract_sha256,
        "criteria": criteria,
        "diagnostics": {"exact_historical_patch_match": patch["sha256"] == patch["historical_patch_sha256"]},
        "evidence_sha256": expected_evidence_sha256,
        "passed": all(criteria.values()),
        "primary_contract": "behavioral",
        "schema_version": RESULT_SCHEMA,
    }
