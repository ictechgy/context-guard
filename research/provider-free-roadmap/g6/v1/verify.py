#!/usr/bin/env python3
"""Captured-byte verifier for the immutable G6 prepared-unapproved packet."""
from __future__ import annotations

import hashlib
import json
import re
import socket
import subprocess
import sys
from typing import Mapping


G5_LOCK_SHA256 = "c579875e5724d88d37d79fffd69154af02dc35141f77ce459bdce47ed495b607"
G5_TREE_SHA256 = "96eba2492b7190489713091e1c6567e555804c66fafd2ffbbc06afe108b3aef0"
G5_PREREG = {
    "bytes": 12139,
    "path": "research/provider-free-roadmap/g5/v1/preregistration.json",
    "sha256": "b0f76c641ffaf058313b9bf59b85dcd9f1a62f1eedc5bca11f16c6d9199de467",
}
G5_SCHEDULE = {
    "bytes": 65964,
    "path": "research/provider-free-roadmap/g5/v1/schedule.json",
    "sha256": "326fc47df7871e39b2f9af2d888b8385ab91fe4347c6467f08dd4a6e386e7965",
}
G5_VERIFIER = {
    "bytes": 45010,
    "path": "research/provider-free-roadmap/g5/v1/verify.py",
    "sha256": "6b80f2f00e3136e8c190301b9ef5af1814f29f4fefaec3a325e1db780238287b",
}
G5_SCHEMA_SET = {
    "bytes": 41710,
    "sha256": "cedfcd74de67d5a4dc9478af27549cb2604460381189d7c2c708432042e884de",
}
PACKET_SCHEMA_SHA256 = "8d387adc693bb5dad6057a07a53014c0ae2d3cf6e84310a07c9712b37de932db"
SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs", "$ref", "$schema", "additionalProperties", "const", "enum",
    "items", "maxItems", "maximum", "minItems", "minLength", "minimum",
    "pattern", "properties", "required", "type", "uniqueItems",
}
MATERIALIZATION_KEYS = {
    "approval_receipt", "argv", "command_argv", "credential_reference",
    "destination", "destinations", "executable", "model_id", "output_root",
    "provider_id", "spend_cap",
}


class VerificationError(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise VerificationError(f"nonfinite JSON number: {value}")


def parse(raw: bytes, label: str, *, require_canonical: bool = False) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"object required: {label}")
    if require_canonical and raw != canonical(value):
        raise VerificationError(f"noncanonical {label}")
    return value


def map_identity(files: Mapping[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256(b"contextguard.g6-captured-map/v1\x00")
    total = 0
    for name, raw in sorted(files.items()):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        total += len(raw)
    return {"bytes": total, "sha256": digest.hexdigest()}


def recursive_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        found.update(value)
        for item in value.values():
            found.update(recursive_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(recursive_keys(item))
    return found


def reject_materialization(value: object) -> None:
    forbidden = recursive_keys(value) & MATERIALIZATION_KEYS
    if forbidden:
        raise VerificationError(f"materializable field: {sorted(forbidden)[0]}")
    serialized = canonical(value).lower()
    for forbidden_value in (
        b"https://", b"http://", b"api.anthropic.com", b"/private/tmp/",
        b'"provider": "anthropic"', b'"model": "sonnet"', b"command_argv",
    ):
        if forbidden_value in serialized:
            raise VerificationError("materializable value in G6 packet")


def json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unsupported"


def resolve_ref(root: dict, reference: str) -> dict:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise VerificationError("unsupported schema reference")
    value: object = root
    for part in reference[2:].split("/"):
        if not isinstance(value, dict) or part not in value:
            raise VerificationError("invalid schema reference")
        value = value[part]
    if not isinstance(value, dict):
        raise VerificationError("schema reference target must be an object")
    return value


def audit_schema(schema: object, location: str = "schema") -> None:
    if not isinstance(schema, dict):
        raise VerificationError(f"schema node must be an object: {location}")
    unsupported = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    if unsupported:
        raise VerificationError(f"unsupported schema keyword: {sorted(unsupported)[0]}")
    if schema.get("type") == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            schema.get("additionalProperties") is not False
            or not isinstance(properties, dict) or not isinstance(required, list)
            or len(required) != len(set(required)) or set(required) != set(properties)
        ):
            raise VerificationError(f"schema object is not recursively closed: {location}")
    for key in ("$defs", "properties"):
        children = schema.get(key, {})
        if isinstance(children, dict):
            for name, child in children.items():
                audit_schema(child, f"{location}.{key}.{name}")
    if isinstance(schema.get("items"), dict):
        audit_schema(schema["items"], f"{location}.items")


def validate_schema(value: object, schema: dict, root: dict, location: str) -> None:
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise VerificationError(f"schema reference has siblings: {location}")
        validate_schema(value, resolve_ref(root, schema["$ref"]), root, location)
        return
    expected = schema.get("type")
    if expected is not None:
        allowed = [expected] if isinstance(expected, str) else expected
        if not isinstance(allowed, list) or json_type(value) not in allowed:
            raise VerificationError(f"schema type mismatch: {location}")
    if "const" in schema and value != schema["const"]:
        raise VerificationError(f"schema const mismatch: {location}")
    if "enum" in schema and value not in schema["enum"]:
        raise VerificationError(f"schema enum mismatch: {location}")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        missing = [name for name in schema.get("required", []) if name not in value]
        unknown = sorted(set(value) - set(properties)) if schema.get("additionalProperties") is False else []
        if missing or unknown:
            raise VerificationError(f"schema object mismatch: {location}")
        for name, item in value.items():
            if name in properties:
                validate_schema(item, properties[name], root, f"{location}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or (
            "maxItems" in schema and len(value) > schema["maxItems"]
        ):
            raise VerificationError(f"schema array length mismatch: {location}")
        encoded = [canonical(item) for item in value]
        if schema.get("uniqueItems") is True and len(encoded) != len(set(encoded)):
            raise VerificationError(f"schema array duplicate: {location}")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], root, f"{location}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise VerificationError(f"schema string too short: {location}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise VerificationError(f"schema pattern mismatch: {location}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise VerificationError(f"schema minimum mismatch: {location}")
        if "maximum" in schema and value > schema["maximum"]:
            raise VerificationError(f"schema maximum mismatch: {location}")


def validate_upstream(
    packet: dict, *, g5_lock_bytes: bytes, g5_prereg_bytes: bytes,
    g5_schedule_bytes: bytes, g5_schema_bytes: Mapping[str, bytes],
    g5_verifier_bytes: bytes,
) -> None:
    if sha256(g5_lock_bytes) != G5_LOCK_SHA256:
        raise VerificationError("captured G5 freeze lock drift")
    lock = parse(g5_lock_bytes, "captured G5 freeze lock", require_canonical=True)
    if lock.get("tree_root_sha256") != G5_TREE_SHA256:
        raise VerificationError("captured G5 tree drift")
    if (
        {"bytes": len(g5_prereg_bytes), "path": G5_PREREG["path"], "sha256": sha256(g5_prereg_bytes)} != G5_PREREG
        or {"bytes": len(g5_schedule_bytes), "path": G5_SCHEDULE["path"], "sha256": sha256(g5_schedule_bytes)} != G5_SCHEDULE
        or {"bytes": len(g5_verifier_bytes), "path": G5_VERIFIER["path"], "sha256": sha256(g5_verifier_bytes)} != G5_VERIFIER
        or set(g5_schema_bytes) != {
            "authoritative-observation.schema.json", "preregistration.schema.json",
            "schedule.schema.json",
        }
        or map_identity(g5_schema_bytes) != G5_SCHEMA_SET
    ):
        raise VerificationError("captured G5 consumed-byte identity drift")
    inventory = {
        entry.get("path"): entry for entry in lock.get("inventory", [])
        if isinstance(entry, dict)
    }
    for expected in (G5_PREREG, G5_SCHEDULE, G5_VERIFIER):
        frozen = inventory.get(expected["path"])
        if not isinstance(frozen, dict) or any(
            frozen.get(key) != expected[key] for key in ("bytes", "path", "sha256")
        ):
            raise VerificationError("G5 lock does not bind consumed input")
    expected_contract = {
        "g5_freeze_lock_path": "research/provider-free-roadmap/g5/freeze-lock.json",
        "g5_freeze_lock_sha256": G5_LOCK_SHA256,
        "g5_tree_sha256": G5_TREE_SHA256,
        "g5_preregistration": G5_PREREG,
        "g5_schedule": G5_SCHEDULE,
        "g5_schema_set": G5_SCHEMA_SET,
        "g5_verifier": G5_VERIFIER,
    }
    if packet["upstream_contract"] != expected_contract:
        raise VerificationError("G6 packet upstream contract drift")


def validate_captured(
    *, packet_bytes: bytes, packet_schema_bytes: bytes, g5_lock_bytes: bytes,
    g5_prereg_bytes: bytes, g5_schedule_bytes: bytes,
    g5_schema_bytes: Mapping[str, bytes], g5_verifier_bytes: bytes,
) -> dict[str, object]:
    if sha256(packet_schema_bytes) != PACKET_SCHEMA_SHA256:
        raise VerificationError("captured G6 schema drift")
    packet = parse(packet_bytes, "captured G6 preparation packet", require_canonical=True)
    schema = parse(packet_schema_bytes, "captured G6 packet schema", require_canonical=True)
    audit_schema(schema, "G6 packet schema")
    validate_schema(packet, schema, schema, "G6 preparation packet")
    reject_materialization(packet)
    if not (
        packet["packet_status"] == "prepared_unapproved"
        and packet["execution_authorized"] is False
        and packet["authority_effect"] == "none"
        and packet["external_approval_required"] is True
        and packet["approval_evidence"] is None
        and packet["runner_present"] is False
        and packet["command_materializable"] is False
        and set(packet["authority_flags"].values()) == {False}
        and all(item == {"state": "blocking_unselected", "value": None} for item in packet["execution_selections"].values())
        and all(item == {"state": "blocking_unselected", "value": None} for item in packet["external_requirements"].values())
        and len(packet["future_approval_requirements"]) == 20
        and set(packet["future_approval_requirements"].values()) == {True}
        and packet["future_call_cap_requirement"] == {
            "finite_call_cap_required": True,
            "maximum_calls_upper_bound": 240,
        }
        and all(item == {"authorized": False, "state": "blocking_unselected", "value": None} for item in packet["optional_surfaces"].values())
        and packet["verification_interpretation"]["authorization_after_integrity_success"] is False
    ):
        raise VerificationError("G6 prepared-unapproved authority invariant drift")
    validate_upstream(
        packet, g5_lock_bytes=g5_lock_bytes, g5_prereg_bytes=g5_prereg_bytes,
        g5_schedule_bytes=g5_schedule_bytes, g5_schema_bytes=g5_schema_bytes,
        g5_verifier_bytes=g5_verifier_bytes,
    )
    return {
        "authorization": False,
        "authority_effect": "none",
        "integrity": "verified",
        "status": "prepared_unapproved",
    }


def validate_candidate(
    candidate_bytes: bytes, *, expected_packet_bytes: bytes, **inputs: object,
) -> None:
    candidate = parse(candidate_bytes, "candidate G6 packet", require_canonical=True)
    expected = parse(expected_packet_bytes, "captured G6 packet", require_canonical=True)
    if canonical(candidate) != canonical(expected):
        raise VerificationError("candidate differs from exact prepared-unapproved packet")
    validate_captured(packet_bytes=candidate_bytes, **inputs)


_ACTIVE_PROBE: dict[str, int] | None = None
_AUDIT_INSTALLED = False


def _audit(event: str, args: tuple[object, ...]) -> None:
    if _ACTIVE_PROBE is None:
        return
    if event == "socket.getaddrinfo":
        _ACTIVE_PROBE["dns_denials"] += 1
        raise PermissionError("G6 denied DNS")
    if event.startswith("socket."):
        _ACTIVE_PROBE["network_denials"] += 1
        raise PermissionError("G6 denied network")
    if event == "subprocess.Popen":
        _ACTIVE_PROBE["process_denials"] += 1
        raise PermissionError("G6 denied process")
    if event == "open" and len(args) > 1 and any(flag in str(args[1]) for flag in ("w", "a", "x", "+")):
        _ACTIVE_PROBE["write_denials"] += 1
        raise PermissionError("G6 denied write")


def audited_negative_probes() -> dict[str, int]:
    global _ACTIVE_PROBE, _AUDIT_INSTALLED
    if not _AUDIT_INSTALLED:
        sys.addaudithook(_audit)
        _AUDIT_INSTALLED = True
    counters = {"dns_denials": 0, "network_denials": 0, "process_denials": 0, "write_denials": 0}
    _ACTIVE_PROBE = counters
    operations = (
        lambda: socket.socket(),
        lambda: socket.getaddrinfo("203.0.113.1", 443, flags=socket.AI_NUMERICHOST),
        lambda: subprocess.run(["/g6-process-decoy"], check=False),
        lambda: open("/g6-write-decoy", "wb"),
    )
    try:
        for operation in operations:
            try:
                operation()
            except (PermissionError, OSError):
                continue
            raise VerificationError("G6 negative probe was not denied")
    finally:
        _ACTIVE_PROBE = None
    if set(counters.values()) != {1}:
        raise VerificationError("G6 negative probe counters drift")
    return counters


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable G6 verifier cannot approve or execute; use the pinned integrity profile",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
