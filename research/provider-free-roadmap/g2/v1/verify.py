#!/usr/bin/env python3
"""Provider-free verifier library for the frozen G2 structural ablation.

The independently pinned caller supplies this module as captured bytes.  This
module then captures all public experiment bytes before execution, runs the
bound packer in an isolated Python child with a fail-closed audit policy, seals
all structural outputs, and only then captures scorer-only bytes.
"""

from __future__ import annotations

import base64
import ast
import collections
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import math
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable


G2_RELATIVE = Path("research/provider-free-roadmap/g2")
V1_RELATIVE = G2_RELATIVE / "v1"
LOCK_RELATIVE = G2_RELATIVE / "freeze-lock.json"
ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
PARTITIONS = ("train", "calibration", "evaluation")
CANONICAL_PACKER = Path("context-guard-kit/context_pack.py")
PLUGIN_PACKER = Path("plugins/context-guard/bin/context-guard-pack")
PACKER_SHA256 = "86f69c93d80ba6907e2131659f0e73dac0c24f45e09f304ea288c1558e08e08e"
LOCK_SCHEMA = "contextguard.g2-freeze-lock/v2"
TREE_DOMAIN = b"contextguard.g2-v1-tree/v2\x00"
ENTRY_DOMAIN = b"contextguard.g2-v1-entry/v2\x00"
SCORER_PREFIX = (V1_RELATIVE / "scorer-only").as_posix() + "/"
FORBIDDEN_PUBLIC_KEYS = {
    "adaptive_labels",
    "answer_signature",
    "expected_output",
    "graph_evidence",
    "hidden_oracle",
    "oracle",
    "required_paths",
    "required_symbols",
}
SCHEMA_INSTANCES = {
    "contract": "contract.json",
    "arms": "arms.json",
    "tasks": "tasks.json",
    "graph": "scorer-only/graph.json",
    "oracle": "scorer-only/oracle.json",
    "run": "run.json",
    "result": "result.example.json",
}
SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs", "$ref", "$schema", "additionalProperties", "const", "enum",
    "items", "maxItems", "maximum", "minItems", "minLength", "minimum",
    "pattern", "properties", "required", "type", "uniqueItems",
}
SEALED_FIELDS = (
    "adaptive_k_application",
    "adaptive_k_selected_evidence",
    "graph_application",
    "selected_paths",
    "symbol_memory",
)
PACKER_CHILD_TIMEOUT_SECONDS = 30.0


class VerificationError(Exception):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> object:
    raise ValueError(f"non-finite number: {value}")


def load_json_bytes(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise VerificationError(f"invalid JSON {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"invalid JSON {label}: root must be an object")
    return value


def load_json(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VerificationError(f"invalid JSON {path}: {exc}") from exc
    return load_json_bytes(raw, str(path))


def safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"unsafe {label}")
    path = PurePosixPath(value)
    if (
        path.is_absolute() or path.as_posix() != value or value == "."
        or ".." in path.parts or ":" in value or "\x00" in value
    ):
        raise VerificationError(f"unsafe {label}: {value}")
    return value


def validate_mode(mode: int, label: str, expected: str | None = None) -> str:
    bits = stat.S_IMODE(mode)
    if bits & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise VerificationError(f"special mode bits on {label}")
    if bits & 0o022:
        raise VerificationError(f"unsafe mode on {label}")
    portable = "0755" if bits & 0o111 else "0644"
    if bits not in {0o644, 0o755}:
        raise VerificationError(f"unsafe mode on {label}: {bits:04o}")
    if expected is not None and portable != expected:
        raise VerificationError(f"mode mismatch for {label}")
    return portable


def length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def inventory_tree_root(entries: list[dict[str, object]]) -> str:
    digest = hashlib.sha256(TREE_DOMAIN)
    for entry in entries:
        encoded = b"".join(
            length_prefix(str(entry[key]).encode("utf-8"))
            for key in ("path", "mode", "bytes", "sha256")
        )
        digest.update(length_prefix(ENTRY_DOMAIN + encoded))
    return digest.hexdigest()


def safe_read_file(
    root: Path,
    relative: str,
    *,
    expected: dict[str, object] | None = None,
) -> bytes:
    """Read one regular file through no-follow dirfds and stable fstat identity."""
    relative = safe_relative(relative, "captured path")
    parts = PurePosixPath(relative).parts
    root_fd: int | None = None
    current_fd: int | None = None
    file_fd: int | None = None
    try:
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        current_fd = root_fd
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise VerificationError(f"nonregular captured file: {relative}")
        if before.st_nlink != 1:
            raise VerificationError(f"hardlink or invalid link count: {relative}")
        expected_mode = str(expected["mode"]) if expected is not None else None
        mode = validate_mode(before.st_mode, relative, expected_mode)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(file_fd, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns)
        if identity(before) != identity(after) or len(raw) != after.st_size:
            raise VerificationError(f"captured file changed while reading: {relative}")
        if expected is not None:
            actual = {
                "bytes": len(raw), "mode": mode, "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            if actual != expected:
                raise VerificationError(f"frozen content drift: {relative}")
        return raw
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"missing frozen file: {relative}: {exc}") from exc
    finally:
        for descriptor in (file_fd, current_fd, root_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def enumerate_v1_metadata(root: Path) -> dict[str, tuple[int, int]]:
    base = root / V1_RELATIVE
    try:
        base_meta = base.lstat()
    except OSError as exc:
        raise VerificationError(f"missing frozen v1 root: {exc}") from exc
    if stat.S_ISLNK(base_meta.st_mode) or not stat.S_ISDIR(base_meta.st_mode):
        raise VerificationError("unsafe frozen v1 root")
    found: dict[str, tuple[int, int]] = {}
    for directory, names, files in os.walk(base, topdown=True, followlinks=False):
        names.sort()
        files.sort()
        for name in list(names):
            path = Path(directory) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise VerificationError(f"symlink or non-directory in frozen v1 tree: {path}")
        for name in files:
            path = Path(directory) / name
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            safe_relative(relative, "freeze inventory path")
            if stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"symlink in frozen v1 tree: {relative}")
            if not stat.S_ISREG(metadata.st_mode):
                raise VerificationError(f"nonregular frozen v1 path: {relative}")
            if metadata.st_nlink != 1:
                raise VerificationError(f"hardlink or invalid link count in frozen v1 tree: {relative}")
            validate_mode(metadata.st_mode, relative)
            found[relative] = (metadata.st_size, metadata.st_mode)
    return found


def _inventory_entry(root: Path, relative: str) -> dict[str, object]:
    raw = safe_read_file(root, relative)
    metadata = (root / relative).lstat()
    return {
        "bytes": len(raw), "mode": validate_mode(metadata.st_mode, relative),
        "path": relative, "sha256": hashlib.sha256(raw).hexdigest(),
    }


def regular_inventory(root: Path) -> list[dict[str, object]]:
    return [_inventory_entry(root, path) for path in sorted(enumerate_v1_metadata(root))]


def binding_record(root: Path, path: Path) -> dict[str, object]:
    relative = safe_relative(path.as_posix(), "bound packer path")
    return _inventory_entry(root, relative)


def python_binding() -> dict[str, object]:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise VerificationError("unsupported Python implementation/version; CPython 3.14 is required")
    executable = Path(sys.executable).resolve(strict=True)
    metadata = executable.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise VerificationError("unsafe pinned Python executable")
    validate_mode(metadata.st_mode, "pinned Python executable")
    raw = executable.read_bytes()
    return {
        "bytes": len(raw),
        "implementation": "cpython",
        "path": str(executable),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }


def rebuild_lock(root: Path) -> dict:
    entries = regular_inventory(root)
    public = [item for item in entries if not str(item["path"]).startswith(SCORER_PREFIX)]
    scorer = [item for item in entries if str(item["path"]).startswith(SCORER_PREFIX)]
    canonical = binding_record(root, CANONICAL_PACKER)
    plugin = binding_record(root, PLUGIN_PACKER)
    combined = public + scorer
    return {
        "packer_bindings": {
            "canonical": canonical,
            "plugin": plugin,
            "require_byte_equality": True,
        },
        "public_inventory": public,
        "public_tree_root_sha256": inventory_tree_root(public),
        "python_binding": python_binding(),
        "schema_version": LOCK_SCHEMA,
        "scorer_inventory": scorer,
        "scorer_tree_root_sha256": inventory_tree_root(scorer),
        "tree_algorithm": "sha256-domain-separated-length-prefixed-v2",
        "tree_root_sha256": inventory_tree_root(combined),
    }


def _validate_inventory(value: object, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise VerificationError(f"invalid {label} inventory")
    entries: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"bytes", "mode", "path", "sha256"}:
            raise VerificationError(f"invalid {label} inventory entry")
        relative = safe_relative(item.get("path"), f"{label} inventory path")
        if (
            not isinstance(item.get("bytes"), int) or isinstance(item.get("bytes"), bool)
            or int(item["bytes"]) < 0 or item.get("mode") not in {"0644", "0755"}
            or not isinstance(item.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])) is None
        ):
            raise VerificationError(f"invalid {label} inventory metadata: {relative}")
        entries.append(item)
    paths = [str(item["path"]) for item in entries]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise VerificationError(f"duplicate or unsorted {label} inventory path")
    return entries


def parse_lock(
    raw: bytes,
    *,
    expected_lock_sha256: str | None = None,
    expected_tree_root: str | None = None,
) -> dict:
    digest = hashlib.sha256(raw).hexdigest()
    if expected_lock_sha256 is not None and digest != expected_lock_sha256:
        raise VerificationError("independently pinned freeze lock SHA mismatch")
    lock = load_json_bytes(raw, "captured freeze-lock.json")
    required = {
        "packer_bindings", "public_inventory", "public_tree_root_sha256",
        "python_binding", "schema_version", "scorer_inventory",
        "scorer_tree_root_sha256", "tree_algorithm", "tree_root_sha256",
    }
    if set(lock) != required or lock.get("schema_version") != LOCK_SCHEMA:
        raise VerificationError("invalid freeze lock shape or version")
    if lock.get("tree_algorithm") != "sha256-domain-separated-length-prefixed-v2":
        raise VerificationError("invalid freeze tree algorithm")
    public = _validate_inventory(lock["public_inventory"], "public")
    scorer = _validate_inventory(lock["scorer_inventory"], "scorer")
    if any(str(item["path"]).startswith(SCORER_PREFIX) for item in public):
        raise VerificationError("scorer path present in public inventory")
    if any(not str(item["path"]).startswith(SCORER_PREFIX) for item in scorer):
        raise VerificationError("public path present in scorer inventory")
    if lock["public_tree_root_sha256"] != inventory_tree_root(public):
        raise VerificationError("public tree root mismatch")
    if lock["scorer_tree_root_sha256"] != inventory_tree_root(scorer):
        raise VerificationError("scorer tree root mismatch")
    if lock["tree_root_sha256"] != inventory_tree_root(public + scorer):
        raise VerificationError("freeze lock tree root mismatch")
    if expected_tree_root is not None and lock["tree_root_sha256"] != expected_tree_root:
        raise VerificationError("independently pinned freeze tree root mismatch")
    return lock


def _capture_entries(root: Path, entries: list[dict[str, object]]) -> dict[str, bytes]:
    return {
        str(item["path"]): safe_read_file(root, str(item["path"]), expected=item)
        for item in entries
    }


def capture_public_snapshot(root: Path, lock: dict) -> dict[str, object]:
    metadata = enumerate_v1_metadata(root)
    all_expected = {
        str(item["path"])
        for item in lock["public_inventory"] + lock["scorer_inventory"]
    }
    extra = sorted(set(metadata) - all_expected)
    missing = sorted(all_expected - set(metadata))
    if extra:
        raise VerificationError(f"unlisted extra frozen file: {extra[0]}")
    if missing:
        raise VerificationError(f"missing frozen file: {missing[0]}")
    files = _capture_entries(root, lock["public_inventory"])
    bindings = lock.get("packer_bindings")
    if not isinstance(bindings, dict) or set(bindings) != {"canonical", "plugin", "require_byte_equality"}:
        raise VerificationError("invalid packer bindings in freeze lock")
    if bindings["require_byte_equality"] is not True:
        raise VerificationError("packer byte equality must be required")
    try:
        canonical = safe_read_file(root, CANONICAL_PACKER.as_posix(), expected=bindings["canonical"])
    except VerificationError as exc:
        raise VerificationError(f"canonical packer drift: {exc}") from exc
    try:
        plugin = safe_read_file(root, PLUGIN_PACKER.as_posix(), expected=bindings["plugin"])
    except VerificationError as exc:
        raise VerificationError(f"plugin packer drift: {exc}") from exc
    if hashlib.sha256(canonical).hexdigest() != PACKER_SHA256:
        raise VerificationError("canonical packer drift")
    if hashlib.sha256(plugin).hexdigest() != PACKER_SHA256:
        raise VerificationError("plugin packer drift")
    if canonical != plugin:
        raise VerificationError("canonical and plugin packer bytes differ")
    if lock.get("python_binding") != python_binding():
        raise VerificationError("pinned Python executable drift")
    return {"files": files, "packer": canonical}


def verify_lock(root: Path) -> dict:
    raw = safe_read_file(root, LOCK_RELATIVE.as_posix())
    lock = parse_lock(raw)
    capture_public_snapshot(root, lock)
    _capture_entries(root, lock["scorer_inventory"])
    return lock


def json_type_matches(value: object, expected: str) -> bool:
    if expected == "object": return isinstance(value, dict)
    if expected == "array": return isinstance(value, list)
    if expected == "string": return isinstance(value, str)
    if expected == "integer": return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number": return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
    if expected == "boolean": return isinstance(value, bool)
    if expected == "null": return value is None
    raise VerificationError(f"unsupported strict schema type: {expected}")


def assert_supported_schema(schema: dict, location: str = "schema") -> None:
    unsupported = sorted(set(schema) - SUPPORTED_SCHEMA_KEYWORDS)
    if unsupported:
        raise VerificationError(f"unsupported schema keyword at {location}: {unsupported[0]}")
    for container in ("properties", "$defs"):
        children = schema.get(container)
        if children is not None and not isinstance(children, dict):
            raise VerificationError(f"invalid strict schema {container} at {location}")
        for name, child in (children or {}).items():
            if not isinstance(child, dict):
                raise VerificationError(f"invalid strict schema child at {location}.{container}.{name}")
            assert_supported_schema(child, f"{location}.{container}.{name}")
    items = schema.get("items")
    if items is not None:
        if not isinstance(items, dict):
            raise VerificationError(f"unsupported schema keyword form at {location}.items")
        assert_supported_schema(items, f"{location}.items")


def resolve_schema_ref(schema_root: dict, reference: str) -> dict:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise VerificationError(f"unsupported strict schema reference: {reference}")
    value: object = schema_root
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or part not in value:
            raise VerificationError(f"invalid strict schema reference: {reference}")
        value = value[part]
    if not isinstance(value, dict):
        raise VerificationError(f"invalid strict schema reference target: {reference}")
    return value


def validate_schema(value: object, schema: dict, schema_root: dict, location: str) -> None:
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise VerificationError(f"unsupported schema keyword sibling at {location}.$ref")
        validate_schema(value, resolve_schema_ref(schema_root, schema["$ref"]), schema_root, location)
        return
    expected_type = schema.get("type")
    if expected_type is not None:
        if not isinstance(expected_type, str) or not json_type_matches(value, expected_type):
            raise VerificationError(f"schema validation failed at {location}: expected {expected_type}")
    if "const" in schema and value != schema["const"]:
        raise VerificationError(f"schema validation failed at {location}: const mismatch")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or value not in enum:
            raise VerificationError(f"schema validation failed at {location}: enum mismatch")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list) or any(not isinstance(k, str) for k in required):
            raise VerificationError(f"invalid strict object schema at {location}")
        missing = [key for key in required if key not in value]
        if missing:
            raise VerificationError(f"schema validation failed at {location}: missing {missing[0]}")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise VerificationError(f"schema validation failed at {location}: unknown {unknown[0]}")
        for key, item in value.items():
            if key in properties:
                validate_schema(item, properties[key], schema_root, f"{location}.{key}")
    if isinstance(value, list):
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems")
        if not isinstance(minimum, int) or isinstance(minimum, bool):
            raise VerificationError(f"invalid strict array minimum at {location}")
        if len(value) < minimum:
            raise VerificationError(f"schema validation failed at {location}: too few items")
        if maximum is not None and (not isinstance(maximum, int) or isinstance(maximum, bool)):
            raise VerificationError(f"invalid strict array maximum at {location}")
        if isinstance(maximum, int) and len(value) > maximum:
            raise VerificationError(f"schema validation failed at {location}: too many items")
        if schema.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                raise VerificationError(f"schema validation failed at {location}: duplicate items")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                validate_schema(item, items, schema_root, f"{location}[{index}]")
    if isinstance(value, str):
        minimum = schema.get("minLength", 0)
        if not isinstance(minimum, int) or isinstance(minimum, bool):
            raise VerificationError(f"invalid strict string minimum at {location}")
        if len(value) < minimum:
            raise VerificationError(f"schema validation failed at {location}: string too short")
        pattern = schema.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                raise VerificationError(f"invalid strict pattern at {location}")
            try:
                matched = re.fullmatch(pattern, value)
            except re.error as exc:
                raise VerificationError(f"invalid strict pattern at {location}: {exc}") from exc
            if matched is None:
                raise VerificationError(f"schema validation failed at {location}: pattern mismatch")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            raise VerificationError(f"schema validation failed at {location}: non-finite")
        if "minimum" in schema and value < schema["minimum"]:
            raise VerificationError(f"schema validation failed at {location}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise VerificationError(f"schema validation failed at {location}: above maximum")


def assert_closed_schema(schema: dict, location: str = "schema") -> None:
    if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
        raise VerificationError(f"schema object is not closed at {location}")
    for key in ("properties", "$defs"):
        for name, child in (schema.get(key) or {}).items():
            assert_closed_schema(child, f"{location}.{key}.{name}")
    if isinstance(schema.get("items"), dict):
        assert_closed_schema(schema["items"], f"{location}.items")


def _validate_instances_from_files(files: dict[str, bytes], include_scorer: bool) -> dict[str, dict]:
    names = ("contract", "arms", "tasks", "run", "result")
    if include_scorer:
        names += ("oracle", "graph")
    instances: dict[str, dict] = {}
    prefix = V1_RELATIVE.as_posix() + "/"
    for name in names:
        schema_rel = prefix + f"schemas/{name}.schema.json"
        instance_rel = prefix + SCHEMA_INSTANCES[name]
        schema = load_json_bytes(files[schema_rel], schema_rel)
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise VerificationError(f"schema validation failed: {name} is not Draft 2020-12")
        assert_supported_schema(schema, name)
        assert_closed_schema(schema, name)
        instance = load_json_bytes(files[instance_rel], instance_rel)
        validate_schema(instance, schema, schema, name)
        instances[name] = instance
    return instances


def validate_instances(v1: Path, include_scorer: bool) -> dict[str, dict]:
    names = ("contract", "arms", "tasks", "run", "result") + (("oracle", "graph") if include_scorer else ())
    files: dict[str, bytes] = {}
    prefix = V1_RELATIVE.as_posix() + "/"
    for name in names:
        for relative in (f"schemas/{name}.schema.json", SCHEMA_INSTANCES[name]):
            files[prefix + relative] = (v1 / relative).read_bytes()
    return _validate_instances_from_files(files, include_scorer)


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for item in value.values(): result.update(recursive_keys(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value: result.update(recursive_keys(item))
        return result
    return set()


def public_projection(task: dict, arm: str) -> dict:
    if arm not in ARMS:
        raise VerificationError(f"unknown canonical arm: {arm}")
    projection = {
        "arm": arm, "fixture_root": task["fixture_root"], "pack": task["pack"],
        "partition": task["partition"], "prompt": task["prompt"],
        "provenance": task["provenance"],
        "schema_version": "contextguard.g2-arm-projection/v1",
        "stratum": task["stratum"], "task_id": task["task_id"],
        "workspace_policy": task["workspace_policy"],
    }
    leaked = FORBIDDEN_PUBLIC_KEYS & recursive_keys(projection)
    if leaked:
        raise VerificationError(f"hidden oracle key leaked into public projection: {sorted(leaked)[0]}")
    return projection


def _materialize_from_snapshot(files: dict[str, bytes], task: dict, arm: str, destination: Path) -> tuple[dict, list[str]]:
    projection = public_projection(task, arm)
    fixture_prefix = (V1_RELATIVE / task["fixture_root"]).as_posix() + "/"
    selected = sorted(path for path in files if path.startswith(fixture_prefix))
    if not selected:
        raise VerificationError(f"empty frozen fixture: {task['task_id']}")
    try:
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        workspace = destination / "workspace"
        workspace.mkdir(mode=0o700)
        inventory: list[str] = []
        for relative in selected:
            local = relative[len(fixture_prefix):]
            safe_relative(local, "projection fixture path")
            target = workspace / local
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as handle:
                handle.write(files[relative])
            target.chmod(0o400)
            inventory.append(local)
    except OSError as exc:
        raise VerificationError(f"unable to materialize public arm projection: {exc}") from exc
    if any("scorer-only" in path.relative_to(destination).parts for path in destination.rglob("*")):
        raise VerificationError("scorer-only content present in arm projection")
    return projection, inventory


def materialize_arm_projection(root: Path, task_id: str, arm: str, destination: Path) -> dict:
    tasks = load_json(root / V1_RELATIVE / "tasks.json").get("tasks", [])
    matches = [task for task in tasks if task.get("task_id") == task_id]
    if len(matches) != 1:
        raise VerificationError(f"unknown or duplicate task: {task_id}")
    fixture_prefix = (V1_RELATIVE / matches[0]["fixture_root"]).as_posix() + "/"
    files = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted((root / V1_RELATIVE / matches[0]["fixture_root"]).rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    projection, _inventory = _materialize_from_snapshot(files, matches[0], arm, destination)
    return projection


def normalized_tokens(raw: bytes) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9_]+", raw.decode("utf-8", "replace").lower()) if len(token) >= 4}


def fixture_tree_hash(path: Path) -> str:
    digest = hashlib.sha256(b"contextguard.g2-fixture-tree/v1\x00")
    for file_path in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
        if not file_path.is_file() or file_path.is_symlink(): continue
        raw = file_path.read_bytes()
        digest.update(length_prefix(file_path.relative_to(path).as_posix().encode()))
        digest.update(length_prefix(hashlib.sha256(raw).digest()))
    return digest.hexdigest()


def _snapshot_fixture(files: dict[str, bytes], task: dict) -> dict[str, bytes]:
    prefix = (V1_RELATIVE / task["fixture_root"]).as_posix() + "/"
    return {path[len(prefix):]: raw for path, raw in files.items() if path.startswith(prefix)}


def _fixture_hash_from_bytes(fixture: dict[str, bytes]) -> str:
    digest = hashlib.sha256(b"contextguard.g2-fixture-tree/v1\x00")
    for relative, raw in sorted(fixture.items()):
        digest.update(length_prefix(relative.encode()))
        digest.update(length_prefix(hashlib.sha256(raw).digest()))
    return digest.hexdigest()


CODE_SUFFIXES = {".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}
MAX_JSTS_LEXICAL_CHARS = 262_144
MAX_JSTS_LEXICAL_TOKENS = 65_536
MAX_JSTS_DELIMITER_DEPTH = 1_024


def _lex_jsts(text: str) -> list[tuple[str, str, int, bool]]:
    """Tokenize the small JS/TS surface needed for static module edges.

    Comments and template literals are deliberately discarded.  Ordinary
    quoted strings are retained as indivisible tokens so only a string in a
    syntactically recognizable static import/export position can become an
    edge.  This is a bounded lexical recognizer, not a general JS parser.
    """

    if len(text) > MAX_JSTS_LEXICAL_CHARS:
        raise VerificationError("bounded JS/TS lexical scanner character limit exceeded")
    tokens: list[tuple[str, str, int, bool]] = []
    length = len(text)

    def fail(kind: str) -> None:
        raise VerificationError(f"unterminated JS/TS lexical {kind}")

    def skip_line_comment(index: int, line: int) -> tuple[int, int]:
        index += 2
        while index < length and text[index] not in "\r\n":
            index += 1
        return index, line

    def skip_block_comment(index: int, line: int) -> tuple[int, int]:
        index += 2
        while index < length:
            if text.startswith("*/", index):
                return index + 2, line
            if text[index] == "\n":
                line += 1
            index += 1
        fail("block comment")
        raise AssertionError("unreachable")

    def scan_quote(index: int, line: int) -> tuple[int, int, str, bool]:
        quote = text[index]
        index += 1
        value: list[str] = []
        escaped = False
        while index < length:
            char = text[index]
            if char == quote:
                return index + 1, line, "".join(value), escaped
            if char in "\r\n":
                fail("quoted string")
            if char == "\\":
                escaped = True
                index += 1
                if index >= length:
                    fail("quoted string")
                escaped_char = text[index]
                if escaped_char == "\r":
                    index += 1
                    if index < length and text[index] == "\n":
                        index += 1
                    line += 1
                    continue
                if escaped_char == "\n":
                    line += 1
                    index += 1
                    continue
                value.append(escaped_char)
                index += 1
                continue
            value.append(char)
            index += 1
        fail("quoted string")
        raise AssertionError("unreachable")

    def skip_template_expression(index: int, line: int) -> tuple[int, int]:
        delimiter_stack = ["{"]
        matching_opener = {"}": "{", ")": "(", "]": "["}
        while index < length:
            char = text[index]
            if char in "'\"":
                index, line, _value, _escaped = scan_quote(index, line)
                continue
            if char == "`":
                index, line = skip_template(index, line)
                continue
            if text.startswith("//", index):
                index, line = skip_line_comment(index, line)
                continue
            if text.startswith("/*", index):
                index, line = skip_block_comment(index, line)
                continue
            if char == "/":
                raise VerificationError("unsupported non-comment JS/TS slash")
            if char in {"{", "(", "["}:
                if len(delimiter_stack) >= MAX_JSTS_DELIMITER_DEPTH:
                    raise VerificationError("bounded JS/TS delimiter depth exceeded")
                delimiter_stack.append(char)
            elif char in matching_opener:
                if delimiter_stack[-1] != matching_opener[char]:
                    raise VerificationError(
                        f"mismatched closing JS/TS template interpolation delimiter: {char}"
                    )
                delimiter_stack.pop()
                if not delimiter_stack:
                    return index + 1, line
            elif char == "\n":
                line += 1
            index += 1
        fail("template interpolation")
        raise AssertionError("unreachable")

    def skip_template(index: int, line: int) -> tuple[int, int]:
        index += 1
        while index < length:
            char = text[index]
            if char == "\\":
                index += 1
                if index >= length:
                    fail("template literal")
                if text[index] == "\n":
                    line += 1
                index += 1
                continue
            if char == "`":
                return index + 1, line
            if text.startswith("${", index):
                index, line = skip_template_expression(index + 2, line)
                continue
            if char == "\n":
                line += 1
            index += 1
        fail("template literal")
        raise AssertionError("unreachable")

    index = 0
    line = 1
    while index < length:
        char = text[index]
        if char in " \t\f\v":
            index += 1
            continue
        if char == "\r":
            if index + 1 < length and text[index + 1] == "\n":
                index += 1
            line += 1
            index += 1
            continue
        if char == "\n":
            line += 1
            index += 1
            continue
        if text.startswith("//", index):
            index, line = skip_line_comment(index, line)
            continue
        if text.startswith("/*", index):
            index, line = skip_block_comment(index, line)
            continue
        if char in "'\"":
            start_line = line
            index, line, value, escaped = scan_quote(index, line)
            tokens.append(("string", value, start_line, escaped))
        elif char == "`":
            index, line = skip_template(index, line)
        elif char == "/":
            raise VerificationError("unsupported non-comment JS/TS slash")
        elif char.isalpha() or char in "_$":
            start = index
            index += 1
            while index < length and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            tokens.append(("identifier", text[start:index], line, False))
        else:
            tokens.append(("punctuation", char, line, False))
            index += 1
        if len(tokens) > MAX_JSTS_LEXICAL_TOKENS:
            raise VerificationError("bounded JS/TS lexical scanner token limit exceeded")
    return tokens


def scan_jsts_static_module_specifiers(text: str) -> list[dict[str, object]]:
    """Return genuine top-level ESM import and static re-export specifiers."""

    tokens = _lex_jsts(text)
    records: list[dict[str, object]] = []
    delimiter_stack: list[str] = []
    matching_opener = {"}": "{", ")": "(", "]": "["}

    def string_target(index: int) -> str | None:
        if index >= len(tokens) or tokens[index][0] != "string":
            return None
        if tokens[index][3]:
            raise VerificationError("escaped JS/TS static module specifier is unsupported")
        return tokens[index][1]

    def from_target(start: int) -> str | None:
        end = min(len(tokens), start + 256)
        for cursor in range(start, end):
            kind, value, _line, _escaped = tokens[cursor]
            if value == ";":
                return None
            if kind == "identifier" and value == "from":
                return string_target(cursor + 1)
        if end < len(tokens):
            raise VerificationError("bounded JS/TS static module statement limit exceeded")
        return None

    for index, token in enumerate(tokens):
        kind, value, line, _escaped = token
        at_top = not delimiter_stack
        previous = tokens[index - 1] if index else None
        statement_boundary = (
            previous is None
            or previous[1] in {";", "}"}
            or previous[2] < line
        )
        if at_top and statement_boundary and kind == "identifier" and value == "import":
            next_value = tokens[index + 1][1] if index + 1 < len(tokens) else None
            if next_value not in {"(", "."}:
                target = string_target(index + 1) or from_target(index + 1)
                if target is not None:
                    records.append({"kind": "import", "line": line, "target": target})
        elif at_top and statement_boundary and kind == "identifier" and value == "export":
            next_value = tokens[index + 1][1] if index + 1 < len(tokens) else None
            if next_value in {"*", "{"} or next_value == "type":
                target = from_target(index + 1)
                if target is not None:
                    records.append({"kind": "reexport", "line": line, "target": target})

        if kind == "punctuation":
            if value in {"{", "(", "["}:
                if len(delimiter_stack) >= MAX_JSTS_DELIMITER_DEPTH:
                    raise VerificationError("bounded JS/TS delimiter depth exceeded")
                delimiter_stack.append(value)
            elif value in matching_opener:
                if not delimiter_stack:
                    raise VerificationError(f"unmatched closing JS/TS delimiter: {value}")
                if delimiter_stack[-1] != matching_opener[value]:
                    raise VerificationError(f"mismatched closing JS/TS delimiter: {value}")
                delimiter_stack.pop()
    if delimiter_stack:
        raise VerificationError("unclosed JS/TS delimiter at end of input")
    return records


def _normalize_semantic_path(value: str) -> str:
    normalized = posixpath.normpath(value.replace("\\", "/"))
    return "" if normalized == "." else normalized.lstrip("/")


def _resolve_semantic_target(target: str, source: str, known: set[str]) -> str | None:
    source_dir = posixpath.dirname(source)
    candidates: list[str] = []
    if target.startswith("."):
        if target.startswith("./") or target.startswith("../"):
            base = _normalize_semantic_path(posixpath.join(source_dir, target))
        else:
            leading = len(target) - len(target.lstrip("."))
            base_dir = source_dir
            for _ in range(max(0, leading - 1)):
                base_dir = posixpath.dirname(base_dir)
            remainder = target[leading:].replace(".", "/")
            base = _normalize_semantic_path(posixpath.join(base_dir, remainder))
    else:
        base = target.replace(".", "/")
    candidates.extend(
        [
            base,
            f"{base}.py",
            f"{base}.ts",
            f"{base}.tsx",
            f"{base}.js",
            f"{base}.jsx",
            f"{base}.mjs",
            f"{base}/__init__.py",
            f"{base}/index.ts",
            f"{base}/index.js",
            f"{base}/index.mjs",
        ]
    )
    return next((candidate for candidate in candidates if candidate in known), None)


def _semantic_import_edges(fixture: dict[str, bytes]) -> list[dict[str, object]]:
    known = {
        path for path in fixture if PurePosixPath(path).suffix.lower() in CODE_SUFFIXES
    }
    edges: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()

    def add(source: str, target_text: str, mechanism: str, line: int, reexport: bool) -> None:
        target = _resolve_semantic_target(target_text, source, known)
        if target is None or target == source or (source, target) in seen:
            return
        seen.add((source, target))
        edges.append(
            {
                "from": source,
                "line": line,
                "mechanism": mechanism,
                "reexport": reexport,
                "specifier_class": (
                    "parent_relative"
                    if target_text.startswith("../")
                    else "sibling_relative"
                    if target_text.startswith("./")
                    else "python_package_relative"
                    if target_text.startswith(".")
                    else "bare_or_absolute_module"
                ),
                "to": target,
            }
        )

    for source in sorted(known):
        text = fixture[source].decode("utf-8", "replace")
        suffix = PurePosixPath(source).suffix.lower()
        if suffix == ".py":
            try:
                module = ast.parse(text)
            except (SyntaxError, ValueError, RecursionError):
                continue
            for node in ast.walk(module):
                if isinstance(node, ast.ImportFrom):
                    dots = "." * int(node.level or 0)
                    add(
                        source,
                        dots + (node.module or ""),
                        "python_relative_from" if node.level else "python_absolute_from",
                        node.lineno,
                        False,
                    )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        add(source, alias.name, "python_import", node.lineno, False)
            continue
        for record in scan_jsts_static_module_specifiers(text):
            reexport = record["kind"] == "reexport"
            mechanism = (
                "typescript_reexport"
                if reexport and suffix in {".ts", ".tsx"}
                else "esm_reexport"
                if reexport
                else "typescript_es_import"
                if suffix in {".ts", ".tsx"}
                else "esm_import"
            )
            add(source, str(record["target"]), mechanism, int(record["line"]), reexport)
    return edges


def _shortest_path(edges: list[dict[str, object]], start: str, target: str) -> int | None:
    adjacency: dict[str, set[str]] = collections.defaultdict(set)
    for edge in edges:
        adjacency[str(edge["from"])].add(str(edge["to"]))
    queue = collections.deque([(start, 0)])
    visited = {start}
    while queue:
        node, distance = queue.popleft()
        if node == target:
            return distance
        for neighbor in sorted(adjacency.get(node, set())):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))
    return None


def _undirected_shortest_path(
    edges: list[dict[str, object]], start: str, target: str
) -> int | None:
    adjacency: dict[str, set[str]] = collections.defaultdict(set)
    for edge in edges:
        source, destination = str(edge["from"]), str(edge["to"])
        adjacency[source].add(destination)
        adjacency[destination].add(source)
    queue = collections.deque([(start, 0)])
    visited = {start}
    while queue:
        node, distance = queue.popleft()
        if node == target:
            return distance
        for neighbor in sorted(adjacency.get(node, set())):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, distance + 1))
    return None


def _topology_family(
    node_count: int,
    edge_count: int,
    component_sizes: list[int],
    seed_indegree: int,
    seed_outdegree: int,
    degree_pairs: list[tuple[int, int]],
) -> str:
    if node_count != 3 or edge_count != 2 or component_sizes != [3]:
        return "other"
    if seed_indegree == 0 and seed_outdegree == 1 and degree_pairs == [(0, 1), (1, 0), (1, 1)]:
        return "outgoing_chain"
    if seed_indegree == 0 and seed_outdegree == 2 and degree_pairs == [(0, 2), (1, 0), (1, 0)]:
        return "outgoing_fork"
    if seed_indegree == 2 and seed_outdegree == 0 and degree_pairs == [(0, 1), (0, 1), (2, 0)]:
        return "incoming_fan_in"
    return "other"


def _graph_topology_profile(
    fixture: dict[str, bytes], task: dict, required_paths: list[str] | None = None
) -> dict[str, object]:
    nodes = sorted(
        path for path in fixture if PurePosixPath(path).suffix.lower() in CODE_SUFFIXES
    )
    edges = _semantic_import_edges(fixture)
    indegree = {node: 0 for node in nodes}
    outdegree = {node: 0 for node in nodes}
    adjacency: dict[str, set[str]] = collections.defaultdict(set)
    undirected: dict[str, set[str]] = collections.defaultdict(set)
    for edge in edges:
        source, target = str(edge["from"]), str(edge["to"])
        outdegree[source] += 1
        indegree[target] += 1
        adjacency[source].add(target)
        undirected[source].add(target)
        undirected[target].add(source)
    component_sizes: list[int] = []
    unseen = set(nodes)
    while unseen:
        seed = min(unseen)
        queue = [seed]
        unseen.remove(seed)
        size = 0
        while queue:
            node = queue.pop()
            size += 1
            for neighbor in undirected.get(node, set()):
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    queue.append(neighbor)
        component_sizes.append(size)
    entry = str(task["pack"]["files"][0])
    from_entry = {
        node: distance
        for node in nodes
        if (distance := _shortest_path(edges, entry, node)) is not None
    }
    to_entry = {
        node: distance
        for node in nodes
        if (distance := _shortest_path(edges, node, entry)) is not None
    }
    connected_to_entry = {
        node for node in nodes if _undirected_shortest_path(edges, entry, node) is not None
    }
    disconnected_edge_count = sum(
        1
        for edge in edges
        if str(edge["from"]) not in connected_to_entry
        or str(edge["to"]) not in connected_to_entry
    )
    required_distance: int | None = None
    required_direction: str | None = None
    if required_paths:
        non_entry_required = [path for path in required_paths if path != entry]
        candidates = [_undirected_shortest_path(edges, entry, path) for path in non_entry_required]
        reachable = [distance for distance in candidates if distance is not None]
        required_distance = min(reachable) if reachable else None
        for path in non_entry_required:
            if any(edge["from"] == entry and edge["to"] == path for edge in edges):
                required_direction = "outgoing"
                break
            if any(edge["from"] == path and edge["to"] == entry for edge in edges):
                required_direction = "incoming"
                break
    degree_pairs = sorted((indegree[node], outdegree[node]) for node in nodes)
    family = _topology_family(
        len(nodes), len(edges), sorted(component_sizes),
        indegree.get(entry, 0), outdegree.get(entry, 0), degree_pairs,
    )
    node_signatures = sorted(
        (
            indegree[node],
            outdegree[node],
            from_entry.get(node, -1),
            to_entry.get(node, -1),
        )
        for node in nodes
    )
    core = {
        "component_sizes": sorted(component_sizes),
        "depth_distribution": sorted(len(PurePosixPath(node).parts) for node in nodes),
        "directed_edge_count": len(edges),
        "disconnected_edge_count": disconnected_edge_count,
        "disconnected_node_count": len(nodes) - len(connected_to_entry),
        "entry_indegree": indegree.get(entry, 0),
        "entry_outdegree": outdegree.get(entry, 0),
        "in_out_degree_pairs": degree_pairs,
        "node_count": len(nodes),
        "node_topology_signatures": node_signatures,
    }
    return {
        **core,
        "entry_to_required_shortest_path": required_distance,
        "family": family,
        "has_branching": any(value > 1 for value in outdegree.values()) or any(value > 1 for value in indegree.values()),
        "has_reexport": any(bool(edge["reexport"]) for edge in edges),
        "import_mechanisms": sorted({str(edge["mechanism"]) for edge in edges}),
        "required_adjacency_direction": required_direction,
        "specifier_resolution_classes": sorted(
            {str(edge["specifier_class"]) for edge in edges}
        ),
        "topology_sha256": hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def derive_graph_topology_profiles(root: Path, tasks: list[dict]) -> dict[str, dict]:
    required: dict[str, list[str]] = {}
    oracle_path = root / V1_RELATIVE / "scorer-only/oracle.json"
    if oracle_path.is_file():
        oracle = load_json(oracle_path)
        required = {
            entry["task_id"]: entry["required_paths"] for entry in oracle.get("entries", [])
        }
    profiles: dict[str, dict] = {}
    for task in tasks:
        if task["stratum"] != "realistic_fallback":
            continue
        fixture_root = root / V1_RELATIVE / task["fixture_root"]
        fixture = {
            path.relative_to(fixture_root).as_posix(): path.read_bytes()
            for path in sorted(fixture_root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }
        profiles[task["task_id"]] = _graph_topology_profile(
            fixture, task, required.get(task["task_id"])
        )
    return profiles


def _closed_morphology(fixture: dict[str, bytes], task: dict) -> dict[str, object]:
    json_object_count = 0
    tabular_shapes: list[tuple[str, int, int]] = []
    heading_count = 0
    for path, raw in sorted(fixture.items()):
        text = raw.decode("utf-8", "replace")
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            json_object_count += 1
        heading_count += len(re.findall(r"(?m)^#{1,6}\s+", text))
        lines = [line for line in text.splitlines() if line.strip()]
        for delimiter, label in ((",", "comma"), ("\t", "tab")):
            widths = [len(line.split(delimiter)) for line in lines]
            if len(widths) >= 2 and min(widths) > 1 and len(set(widths)) == 1:
                tabular_shapes.append((label, len(lines), widths[0]))
    return {
        "explicit_source_count": len(task["pack"]["files"]),
        "file_count": len(fixture),
        "heading_count": heading_count,
        "json_object_count": json_object_count,
        "nested_depths": sorted(len(PurePosixPath(path).parts) for path in fixture),
        "tabular_shapes": tabular_shapes,
    }


def _structure_profiles_from_snapshot(files: dict[str, bytes], tasks: list[dict]) -> dict[str, str]:
    result: dict[str, str] = {}
    for task in tasks:
        fixture = _snapshot_fixture(files, task)
        record = (
            _graph_topology_profile(fixture, task)
            if task["stratum"] == "realistic_fallback"
            else _closed_morphology(fixture, task)
        )
        result[task["task_id"]] = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    return result


def derive_structure_profiles(root: Path, tasks: list[dict]) -> dict[str, str]:
    files: dict[str, bytes] = {}
    for task in tasks:
        fixture_root = root / V1_RELATIVE / task["fixture_root"]
        for path in sorted(fixture_root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                files[path.relative_to(root).as_posix()] = path.read_bytes()
    return _structure_profiles_from_snapshot(files, tasks)


def validate_public_tasks(files: dict[str, bytes], tasks_value: dict, arms_value: dict) -> tuple[list[dict], dict[str, str]]:
    tasks = tasks_value["tasks"]
    expected_factors = {
        "ordinary": [], "adaptive_only": ["adaptive_k"],
        "symbol_only": ["symbol_memory"], "combined": ["adaptive_k", "symbol_memory"],
    }
    arms = arms_value["arms"]
    names = [item["name"] for item in arms]
    if names != list(ARMS):
        raise VerificationError("duplicate arm" if len(names) != len(set(names)) else "canonical arms do not match")
    for item in arms:
        if item["factors"] != expected_factors[item["name"]]:
            raise VerificationError(f"canonical arm factor contamination: {item['name']}")
    if arms_value["application_order"] != ["ordinary", "adaptive_k", "symbol_memory"]:
        raise VerificationError("combined application order mismatch")
    if len(tasks) != 6: raise VerificationError("exactly six tasks are required")
    ids = [task["task_id"] for task in tasks]
    if len(ids) != len(set(ids)): raise VerificationError("duplicate task")
    for partition in PARTITIONS:
        selected = [task for task in tasks if task["partition"] == partition]
        if sorted(task["stratum"] for task in selected) != ["closed_pack", "realistic_fallback"]:
            raise VerificationError(f"invalid task strata for {partition}")
    for field in ("structure_id", "lineage_id"):
        values = [task[field] for task in tasks]
        if len(values) != len(set(values)): raise VerificationError(f"duplicate {field}")
    file_hash_owners: dict[str, tuple[str, str]] = {}
    fixture_hashes: list[str] = []
    token_sets: dict[str, set[str]] = {}
    for task in tasks:
        expected_root = f"fixtures/{task['partition']}/{task['stratum']}"
        if task["fixture_root"] != expected_root:
            raise VerificationError(f"fixture root and public stratum disagree: {task['task_id']}")
        fixture = _snapshot_fixture(files, task)
        if len(fixture) < 4:
            raise VerificationError(f"fixture requires multiple independent files: {task['task_id']}")
        tree_hash = _fixture_hash_from_bytes(fixture)
        fixture_hashes.append(tree_hash)
        if task["fixture_tree_sha256"] != tree_hash:
            raise VerificationError(f"fixture tree hash mismatch: {task['task_id']}")
        concatenated = bytearray()
        for relative, raw in sorted(fixture.items()):
            digest = hashlib.sha256(raw).hexdigest()
            if digest in file_hash_owners:
                owner = file_hash_owners[digest]
                raise VerificationError(f"shared fixture file hash: {owner[0]}/{owner[1]} and {task['task_id']}/{relative}")
            file_hash_owners[digest] = (task["task_id"], relative)
            concatenated.extend(raw + b"\n")
        token_sets[task["task_id"]] = normalized_tokens(bytes(concatenated))
        policy = task["workspace_policy"]
        expected_policy = ({
            "allowed_sources": ["embedded_pack"], "bounded_reads": 0,
            "fallback_triggers": [], "read_only": False, "workspace_access": False,
        } if task["stratum"] == "closed_pack" else {
            "allowed_sources": ["embedded_pack", "local_exact_slice", "local_direct_import_neighbor"],
            "bounded_reads": 3, "fallback_triggers": ["ordinary_required_source_omitted"],
            "read_only": True, "workspace_access": True,
        })
        if policy != expected_policy: raise VerificationError(f"stratum policy mismatch: {task['task_id']}")
        for file_name in task["pack"]["files"]:
            safe_relative(file_name, f"pack file for {task['task_id']}")
            if file_name not in fixture: raise VerificationError(f"missing exact pack file: {task['task_id']}/{file_name}")
    if len(fixture_hashes) != len(set(fixture_hashes)): raise VerificationError("duplicate fixture tree hash")
    profiles = _structure_profiles_from_snapshot(files, tasks)
    if len(set(profiles.values())) != 6:
        raise VerificationError("same or similar cross-partition structure profile")
    graph_profiles = {
        task["task_id"]: _graph_topology_profile(_snapshot_fixture(files, task), task)
        for task in tasks
        if task["stratum"] == "realistic_fallback"
    }
    topology_owners: dict[str, str] = {}
    expected_graph_families = {
        "train_graph": "outgoing_chain",
        "calibration_graph": "outgoing_fork",
        "evaluation_graph": "incoming_fan_in",
    }
    for task_id, profile in graph_profiles.items():
        topology = str(profile["topology_sha256"])
        if topology in topology_owners:
            raise VerificationError(
                f"cloned graph topology: {topology_owners[topology]} and {task_id}"
            )
        topology_owners[topology] = task_id
        if int(profile["disconnected_node_count"]) or int(profile["disconnected_edge_count"]):
            raise VerificationError(f"disconnected graph topology: {task_id}")
        if profile["family"] != expected_graph_families[task_id]:
            raise VerificationError(
                f"graph topology family mismatch: {task_id}"
            )
    for index, left in enumerate(tasks):
        for right in tasks[index + 1:]:
            if left["partition"] == right["partition"]: continue
            a, b = token_sets[left["task_id"]], token_sets[right["task_id"]]
            if len(a & b) / max(1, len(a | b)) >= 0.75:
                raise VerificationError(f"high cross-partition public-content similarity: {left['task_id']} and {right['task_id']}")
    return tasks, profiles


def arm_arguments(task: dict, arm: str) -> list[str]:
    pack = task["pack"]
    arguments = [
        "auto", "--root", ".", "--query", pack["query"], "--files", ",".join(pack["files"]),
        "--top", str(pack["top"]), "--budget-bytes", str(pack["budget_bytes"]), "--no-artifact", "--json",
    ]
    if arm in {"adaptive_only", "combined"}: arguments += ["--apply-adaptive-k", "--adaptive-k-policy", "precision"]
    if arm in {"symbol_only", "combined"}: arguments.append("--apply-symbol-memory")
    return arguments


PACKER_CHILD_BOOTSTRAP = r'''
import __future__, _colorize, argparse, ast, base64, collections, copy, hashlib, heapq, importlib.machinery, importlib.util
import fnmatch, gettext, json, locale, math, os, pathlib, posixpath, re, shlex, shutil, stat, subprocess, sys, threading, time, types, typing
from dataclasses import dataclass
request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
os.environ.pop("__CF_USER_TEXT_ENCODING", None)
workspace = pathlib.Path(request["workspace"]).resolve(strict=True)
inventory = tuple(request["inventory"])
source = base64.b64decode(request["packer_b64"], validate=True)
def inside(path):
    try:
        resolved = pathlib.Path(path if os.path.isabs(os.fspath(path)) else workspace / os.fspath(path)).resolve(strict=False)
    except Exception:
        return False
    return resolved == workspace or workspace in resolved.parents
def deny(event):
    raise RuntimeError("audit boundary denied: " + event)
def audit(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.posix_spawnp"}:
        deny(event)
    if event.startswith("os.exec") or event.startswith("os.spawn") or event in {"ctypes.dlopen", "os.putenv", "os.unsetenv"}:
        deny(event)
    if event == "import":
        name = args[0] if args else ""
        if name not in sys.modules:
            deny("late dynamic load " + str(name))
    if event == "open":
        path = args[0] if args else None
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if isinstance(path, int):
            return
        if any(flag in str(mode) for flag in "wax+") or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            deny("write open")
        if path is not None and not inside(path):
            deny("out-of-snapshot read")
    if event in {"os.listdir", "os.scandir", "pathlib.Path.glob", "pathlib.Path.rglob"}:
        if args and not isinstance(args[0], int) and not inside(args[0]):
            deny("out-of-snapshot enumeration")
    if event in {"os.remove", "os.rmdir", "os.rename", "os.replace", "os.link", "os.symlink", "os.mkdir", "os.chmod", "os.chown", "os.truncate"}:
        deny(event)
sys.addaudithook(audit)
module = types.ModuleType("_captured_context_pack")
module.__file__ = str(workspace / "captured-context-pack.py")
sys.modules[module.__name__] = module
exec(compile(source, module.__file__, "exec"), module.__dict__, module.__dict__)
if request["entrypoint"] == "probe":
    raise SystemExit(0)
class CapturedLineSanitizer(module.FallbackLineSanitizer):
    def __init__(self, *, show_paths=False, context="unknown_text", private_roots=()):
        super().__init__(show_paths=show_paths, context=context)
module._LINE_SANITIZER_FACTORY_CACHE = CapturedLineSanitizer
module.git_ls_files = lambda _root, _diagnostics=None: list(inventory)
raise SystemExit(module.main(list(request["arguments"])))
'''


def run_captured_packer_child(
    *, packer_bytes: bytes, sanitizer_bytes: bytes, workspace: Path,
    arguments: list[str], frozen_inventory: list[str], entrypoint: str = "packer",
    timeout_seconds: float = PACKER_CHILD_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    del sanitizer_bytes  # The reviewed packer's byte-identical built-in sanitizer is forced.
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise VerificationError("invalid captured packer child timeout")
    bounded_timeout = min(float(timeout_seconds), PACKER_CHILD_TIMEOUT_SECONDS)
    python = python_binding()
    request = {
        "arguments": arguments, "entrypoint": entrypoint,
        "inventory": frozen_inventory,
        "packer_b64": base64.b64encode(packer_bytes).decode("ascii"),
        "workspace": str(Path(workspace).resolve(strict=True)),
    }
    try:
        return subprocess.run(
            [str(python["path"]), "-I", "-B", "-c", PACKER_CHILD_BOOTSTRAP],
            cwd=workspace,
            env={"LANG": "C.UTF-8"},
            input=json.dumps(request, sort_keys=True, separators=(",", ":")).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=bounded_timeout,
        )
    except subprocess.TimeoutExpired:
        raise VerificationError("captured packer child timed out") from None


def execute_arm(
    packer_bytes: bytes, workspace: Path, inventory: list[str], task: dict, arm: str,
    *, timeout_seconds: float = PACKER_CHILD_TIMEOUT_SECONDS,
) -> dict:
    try:
        result = run_captured_packer_child(
            packer_bytes=packer_bytes, sanitizer_bytes=b"", workspace=workspace,
            arguments=arm_arguments(task, arm), frozen_inventory=inventory,
            timeout_seconds=timeout_seconds,
        )
    except VerificationError as exc:
        raise VerificationError(
            f"bound packer failed for {task['task_id']}/{arm}: {exc}"
        ) from None
    if result.returncode != 0:
        raise VerificationError(f"bound packer failed for {task['task_id']}/{arm}: {result.stderr.decode('utf-8', 'replace')}")
    return load_json_bytes(result.stdout, f"bound packer output {task['task_id']}/{arm}")


def selected_paths(payload: dict) -> list[str]:
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        raise VerificationError("bound packer payload lacks structural manifest")
    paths = [item.get("path") for item in manifest["sources"] if isinstance(item, dict)]
    if not paths or any(not isinstance(path, str) for path in paths) or len(paths) != len(set(paths)):
        raise VerificationError("bound packer structural manifest has invalid or repeated paths")
    return paths


def validate_oracle(tasks: list[dict], oracle: dict) -> dict[str, dict]:
    entries = oracle["entries"]
    ids = [entry["task_id"] for entry in entries]
    if len(ids) != len(set(ids)): raise VerificationError("duplicate oracle entry")
    if set(ids) != {task["task_id"] for task in tasks}: raise VerificationError("oracle/task cross-object mismatch")
    for field, label in (("answer_signature", "answer signature"), ("expected_output", "expected output")):
        values = [entry[field] for entry in entries]
        if len(values) != len(set(values)): raise VerificationError(f"duplicate {label}")
    public_encoded = json.dumps(tasks, sort_keys=True)
    for entry in entries:
        for secret in (entry["answer_signature"], entry["expected_output"]):
            if secret in public_encoded: raise VerificationError("transitive oracle leakage in public task content")
    return {entry["task_id"]: entry for entry in entries}


def validate_graph_evidence(
    files: dict[str, bytes], tasks: dict[str, dict], graph: dict,
    outcomes: dict, oracle: dict[str, dict],
) -> None:
    cases = graph["cases"]
    ids = [case["task_id"] for case in cases]
    if len(ids) != len(set(ids)): raise VerificationError("duplicate graph case")
    if set(ids) != {"train_graph", "calibration_graph", "evaluation_graph"}:
        raise VerificationError("graph/task cross-object mismatch")
    for case in cases:
        task_id = case["task_id"]
        fixture = _snapshot_fixture(files, tasks[task_id])
        evidence = case["derived_evidence"]
        edge = evidence["import_edges"][0]
        if edge["from"] not in fixture or edge["to"] not in fixture:
            raise VerificationError(f"missing import edge endpoint: {task_id}")
        lines = fixture[edge["from"]].decode("utf-8", "strict").splitlines()
        line_index = edge["source_line"] - 1
        if line_index >= len(lines) or lines[line_index] != edge["source_text"]:
            raise VerificationError(f"fabricated import edge source-line evidence: {task_id}")
        ordinary_paths = set(selected_paths(outcomes[(task_id, "ordinary")]))
        required_paths = set(oracle[task_id]["required_paths"]) - ordinary_paths
        required_endpoint = next(
            (
                endpoint
                for endpoint in (edge["from"], edge["to"])
                if endpoint in required_paths
            ),
            None,
        )
        if required_endpoint is None:
            raise VerificationError(f"import edge does not bind required neighbor: {task_id}")
        other_endpoint = edge["to"] if edge["from"] == required_endpoint else edge["from"]
        if other_endpoint not in ordinary_paths:
            raise VerificationError(f"import edge required neighbor is not directly recoverable: {task_id}")
        application = outcomes[(task_id, "symbol_only")].get("graph_application", {}).get("selected_sources", [])
        if not any(item.get("path") == required_endpoint and item.get("reason") == "direct_import_neighbor" for item in application if isinstance(item, dict)):
            raise VerificationError(f"missing import edge in bound packer evidence: {task_id}")
        rank = evidence["graph_ranks"][0]
        if rank["path"] != required_endpoint:
            raise VerificationError(f"graph rank does not bind required neighbor: {task_id}")
        ranks = outcomes[(task_id, "symbol_only")].get("symbol_memory", {}).get("graph_context", [])
        actual = next((index for index, item in enumerate(ranks, 1) if item.get("path") == rank["path"]), None)
        if actual != rank["rank"]: raise VerificationError(f"fabricated or missing graph rank: {task_id}")


def score_adaptive_labels(tasks: list[dict], oracle: dict[str, dict], outcomes: dict) -> list[dict]:
    scores: list[dict] = []
    for task in tasks:
        task_id = task["task_id"]
        labels = oracle[task_id]["adaptive_labels"]
        if len(labels) != 4: raise VerificationError(f"adaptive labels must cover four candidates: {task_id}")
        if not any(item["origin"] == "heuristic" and item["decision"] == "retain" for item in labels):
            raise VerificationError(f"adaptive labels lack heuristic retain: {task_id}")
        if not any(item["origin"] == "heuristic" and item["decision"] == "drop" for item in labels):
            raise VerificationError(f"adaptive labels lack heuristic drop: {task_id}")
        expected = {item["path"]: item for item in labels}
        if len(expected) != len(labels): raise VerificationError(f"duplicate adaptive label: {task_id}")
        for arm in ("adaptive_only", "combined"):
            payload = outcomes[(task_id, arm)]
            items = payload.get("adaptive_k", {}).get("selected_evidence", {}).get("items", [])
            candidates = [item.get("path") for item in items if isinstance(item, dict)]
            if set(candidates) != set(expected) or len(candidates) != len(expected):
                raise VerificationError(f"adaptive labels do not cover every candidate: {task_id}/{arm}")
            retained = set(selected_paths(payload))
            if arm == "combined":
                graph_added = {
                    item.get("path")
                    for item in payload.get("graph_application", {}).get("selected_sources", [])
                    if isinstance(item, dict) and isinstance(item.get("path"), str)
                }
                retained -= graph_added
            explicit = set(task["pack"]["files"])
            for path in candidates:
                label = expected[path]
                actual_origin = "explicit" if path in explicit else "heuristic"
                actual_decision = "retain" if path in retained else "drop"
                correct = label["origin"] == actual_origin and label["decision"] == actual_decision
                scores.append({"arm": arm, "correct": correct, "path": path, "task_id": task_id})
                if not correct: raise VerificationError(f"adaptive label mismatch: {task_id}/{arm}/{path}")
    return scores


def validate_required_symbols(files: dict[str, bytes], tasks: list[dict], oracle: dict[str, dict], outcomes: dict) -> int:
    count = 0
    for task in tasks:
        task_id = task["task_id"]
        fixture = _snapshot_fixture(files, task)
        ordinary_paths = set(selected_paths(outcomes[(task_id, "ordinary")]))
        missed_required_paths = set(oracle[task_id]["required_paths"]) - ordinary_paths
        for symbol in oracle[task_id]["required_symbols"]:
            count += 1
            if not any(
                path in missed_required_paths
                and re.search(rf"\b{re.escape(symbol)}\b", raw.decode("utf-8", "replace"))
                for path, raw in fixture.items()
            ):
                raise VerificationError(f"required symbol absent from ordinary-missed neighbor: {task_id}/{symbol}")
            for arm in ("symbol_only", "combined"):
                symbols = outcomes[(task_id, arm)].get("symbol_memory", {}).get("symbols", [])
                if not any(
                    item.get("name") == symbol and item.get("path") in missed_required_paths
                    for item in symbols
                    if isinstance(item, dict)
                ):
                    raise VerificationError(f"required symbol absent from ordinary-missed bound packer evidence: {task_id}/{arm}/{symbol}")
    return count


def validate_required_topology(
    files: dict[str, bytes], tasks: list[dict], oracle: dict[str, dict]
) -> None:
    expected = {
        "train_graph": ("outgoing_chain", "outgoing"),
        "calibration_graph": ("outgoing_fork", "outgoing"),
        "evaluation_graph": ("incoming_fan_in", "incoming"),
    }
    for task in tasks:
        task_id = task["task_id"]
        if task_id not in expected:
            continue
        profile = _graph_topology_profile(
            _snapshot_fixture(files, task), task, oracle[task_id]["required_paths"]
        )
        family, direction = expected[task_id]
        if (
            profile["family"] != family
            or profile["required_adjacency_direction"] != direction
            or profile["entry_to_required_shortest_path"] != 1
        ):
            raise VerificationError(f"required graph topology mismatch: {task_id}")


def _post_capture_drift_check(root: Path, initial_lock_raw: bytes, lock: dict) -> None:
    try:
        current_lock = safe_read_file(root, LOCK_RELATIVE.as_posix())
        if current_lock != initial_lock_raw: raise VerificationError("post-capture lock drift")
        metadata = enumerate_v1_metadata(root)
        expected_paths = {str(item["path"]) for item in lock["public_inventory"] + lock["scorer_inventory"]}
        if set(metadata) != expected_paths: raise VerificationError("post-capture inventory drift")
        for item in lock["public_inventory"] + lock["scorer_inventory"]:
            safe_read_file(root, str(item["path"]), expected=item)
        bindings = lock["packer_bindings"]
        safe_read_file(root, CANONICAL_PACKER.as_posix(), expected=bindings["canonical"])
        safe_read_file(root, PLUGIN_PACKER.as_posix(), expected=bindings["plugin"])
        if lock["python_binding"] != python_binding(): raise VerificationError("post-capture Python drift")
    except VerificationError as exc:
        if str(exc).startswith("post-capture"):
            raise
        raise VerificationError(f"post-capture repository drift: {exc}") from exc


def verify_repository(
    root: Path, *, phase_observer: Callable[[str, dict], None] | None = None,
    captured_lock_bytes: bytes | None = None,
    expected_lock_sha256: str | None = None,
    expected_tree_root: str | None = None,
) -> dict:
    root = Path(root).resolve(strict=True)
    observer = phase_observer or (lambda _event, _payload: None)
    lock_raw = captured_lock_bytes if captured_lock_bytes is not None else safe_read_file(root, LOCK_RELATIVE.as_posix())
    lock = parse_lock(lock_raw, expected_lock_sha256=expected_lock_sha256, expected_tree_root=expected_tree_root)
    snapshot = capture_public_snapshot(root, lock)
    public_files = snapshot["files"]
    assert isinstance(public_files, dict)
    observer("public_snapshot_sealed", {"public_tree_root_sha256": lock["public_tree_root_sha256"]})
    public = _validate_instances_from_files(public_files, include_scorer=False)
    tasks, profiles = validate_public_tasks(public_files, public["tasks"], public["arms"])
    task_map = {task["task_id"]: task for task in tasks}
    outcomes: dict[tuple[str, str], dict] = {}
    seals: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="contextguard-g2-snapshot-") as temporary:
        projection_root = Path(temporary)
        projection_root.chmod(0o700)
        for task in tasks:
            for arm in ARMS:
                destination = projection_root / task["task_id"] / arm
                projection, inventory = _materialize_from_snapshot(public_files, task, arm, destination)
                if FORBIDDEN_PUBLIC_KEYS & recursive_keys(projection):
                    raise VerificationError("oracle data present in arm projection")
                payload = execute_arm(snapshot["packer"], destination / "workspace", inventory, task, arm)
                outcomes[(task["task_id"], arm)] = payload
                structural = {
                    "adaptive_k_application": copy.deepcopy(payload.get("adaptive_k_application")),
                    "adaptive_k_selected_evidence": copy.deepcopy(
                        payload.get("adaptive_k", {}).get("selected_evidence")
                    ),
                    "graph_application": copy.deepcopy(payload.get("graph_application")),
                    "selected_paths": selected_paths(payload),
                    "symbol_memory": copy.deepcopy(payload.get("symbol_memory")),
                }
                sealed_record = {"arm": arm, "structural": structural, "task_id": task["task_id"]}
                seal = {
                    "arm": arm,
                    "sealed_fields": list(SEALED_FIELDS),
                    "sha256": hashlib.sha256(json.dumps(sealed_record, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                    "task_id": task["task_id"],
                }
                seals.append(seal)
                observer("output_sealed", dict(seal))
    if len(seals) != 24: raise VerificationError("all four outputs per task were not sealed")
    observer("all_outputs_sealed", {"sealed_output_count": len(seals)})
    scorer_files = _capture_entries(root, lock["scorer_inventory"])
    observer("oracle_load", {"sealed_output_count": len(seals)})
    all_files = dict(public_files)
    all_files.update(scorer_files)
    scorer = _validate_instances_from_files(all_files, include_scorer=True)
    oracle = validate_oracle(tasks, scorer["oracle"])
    validate_graph_evidence(all_files, task_map, scorer["graph"], outcomes, oracle)
    validate_required_topology(all_files, tasks, oracle)
    adaptive_scores = score_adaptive_labels(tasks, oracle, outcomes)
    required_symbol_count = validate_required_symbols(all_files, tasks, oracle, outcomes)
    for task in tasks:
        task_id = task["task_id"]
        required = set(oracle[task_id]["required_paths"])
        paths = {arm: set(selected_paths(outcomes[(task_id, arm)])) for arm in ARMS}
        fixture_names = set(_snapshot_fixture(all_files, task))
        if task["stratum"] == "closed_pack":
            if not required <= paths["ordinary"]:
                raise VerificationError(f"closed ordinary pack lacks required evidence: {task_id}")
        else:
            missing = required - paths["ordinary"]
            if not missing: raise VerificationError(f"graph ordinary must miss a required direct import neighbor: {task_id}")
            if not missing <= fixture_names: raise VerificationError(f"realistic fallback required path is not locally recoverable: {task_id}")
            if required <= paths["adaptive_only"]: raise VerificationError(f"graph adaptive_only must preserve ordinary direct-neighbor miss: {task_id}")
            for arm in ("symbol_only", "combined"):
                if not required <= paths[arm]: raise VerificationError(f"graph {arm} failed direct-neighbor recovery: {task_id}")
        for arm in ("adaptive_only", "combined"):
            application = outcomes[(task_id, arm)].get("adaptive_k_application")
            if not isinstance(application, dict): raise VerificationError(f"missing adaptive application receipt: {task_id}/{arm}")
            if application.get("omitted_source_count", 0) < 1: raise VerificationError(f"adaptive arm must prune at least one distractor: {task_id}/{arm}")
            if not required & paths[arm]: raise VerificationError(f"adaptive arm retained no oracle-required source: {task_id}/{arm}")
    _post_capture_drift_check(root, lock_raw, lock)
    encoded = json.dumps(seals, sort_keys=True, separators=(",", ":")).encode()
    return {
        "adaptive_label_count": sum(len(item["adaptive_labels"]) for item in oracle.values()),
        "adaptive_label_score_count": len(adaptive_scores),
        "adaptive_label_scores": adaptive_scores,
        "arms": list(ARMS),
        "freeze_tree_root_sha256": lock["tree_root_sha256"],
        "output_seals": seals,
        "replay_sha256": hashlib.sha256(encoded).hexdigest(),
        "required_symbol_count": required_symbol_count,
        "schema_version": "contextguard.g2-verification-report/v1",
        "sealed_output_count": len(seals),
        "structure_profile_count": len(set(profiles.values())),
        "task_count": len(tasks),
    }


def main() -> int:
    print("direct unbound g2 command is unavailable; use the independently pinned g2-contract-tests profile", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
