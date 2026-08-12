#!/usr/bin/env python3
"""Captured-byte G3 provider-free rehearsal and replay verifier.

The mutable-path command is intentionally unavailable.  The independently
pinned provider-free profile injects this module and every G3/G2 contract byte.
"""

from __future__ import annotations

import __future__
import _colorize
import argparse
import ast
import base64
import collections
import copy
import ctypes
import encodings.idna
import fnmatch
import gettext
import hashlib
import heapq
import importlib.machinery
import importlib.util
import itertools
import json
import locale
import math
import os
import pathlib
import posixpath
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import typing
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType


SCHEMA = "contextguard.g3-rehearsal-manifest/v2"
COST_SCHEMA = "contextguard.g3-cost-model/v1"
ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
TASK_IDS = (
    "train_closed", "train_graph", "calibration_closed", "calibration_graph",
    "evaluation_closed", "evaluation_graph",
)
DETERMINISTIC_FILES = (
    "aggregate-results.json", "events.jsonl", "reproducibility.json",
    "resolved-manifest.json", "task-arm-results.json",
)
TIMING_FILES = ("timing-summary.json", "timing.jsonl")
TIMING_NORMALIZATION = (
    "timing-summary.json:pack_invocation.*_ns",
    "timing.jsonl:*.pack_invocation_ns",
)
OUTPUT_FILES = tuple(sorted(DETERMINISTIC_FILES + TIMING_FILES + ("artifact-inventory.json",)))
SCORER_SUFFIX = "/scorer-only/"
FORBIDDEN_PUBLIC_KEYS = {
    "adaptive_labels", "answer_signature", "expected_output", "graph_evidence",
    "hidden_oracle", "oracle", "required_paths", "required_symbols", "scorer_private",
}


class RehearsalError(Exception):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RehearsalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> object:
    raise RehearsalError(f"non-finite JSON number: {value}")


def parse_json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RehearsalError(f"invalid JSON {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise RehearsalError(f"JSON object required: {label}")
    return value


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def line_slice(raw: bytes, start: int, end: int) -> bytes:
    try:
        lines = raw.decode("utf-8", "strict").splitlines(keepends=True)
    except UnicodeError as exc:
        raise RehearsalError("fixture source is not strict UTF-8") from exc
    if start < 1 or end < start or end > len(lines):
        raise RehearsalError(f"invalid captured source range {start}:{end}")
    return "".join(lines[start - 1:end]).encode("utf-8")


def identity(raw: bytes) -> dict[str, object]:
    return {"bytes": len(raw), "sha256": sha256(raw)}


def map_identity(files: typing.Mapping[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256(b"contextguard.g3-captured-map/v1\x00")
    total = 0
    for path, raw in sorted(files.items()):
        path_raw = path.encode("utf-8")
        digest.update(len(path_raw).to_bytes(8, "big") + path_raw)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        total += len(raw)
    return {"bytes": total, "sha256": digest.hexdigest()}


def recursive_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        result.update(str(key) for key in value)
        for item in value.values():
            result.update(recursive_keys(item))
    elif isinstance(value, list):
        for item in value:
            result.update(recursive_keys(item))
    return result


def reject_private_keys(value: object, label: str) -> None:
    forbidden = FORBIDDEN_PUBLIC_KEYS & recursive_keys(value)
    if forbidden:
        raise RehearsalError(f"private scorer/oracle key in {label}: {sorted(forbidden)[0]}")


def sealed_json(value: object) -> dict[str, object]:
    reject_private_keys(value, "public sealed JSON")
    raw = canonical(value)
    return {
        "canonical_base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "sha256": sha256(raw),
    }


def unseal_json(value: dict, label: str) -> object:
    try:
        raw = base64.b64decode(value["canonical_base64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise RehearsalError(f"invalid sealed JSON receipt: {label}") from exc
    if value != {"canonical_base64": value["canonical_base64"], **identity(raw)}:
        raise RehearsalError(f"sealed JSON receipt identity mismatch: {label}")
    parsed = json.loads(raw.decode("ascii"))
    if canonical(parsed) != raw:
        raise RehearsalError(f"noncanonical sealed JSON receipt: {label}")
    reject_private_keys(parsed, label)
    return parsed


def unseal_all(value: object, label: str) -> None:
    if isinstance(value, dict):
        if set(value) == {"bytes", "canonical_base64", "sha256"}:
            unseal_json(value, label)
            return
        for key, item in value.items():
            unseal_all(item, f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            unseal_all(item, f"{label}[{index}]")


def event_id(value: dict) -> str:
    return sha256(b"contextguard.g3-event/v1\x00" + canonical(value))


def load_g2(raw: bytes, expected_sha256: str) -> types.ModuleType:
    if sha256(raw) != expected_sha256:
        raise RehearsalError("changed independently pinned G2 verifier")
    module = types.ModuleType("captured_contextguard_g2_verifier")
    module.__file__ = "<captured-g2-verifier>"
    sys.modules[module.__name__] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


@dataclass
class BoundaryPolicy:
    root: Path
    g2: types.ModuleType
    lock: dict
    temporary_roots: tuple[Path, ...]
    output_parent: Path | None = None
    phase: str = "public"
    network_denials: int = 0
    dns_denials: int = 0
    process_denials: int = 0
    exec_denials: int = 0
    environment_denials: int = 0
    native_load_denials: int = 0
    out_of_snapshot_read_denials: int = 0
    credential_decoy_denials: int = 0
    authorized_g2_child_processes: int = 0
    post_scorer_experimental_executions: int = 0

    def phase_entries(self) -> list[dict[str, object]]:
        if self.phase == "public":
            return list(self.lock["public_inventory"])
        if self.phase == "scorer":
            return list(self.lock["scorer_inventory"])
        if self.phase == "post_scorer":
            return list(self.lock["public_inventory"] + self.lock["scorer_inventory"])
        return []

    def repository_read_nodes(self) -> set[Path]:
        relatives = {str(item["path"]) for item in self.phase_entries()} | ({
            self.g2.LOCK_RELATIVE.as_posix(),
            self.g2.CANONICAL_PACKER.as_posix(),
            self.g2.PLUGIN_PACKER.as_posix(),
        } if self.phase in {"public", "post_scorer"} else set())
        nodes = {self.root}
        for relative in relatives:
            path = self.root / relative
            nodes.add(path)
            while path != self.root:
                path = path.parent
                nodes.add(path)
        return nodes

    def permitted_absolute_read(self, path: object) -> bool:
        try:
            raw = os.fspath(path)
            if isinstance(raw, bytes):
                raw = os.fsdecode(raw)
            candidate = Path(raw).resolve(strict=False)
        except (TypeError, ValueError, OSError):
            return False
        python = Path(str(self.lock["python_binding"]["path"])).resolve(strict=False)
        if candidate == python or candidate in self.repository_read_nodes():
            return True
        roots = self.temporary_roots
        if self.output_parent is not None:
            roots += (self.output_parent,)
        return any(candidate == root or root in candidate.parents for root in roots)

    def permitted_relative_read(self, path: str) -> bool:
        allowed = {"."}
        for item in self.phase_entries():
            allowed.update(PurePosixPath(str(item["path"])).parts)
        for relative in (() if self.phase == "scorer" else (
            self.g2.LOCK_RELATIVE.as_posix(), self.g2.CANONICAL_PACKER.as_posix(),
            self.g2.PLUGIN_PACKER.as_posix(),
        )):
            allowed.update(PurePosixPath(relative).parts)
        return path in allowed

    def is_within(self, path: object, roots: tuple[Path, ...]) -> bool:
        try:
            raw = os.fspath(path)
            if isinstance(raw, bytes):
                raw = os.fsdecode(raw)
            candidate = Path(raw)
            if not candidate.is_absolute():
                return True  # dirfd-relative opens are authenticated by G2 safe_read_file.
            resolved = candidate.resolve(strict=False)
        except (TypeError, ValueError, OSError):
            return False
        return any(resolved == root or root in resolved.parents for root in roots)

    def audit(self, event: str, args: tuple[object, ...]) -> None:
        if event == "socket.getaddrinfo":
            self.dns_denials += 1
            raise PermissionError("G3 audited boundary denied DNS")
        if event.startswith("socket."):
            self.network_denials += 1
            raise PermissionError("G3 audited boundary denied network")
        if event == "subprocess.Popen":
            executable = str(args[0]) if args else ""
            arguments = list(args[1]) if len(args) > 1 and isinstance(args[1], (list, tuple)) else []
            cwd = args[2] if len(args) > 2 else None
            environment = args[3] if len(args) > 3 else None
            expected_python = str(self.lock["python_binding"]["path"])
            expected = [expected_python, "-I", "-B", "-c", self.g2.PACKER_CHILD_BOOTSTRAP]
            allowed_cwd = cwd is not None and self.is_within(cwd, self.temporary_roots)
            allowed_environment = environment == {"LANG": "C.UTF-8"}
            if (
                self.phase == "public" and executable == expected_python
                and arguments == expected and allowed_cwd and allowed_environment
            ):
                self.authorized_g2_child_processes += 1
                return
            if self.phase != "public":
                self.post_scorer_experimental_executions += 1
            self.process_denials += 1
            raise PermissionError("G3 audited boundary denied process spawn")
        if event.startswith("os.exec") or event.startswith("os.spawn"):
            self.exec_denials += 1
            raise PermissionError("G3 audited boundary denied exec")
        if event in {"os.system", "os.posix_spawn", "os.posix_spawnp"}:
            self.process_denials += 1
            raise PermissionError("G3 audited boundary denied process spawn")
        if event in {"os.putenv", "os.unsetenv"}:
            self.environment_denials += 1
            raise PermissionError("G3 audited boundary denied environment mutation")
        if event == "ctypes.dlopen":
            self.native_load_denials += 1
            raise PermissionError("G3 audited boundary denied native load")
        if event == "import":
            name = args[0] if args else ""
            if name not in sys.modules:
                self.native_load_denials += 1
                raise PermissionError(f"G3 audited boundary denied late load: {name}")
        if event == "open" and args and not isinstance(args[0], int):
            path = args[0]
            path_text = os.fsdecode(path) if isinstance(path, bytes) else str(path)
            lower_name = Path(path_text).name.lower()
            if self.phase == "public" and (
                lower_name in {"oracle.json", "graph.json"}
                or SCORER_SUFFIX in path_text.replace("\\", "/")
            ):
                self.out_of_snapshot_read_denials += 1
                raise PermissionError("G3 public phase denied scorer path")
            if "credential-decoy" in lower_name:
                self.credential_decoy_denials += 1
                self.out_of_snapshot_read_denials += 1
                raise PermissionError("G3 audited boundary denied credential decoy")
            is_absolute = Path(path_text).is_absolute()
            if (
                (is_absolute and not self.permitted_absolute_read(path))
                or (not is_absolute and not self.permitted_relative_read(path_text))
            ):
                self.out_of_snapshot_read_denials += 1
                raise PermissionError("G3 audited boundary denied out-of-snapshot read")

    def receipt(self, sealed_count: int) -> dict[str, object]:
        return {
            "authorized_g2_child_processes": self.authorized_g2_child_processes,
            "claim": "audited_cpython_process_boundary_not_os_sandbox",
            "credential_decoy_denials": self.credential_decoy_denials,
            "dns_denials": self.dns_denials,
            "environment_denials": self.environment_denials,
            "exec_denials": self.exec_denials,
            "native_load_denials": self.native_load_denials,
            "network_denials": self.network_denials,
            "out_of_snapshot_read_denials": self.out_of_snapshot_read_denials,
            "post_scorer_experimental_executions": self.post_scorer_experimental_executions,
            "process_denials": self.process_denials,
            "scorer_loaded_after_seal_count": sealed_count,
        }


_ACTIVE_POLICY: BoundaryPolicy | None = None
_AUDIT_INSTALLED = False


def _audit(event: str, args: tuple[object, ...]) -> None:
    if _ACTIVE_POLICY is not None:
        _ACTIVE_POLICY.audit(event, args)


def install_audit_hook() -> None:
    global _AUDIT_INSTALLED
    if not _AUDIT_INSTALLED:
        sys.addaudithook(_audit)
        _AUDIT_INSTALLED = True


def expect_denial(operation: typing.Callable[[], object], label: str) -> None:
    try:
        operation()
    except (PermissionError, RuntimeError, OSError):
        return
    raise RehearsalError(f"boundary negative probe was not denied: {label}")


def run_boundary_probes(decoy_root: Path) -> None:
    credential = decoy_root / "credential-decoy.json"
    outside = decoy_root / "outside-snapshot-decoy.txt"
    native = decoy_root / "native-decoy.dylib"
    executable = decoy_root / "process-decoy"
    expect_denial(lambda: socket.socket(), "network")
    expect_denial(
        lambda: socket.getaddrinfo(
            "203.0.113.1", 443, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST
        ),
        "DNS",
    )
    expect_denial(
        lambda: subprocess.run([str(executable)], check=False), "process spawn"
    )
    expect_denial(lambda: os.execv(str(executable), [str(executable)]), "exec")
    expect_denial(lambda: os.environ.__setitem__("CONTEXTGUARD_G3_DECOY", "1"), "environment")
    expect_denial(lambda: ctypes.CDLL(str(native)), "native load")
    expect_denial(lambda: credential.read_bytes(), "credential decoy read")
    expect_denial(lambda: outside.read_bytes(), "out-of-snapshot read")


@dataclass(frozen=True, slots=True)
class PreOracleCapture:
    root: Path
    g2: types.ModuleType
    lock_raw: bytes
    lock: typing.Mapping[str, object]
    public_files: typing.Mapping[str, bytes]
    packer_bytes: bytes
    manifest_bytes: bytes
    cost_model_bytes: bytes
    schema_bytes: typing.Mapping[str, bytes]
    receipt_bytes: tuple[bytes, ...]
    seal_bytes: tuple[bytes, ...]
    event_bytes: tuple[bytes, ...]
    retrieval_event_bytes: tuple[bytes, ...]
    timing_values: tuple[tuple[str, str, int], ...]
    pack_invocation_count: int
    context_mutation_count: int
    policy: BoundaryPolicy


def validate_manifest(
    manifest: dict, cost_model: dict, public_files: dict[str, bytes],
    tasks: list[dict], captured_inputs: dict,
) -> None:
    reject_private_keys(manifest, "public G3 manifest")
    reject_private_keys(cost_model, "public G3 cost model")
    if manifest.get("schema_version") != SCHEMA or tuple(manifest.get("arms", ())) != ARMS:
        raise RehearsalError("invalid G3 manifest shape or version")
    if cost_model.get("schema_version") != COST_SCHEMA:
        raise RehearsalError("invalid G3 cost model")
    if manifest.get("cost_model") != cost_model:
        raise RehearsalError("manifest cost model is not byte-equivalent to frozen model")
    g2_source = manifest.get("g2_source")
    if not isinstance(g2_source, dict) or g2_source.get("lock_sha256") is None:
        raise RehearsalError("invalid independently pinned G2 source binding")
    bindings = manifest.get("receipt_bindings")
    if not isinstance(bindings, dict) or bindings.get("captured_inputs") != captured_inputs:
        raise RehearsalError("manifest captured input bindings drift")
    expected_task_bindings = [
        {
            "fixture_inputs_sha256": sha256(canonical(fixture_inputs_from_files(public_files, task))),
            "public_task": identity(canonical(task)),
            "task_id": task["task_id"],
        }
        for task in tasks
    ]
    if bindings.get("tasks") != expected_task_bindings:
        raise RehearsalError("manifest public task or fixture input bindings drift")
    packer_bindings = bindings.get("packer_receipts")
    if not isinstance(packer_bindings, list) or [
        (item.get("task_id"), item.get("arm")) for item in packer_bindings
        if isinstance(item, dict)
    ] != [(task_id, arm) for task_id in TASK_IDS for arm in ARMS]:
        raise RehearsalError("manifest packer receipt binding coverage drift")
    plans = manifest.get("retrieval_plans")
    if not isinstance(plans, list) or [item.get("task_id") for item in plans] != list(TASK_IDS):
        raise RehearsalError("G3 retrieval plans must bind all tasks in canonical order")
    task_map = {task["task_id"]: task for task in tasks}
    for plan in plans:
        if set(plan) != {"closed_world", "fixture_tree_sha256", "steps", "task_id"}:
            raise RehearsalError("invalid closed retrieval plan")
        if plan["closed_world"] is not True:
            raise RehearsalError("retrieval plan is not closed")
        task = task_map[plan["task_id"]]
        if plan["fixture_tree_sha256"] != task["fixture_tree_sha256"]:
            raise RehearsalError("retrieval plan fixture tree drift")
        fixture = task["fixture_root"]
        seen: set[tuple[str, int]] = set()
        for ordinal, step in enumerate(plan["steps"], 1):
            if set(step) != {"kind", "path", "range", "slice", "source"}:
                raise RehearsalError("invalid retrieval step shape")
            if step["kind"] not in {"retrieval", "fallback", "correction"}:
                raise RehearsalError("invalid retrieval step kind")
            path = step["path"]
            if not isinstance(path, str) or (path, ordinal) in seen:
                raise RehearsalError("unsafe or duplicate retrieval step")
            seen.add((path, ordinal))
            source_key = f"research/provider-free-roadmap/g2/v1/{fixture}/{path}"
            raw = public_files.get(source_key)
            if raw is None:
                raise RehearsalError(f"retrieval target absent from captured fixture: {path}")
            start, end = step["range"].get("start"), step["range"].get("end")
            if not isinstance(start, int) or not isinstance(end, int):
                raise RehearsalError("invalid retrieval range")
            sliced = line_slice(raw, start, end)
            if step["source"] != identity(raw) or step["slice"] != identity(sliced):
                raise RehearsalError("retrieval source or slice binding drift")


def plan_by_task(manifest: dict) -> dict[str, dict]:
    return {plan["task_id"]: plan for plan in manifest["retrieval_plans"]}


def binding_by_task(manifest: dict) -> dict[str, dict]:
    return {item["task_id"]: item for item in manifest["receipt_bindings"]["tasks"]}


def packer_binding_by_key(manifest: dict) -> dict[tuple[str, str], dict]:
    return {
        (item["task_id"], item["arm"]): item
        for item in manifest["receipt_bindings"]["packer_receipts"]
    }


def fixture_inputs_from_files(files: dict[str, bytes], task: dict) -> list[dict]:
    prefix = f"research/provider-free-roadmap/g2/v1/{task['fixture_root']}/"
    fixture = {
        path[len(prefix):]: raw for path, raw in files.items() if path.startswith(prefix)
    }
    if not fixture:
        raise RehearsalError(f"captured fixture is empty: {task['task_id']}")
    return [
        {"path": path, "source": identity(raw)} for path, raw in sorted(fixture.items())
    ]


def fixture_inputs(g2: types.ModuleType, files: dict[str, bytes], task: dict) -> list[dict]:
    fixture = g2._snapshot_fixture(files, task)
    result = [
        {"path": path, "source": identity(raw)} for path, raw in sorted(fixture.items())
    ]
    if result != fixture_inputs_from_files(files, task):
        raise RehearsalError("captured fixture projection mismatch")
    return result


def source_receipt(fixture: dict[str, bytes], item: dict) -> dict:
    path = item.get("path")
    lines = item.get("lines")
    if not isinstance(path, str) or path not in fixture or not isinstance(lines, dict):
        raise RehearsalError("invalid bound packer manifest source")
    start, end = lines.get("start"), lines.get("end")
    if not isinstance(start, int) or not isinstance(end, int):
        raise RehearsalError("invalid bound packer manifest range")
    raw = fixture[path]
    sliced = line_slice(raw, start, end)
    return {
        "label": item.get("label"),
        "path": path,
        "priority": item.get("priority"),
        "range": {"end": end, "start": start},
        "slice": identity(sliced),
        "source": identity(raw),
    }


def make_receipt(
    *, g2: types.ModuleType, public_files: dict[str, bytes], task: dict, arm: str,
    payload: dict, plan: dict, cost_model: dict, captured_inputs: dict,
) -> tuple[dict, list[dict], list[dict]]:
    fixture = g2._snapshot_fixture(public_files, task)
    payload_manifest = payload.get("manifest")
    if not isinstance(payload_manifest, dict) or not isinstance(payload_manifest.get("sources"), list):
        raise RehearsalError("bound packer payload lacks manifest sources")
    sources = [source_receipt(fixture, item) for item in payload_manifest["sources"]]
    selected = [item["path"] for item in sources]
    if not selected or len(selected) != len(set(selected)):
        raise RehearsalError("invalid selected paths")
    build = payload.get("build")
    if not isinstance(build, dict) or not isinstance(build.get("pack"), str):
        raise RehearsalError("bound packer payload lacks rendered pack")
    rendered = build["pack"].encode("utf-8")
    if build.get("pack_bytes") != len(rendered) or payload.get("pack_bytes") != len(rendered):
        raise RehearsalError("bound packer rendered byte count mismatch")
    content_address = build.get("content_address", {})
    if content_address.get("digest") != sha256(rendered) or content_address.get("bytes") != len(rendered):
        raise RehearsalError("bound packer content address mismatch")
    pack_event_core = {
        "arm": arm, "event": "pack_captured", "manifest_sources": sources,
        "rendered_pack_sha256": sha256(rendered), "task_id": task["task_id"],
    }
    pack_event = dict(pack_event_core, event_id=event_id(pack_event_core))
    context_items = [
        {
            "origin_event_id": pack_event["event_id"], "path": source["path"],
            "range": source["range"], "slice": source["slice"], "source": source["source"],
        }
        for source in sources
    ]
    retrieval_events: list[dict] = []
    for ordinal, step in enumerate(plan["steps"], 1):
        already = any(item["path"] == step["path"] for item in context_items)
        core = {
            "arm": arm, "kind": step["kind"], "ordinal": ordinal,
            "path": step["path"], "plan_sha256": sha256(canonical(plan)),
            "range": step["range"], "slice": step["slice"], "source": step["source"],
            "status": "already_present" if already else "added", "task_id": task["task_id"],
        }
        identifier = event_id(core)
        round_core = {
            "arm": arm, "event_ids": [identifier], "ordinal": ordinal,
            "task_id": task["task_id"],
        }
        event = dict(
            core, event_id=identifier, round_id=event_id(round_core),
            returned_bytes=0 if already else step["slice"]["bytes"],
        )
        retrieval_events.append(event)
        if not already:
            context_items.append({
                "origin_event_id": identifier, "path": step["path"],
                "range": step["range"], "slice": step["slice"], "source": step["source"],
            })
    context_digest = sha256(canonical(context_items))
    origins = list(dict.fromkeys(item["origin_event_id"] for item in context_items))
    final_core = {
        "arm": arm, "context_sha256": context_digest, "event": "final_context_sealed",
        "origin_event_ids": origins, "task_id": task["task_id"],
    }
    final_event = dict(final_core, event_id=event_id(final_core))
    context_identity = sha256(canonical({
        "final_event_id": final_event["event_id"], "origin_event_ids": origins,
    }))
    packer_receipt = {
        "adaptive_k_application": sealed_json(payload.get("adaptive_k_application")),
        "adaptive_k_selected_evidence": sealed_json(
            payload.get("adaptive_k", {}).get("selected_evidence")
        ),
        "graph_application": sealed_json(payload.get("graph_application")),
        "manifest_sources": sources,
        "pack_bytes": len(rendered),
        "rendered_pack_base64": base64.b64encode(rendered).decode("ascii"),
        "rendered_pack_sha256": sha256(rendered),
        "selected_paths": selected,
        "symbol_memory": sealed_json(payload.get("symbol_memory")),
    }
    receipt = {
        "arm": arm,
        "captured_inputs": copy.deepcopy(captured_inputs),
        "cost_model_sha256": sha256(canonical(cost_model)),
        "final_context": {
            "context_sha256": context_digest, "identity": context_identity,
            "items": context_items, "origin_event_ids": origins,
        },
        "fixture_inputs": fixture_inputs(g2, public_files, task),
        "packer_receipt": packer_receipt,
        "public_task": sealed_json(task),
        "retrieval_events": retrieval_events,
        "retrieval_plan": copy.deepcopy(plan),
        "retrieval_plan_sha256": sha256(canonical(plan)),
        "schema_version": "contextguard.g3-pre-oracle-receipt/v1",
        "stratum": task["stratum"],
        "task_id": task["task_id"],
    }
    receipt["cost"] = recompute_cost(receipt, cost_model)
    return receipt, [pack_event, *retrieval_events, final_event], retrieval_events


def recompute_cost(receipt: dict, cost_model: dict) -> dict:
    events = receipt["retrieval_events"]
    overhead = cost_model["attempt_overhead_bytes"]
    components = {
        "initial_packing": receipt["packer_receipt"]["pack_bytes"],
        "retrieval": sum(overhead + event["returned_bytes"] for event in events if event["kind"] == "retrieval"),
        "fallback": sum(overhead + event["returned_bytes"] for event in events if event["kind"] == "fallback"),
        "correction": sum(overhead + event["returned_bytes"] for event in events if event["kind"] == "correction"),
        "fixed_overhead": cost_model["fixed_overhead_per_task_arm"],
    }
    return {
        "component_formulas": cost_model["component_formulas"],
        "components": components,
        "formula": cost_model["formula"],
        "total": sum(components.values()),
        "units": "byte_equivalent_units",
    }


def capture_pre_oracle(
    root: Path, *, manifest_bytes: bytes, cost_model_bytes: bytes,
    schema_bytes: dict[str, bytes], g2_verifier_bytes: bytes, g2_lock_bytes: bytes,
    expected_g2_lock_sha256: str, expected_g2_tree_root: str,
    expected_g2_verifier_sha256: str,
) -> PreOracleCapture:
    global _ACTIVE_POLICY
    root = Path(root).resolve(strict=True)
    g2 = load_g2(g2_verifier_bytes, expected_g2_verifier_sha256)
    lock = g2.parse_lock(
        g2_lock_bytes, expected_lock_sha256=expected_g2_lock_sha256,
        expected_tree_root=expected_g2_tree_root,
    )
    manifest = parse_json(manifest_bytes, "captured G3 manifest")
    cost_model = parse_json(cost_model_bytes, "captured G3 cost model")
    if manifest.get("g2_source") != {
        "lock_sha256": expected_g2_lock_sha256,
        "tree_root_sha256": expected_g2_tree_root,
        "verifier_sha256": expected_g2_verifier_sha256,
    }:
        raise RehearsalError("G3 manifest does not bind the exact current G2 contract")
    required_schemas = set(manifest.get("schemas", {}).values())
    if required_schemas != set(schema_bytes):
        raise RehearsalError("captured G3 schema set mismatch")
    for name, raw in schema_bytes.items():
        schema = parse_json(raw, f"captured schema {name}")
        g2.assert_supported_schema(schema, name)
        g2.assert_closed_schema(schema, name)
    manifest_schema = parse_json(schema_bytes["manifest.schema.json"], "manifest schema")
    g2.validate_schema(manifest, manifest_schema, manifest_schema, "manifest")

    with tempfile.TemporaryDirectory(prefix="contextguard-g3-boundary-") as boundary_name:
        boundary_root = Path(boundary_name).resolve(strict=True)
        decoys = boundary_root / "decoys"
        projections = boundary_root / "projections"
        decoys.mkdir(mode=0o700)
        projections.mkdir(mode=0o700)
        for name in (
            "credential-decoy.json", "outside-snapshot-decoy.txt",
            "native-decoy.dylib", "process-decoy",
        ):
            (decoys / name).write_bytes(b"decoy only; no credential or executable material\n")
        policy = BoundaryPolicy(root, g2, lock, (projections,))
        install_audit_hook()
        _ACTIVE_POLICY = policy
        try:
            run_boundary_probes(decoys)
            snapshot = g2.capture_public_snapshot(root, lock)
            public_files = snapshot["files"]
            public = g2._validate_instances_from_files(public_files, include_scorer=False)
            tasks, _profiles = g2.validate_public_tasks(public_files, public["tasks"], public["arms"])
            if tuple(task["task_id"] for task in tasks) != TASK_IDS:
                raise RehearsalError("G2 task order drift")
            captured_inputs = {
                "g2_lock": identity(g2_lock_bytes),
                "g2_packer": identity(snapshot["packer"]),
                "g2_public_snapshot": map_identity(public_files),
                "g3_cost_model": identity(cost_model_bytes),
                "g3_schema_set": map_identity(schema_bytes),
            }
            validate_manifest(manifest, cost_model, public_files, tasks, captured_inputs)
            plans = plan_by_task(manifest)
            packer_bindings = packer_binding_by_key(manifest)
            receipts: list[bytes] = []
            seals: list[bytes] = []
            events: list[bytes] = []
            retrieval_event_bytes: list[bytes] = []
            timings: list[tuple[str, str, int]] = []
            for task in tasks:
                for arm in ARMS:
                    destination = projections / task["task_id"] / arm
                    projection, inventory = g2._materialize_from_snapshot(
                        public_files, task, arm, destination
                    )
                    if FORBIDDEN_PUBLIC_KEYS & recursive_keys(projection):
                        raise RehearsalError("scorer data present in public arm projection")
                    started = time.monotonic_ns()
                    result = g2.run_captured_packer_child(
                        packer_bytes=snapshot["packer"], sanitizer_bytes=b"",
                        workspace=destination / "workspace",
                        arguments=g2.arm_arguments(task, arm), frozen_inventory=inventory,
                    )
                    elapsed = time.monotonic_ns() - started
                    if result.returncode != 0:
                        raise RehearsalError(
                            f"bound G2 packer failed for {task['task_id']}/{arm}: "
                            + result.stderr.decode("utf-8", "replace")
                        )
                    payload = g2.load_json_bytes(
                        result.stdout, f"G3 bound packer output {task['task_id']}/{arm}"
                    )
                    receipt, arm_events, retrieval_events = make_receipt(
                        g2=g2, public_files=public_files, task=task, arm=arm,
                        payload=payload, plan=plans[task["task_id"]], cost_model=cost_model,
                        captured_inputs=captured_inputs,
                    )
                    expected_packer = packer_bindings[(task["task_id"], arm)]
                    if sha256(canonical(receipt["packer_receipt"])) != expected_packer[
                        "packer_receipt_sha256"
                    ]:
                        raise RehearsalError(
                            f"captured G2 packer receipt binding drift: {task['task_id']}/{arm}"
                        )
                    del payload, result
                    receipt_raw = canonical(receipt)
                    seal = {
                        "arm": arm,
                        "receipt_sha256": sha256(receipt_raw),
                        "sealed_fields": sorted(receipt),
                        "task_id": task["task_id"],
                    }
                    receipts.append(receipt_raw)
                    seals.append(canonical(seal))
                    events.extend(canonical(event) for event in arm_events)
                    retrieval_event_bytes.extend(canonical(event) for event in retrieval_events)
                    timings.append((task["task_id"], arm, elapsed))
            if len(receipts) != 24 or policy.authorized_g2_child_processes != 24:
                raise RehearsalError("exactly 24 arm receipts must be sealed before scorer load")
            immutable_files = MappingProxyType(dict(public_files))
            capture = PreOracleCapture(
                root=root, g2=g2, lock_raw=bytes(g2_lock_bytes),
                lock=MappingProxyType(copy.deepcopy(lock)), public_files=immutable_files,
                packer_bytes=bytes(snapshot["packer"]), manifest_bytes=bytes(manifest_bytes),
                cost_model_bytes=bytes(cost_model_bytes),
                schema_bytes=MappingProxyType(dict(schema_bytes)),
                receipt_bytes=tuple(receipts), seal_bytes=tuple(seals),
                event_bytes=tuple(events), retrieval_event_bytes=tuple(retrieval_event_bytes),
                timing_values=tuple(timings), pack_invocation_count=24,
                context_mutation_count=len(retrieval_event_bytes), policy=policy,
            )
        finally:
            _ACTIVE_POLICY = None
    return capture


def capture_scorer_files(capture: PreOracleCapture) -> dict[str, bytes]:
    global _ACTIVE_POLICY
    if len(capture.receipt_bytes) != 24 or len(capture.seal_bytes) != 24:
        raise RehearsalError("scorer capture requires exactly 24 immutable seals")
    capture.policy.phase = "scorer"
    _ACTIVE_POLICY = capture.policy
    try:
        result = capture.g2._capture_entries(capture.root, capture.lock["scorer_inventory"])
    finally:
        _ACTIVE_POLICY = None
    return result


def receipt_outcomes(capture: PreOracleCapture) -> tuple[dict, dict]:
    outcomes: dict[tuple[str, str], dict] = {}
    receipts: dict[tuple[str, str], dict] = {}
    for raw in capture.receipt_bytes:
        receipt = parse_json(raw, "sealed pre-oracle receipt")
        key = (receipt["task_id"], receipt["arm"])
        packer = receipt["packer_receipt"]
        outcomes[key] = {
            "adaptive_k_application": unseal_json(
                packer["adaptive_k_application"], "adaptive_k_application"
            ),
            "adaptive_k": {"selected_evidence": unseal_json(
                packer["adaptive_k_selected_evidence"], "adaptive_k_selected_evidence"
            )},
            "graph_application": unseal_json(packer["graph_application"], "graph_application"),
            "manifest": {"sources": [{"path": path} for path in packer["selected_paths"]]},
            "symbol_memory": unseal_json(packer["symbol_memory"], "symbol_memory"),
        }
        receipts[key] = receipt
    if len(outcomes) != 24:
        raise RehearsalError("sealed receipt key collision")
    return outcomes, receipts


def validate_g2_arm_contract(g2: types.ModuleType, files: dict[str, bytes], tasks: list[dict], oracle: dict, outcomes: dict) -> None:
    for task in tasks:
        task_id = task["task_id"]
        required = set(oracle[task_id]["required_paths"])
        paths = {arm: set(g2.selected_paths(outcomes[(task_id, arm)])) for arm in ARMS}
        fixture_names = set(g2._snapshot_fixture(files, task))
        if task["stratum"] == "closed_pack":
            if not required <= paths["ordinary"]:
                raise RehearsalError(f"closed ordinary required evidence mismatch: {task_id}")
        else:
            missing = required - paths["ordinary"]
            if not missing or not missing <= fixture_names:
                raise RehearsalError(f"realistic required path recovery mismatch: {task_id}")
            if required <= paths["adaptive_only"]:
                raise RehearsalError(f"adaptive-only required miss changed: {task_id}")
            for arm in ("symbol_only", "combined"):
                if not required <= paths[arm]:
                    raise RehearsalError(f"symbol required recovery mismatch: {task_id}/{arm}")
        for arm in ("adaptive_only", "combined"):
            application = outcomes[(task_id, arm)].get("adaptive_k_application")
            if not isinstance(application, dict) or application.get("omitted_source_count", 0) < 1:
                raise RehearsalError(f"adaptive application receipt mismatch: {task_id}/{arm}")
            if not required & paths[arm]:
                raise RehearsalError(f"adaptive arm retained no required source: {task_id}/{arm}")


def score_capture(capture: PreOracleCapture, scorer_files: dict[str, bytes]) -> dict:
    g2 = capture.g2
    public_files = dict(capture.public_files)
    public = g2._validate_instances_from_files(public_files, include_scorer=False)
    tasks, profiles = g2.validate_public_tasks(public_files, public["tasks"], public["arms"])
    task_map = {task["task_id"]: task for task in tasks}
    outcomes, receipts = receipt_outcomes(capture)
    if map_identity(public_files) != next(iter(receipts.values()))["captured_inputs"]["g2_public_snapshot"]:
        raise RehearsalError("sealed public snapshot identity mismatch")
    for task in tasks:
        for arm in ARMS:
            receipt = receipts[(task["task_id"], arm)]
            if unseal_json(receipt["public_task"], "public_task") != task:
                raise RehearsalError("sealed public task mismatch")
    all_files = dict(public_files)
    all_files.update(scorer_files)
    scorer = g2._validate_instances_from_files(all_files, include_scorer=True)
    oracle = g2.validate_oracle(tasks, scorer["oracle"])
    g2.validate_graph_evidence(all_files, task_map, scorer["graph"], outcomes, oracle)
    g2.validate_required_topology(all_files, tasks, oracle)
    adaptive_scores = g2.score_adaptive_labels(tasks, oracle, outcomes)
    required_symbols = g2.validate_required_symbols(all_files, tasks, oracle, outcomes)
    validate_g2_arm_contract(g2, all_files, tasks, oracle, outcomes)
    for task in tasks:
        required = set(oracle[task["task_id"]]["required_paths"])
        for arm in ARMS:
            receipt = receipts[(task["task_id"], arm)]
            context_paths = {item["path"] for item in receipt["final_context"]["items"]}
            if not required <= context_paths:
                raise RehearsalError(
                    f"retrieval plan final context lacks required evidence: {task['task_id']}/{arm}"
                )
    return {
        "adaptive_label_score_count": len(adaptive_scores),
        "required_symbol_count": required_symbols,
        "structure_profile_count": len(set(profiles.values())),
        "validation": "full_g2_oracle_graph_topology_adaptive_symbol_arm_passed",
    }


def rational(numerator: int) -> dict[str, int]:
    return {"denominator": 6, "numerator": numerator}


def exact_paired_enumeration(records: list[dict]) -> dict:
    costs: dict[str, list[int]] = {arm: [] for arm in ARMS}
    by_key = {(record["task_id"], record["arm"]): record["cost"]["total"] for record in records}
    for arm in ARMS:
        costs[arm] = [by_key[(task_id, arm)] for task_id in TASK_IDS]
    distributions = {arm: [] for arm in ARMS}
    deltas = {arm: [] for arm in ARMS if arm != "ordinary"}
    for indices in itertools.product(range(6), repeat=6):
        ordinary_sum = sum(costs["ordinary"][index] for index in indices)
        distributions["ordinary"].append(ordinary_sum)
        for arm in ARMS[1:]:
            arm_sum = sum(costs[arm][index] for index in indices)
            distributions[arm].append(arm_sum)
            deltas[arm].append(arm_sum - ordinary_sum)
    lower_rank, upper_rank = 1167, 45490

    def summarize(values: list[int], observed: int) -> dict:
        ordered = sorted(values)
        return {
            "interval_95": {
                "lower": rational(ordered[lower_rank - 1]),
                "upper": rational(ordered[upper_rank - 1]),
            },
            "mean": rational(observed),
        }

    return {
        "confidence_level": {"denominator": 100, "numerator": 95},
        "descriptive_only": True,
        "enumeration_count": 6 ** 6,
        "method": "exact_paired_task_block_enumeration",
        "nearest_rank_95": {"lower": lower_rank, "upper": upper_rank},
        "paired_deltas_vs_ordinary": {
            arm: summarize(deltas[arm], sum(costs[arm]) - sum(costs["ordinary"]))
            for arm in ARMS[1:]
        },
        "per_arm": {
            arm: summarize(distributions[arm], sum(costs[arm])) for arm in ARMS
        },
        "sampling_unit": "paired_task_block",
    }


def nearest_rank(values: list[int], numerator: int, denominator: int) -> int:
    ordered = sorted(values)
    rank = (len(ordered) * numerator + denominator - 1) // denominator
    return ordered[max(0, rank - 1)]


def timing_summary(values: tuple[tuple[str, str, int], ...]) -> dict:
    observations = [value for _task, _arm, value in values]
    ordered = sorted(observations)
    middle = len(ordered) // 2
    median = (ordered[middle - 1] + ordered[middle]) // 2
    return {
        "clock": "time.monotonic_ns",
        "observation_count": 24,
        "pack_invocation": {
            "max_ns": ordered[-1], "median_ns": median, "min_ns": ordered[0],
            "p95_ns": nearest_rank(ordered, 95, 100),
        },
        "schema_version": "contextguard.g3-timing-summary/v1",
        "scope": "exact_bound_packer_child_invocation",
        "task_execution": {"availability": "unavailable", "observations": None},
    }


def normalized_timing_artifacts(artifacts: typing.Mapping[str, bytes]) -> dict[str, bytes]:
    summary = parse_json(artifacts["timing-summary.json"], "timing summary")
    normalized_summary = copy.deepcopy(summary)
    pack_invocation = normalized_summary.get("pack_invocation")
    if not isinstance(pack_invocation, dict):
        raise RehearsalError("timing summary pack invocation is invalid")
    for key in ("max_ns", "median_ns", "min_ns", "p95_ns"):
        if key not in pack_invocation:
            raise RehearsalError("timing summary pack invocation is incomplete")
        pack_invocation[key] = 0
    normalized_events = bytearray()
    observations: list[tuple[str, str, int]] = []
    for raw_line in artifacts["timing.jsonl"].splitlines():
        event = parse_json(raw_line, "timing event")
        if "pack_invocation_ns" not in event:
            raise RehearsalError("timing event pack invocation is missing")
        observations.append((event.get("task_id"), event.get("arm"), event["pack_invocation_ns"]))
        event["pack_invocation_ns"] = 0
        normalized_events.extend(canonical(event))
    expected_identities = [(task, arm) for task in TASK_IDS for arm in ARMS]
    if [(task, arm) for task, arm, _elapsed in observations] != expected_identities:
        raise RehearsalError("timing events do not cover the 24 pack invocations in order")
    if summary != timing_summary(tuple(observations)):
        raise RehearsalError("timing summary does not derive from timing events")
    return {
        "timing-summary.json": canonical(normalized_summary),
        "timing.jsonl": bytes(normalized_events),
    }


def reproducibility_projection(repro: dict) -> dict:
    return {key: value for key, value in repro.items() if key != "deterministic_evidence_sha256"}


def bundle_commitment(artifacts: typing.Mapping[str, bytes], repro: dict) -> str:
    bundle = {
        "aggregate-results.json": artifacts["aggregate-results.json"],
        "events.jsonl": artifacts["events.jsonl"],
        "reproducibility.json": canonical(reproducibility_projection(repro)),
        "resolved-manifest.json": artifacts["resolved-manifest.json"],
        "task-arm-results.json": artifacts["task-arm-results.json"],
        **normalized_timing_artifacts(artifacts),
    }
    digest = hashlib.sha256(b"contextguard.g3-deterministic-bundle/v2\x00")
    for name in sorted(bundle):
        name_raw = name.encode("ascii")
        raw = bundle[name]
        digest.update(len(name_raw).to_bytes(8, "big") + name_raw)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()


def build_artifacts(capture: PreOracleCapture, score: dict) -> dict[str, bytes]:
    manifest = parse_json(capture.manifest_bytes, "captured G3 manifest")
    records: list[dict] = []
    for raw, seal_raw in zip(capture.receipt_bytes, capture.seal_bytes, strict=True):
        receipt = parse_json(raw, "sealed receipt")
        seal = parse_json(seal_raw, "sealed receipt seal")
        records.append({
            "arm": receipt["arm"], "cost": receipt["cost"], "receipt": receipt,
            "receipt_sha256": seal["receipt_sha256"],
            "schema_version": "contextguard.g3-task-arm-result/v2",
            "scorer_validation": score["validation"], "stratum": receipt["stratum"],
            "task_id": receipt["task_id"],
        })
    task_results = {
        "record_count": 24, "records": records,
        "schema_version": "contextguard.g3-task-arm-results/v2",
    }
    aggregate = {
        "availability": {
            "provider_metrics": "unavailable", "savings_claims": "unavailable",
            "token_metrics": "unavailable", "usd_metrics": "unavailable",
        },
        "cost_inference": exact_paired_enumeration(records),
        "record_count": 24,
        "schema_version": "contextguard.g3-aggregate-results/v2",
        "units": "byte_equivalent_units",
    }
    deterministic_core = {
        "aggregate-results.json": canonical(aggregate),
        "events.jsonl": b"".join(capture.event_bytes),
        "resolved-manifest.json": canonical(manifest),
        "task-arm-results.json": canonical(task_results),
    }
    timing_artifacts = {
        "timing.jsonl": b"".join(
            canonical({
                "arm": arm, "pack_invocation_ns": elapsed,
                "schema_version": "contextguard.g3-timing-event/v1", "task_id": task_id,
            })
            for task_id, arm, elapsed in capture.timing_values
        ),
        "timing-summary.json": canonical(timing_summary(capture.timing_values)),
    }
    reproducibility = {
        "boundary": capture.policy.receipt(24),
        "deterministic_evidence_sha256": "0" * 64,
        "environment": {
            "implementation": sys.implementation.name,
            "python": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        },
        "g2_source": manifest["g2_source"],
        "oracle_validation_counts": {
            "adaptive_label_scores": score["adaptive_label_score_count"],
            "required_symbols": score["required_symbol_count"],
            "structure_profiles": score["structure_profile_count"],
        },
        "schema_version": "contextguard.g3-reproducibility/v2",
        "timing_normalization": {
            "excluded_from_deterministic_digest": list(TIMING_NORMALIZATION)
        },
    }
    reproducibility["deterministic_evidence_sha256"] = bundle_commitment(
        {**deterministic_core, **timing_artifacts}, reproducibility
    )
    artifacts = dict(deterministic_core)
    artifacts["reproducibility.json"] = canonical(reproducibility)
    artifacts.update(timing_artifacts)
    return artifacts


def schema_mapping() -> dict[str, str]:
    return {
        "aggregate-results.json": "aggregate-results.schema.json",
        "artifact-inventory.json": "artifact-inventory.schema.json",
        "reproducibility.json": "reproducibility.schema.json",
        "resolved-manifest.json": "manifest.schema.json",
        "task-arm-results.json": "task-arm-results.schema.json",
        "timing-summary.json": "timing-summary.schema.json",
    }


def validate_artifact_schemas(artifacts: dict[str, bytes], schema_bytes: typing.Mapping[str, bytes]) -> None:
    g2 = next(
        (
            module for name, module in sys.modules.items()
            if name == "captured_contextguard_g2_verifier"
        ),
        None,
    )
    if g2 is None:
        raise RehearsalError("captured schema validator is unavailable")
    for artifact_name, schema_name in schema_mapping().items():
        if artifact_name == "artifact-inventory.json" and artifact_name not in artifacts:
            continue
        if artifact_name not in artifacts or schema_name not in schema_bytes:
            raise RehearsalError(f"missing schema binding for {artifact_name}")
        value = parse_json(artifacts[artifact_name], artifact_name)
        schema = parse_json(schema_bytes[schema_name], schema_name)
        g2.assert_supported_schema(schema, schema_name)
        g2.assert_closed_schema(schema, schema_name)
        g2.validate_schema(value, schema, schema, artifact_name)
    event_schema = parse_json(schema_bytes["event.schema.json"], "event schema")
    timing_schema = parse_json(schema_bytes["timing-event.schema.json"], "timing schema")
    for artifact_name, schema in (("events.jsonl", event_schema), ("timing.jsonl", timing_schema)):
        g2.assert_supported_schema(schema, artifact_name)
        g2.assert_closed_schema(schema, artifact_name)
        for raw_line in artifacts[artifact_name].splitlines():
            value = parse_json(raw_line, artifact_name)
            g2.validate_schema(value, schema, schema, artifact_name)


def validate_sealed_packer_claims(receipt: dict) -> None:
    packer = receipt["packer_receipt"]
    claims = {
        key: unseal_json(packer[key], key)
        for key in (
            "adaptive_k_application", "adaptive_k_selected_evidence",
            "graph_application", "symbol_memory",
        )
    }
    expected_presence = {
        "ordinary": (False, False),
        "adaptive_only": (True, False),
        "symbol_only": (False, True),
        "combined": (True, True),
    }[receipt["arm"]]
    adaptive_present, graph_present = expected_presence
    if (
        (claims["adaptive_k_application"] is not None) != adaptive_present
        or (claims["adaptive_k_selected_evidence"] is not None) != adaptive_present
        or (claims["graph_application"] is not None) != graph_present
        or (claims["symbol_memory"] is not None) != graph_present
    ):
        raise RehearsalError("sealed packer claim presence does not match arm")
    selected_paths = packer["selected_paths"]
    fixture_paths = {item["path"] for item in receipt["fixture_inputs"]}
    source_by_path = {item["path"]: item for item in packer["manifest_sources"]}
    if set(selected_paths) - fixture_paths:
        raise RehearsalError("sealed packer claim escaped captured fixture")
    if adaptive_present:
        application = claims["adaptive_k_application"]
        evidence = claims["adaptive_k_selected_evidence"]
        if not isinstance(application, dict) or not isinstance(evidence, dict):
            raise RehearsalError("invalid sealed adaptive claim")
        items = evidence.get("items")
        recommended = application.get("recommended_k")
        if (
            application.get("schema_version") != "contextguard.pack-adaptive-k-application.v1"
            or application.get("status") != "applied"
            or application.get("mode") != "explicit_opt_in"
            or not isinstance(items, list)
            or evidence.get("selected_count") != len(items)
            or isinstance(recommended, bool) or not isinstance(recommended, int)
            or recommended < 1 or application.get("applied_source_count") != recommended
            or application.get("input_source_count") - application.get("omitted_source_count")
            != recommended
        ):
            raise RehearsalError("sealed adaptive claim is not internally derived")
        retained = items[:recommended]
        if [item.get("rank") for item in items] != list(range(1, len(items) + 1)):
            raise RehearsalError("sealed adaptive evidence ranks are not positional")
        for item in retained:
            source = source_by_path.get(item.get("path"))
            if source is None or item.get("lines") != source["range"]:
                raise RehearsalError("sealed adaptive evidence differs from packed sources")
    if graph_present:
        graph = claims["graph_application"]
        symbol = claims["symbol_memory"]
        if not isinstance(graph, dict) or not isinstance(symbol, dict):
            raise RehearsalError("invalid sealed graph or symbol claim")
        selected_sources = graph.get("selected_sources")
        if (
            graph.get("schema_version") != "contextguard.pack-graph-application.v1"
            or not isinstance(selected_sources, list)
            or graph.get("selected_source_count") != len(selected_sources)
            or graph.get("candidate_count") < len(selected_sources)
        ):
            raise RehearsalError("sealed graph claim is not internally derived")
        for item in selected_sources:
            source = source_by_path.get(item.get("path"))
            if source is None or item.get("lines") != source["range"]:
                raise RehearsalError("sealed graph claim differs from packed sources")
        summary = symbol.get("summary")
        graph_context = symbol.get("graph_context")
        symbols = symbol.get("symbols")
        if (
            symbol.get("schema_version") != "contextguard.pack-symbol-memory.v1"
            or not isinstance(summary, dict) or not isinstance(graph_context, list)
            or not isinstance(symbols, list)
            or summary.get("graph_context") != len(graph_context)
            or summary.get("symbols") != len(symbols)
            or any(item.get("path") not in fixture_paths for item in graph_context + symbols)
        ):
            raise RehearsalError("sealed symbol claim is not internally derived")


def semantic_replay(
    artifacts: dict[str, bytes], *, expected_manifest_bytes: bytes,
    expected_manifest_sha256: str,
) -> None:
    if sha256(expected_manifest_bytes) != expected_manifest_sha256:
        raise RehearsalError("authenticated captured manifest hash mismatch")
    manifest = parse_json(expected_manifest_bytes, "authenticated captured manifest")
    if artifacts["resolved-manifest.json"] != canonical(manifest):
        raise RehearsalError("output resolved manifest differs from authenticated captured root")
    model = manifest["cost_model"]
    reject_private_keys(manifest, "resolved manifest")
    plans = plan_by_task(manifest)
    task_bindings = binding_by_task(manifest)
    packer_bindings = packer_binding_by_key(manifest)
    result = parse_json(artifacts["task-arm-results.json"], "task arm results")
    records = result["records"]
    if len(records) != 24 or {
        (record["task_id"], record["arm"]) for record in records
    } != {(task, arm) for task in TASK_IDS for arm in ARMS}:
        raise RehearsalError("semantic replay record coverage mismatch")
    expected_events: list[bytes] = []
    for record in records:
        receipt = record["receipt"]
        reject_private_keys(receipt, "public result receipt")
        unseal_all(receipt, "public result receipt")
        if (
            record["task_id"] != receipt["task_id"]
            or record["arm"] != receipt["arm"]
            or record["stratum"] != receipt["stratum"]
        ):
            raise RehearsalError("semantic replay outer record identity mismatch")
        receipt_raw = canonical(receipt)
        if record["receipt_sha256"] != sha256(receipt_raw):
            raise RehearsalError("semantic replay receipt seal mismatch")
        recomputed_cost = recompute_cost(receipt, model)
        if receipt["cost"] != record["cost"] or record["cost"] != recomputed_cost:
            raise RehearsalError("semantic replay inner/outer/recomputed cost mismatch")
        binding = task_bindings.get(receipt["task_id"])
        if binding is None or receipt["captured_inputs"] != manifest["receipt_bindings"]["captured_inputs"]:
            raise RehearsalError("semantic replay captured input claim mismatch")
        if sha256(canonical(receipt["fixture_inputs"])) != binding["fixture_inputs_sha256"]:
            raise RehearsalError("semantic replay fixture input identity mismatch")
        public_task = unseal_json(receipt["public_task"], "public task")
        if identity(canonical(public_task)) != binding["public_task"]:
            raise RehearsalError("semantic replay public task identity mismatch")
        if (
            public_task.get("task_id") != receipt["task_id"]
            or public_task.get("stratum") != receipt["stratum"]
        ):
            raise RehearsalError(
                "semantic replay receipt stratum differs from authenticated public task"
            )
        validate_sealed_packer_claims(receipt)
        packer = receipt["packer_receipt"]
        expected_packer = packer_bindings.get((receipt["task_id"], receipt["arm"]))
        if (
            expected_packer is None
            or sha256(canonical(packer)) != expected_packer["packer_receipt_sha256"]
        ):
            raise RehearsalError("semantic replay packer provenance binding mismatch")
        rendered = base64.b64decode(packer["rendered_pack_base64"], validate=True)
        if len(rendered) != packer["pack_bytes"] or sha256(rendered) != packer["rendered_pack_sha256"]:
            raise RehearsalError("semantic replay rendered pack mismatch")
        if packer["selected_paths"] != [item["path"] for item in packer["manifest_sources"]]:
            raise RehearsalError("semantic replay selected path mismatch")
        fixture_by_path = {
            item["path"]: item["source"] for item in receipt["fixture_inputs"]
        }
        for source in packer["manifest_sources"]:
            if fixture_by_path.get(source["path"]) != source["source"]:
                raise RehearsalError("semantic replay packed source differs from captured fixture")
        plan = receipt["retrieval_plan"]
        manifest_plan = plans.get(receipt["task_id"])
        if plan != manifest_plan:
            raise RehearsalError("semantic replay receipt plan differs from resolved manifest")
        if receipt["retrieval_plan_sha256"] != sha256(canonical(plan)):
            raise RehearsalError("semantic replay retrieval plan identity mismatch")
        if receipt["cost_model_sha256"] != sha256(canonical(model)):
            raise RehearsalError("semantic replay cost model identity mismatch")
        pack_core = {
            "arm": receipt["arm"], "event": "pack_captured",
            "manifest_sources": packer["manifest_sources"],
            "rendered_pack_sha256": packer["rendered_pack_sha256"],
            "task_id": receipt["task_id"],
        }
        pack_event = dict(pack_core, event_id=event_id(pack_core))
        expected_events.append(canonical(pack_event))
        if len(receipt["retrieval_events"]) != len(plan["steps"]):
            raise RehearsalError("semantic replay retrieval event/plan length mismatch")
        initial_paths = {item["path"] for item in packer["manifest_sources"]}
        added_paths: set[str] = set()
        for position, (retrieval, step) in enumerate(
            zip(receipt["retrieval_events"], plan["steps"], strict=True), 1
        ):
            expected_status = (
                "already_present"
                if step["path"] in initial_paths or step["path"] in added_paths
                else "added"
            )
            projection = {
                "kind": retrieval["kind"], "path": retrieval["path"],
                "range": retrieval["range"], "slice": retrieval["slice"],
                "source": retrieval["source"],
            }
            if (
                position != retrieval["ordinal"] or projection != step
                or retrieval["plan_sha256"] != receipt["retrieval_plan_sha256"]
                or retrieval["status"] != expected_status
                or retrieval["arm"] != receipt["arm"]
                or retrieval["task_id"] != receipt["task_id"]
            ):
                raise RehearsalError("semantic replay retrieval position does not match plan step")
            if expected_status == "added":
                added_paths.add(step["path"])
            core = {
                key: retrieval[key]
                for key in (
                    "arm", "kind", "ordinal", "path", "plan_sha256", "range",
                    "slice", "source", "status", "task_id",
                )
            }
            identifier = event_id(core)
            round_core = {
                "arm": retrieval["arm"], "event_ids": [identifier],
                "ordinal": retrieval["ordinal"], "task_id": retrieval["task_id"],
            }
            expected_returned = 0 if retrieval["status"] == "already_present" else retrieval["slice"]["bytes"]
            if (
                retrieval["event_id"] != identifier
                or retrieval["round_id"] != event_id(round_core)
                or retrieval["returned_bytes"] != expected_returned
            ):
                raise RehearsalError("semantic replay retrieval event identity mismatch")
            expected_events.append(canonical(retrieval))
        items = receipt["final_context"]["items"]
        expected_context = [
            {
                "origin_event_id": pack_event["event_id"], "path": source["path"],
                "range": source["range"], "slice": source["slice"], "source": source["source"],
            }
            for source in packer["manifest_sources"]
        ] + [
            {
                "origin_event_id": event["event_id"], "path": event["path"],
                "range": event["range"], "slice": event["slice"], "source": event["source"],
            }
            for event in receipt["retrieval_events"] if event["status"] == "added"
        ]
        if items != expected_context:
            raise RehearsalError("semantic replay context additions differ from successful events")
        if sha256(canonical(items)) != receipt["final_context"]["context_sha256"]:
            raise RehearsalError("semantic replay final context digest mismatch")
        origins = list(dict.fromkeys(item["origin_event_id"] for item in items))
        if origins != receipt["final_context"]["origin_event_ids"]:
            raise RehearsalError("semantic replay context origin identity mismatch")
        final_core = {
            "arm": receipt["arm"],
            "context_sha256": receipt["final_context"]["context_sha256"],
            "event": "final_context_sealed", "origin_event_ids": origins,
            "task_id": receipt["task_id"],
        }
        final_event = dict(final_core, event_id=event_id(final_core))
        expected_identity = sha256(canonical({
            "final_event_id": final_event["event_id"], "origin_event_ids": origins,
        }))
        if receipt["final_context"]["identity"] != expected_identity:
            raise RehearsalError("semantic replay final context identity mismatch")
        expected_events.append(canonical(final_event))
    if b"".join(expected_events) != artifacts["events.jsonl"]:
        raise RehearsalError("semantic replay event log identity mismatch")
    aggregate = parse_json(artifacts["aggregate-results.json"], "aggregate results")
    if aggregate["cost_inference"] != exact_paired_enumeration(records):
        raise RehearsalError("semantic replay exact enumeration mismatch")
    repro = parse_json(artifacts["reproducibility.json"], "reproducibility")
    expected_repro = {
        "boundary": {
            "authorized_g2_child_processes": 24,
            "claim": "audited_cpython_process_boundary_not_os_sandbox",
            "credential_decoy_denials": 1, "dns_denials": 1,
            "environment_denials": 1, "exec_denials": 1, "native_load_denials": 1,
            "network_denials": 1, "out_of_snapshot_read_denials": 2,
            "post_scorer_experimental_executions": 0, "process_denials": 1,
            "scorer_loaded_after_seal_count": 24,
        },
        "environment": {
            "implementation": sys.implementation.name,
            "python": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
        },
        "g2_source": manifest["g2_source"],
        "oracle_validation_counts": {
            "adaptive_label_scores": 48, "required_symbols": 3, "structure_profiles": 6,
        },
        "schema_version": "contextguard.g3-reproducibility/v2",
        "timing_normalization": {
            "excluded_from_deterministic_digest": list(TIMING_NORMALIZATION)
        },
    }
    if reproducibility_projection(repro) != expected_repro:
        raise RehearsalError("semantic replay reproducibility derivation mismatch")
    if repro["deterministic_evidence_sha256"] != bundle_commitment(artifacts, repro):
        raise RehearsalError("semantic replay deterministic evidence mismatch")


def safe_write(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RehearsalError(f"unsafe staged artifact: {path.name}")


def publish(
    output: Path, artifacts: dict[str, bytes], schema_bytes: typing.Mapping[str, bytes],
    *, expected_manifest_bytes: bytes, expected_manifest_sha256: str,
) -> str:
    output = Path(output)
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RehearsalError("preexisting or symlink output root is prohibited")
    parent = output.parent.resolve(strict=True)
    parent_meta = parent.lstat()
    if stat.S_ISLNK(parent_meta.st_mode) or not stat.S_ISDIR(parent_meta.st_mode):
        raise RehearsalError("unsafe output parent")
    staging = Path(tempfile.mkdtemp(prefix=".contextguard-g3-stage-", dir=parent))
    staging.chmod(0o700)
    try:
        validate_artifact_schemas(artifacts, schema_bytes)
        semantic_replay(
            artifacts, expected_manifest_bytes=expected_manifest_bytes,
            expected_manifest_sha256=expected_manifest_sha256,
        )
        for name in sorted(artifacts):
            safe_write(staging / name, artifacts[name])
        inventory = {
            "artifacts": [
                {"bytes": len(artifacts[name]), "path": name, "sha256": sha256(artifacts[name])}
                for name in sorted(artifacts)
            ],
            "schema_version": "contextguard.g3-artifact-inventory/v1",
            "self_inventory_policy": "excluded_self_referential_file",
            "timing_normalization": {
                "excluded_from_deterministic_digest": list(TIMING_NORMALIZATION)
            },
        }
        inventory_raw = canonical(inventory)
        augmented = dict(artifacts, **{"artifact-inventory.json": inventory_raw})
        validate_artifact_schemas(augmented, schema_bytes)
        safe_write(staging / "artifact-inventory.json", inventory_raw)
        names = sorted(path.name for path in staging.iterdir())
        if names != list(OUTPUT_FILES):
            raise RehearsalError("staged artifact inventory is incomplete or has extras")
        descriptor = os.open(staging, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(staging, output)
        staging = Path()
        return sha256(inventory_raw)
    finally:
        if staging != Path() and staging.exists():
            shutil.rmtree(staging)


def verify_output(
    output: Path, schema_bytes: dict[str, bytes], *, expected_manifest_bytes: bytes,
    expected_manifest_sha256: str,
) -> dict[str, object]:
    output = Path(output)
    metadata = output.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RehearsalError("unsafe published output root")
    names = sorted(path.name for path in output.iterdir())
    if names != list(OUTPUT_FILES):
        raise RehearsalError("published artifact inventory has missing or extra paths")
    artifacts: dict[str, bytes] = {}
    for name in names:
        path = output / name
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600:
            raise RehearsalError(f"unsafe published artifact: {name}")
        artifacts[name] = path.read_bytes()
    inventory = parse_json(artifacts["artifact-inventory.json"], "artifact inventory")
    inventory_entries = inventory.get("artifacts")
    if not isinstance(inventory_entries, list):
        raise RehearsalError("published artifact inventory must be a list")
    inventory_paths = [entry.get("path") for entry in inventory_entries if isinstance(entry, dict)]
    if len(inventory_paths) != len(inventory_entries) or len(inventory_paths) != len(set(inventory_paths)):
        raise RehearsalError("duplicate or invalid published artifact inventory path")
    expected = {entry["path"]: entry for entry in inventory_entries}
    if set(expected) != set(artifacts) - {"artifact-inventory.json"}:
        raise RehearsalError("published inventory coverage mismatch")
    for name, entry in expected.items():
        if entry != {"bytes": len(artifacts[name]), "path": name, "sha256": sha256(artifacts[name])}:
            raise RehearsalError(f"published artifact drift: {name}")
    validate_artifact_schemas(artifacts, schema_bytes)
    semantic_replay(
        artifacts, expected_manifest_bytes=expected_manifest_bytes,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    return {"artifact_count": len(artifacts), "status": "verified"}


def run_captured(root: Path, output: Path, **inputs: object) -> dict[str, object]:
    global _ACTIVE_POLICY
    capture = capture_pre_oracle(root, **inputs)
    scorer_files = capture_scorer_files(capture)
    capture.policy.phase = "post_scorer"
    _ACTIVE_POLICY = capture.policy
    try:
        score = score_capture(capture, scorer_files)
        capture.g2._post_capture_drift_check(capture.root, capture.lock_raw, capture.lock)
    finally:
        _ACTIVE_POLICY = None
    artifacts = build_artifacts(capture, score)
    inventory_sha = publish(
        Path(output), artifacts, capture.schema_bytes,
        expected_manifest_bytes=capture.manifest_bytes,
        expected_manifest_sha256=sha256(capture.manifest_bytes),
    )
    return {
        "artifact_inventory_sha256": inventory_sha,
        "deterministic_evidence_sha256": parse_json(
            artifacts["reproducibility.json"], "reproducibility"
        )["deterministic_evidence_sha256"],
        "record_count": 24,
        "status": "provider_free_rehearsal_recorded",
    }


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable G3 runner is unavailable; use the independently pinned g3-rehearsal-tests profile",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
