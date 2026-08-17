#!/usr/bin/env python3
"""Build and verify the provider-free P3 v3 provider-input rehearsal."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


V3 = Path(__file__).resolve().parent
ROOT = V3.parents[3]
CORPUS = V3 / "corpus-manifest.json"
SCHEDULE = V3 / "schedule.json"
CHECKERS = V3 / "scorer-only/checkers.json"
PROMPT_TEMPLATE = V3 / "provider-prompt-template.txt"
PREREGISTRATION = V3 / "preregistration.json"
CANONICAL_PACKER = ROOT / "context-guard-kit/context_pack.py"
PLUGIN_PACKER = ROOT / "plugins/context-guard/bin/context-guard-pack"
CANONICAL_SANITIZER = ROOT / "context-guard-kit/sanitize_output.py"
PLUGIN_SANITIZER = ROOT / "plugins/context-guard/bin/context-guard-sanitize-output"
CANONICAL_CREDENTIAL_POLICY = ROOT / "context-guard-kit/credential_policy.py"
PLUGIN_CREDENTIAL_POLICY = ROOT / "plugins/context-guard/lib/credential_policy.py"
CAPTURE_SCHEMA = "contextguard.p3-api-factorial-provider-input-freeze/v4"
REPORT_SCHEMA = "contextguard.p3-api-factorial-provider-free-rehearsal/v4"
PREREGISTRATION_COMMIT = "fdafb4c41a79c5885c38ec38b52efacc35ae9d6b"
PROVIDER_TASK_FIELDS = frozenset({"allowed_patch_paths", "prompt"})
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LS_TREE = re.compile(rb"^(100644|100755|120000) blob ([0-9a-f]{40}) +([0-9]+)\t(.+)$", re.DOTALL)
DIFF_PATH = re.compile(rb"^diff --git a/([^\n]+) b/([^\n]+)$", re.MULTILINE)
PRIVATE_ARTIFACT_KEYS = frozenset({
    "prompt", "pack", "response", "symbols", "checkers_by_task_id",
    "tasks_by_id", "required_literals", "forbidden_literals",
    "historical_subject", "excluded_upstream_changed_paths",
})
LIMITS = {
    "archive_bytes": 2_000_000_000,
    "archive_files": 100_000,
    "checker_timeout_seconds": 120,
    "max_pack_bytes": 49_152,
    "max_packer_stdout_bytes": 4_000_000,
    "max_projection_bytes": 32_768,
    "max_prompt_bytes": 96_000,
    "max_response_bytes": 8_192,
    "packer_timeout_seconds": 120,
    "provider_calls": 0,
    "scheduled_units": 288,
    "unique_task_arm_cells": 96,
}


class EvaluationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise EvaluationError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def parse_object(raw: bytes, artifact_name: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationError(f"invalid frozen artifact: {artifact_name}") from exc
    if type(value) is not dict:
        fail(f"invalid frozen artifact: {artifact_name}")
    return value


def load_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvaluationError(f"invalid frozen artifact: {path.name}") from exc
    return parse_object(raw, path.name)


def safe_path(value: str) -> PurePosixPath:
    if type(value) is not str:
        fail("unsafe frozen path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        fail("unsafe frozen path")
    return path


def git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "credential.helper",
        "GIT_CONFIG_VALUE_0": "",
        "GIT_CONFIG_KEY_1": "core.askPass",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "protocol.allow",
        "GIT_CONFIG_VALUE_2": "never",
        "GIT_CONFIG_KEY_3": "http.followRedirects",
        "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
    }


def run_git(
    repo: Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    timeout_seconds: int | float = LIMITS["checker_timeout_seconds"],
) -> bytes:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        fail("invalid source operation timeout")
    try:
        completed = subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=repo,
            env=git_environment(),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=float(timeout_seconds),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvaluationError("captured source operation failed") from exc
    if completed.returncode:
        fail("captured source operation failed")
    return completed.stdout


def parse_ls_tree(raw: bytes) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for record in raw.split(b"\0"):
        if not record:
            continue
        match = LS_TREE.fullmatch(record)
        if match is None:
            prefix = record.split(b"\t", 1)[0][:96].decode("ascii", "replace")
            fail(f"unsupported source tree entry: {prefix}")
        mode, object_sha, size_raw, path_raw = match.groups()
        try:
            path = path_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvaluationError("non-UTF-8 source path") from exc
        safe_path(path)
        if path in seen:
            fail("duplicate source path")
        seen.add(path)
        entries.append({
            "bytes": int(size_raw),
            "mode": mode.decode("ascii"),
            "object_sha": object_sha.decode("ascii"),
            "path": path,
        })
    if not entries or len(entries) > LIMITS["archive_files"]:
        fail("invalid source inventory size")
    return entries


def source_inventory(repo: Path, commit: str) -> list[dict[str, object]]:
    if not HEX40.fullmatch(commit):
        fail("invalid source identity")
    raw = run_git(repo, ["ls-tree", "-r", "-z", "--full-tree", "--long", commit])
    entries = parse_ls_tree(raw)
    request = b"".join((str(item["object_sha"]) + "\n").encode("ascii") for item in entries)
    checked = run_git(
        repo,
        ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input_bytes=request,
    ).splitlines()
    if len(checked) != len(entries):
        fail("offline source blob inventory incomplete")
    for item, line in zip(entries, checked, strict=True):
        expected = f'{item["object_sha"]} blob {item["bytes"]}'.encode("ascii")
        if line != expected:
            fail("offline source blob inventory incomplete")
    return entries


def inventory_identity(entries: list[dict[str, object]]) -> dict[str, object]:
    return {
        "file_count": len(entries),
        "source_bytes": sum(int(item["bytes"]) for item in entries),
        "sha256": sha256(canonical(entries)),
    }


def safe_symlink_destination(link_path: PurePosixPath, target_value: str) -> PurePosixPath:
    target = PurePosixPath(target_value)
    if target.is_absolute() or not target.parts:
        fail("unsafe source symlink target")
    parts = list(link_path.parent.parts)
    for part in target.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                fail("unsafe source symlink target")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        fail("unsafe source symlink target")
    return PurePosixPath(*parts)


def git_blob(repo: Path, commit: str, path: str) -> bytes | None:
    if not HEX40.fullmatch(commit):
        fail("invalid source identity")
    safe_path(path)
    exists = subprocess.run(
        ["/usr/bin/git", "cat-file", "-e", f"{commit}:{path}"],
        cwd=repo,
        env=git_environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=LIMITS["checker_timeout_seconds"],
    )
    if exists.returncode == 0:
        return run_git(repo, ["show", f"{commit}:{path}"])
    tree_exists = subprocess.run(
        ["/usr/bin/git", "cat-file", "-e", f"{commit}^{{tree}}"],
        cwd=repo,
        env=git_environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=LIMITS["checker_timeout_seconds"],
    )
    if tree_exists.returncode:
        fail("captured source operation failed")
    return None


def export_snapshot(
    repo: Path,
    commit: str,
    entries: list[dict[str, object]],
    destination: Path,
) -> list[str]:
    archive = run_git(repo, ["archive", "--format=tar", commit], timeout_seconds=120)
    if len(archive) > LIMITS["archive_bytes"]:
        fail("source archive exceeds resource limit")
    expected = {str(item["path"]): item for item in entries}
    written: set[str] = set()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for member in bundle:
                relative = safe_path(member.name.rstrip("/"))
                target = destination.joinpath(*relative.parts)
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                if member.name not in expected or member.name in written:
                    fail("unsupported or extra source archive entry")
                metadata = expected[member.name]
                if member.issym():
                    if metadata["mode"] != "120000":
                        fail("source archive mode mismatch")
                    safe_symlink_destination(relative, member.linkname)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                    written.add(member.name)
                    continue
                if not member.isfile() or metadata["mode"] == "120000":
                    fail("unsupported source archive entry")
                source = bundle.extractfile(member)
                if source is None:
                    fail("source archive entry unavailable")
                raw = source.read()
                # Git blob IDs are SHA-1 object identities, not raw SHA-256.
                # The object was authenticated by cat-file; archive extraction
                # independently preserves its declared byte count.
                if len(raw) != metadata["bytes"]:
                    fail("source archive entry identity mismatch")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with target.open("xb") as handle:
                    handle.write(raw)
                target.chmod(0o700 if metadata["mode"] == "100755" else 0o600)
                written.add(member.name)
    except (OSError, tarfile.TarError) as exc:
        raise EvaluationError("unable to materialize source snapshot") from exc
    if written != set(expected):
        fail("source archive inventory mismatch")
    initialize_no_history_index(destination, entries)
    return sorted(written)


def initialize_no_history_index(workspace: Path, entries: list[dict[str, object]]) -> None:
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    for item in entries:
        if (
            type(item) is not dict
            or item.get("mode") not in {"100644", "100755", "120000"}
            or not HEX40.fullmatch(str(item.get("object_sha", "")))
            or type(item.get("bytes")) is not int
            or item["bytes"] < 0
        ):
            fail("invalid source index entry")
        safe_path(item.get("path"))
    run_git(workspace, ["init", "--quiet"])
    index_records = b"".join(
        f'{item["mode"]} {item["object_sha"]}\t{item["path"]}\n'.encode("utf-8")
        for item in entries
    )
    run_git(workspace, ["update-index", "--info-only", "--index-info"], input_bytes=index_records)
    if run_git(workspace, ["remote"]).strip() or run_git(workspace, ["rev-list", "--all"]).strip():
        fail("source snapshot retained Git history or a remote")


def install_captured_tool(
    workspace: Path,
    *,
    packer_bytes: bytes,
    sanitizer_bytes: bytes,
    credential_policy_bytes: bytes,
) -> Path:
    tool_root = workspace / ".contextguard-evaluator-tool"
    tool_root.mkdir(mode=0o700, exist_ok=False)
    files = {
        "context_pack.py": packer_bytes,
        "credential_policy.py": credential_policy_bytes,
        "sanitize_output.py": sanitizer_bytes,
    }
    for name, raw in files.items():
        target = tool_root / name
        with target.open("xb") as handle:
            handle.write(raw)
        target.chmod(0o400)
    return tool_root


PACKER_CHILD_BOOTSTRAP = r'''
import __future__, _colorize, argparse, ast, base64, codecs, collections, copy, hashlib, heapq, importlib.machinery, importlib.util
import fnmatch, gettext, json, locale, math, os, pathlib, posixpath, queue, re, shlex, shutil, signal, socket, stat, subprocess, sys, threading, time, types, typing
from dataclasses import dataclass
request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
os.environ.pop("__CF_USER_TEXT_ENCODING", None)
workspace = pathlib.Path(request["workspace"]).resolve(strict=True)
source = base64.b64decode(request["packer_b64"], validate=True)
def inside(path):
    try:
        resolved = pathlib.Path(path if os.path.isabs(os.fspath(path)) else workspace / os.fspath(path)).resolve(strict=False)
    except Exception:
        return False
    return resolved == workspace or workspace in resolved.parents
def deny(event):
    raise RuntimeError("audit boundary denied: " + event)
def allowed_git_ls_files(args):
    if len(args) < 2:
        return False
    executable = os.fspath(args[0])
    argv = args[1]
    if executable not in {"git", "/usr/bin/git"} or not isinstance(argv, (list, tuple)):
        return False
    return list(argv) in (
        ["git", "-C", str(workspace), "ls-files", "-z"],
        ["/usr/bin/git", "-C", str(workspace), "ls-files", "-z"],
    )
def audit(event, args):
    if event == "subprocess.Popen" and allowed_git_ls_files(args):
        return
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
        if path is not None and os.fspath(path) == os.devnull:
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
module.__file__ = str(pathlib.Path(request["module_file"]).resolve(strict=True))
sys.modules[module.__name__] = module
exec(compile(source, module.__file__, "exec"), module.__dict__, module.__dict__)
if request["entrypoint"] == "network_probe":
    socket.socket()
    raise RuntimeError("network probe unexpectedly succeeded")
if request["entrypoint"] == "process_probe":
    subprocess.run(["/usr/bin/true"], check=False)
    raise RuntimeError("process probe unexpectedly succeeded")
if request["entrypoint"] == "write_probe":
    pathlib.Path("audit-write-probe").write_bytes(b"forbidden")
    raise RuntimeError("write probe unexpectedly succeeded")
if request["entrypoint"] == "outside_read_probe":
    pathlib.Path(request["outside_probe"]).read_bytes()
    raise RuntimeError("outside read probe unexpectedly succeeded")
raise SystemExit(module.main(list(request["arguments"])))
'''


def run_captured_packer(
    *,
    packer_bytes: bytes,
    workspace: Path,
    module_file: Path,
    arguments: list[str],
    entrypoint: str = "packer",
) -> subprocess.CompletedProcess[bytes]:
    workspace_resolved = workspace.resolve(strict=True)
    module_resolved = module_file.resolve(strict=True)
    if (
        workspace_resolved not in module_resolved.parents
        or module_resolved.read_bytes() != packer_bytes
    ):
        fail("captured packer module identity mismatch")
    request = {
        "arguments": arguments,
        "entrypoint": entrypoint,
        "module_file": str(module_resolved),
        "outside_probe": str(workspace_resolved.parent / "audit-outside-probe"),
        "packer_b64": base64.b64encode(packer_bytes).decode("ascii"),
        "workspace": str(workspace_resolved),
    }
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", PACKER_CHILD_BOOTSTRAP],
            cwd=workspace,
            env={"LANG": "C.UTF-8"},
            input=json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=LIMITS["packer_timeout_seconds"],
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvaluationError("captured shipped packer failed") from exc
    if len(completed.stdout) > LIMITS["max_packer_stdout_bytes"]:
        fail("captured shipped packer output exceeds resource limit")
    return completed


def audit_boundary_receipt(packer_bytes: bytes, workspace: Path, module_file: Path) -> dict[str, int]:
    outside_probe = workspace.resolve(strict=True).parent / "audit-outside-probe"
    with outside_probe.open("xb") as handle:
        handle.write(b"public fixed audit probe\n")
    outside_probe.chmod(0o400)
    denied = 0
    for entrypoint in ("network_probe", "process_probe", "write_probe", "outside_read_probe"):
        completed = run_captured_packer(
            packer_bytes=packer_bytes,
            workspace=workspace,
            module_file=module_file,
            arguments=[],
            entrypoint=entrypoint,
        )
        if completed.returncode == 0 or b"audit boundary denied" not in completed.stderr:
            fail("captured packer audit boundary self-test failed")
        denied += 1
    return {"attempted": 4, "denied": denied, "succeeded": 0}


def arm_arguments(task: dict[str, Any], *, adaptive: bool, graph: bool) -> list[str]:
    arguments = [
        # The retrieval query is a frozen public task-contract field, not a
        # scorer or historical-answer field. Using the first allowed path keeps
        # selection grounded in the requested edit surface across languages.
        "auto", "--root", ".", "--query", task["allowed_patch_paths"][0],
        "--files", ",".join(task["allowed_patch_paths"]),
        "--top", "12", "--budget-bytes", str(LIMITS["max_pack_bytes"]),
        "--context-lines", "6", "--no-artifact", "--json",
    ]
    if adaptive:
        arguments += ["--apply-adaptive-k", "--adaptive-k-policy", "precision"]
    arguments.append("--apply-symbol-memory" if graph else "--symbol-memory")
    return arguments


def load_packer_payload(completed: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    if completed.returncode:
        fail("captured shipped packer failed")
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvaluationError("captured shipped packer returned invalid JSON") from exc
    if type(value) is not dict:
        fail("captured shipped packer returned invalid JSON")
    return value


def normalize_provider_pack(pack: str, workspace: Path) -> bytes:
    if type(pack) is not str:
        fail("captured shipped packer omitted rendered pack")
    resolved = str(workspace.resolve(strict=False))
    normalized = pack.replace(shlex.quote(resolved), ".").replace(resolved, ".")
    for line in normalized.splitlines():
        if line.startswith("Retrieval: `") and " --root /" in line:
            fail("provider pack retained an absolute path")
    if resolved in normalized:
        fail("provider pack retained snapshot path")
    raw = normalized.encode("utf-8")
    if not raw or len(raw) > LIMITS["max_pack_bytes"]:
        fail("provider pack resource limit exceeded")
    return raw


def pure_symbol_projection(payload: dict[str, Any]) -> bytes:
    memory = payload.get("symbol_memory")
    if type(memory) is not dict or type(memory.get("symbols")) is not list:
        fail("captured shipped packer omitted symbol memory")
    projected: list[dict[str, object]] = []
    allowed = ("path", "kind", "name", "signature", "line")
    for symbol in memory["symbols"]:
        if type(symbol) is not dict or any(key not in symbol for key in allowed):
            fail("invalid shipped symbol record")
        item = {key: symbol[key] for key in allowed}
        if not all(type(item[key]) is str for key in ("path", "kind", "name", "signature")):
            fail("invalid shipped symbol record")
        if type(item["line"]) is not int or item["line"] < 1:
            fail("invalid shipped symbol record")
        safe_path(str(item["path"]))
        projected.append(item)
    projected.sort(key=lambda item: (
        str(item["path"]), int(item["line"]), str(item["kind"]),
        str(item["name"]), str(item["signature"]),
    ))
    if not projected:
        fail("pure symbol projection is empty")
    raw = canonical({"schema_version": "contextguard.p3-v3-pure-symbol-projection/v1", "symbols": projected})
    if len(raw) > LIMITS["max_projection_bytes"]:
        fail("pure symbol projection resource limit exceeded")
    return raw


def application_metadata(payload: dict[str, Any], *, adaptive: bool, graph: bool) -> dict[str, object]:
    adaptive_receipt = payload.get("adaptive_k_application")
    if adaptive:
        if (
            type(adaptive_receipt) is not dict
            or adaptive_receipt.get("status") not in {"applied", "no_change"}
            or adaptive_receipt.get("mode") != "explicit_opt_in"
        ):
            fail("adaptive application was not applied")
        omitted = int(adaptive_receipt.get("omitted_source_count", 0))
        adaptive_meta = {
            "applied_source_count": adaptive_receipt.get("applied_source_count"),
            "input_source_count": adaptive_receipt.get("input_source_count"),
            "omitted_source_count": omitted,
            "receipt_sha256": sha256(canonical(adaptive_receipt)),
            "status": "applied" if omitted else "applied_no_omission",
        }
    else:
        if adaptive_receipt is not None:
            fail("unexpected adaptive application receipt")
        adaptive_meta = {
            "applied_source_count": None,
            "input_source_count": None,
            "omitted_source_count": None,
            "receipt_sha256": sha256(canonical({"status": "not_requested"})),
            "status": "not_requested",
        }
    graph_receipt = payload.get("graph_application")
    if graph:
        if type(graph_receipt) is not dict or graph_receipt.get("mode") != "explicit_opt_in":
            fail("graph application was not applied")
        selected = int(graph_receipt.get("selected_source_count", 0))
        graph_meta = {
            "candidate_count": graph_receipt.get("candidate_count"),
            "selected_source_count": selected,
            "receipt_sha256": sha256(canonical(graph_receipt)),
            "status": "applied" if selected else "applied_no_candidates",
        }
    else:
        if graph_receipt is not None:
            fail("unexpected graph application receipt")
        graph_meta = {
            "candidate_count": None,
            "selected_source_count": None,
            "receipt_sha256": sha256(canonical({"status": "not_requested"})),
            "status": "not_requested",
        }
    return {"adaptive": adaptive_meta, "graph_closure": graph_meta}


def provider_task_projection(task: dict[str, Any]) -> dict[str, object]:
    if set(task) != PROVIDER_TASK_FIELDS:
        fail("provider task field allowlist mismatch")
    allowed = task.get("allowed_patch_paths")
    prompt = task.get("prompt")
    if type(allowed) is not list or not allowed or any(type(path) is not str for path in allowed):
        fail("invalid provider task fields")
    if len(allowed) != len(set(allowed)):
        fail("invalid provider task fields")
    for path in allowed:
        safe_path(path)
    if type(prompt) is not str or not prompt:
        fail("invalid provider task fields")
    return {"allowed_patch_paths": list(allowed), "prompt": prompt}


def render_provider_prompt(task_projection: dict[str, object], pack: bytes, projection: bytes) -> bytes:
    provider_task_projection(task_projection)
    try:
        prompt = PROMPT_TEMPLATE.read_text(encoding="utf-8").format(
            allowed_patch_paths_json=json.dumps(
                task_projection["allowed_patch_paths"], ensure_ascii=True, separators=(",", ":")
            ),
            context_pack=pack.decode("utf-8", errors="strict"),
            symbol_projection_or_empty=projection.decode("utf-8", errors="strict"),
            task_prompt=task_projection["prompt"],
        ).encode("utf-8")
    except (UnicodeError, KeyError, ValueError) as exc:
        raise EvaluationError("unable to render provider input") from exc
    if len(prompt) > LIMITS["max_prompt_bytes"]:
        fail("provider input resource limit exceeded")
    return prompt


def cell_identity(cell: dict[str, Any]) -> str:
    unsigned = dict(cell)
    unsigned.pop("cell_seal_sha256", None)
    return sha256(canonical(unsigned))


def binding_identity(binding: dict[str, Any]) -> str:
    unsigned = dict(binding)
    unsigned.pop("binding_sha256", None)
    return sha256(canonical(unsigned))


def capture_identity(capture: dict[str, Any]) -> str:
    unsigned = dict(capture)
    unsigned.pop("capture_sha256", None)
    return sha256(canonical(unsigned))


def relative_identity(path: Path, repo_root: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {
        "bytes": len(raw),
        "path": path.relative_to(repo_root).as_posix(),
        "sha256": sha256(raw),
    }


def artifact_identities(repo_root: Path) -> dict[str, dict[str, object]]:
    paths = {
        "canonical_packer": CANONICAL_PACKER,
        "canonical_credential_policy": CANONICAL_CREDENTIAL_POLICY,
        "canonical_sanitizer": CANONICAL_SANITIZER,
        "corpus": CORPUS,
        "evaluator": Path(__file__).resolve(),
        "plugin_packer": PLUGIN_PACKER,
        "plugin_credential_policy": PLUGIN_CREDENTIAL_POLICY,
        "plugin_sanitizer": PLUGIN_SANITIZER,
        "preregistration": PREREGISTRATION,
        "prompt_template": PROMPT_TEMPLATE,
        "schedule": SCHEDULE,
    }
    result = {name: relative_identity(path, repo_root) for name, path in paths.items()}
    if CANONICAL_PACKER.read_bytes() != PLUGIN_PACKER.read_bytes():
        fail("canonical and plugin packer bytes differ")
    if CANONICAL_SANITIZER.read_bytes() != PLUGIN_SANITIZER.read_bytes():
        fail("canonical and plugin sanitizer bytes differ")
    if CANONICAL_CREDENTIAL_POLICY.read_bytes() != PLUGIN_CREDENTIAL_POLICY.read_bytes():
        fail("canonical and plugin credential policy bytes differ")
    preregistration_path = PREREGISTRATION.relative_to(repo_root).as_posix()
    committed_preregistration = run_git(
        repo_root,
        ["show", f"{PREREGISTRATION_COMMIT}:{preregistration_path}"],
    )
    if committed_preregistration != PREREGISTRATION.read_bytes():
        fail("preregistration commit binding mismatch")
    return result


def capture_task_cells(
    *,
    task: dict[str, Any],
    workspace: Path,
    packer_bytes: bytes,
    sanitizer_bytes: bytes,
    credential_policy_bytes: bytes,
    source_metadata: dict[str, object],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    task_projection = provider_task_projection({key: task[key] for key in sorted(PROVIDER_TASK_FIELDS)})
    task_projection_sha = sha256(canonical(task_projection))
    modes: dict[tuple[bool, bool], dict[str, Any]] = {}
    raw_packs: dict[tuple[bool, bool], bytes] = {}
    base_payload: dict[str, Any] | None = None
    tool_root = install_captured_tool(
        workspace,
        packer_bytes=packer_bytes,
        sanitizer_bytes=sanitizer_bytes,
        credential_policy_bytes=credential_policy_bytes,
    )
    for adaptive in (False, True):
        for graph in (False, True):
            payload = load_packer_payload(run_captured_packer(
                packer_bytes=packer_bytes,
                workspace=workspace,
                module_file=tool_root / "context_pack.py",
                arguments=arm_arguments(task_projection, adaptive=adaptive, graph=graph),
            ))
            build = payload.get("build")
            manifest = payload.get("manifest")
            if type(build) is not dict or type(manifest) is not dict:
                fail("captured shipped packer omitted structural output")
            pack = normalize_provider_pack(build.get("pack"), workspace)
            try:
                applications = application_metadata(payload, adaptive=adaptive, graph=graph)
            except EvaluationError as exc:
                raise EvaluationError(
                    f'{task["id"]} shipped factor application failed '
                    f'(adaptive={adaptive}, graph={graph}): {exc}'
                ) from None
            metadata = {
                "applications": applications,
                "context_pack_bytes": len(pack),
                "context_pack_sha256": sha256(pack),
                "manifest_sha256": sha256(canonical(manifest)),
                "manifest_source_count": len(manifest.get("sources", []))
                if type(manifest.get("sources")) is list else -1,
            }
            if metadata["manifest_source_count"] < 1:
                fail("captured shipped packer returned empty manifest")
            modes[(adaptive, graph)] = metadata
            raw_packs[(adaptive, graph)] = pack
            if not adaptive and not graph:
                base_payload = payload
    if base_payload is None:
        fail("ordinary shipped packer output missing")
    projection = pure_symbol_projection(base_payload)
    cells: list[dict[str, Any]] = []
    private_prompts: dict[str, bytes] = {}
    for adaptive in (False, True):
        for symbol_memory in (False, True):
            for graph in (False, True):
                arm_id = f"a{int(adaptive)}{int(symbol_memory)}{int(graph)}"
                pack = raw_packs[(adaptive, graph)]
                symbol_projection = projection if symbol_memory else b""
                prompt = render_provider_prompt(task_projection, pack, symbol_projection)
                cell_id = f'{task["id"]}:{arm_id}'
                cell = {
                    "applications": modes[(adaptive, graph)]["applications"],
                    "arm": {
                        "adaptive": adaptive,
                        "graph_closure": graph,
                        "id": arm_id,
                        "symbol_memory": symbol_memory,
                    },
                    "cell_id": cell_id,
                    "context_pack_bytes": len(pack),
                    "context_pack_sha256": sha256(pack),
                    "manifest_sha256": modes[(adaptive, graph)]["manifest_sha256"],
                    "manifest_source_count": modes[(adaptive, graph)]["manifest_source_count"],
                    "producer": "captured_shipped_context_pack",
                    "prompt_bytes": len(prompt),
                    "prompt_sha256": sha256(prompt),
                    "provider_task_projection_sha256": task_projection_sha,
                    "source_inventory_sha256": source_metadata["inventory_sha256"],
                    "source_tree_sha": task["parent_tree_sha"],
                    "symbol_projection_bytes": len(symbol_projection),
                    "symbol_projection_sha256": sha256(symbol_projection),
                    "task_id": task["id"],
                }
                cell["cell_seal_sha256"] = cell_identity(cell)
                cells.append(cell)
                private_prompts[cell_id] = prompt
    return cells, private_prompts


def factor_pairs(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(cell["task_id"], cell["arm"]["id"]): cell for cell in cells}
    tasks = sorted({cell["task_id"] for cell in cells})
    pairs: list[dict[str, str]] = []
    for task_id in tasks:
        for factor, bit in (("adaptive", 0), ("symbol_memory", 1), ("graph_closure", 2)):
            for arm_id in sorted(cell["arm"]["id"] for cell in cells if cell["task_id"] == task_id):
                digits = arm_id[1:]
                if digits[bit] != "0":
                    continue
                enabled = "a" + digits[:bit] + "1" + digits[bit + 1:]
                disabled_cell = by_key[(task_id, arm_id)]
                enabled_cell = by_key[(task_id, enabled)]
                section_keys = (
                    "context_pack_sha256", "provider_task_projection_sha256",
                    "symbol_projection_sha256",
                )
                pairs.append({
                    "changed_provider_sections": sorted(
                        key for key in section_keys if disabled_cell[key] != enabled_cell[key]
                    ),
                    "disabled_cell_id": by_key[(task_id, arm_id)]["cell_id"],
                    "enabled_cell_id": by_key[(task_id, enabled)]["cell_id"],
                    "factor": factor,
                })
    return pairs


def schedule_bindings(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    schedule = load_object(SCHEDULE)
    by_id = {cell["cell_id"]: cell for cell in cells}
    result: list[dict[str, Any]] = []
    for block in schedule.get("blocks", []):
        for unit in block.get("units", []):
            cell_id = f'{unit.get("task_id")}:{unit.get("arm_id")}'
            cell = by_id.get(cell_id)
            if cell is None:
                fail("schedule binding references unknown cell")
            binding = {
                "arm_id": unit.get("arm_id"),
                "cell_id": cell_id,
                "prompt_sha256": cell["prompt_sha256"],
                "repetition": unit.get("repetition"),
                "task_id": unit.get("task_id"),
                "unit_id": unit.get("unit_id"),
            }
            binding["binding_sha256"] = binding_identity(binding)
            result.append(binding)
    return result


def recursive_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = set(value)
        for item in value.values():
            result.update(recursive_keys(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(recursive_keys(item))
        return result
    return set()


def validate_factor_isolation(cells: list[dict[str, Any]], pairs: list[dict[str, str]]) -> None:
    if len(pairs) != 144:
        fail("factor isolation accounting mismatch")
    by_id = {cell["cell_id"]: cell for cell in cells}
    if len(by_id) != len(cells):
        fail("cell accounting mismatch")
    section_keys = {
        "context_pack_sha256", "provider_task_projection_sha256", "symbol_projection_sha256",
    }
    for pair in pairs:
        if set(pair) != {"changed_provider_sections", "disabled_cell_id", "enabled_cell_id", "factor"}:
            fail("factor isolation pair shape mismatch")
        disabled = by_id.get(pair["disabled_cell_id"])
        enabled = by_id.get(pair["enabled_cell_id"])
        if disabled is None or enabled is None or disabled["task_id"] != enabled["task_id"]:
            fail("factor isolation pair mismatch")
        factor = pair["factor"]
        allowed_changes = {
            "adaptive": {"context_pack_sha256"},
            "graph_closure": {"context_pack_sha256"},
            "symbol_memory": {"symbol_projection_sha256"},
        }.get(factor)
        if allowed_changes is None:
            fail("factor isolation factor mismatch")
        changed = {key for key in section_keys if disabled[key] != enabled[key]}
        if changed != set(pair["changed_provider_sections"]):
            fail("factor isolation section mismatch")
        if (disabled["prompt_sha256"] != enabled["prompt_sha256"]) != bool(changed):
            fail("factor isolation prompt mismatch")
        if factor == "symbol_memory":
            if changed != allowed_changes:
                fail("factor isolation section mismatch")
        elif not changed.issubset(allowed_changes):
            fail("factor isolation section mismatch")
        for key in ("adaptive", "graph_closure", "symbol_memory"):
            if (disabled["arm"][key] != enabled["arm"][key]) != (key == factor):
                fail("factor isolation arm mismatch")


def validate_application_metadata(applications: object, arm: dict[str, Any]) -> None:
    if type(applications) is not dict or set(applications) != {"adaptive", "graph_closure"}:
        fail("cell metadata shape mismatch")
    adaptive = applications.get("adaptive")
    graph = applications.get("graph_closure")
    if type(adaptive) is not dict or set(adaptive) != {
        "applied_source_count", "input_source_count", "omitted_source_count",
        "receipt_sha256", "status",
    }:
        fail("cell metadata shape mismatch")
    if type(graph) is not dict or set(graph) != {
        "candidate_count", "receipt_sha256", "selected_source_count", "status",
    }:
        fail("cell metadata shape mismatch")
    if not HEX64.fullmatch(str(adaptive.get("receipt_sha256", ""))) or not HEX64.fullmatch(
        str(graph.get("receipt_sha256", ""))
    ):
        fail("cell application identity mismatch")
    not_requested_sha = sha256(canonical({"status": "not_requested"}))
    if arm["adaptive"]:
        counts = (
            adaptive.get("applied_source_count"), adaptive.get("input_source_count"),
            adaptive.get("omitted_source_count"),
        )
        if (
            any(type(value) is not int or value < 0 for value in counts)
            or counts[0] + counts[2] != counts[1]
            or counts[1] < 1
            or adaptive.get("status") != ("applied" if counts[2] else "applied_no_omission")
        ):
            fail("cell application accounting mismatch")
    elif adaptive != {
        "applied_source_count": None,
        "input_source_count": None,
        "omitted_source_count": None,
        "receipt_sha256": not_requested_sha,
        "status": "not_requested",
    }:
        fail("cell application accounting mismatch")
    if arm["graph_closure"]:
        candidate_count = graph.get("candidate_count")
        selected_count = graph.get("selected_source_count")
        if (
            type(candidate_count) is not int
            or type(selected_count) is not int
            or candidate_count < 0
            or not 0 <= selected_count <= candidate_count
            or graph.get("status") != ("applied" if selected_count else "applied_no_candidates")
        ):
            fail("cell application accounting mismatch")
    elif graph != {
        "candidate_count": None,
        "receipt_sha256": not_requested_sha,
        "selected_source_count": None,
        "status": "not_requested",
    }:
        fail("cell application accounting mismatch")


def validate_capture(capture: dict[str, Any], *, repo_root: Path) -> None:
    required = {
        "accounting", "artifact_identities", "boundary", "capture_sha256", "cells", "factor_pairs",
        "limits", "prepared_unit_bindings", "preregistration_commit", "schema_version",
        "source_tasks",
    }
    if set(capture) != required or capture.get("schema_version") != CAPTURE_SCHEMA:
        fail("invalid capture contract")
    if capture.get("preregistration_commit") != PREREGISTRATION_COMMIT or capture.get("limits") != LIMITS:
        fail("invalid capture contract")
    if capture.get("artifact_identities") != artifact_identities(repo_root):
        fail("frozen artifact identity mismatch")
    if capture.get("boundary") != {
        "child_environment": ["LANG"],
        "credentials": "not_available_to_packer_child",
        "network": "denied_by_cpython_audit_hook",
        "provider_calls": 0,
        "source_hydration": "forbidden",
    }:
        fail("provider-free boundary mismatch")
    if PRIVATE_ARTIFACT_KEYS & recursive_keys(capture):
        fail("private material present in metadata-only capture")
    source_tasks = capture.get("source_tasks")
    source_fields = {
        "inventory_file_count", "inventory_sha256", "inventory_source_bytes",
        "parent_commit", "parent_tree_sha", "project_id", "task_id",
    }
    if type(source_tasks) is not list or len(source_tasks) != 12:
        fail("source task accounting mismatch")
    source_by_id: dict[str, dict[str, object]] = {}
    for item in source_tasks:
        if type(item) is not dict or set(item) != source_fields:
            fail("source task shape mismatch")
        task_id = item.get("task_id")
        if type(task_id) is not str or task_id in source_by_id:
            fail("source task accounting mismatch")
        if (
            not HEX64.fullmatch(str(item.get("inventory_sha256", "")))
            or type(item.get("inventory_file_count")) is not int
            or item["inventory_file_count"] < 1
            or type(item.get("inventory_source_bytes")) is not int
            or item["inventory_source_bytes"] < 1
        ):
            fail("source inventory identity mismatch")
        source_by_id[task_id] = item
    cells = capture.get("cells")
    if type(cells) is not list or len(cells) != LIMITS["unique_task_arm_cells"]:
        fail("cell accounting mismatch")
    unique_prompt_count = len({cell.get("prompt_sha256") for cell in cells})
    task_arm_ids: dict[str, set[str]] = {}
    cell_fields = {
        "applications", "arm", "cell_id", "cell_seal_sha256", "context_pack_bytes",
        "context_pack_sha256", "manifest_sha256", "manifest_source_count", "producer",
        "prompt_bytes", "prompt_sha256", "provider_task_projection_sha256",
        "source_inventory_sha256", "source_tree_sha", "symbol_projection_bytes",
        "symbol_projection_sha256", "task_id",
    }
    for cell in cells:
        if type(cell) is not dict or set(cell) != cell_fields:
            fail("cell metadata shape mismatch")
        if cell.get("cell_seal_sha256") != cell_identity(cell):
            fail("cell seal mismatch")
        if cell.get("producer") != "captured_shipped_context_pack":
            fail("cell producer mismatch")
        if any(
            not HEX64.fullmatch(str(cell.get(key, "")))
            for key in (
                "cell_seal_sha256", "context_pack_sha256", "manifest_sha256", "prompt_sha256",
                "provider_task_projection_sha256", "source_inventory_sha256",
                "symbol_projection_sha256",
            )
        ) or not HEX40.fullmatch(str(cell.get("source_tree_sha", ""))):
            fail("prompt identity mismatch")
        if (
            type(cell.get("prompt_bytes")) is not int
            or not 0 < cell["prompt_bytes"] <= LIMITS["max_prompt_bytes"]
        ):
            fail("cell resource limit exceeded")
        if (
            type(cell.get("context_pack_bytes")) is not int
            or not 0 < cell["context_pack_bytes"] <= LIMITS["max_pack_bytes"]
        ):
            fail("cell resource limit exceeded")
        if (
            type(cell.get("symbol_projection_bytes")) is not int
            or not 0 <= cell["symbol_projection_bytes"] <= LIMITS["max_projection_bytes"]
            or type(cell.get("manifest_source_count")) is not int
            or cell["manifest_source_count"] < 1
        ):
            fail("cell resource limit exceeded")
        task_id = cell.get("task_id")
        arm = cell.get("arm")
        if type(task_id) is not str or type(arm) is not dict or set(arm) != {
            "adaptive", "graph_closure", "id", "symbol_memory",
        }:
            fail("cell arm identity mismatch")
        match = re.fullmatch(r"a([01])([01])([01])", str(arm.get("id", "")))
        if (
            match is None
            or any(type(arm[key]) is not bool for key in ("adaptive", "symbol_memory", "graph_closure"))
            or arm["adaptive"] != (match.group(1) == "1")
            or arm["symbol_memory"] != (match.group(2) == "1")
            or arm["graph_closure"] != (match.group(3) == "1")
            or cell.get("cell_id") != f'{task_id}:{arm["id"]}'
        ):
            fail("cell arm identity mismatch")
        task_arm_ids.setdefault(task_id, set()).add(arm["id"])
        validate_application_metadata(cell.get("applications"), arm)
        if bool(cell["arm"]["symbol_memory"]) != (cell["symbol_projection_bytes"] > 0):
            fail("symbol projection factor mismatch")
        source = source_by_id.get(cell.get("task_id"))
        if source is None or (
            cell.get("source_inventory_sha256") != source["inventory_sha256"]
            or cell.get("source_tree_sha") != source["parent_tree_sha"]
        ):
            fail("cell source identity mismatch")
    expected_arm_ids = {f"a{value:03b}" for value in range(8)}
    if set(task_arm_ids) != set(source_by_id) or any(
        arm_ids != expected_arm_ids for arm_ids in task_arm_ids.values()
    ):
        fail("cell arm accounting mismatch")
    corpus = load_object(CORPUS)
    corpus_tasks = {item["id"]: item for item in corpus.get("tasks", [])}
    if set(corpus_tasks) != set(source_by_id):
        fail("source task accounting mismatch")
    for task_id, item in source_by_id.items():
        corpus_task = corpus_tasks[task_id]
        if {
            "parent_commit": item.get("parent_commit"),
            "parent_tree_sha": item.get("parent_tree_sha"),
            "project_id": item.get("project_id"),
        } != {
            "parent_commit": corpus_task.get("parent_commit"),
            "parent_tree_sha": corpus_task.get("parent_tree_sha"),
            "project_id": corpus_task.get("project_id"),
        }:
            fail("source task identity mismatch")
    projection_hashes = {
        task_id: sha256(canonical(provider_task_projection({
            key: task[key] for key in sorted(PROVIDER_TASK_FIELDS)
        })))
        for task_id, task in corpus_tasks.items()
    }
    if any(
        cell["provider_task_projection_sha256"] != projection_hashes[cell["task_id"]]
        for cell in cells
    ):
        fail("provider task projection identity mismatch")
    pairs = capture.get("factor_pairs")
    if type(pairs) is not list:
        fail("factor isolation accounting mismatch")
    if pairs != factor_pairs(cells):
        fail("factor isolation pair set mismatch")
    validate_factor_isolation(cells, pairs)
    byte_effect_pairs = sum(bool(pair["changed_provider_sections"]) for pair in pairs)
    expected_accounting = {
        "factor_no_op_pairs": len(pairs) - byte_effect_pairs,
        "factor_pairs": len(pairs),
        "factor_pairs_with_provider_byte_change": byte_effect_pairs,
        "scheduled_units": LIMITS["scheduled_units"],
        "task_arm_cells": len(cells),
        "unique_provider_inputs": unique_prompt_count,
    }
    if capture.get("accounting") != expected_accounting:
        fail("capture accounting mismatch")
    expected_bindings = schedule_bindings(cells)
    if capture.get("prepared_unit_bindings") != expected_bindings:
        fail("schedule binding mismatch")
    if len(expected_bindings) != LIMITS["scheduled_units"]:
        fail("schedule binding accounting mismatch")
    for binding in expected_bindings:
        if binding["binding_sha256"] != binding_identity(binding):
            fail("schedule binding seal mismatch")
    counts: dict[str, int] = {}
    unit_ids: set[str] = set()
    for binding in expected_bindings:
        counts[binding["cell_id"]] = counts.get(binding["cell_id"], 0) + 1
        unit_ids.add(binding["unit_id"])
    if set(counts.values()) != {3} or len(unit_ids) != LIMITS["scheduled_units"]:
        fail("schedule binding accounting mismatch")
    if capture.get("capture_sha256") != capture_identity(capture):
        fail("capture seal mismatch")


def validate_patch_envelope(response: bytes, allowed_paths: set[str]) -> list[str]:
    if not response or len(response) > LIMITS["max_response_bytes"]:
        fail("invalid historical patch")
    try:
        response.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvaluationError("invalid historical patch") from exc
    if not response.startswith(b"diff --git ") or b"\x00" in response:
        fail("invalid historical patch")
    forbidden = (
        b"GIT binary patch", b"Binary files ", b"old mode ", b"new mode ",
        b"similarity index ", b"rename from ", b"rename to ", b"copy from ", b"copy to ",
        b"new file mode 120000", b"deleted file mode 120000",
        b"new file mode 160000", b"deleted file mode 160000",
    )
    if any(marker in response for marker in forbidden):
        fail("unsupported historical patch feature")
    matches = DIFF_PATH.findall(response)
    if not matches or len(matches) != response.count(b"diff --git "):
        fail("invalid historical patch")
    blocks = [block for block in re.split(rb"(?=^diff --git )", response, flags=re.MULTILINE) if block]
    if len(blocks) != len(matches):
        fail("invalid historical patch")
    paths: list[str] = []
    for (left_raw, right_raw), block in zip(matches, blocks, strict=True):
        try:
            left = left_raw.decode("utf-8")
            right = right_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EvaluationError("invalid historical patch path") from exc
        if left != right:
            fail("renamed historical patch path")
        safe_path(left)
        if left not in allowed_paths or left in paths:
            fail("historical patch path outside allowlist")
        lines = block.splitlines()
        hunk_index = next((index for index, line in enumerate(lines) if line.startswith(b"@@ ")), None)
        if hunk_index is None:
            fail("invalid historical patch")
        metadata_lines = lines[1:hunk_index]
        old_markers = [line[4:] for line in metadata_lines if line.startswith(b"--- ")]
        new_markers = [line[4:] for line in metadata_lines if line.startswith(b"+++ ")]
        for markers in (old_markers, new_markers):
            if len(markers) == 1 and b"\t" in markers[0]:
                marker_path, timestamp = markers[0].split(b"\t", 1)
                if timestamp:
                    fail("invalid historical patch path")
                markers[0] = marker_path
        expected_old = b"a/" + left_raw
        expected_new = b"b/" + right_raw
        if (
            len(old_markers) != 1
            or len(new_markers) != 1
            or old_markers[0] not in {expected_old, b"/dev/null"}
            or new_markers[0] not in {expected_new, b"/dev/null"}
            or (old_markers[0] == b"/dev/null" and new_markers[0] == b"/dev/null")
        ):
            fail("historical patch path outside allowlist")
        paths.append(left)
    return paths


def assertions_pass(workspace: Path, checker: dict[str, Any]) -> bool:
    for assertion in checker.get("assertions", []):
        path = workspace.joinpath(*safe_path(assertion["path"]).parts)
        try:
            raw = path.read_bytes()
        except OSError:
            return False
        if any(value.encode("utf-8") not in raw for value in assertion["required_literals"]):
            return False
        if any(value.encode("utf-8") in raw for value in assertion["forbidden_literals"]):
            return False
    return True


def selected_patch(repo: Path, task: dict[str, Any]) -> bytes:
    response = run_git(repo, [
        "diff", "--binary", "--full-index", "--no-renames",
        task["parent_commit"], task["historical_commit"], "--",
        *task["allowed_patch_paths"],
    ])
    if (
        len(response) != task["selected_path_historical_patch_bytes"]
        or sha256(response) != task["selected_path_historical_patch_sha256"]
    ):
        fail("historical patch identity mismatch")
    return response


def rehearse_historical_checker(
    *,
    task: dict[str, Any],
    checker: dict[str, Any],
    repo: Path,
    workspace: Path,
) -> dict[str, object]:
    target = run_git(
        repo, ["rev-parse", "--verify", f'{task["historical_commit"]}^{{commit}}']
    ).decode().strip()
    target_tree = run_git(
        repo, ["rev-parse", f'{task["historical_commit"]}^{{tree}}']
    ).decode().strip()
    if target != task["historical_commit"] or target_tree != task["target_tree_sha"]:
        fail("historical target identity mismatch")
    response = selected_patch(repo, task)
    changed_paths = validate_patch_envelope(response, set(task["allowed_patch_paths"]))
    if assertions_pass(workspace, checker):
        fail("historical checker does not discriminate the parent snapshot")
    for arguments in (["apply", "--check", "-"], ["apply", "-"]):
        run_git(workspace, arguments, input_bytes=response)
    postimages: list[dict[str, object]] = []
    for path in task["allowed_patch_paths"]:
        target = git_blob(repo, task["historical_commit"], path)
        local_path = workspace.joinpath(*safe_path(path).parts)
        actual = local_path.read_bytes() if local_path.is_file() else None
        if actual != target:
            fail("historical patch postimage mismatch")
        postimages.append({
            "bytes": None if actual is None else len(actual),
            "exists": actual is not None,
            "path_sha256": sha256(path.encode("utf-8")),
            "sha256": None if actual is None else sha256(actual),
        })
    if not assertions_pass(workspace, checker):
        fail("historical target failed frozen source assertions")
    return {
        "changed_path_count": len(changed_paths),
        "checker_sha256": sha256(canonical(checker)),
        "historical_patch_bytes": len(response),
        "historical_patch_sha256": sha256(response),
        "parent_assertions_passed": False,
        "postimage_set_sha256": sha256(canonical(postimages)),
        "task_id": task["id"],
        "target_assertions_passed": True,
        "target_postimages_exact": True,
    }


def validate_report(report: dict[str, Any], *, capture: dict[str, Any], repo_root: Path) -> None:
    required = {
        "audit_boundary", "execution_authorized", "historical_checker_rehearsal",
        "phase_order", "producer", "provider_evidence", "provider_input_capture_sha256",
        "schema_version", "schedule_binding_set_sha256", "scorer_artifact",
    }
    if set(report) != required or report.get("schema_version") != REPORT_SCHEMA:
        fail("invalid rehearsal report")
    validate_capture(capture, repo_root=repo_root)
    if report.get("provider_input_capture_sha256") != sha256(canonical(capture)):
        fail("rehearsal capture identity mismatch")
    if report.get("schedule_binding_set_sha256") != sha256(canonical(capture["prepared_unit_bindings"])):
        fail("rehearsal schedule identity mismatch")
    if report.get("execution_authorized") is not False:
        fail("provider execution was incorrectly authorized")
    if report.get("provider_evidence") != {
        "cost": "unavailable_not_executed",
        "quality": "unavailable_not_executed",
        "savings": "unavailable_not_executed",
        "tokens": "unavailable_not_executed",
    }:
        fail("provider evidence claim mismatch")
    audit = report.get("audit_boundary")
    if audit != {"attempted": 4, "denied": 4, "succeeded": 0}:
        fail("audit boundary evidence mismatch")
    if report.get("phase_order") != [
        "all_96_provider_inputs_sealed",
        "scorer_artifact_captured",
        "12_historical_checkers_rehearsed",
    ]:
        fail("rehearsal phase order mismatch")
    checkers, scorer_identity = load_scorer_contract(capture, repo_root=repo_root)
    if report.get("scorer_artifact") != scorer_identity:
        fail("scorer artifact identity mismatch")
    rehearsal = report.get("historical_checker_rehearsal")
    if type(rehearsal) is not dict or set(rehearsal) != {"failed_tasks", "passed_tasks", "results"}:
        fail("historical checker rehearsal shape mismatch")
    results = rehearsal["results"]
    if type(results) is not list or len(results) != 12:
        fail("historical checker rehearsal accounting mismatch")
    result_fields = {
        "changed_path_count", "checker_sha256", "historical_patch_bytes",
        "historical_patch_sha256", "parent_assertions_passed", "postimage_set_sha256",
        "target_assertions_passed", "target_postimages_exact", "task_id",
    }
    for item in results:
        if type(item) is not dict or set(item) != result_fields:
            fail("rehearsal result shape mismatch")
        if (
            type(item.get("task_id")) is not str
            or type(item.get("changed_path_count")) is not int
            or item["changed_path_count"] < 1
            or type(item.get("historical_patch_bytes")) is not int
            or not 0 < item["historical_patch_bytes"] <= LIMITS["max_response_bytes"]
            or any(
                not HEX64.fullmatch(str(item.get(key, "")))
                for key in ("checker_sha256", "historical_patch_sha256", "postimage_set_sha256")
            )
        ):
            fail("rehearsal result shape mismatch")
    task_ids = {item["task_id"] for item in results}
    source_task_ids = {item["task_id"] for item in capture["source_tasks"]}
    if task_ids != source_task_ids or rehearsal["passed_tasks"] != 12 or rehearsal["failed_tasks"] != 0:
        fail("historical checker rehearsal accounting mismatch")
    if any(
        item["parent_assertions_passed"] is not False
        or item["target_assertions_passed"] is not True
        or item["target_postimages_exact"] is not True
        for item in results
    ):
        fail("historical checker rehearsal failed")
    corpus = load_object(CORPUS)
    tasks = {item["id"]: item for item in corpus.get("tasks", [])}
    for item in results:
        task = tasks[item["task_id"]]
        if (
            item["checker_sha256"] != sha256(canonical(checkers[item["task_id"]]))
            or item["historical_patch_bytes"] != task["selected_path_historical_patch_bytes"]
            or item["historical_patch_sha256"] != task["selected_path_historical_patch_sha256"]
            or item["changed_path_count"] > len(task["allowed_patch_paths"])
        ):
            fail("historical checker rehearsal identity mismatch")
    if report.get("producer") != relative_identity(Path(__file__).resolve(), repo_root):
        fail("rehearsal producer identity mismatch")
    if PRIVATE_ARTIFACT_KEYS & recursive_keys(report):
        fail("private material present in rehearsal report")


def preflight_sources(corpus_root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    corpus = load_object(CORPUS)
    projects = {item["id"]: item for item in corpus.get("projects", [])}
    if set(projects) != {"requests", "swift_argument_parser", "typescript"}:
        fail("unexpected source project set")
    project_contexts: dict[str, dict[str, Any]] = {}
    for project_id, project in projects.items():
        safe_path(project["cache_directory"])
        repo = (corpus_root / project["cache_directory"]).resolve(strict=True)
        if not repo.is_dir():
            fail("captured source cache unavailable")
        intake = run_git(repo, ["rev-parse", "--verify", f'{project["intake_commit"]}^{{commit}}']).decode().strip()
        tree = run_git(repo, ["rev-parse", f'{project["intake_commit"]}^{{tree}}']).decode().strip()
        if intake != project["intake_commit"] or tree != project["intake_tree"]:
            fail("source project intake identity mismatch")
        project_contexts[project_id] = {"project": project, "repo": repo}
    task_contexts: dict[str, dict[str, Any]] = {}
    for task in corpus.get("tasks", []):
        if set(task) & PROVIDER_TASK_FIELDS != PROVIDER_TASK_FIELDS:
            fail("task lacks provider input allowlist fields")
        context = project_contexts.get(task["project_id"])
        if context is None:
            fail("task references unknown source project")
        repo = context["repo"]
        parent = run_git(repo, ["rev-parse", "--verify", f'{task["parent_commit"]}^{{commit}}']).decode().strip()
        tree = run_git(repo, ["rev-parse", f'{task["parent_commit"]}^{{tree}}']).decode().strip()
        if parent != task["parent_commit"] or tree != task["parent_tree_sha"]:
            fail("source identity mismatch")
        inventory = source_inventory(repo, parent)
        task_contexts[task["id"]] = {"inventory": inventory, "repo": repo, "task": task}
    if len(task_contexts) != 12:
        fail("source task accounting mismatch")
    return task_contexts, corpus


def load_scorer_contract(
    capture: dict[str, Any],
    *,
    repo_root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, object]]:
    # Close and authenticate the public phase before opening scorer-only bytes.
    validate_capture(capture, repo_root=repo_root)
    try:
        checkers_raw = CHECKERS.read_bytes()
    except OSError as exc:
        raise EvaluationError("invalid frozen artifact: checkers.json") from exc
    checkers_doc = parse_object(checkers_raw, CHECKERS.name)
    checkers = {item["task_id"]: item for item in checkers_doc.get("checkers", [])}
    task_ids = {str(item["task_id"]) for item in capture["source_tasks"]}
    if set(checkers) != task_ids or len(checkers) != 12:
        fail("checker/task identity mismatch")
    corpus = load_object(CORPUS)
    tasks = {item["id"]: item for item in corpus.get("tasks", [])}
    if set(tasks) != task_ids:
        fail("checker/task identity mismatch")
    for task_id in sorted(task_ids):
        checker = checkers[task_id]
        task = tasks[task_id]
        if checker.get("id") != task.get("checker_id"):
            fail("checker/task identity mismatch")
        if checker.get("expected_selected_path_patch") != {
            "bytes": task["selected_path_historical_patch_bytes"],
            "sha256": task["selected_path_historical_patch_sha256"],
        }:
            fail("checker/patch identity mismatch")
    return checkers, {
        "bytes": len(checkers_raw),
        "path": CHECKERS.relative_to(repo_root).as_posix(),
        "sha256": sha256(checkers_raw),
    }


def generate_evidence(*, repo_root: Path, corpus_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if repo_root.resolve() != ROOT.resolve():
        fail("repository root mismatch")
    identities = artifact_identities(repo_root)
    task_contexts, _corpus = preflight_sources(corpus_root)
    packer_bytes = CANONICAL_PACKER.read_bytes()
    sanitizer_bytes = CANONICAL_SANITIZER.read_bytes()
    credential_policy_bytes = CANONICAL_CREDENTIAL_POLICY.read_bytes()
    if (
        packer_bytes != PLUGIN_PACKER.read_bytes()
        or sanitizer_bytes != PLUGIN_SANITIZER.read_bytes()
        or credential_policy_bytes != PLUGIN_CREDENTIAL_POLICY.read_bytes()
    ):
        fail("canonical and plugin tool bytes differ")
    captured_tool_hashes = {
        "canonical_packer": sha256(packer_bytes),
        "canonical_sanitizer": sha256(sanitizer_bytes),
        "canonical_credential_policy": sha256(credential_policy_bytes),
    }
    if any(identities[name]["sha256"] != digest for name, digest in captured_tool_hashes.items()):
        fail("captured tool identity mismatch")
    all_cells: list[dict[str, Any]] = []
    private_prompts: dict[str, bytes] = {}
    source_tasks: list[dict[str, object]] = []
    checker_results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="contextguard-v3-provider-input-") as directory:
        temp_root = Path(directory)
        audit_workspace = temp_root / "audit"
        audit_workspace.mkdir(mode=0o700)
        audit_tool_root = install_captured_tool(
            audit_workspace,
            packer_bytes=packer_bytes,
            sanitizer_bytes=sanitizer_bytes,
            credential_policy_bytes=credential_policy_bytes,
        )
        audit = audit_boundary_receipt(
            packer_bytes,
            audit_workspace,
            audit_tool_root / "context_pack.py",
        )
        snapshots: dict[str, Path] = {}
        for task_id in sorted(task_contexts):
            context = task_contexts[task_id]
            task = context["task"]
            inventory = context["inventory"]
            snapshot = temp_root / "snapshots" / task_id
            export_snapshot(context["repo"], task["parent_commit"], inventory, snapshot)
            snapshots[task_id] = snapshot
            identity = inventory_identity(inventory)
            source_metadata = {
                "inventory_file_count": identity["file_count"],
                "inventory_sha256": identity["sha256"],
                "inventory_source_bytes": identity["source_bytes"],
                "parent_commit": task["parent_commit"],
                "parent_tree_sha": task["parent_tree_sha"],
                "project_id": task["project_id"],
                "task_id": task_id,
            }
            source_tasks.append(source_metadata)
            cells, prompts = capture_task_cells(
                task=task,
                workspace=snapshot,
                packer_bytes=packer_bytes,
                sanitizer_bytes=sanitizer_bytes,
                credential_policy_bytes=credential_policy_bytes,
                source_metadata=source_metadata,
            )
            all_cells.extend(cells)
            private_prompts.update(prompts)
        all_cells.sort(key=lambda item: item["cell_id"])
        pairs = factor_pairs(all_cells)
        bindings = schedule_bindings(all_cells)
        capture = {
            "accounting": {
                "factor_no_op_pairs": sum(not pair["changed_provider_sections"] for pair in pairs),
                "factor_pairs": len(pairs),
                "factor_pairs_with_provider_byte_change": sum(bool(pair["changed_provider_sections"]) for pair in pairs),
                "scheduled_units": LIMITS["scheduled_units"],
                "task_arm_cells": len(all_cells),
                "unique_provider_inputs": len({cell["prompt_sha256"] for cell in all_cells}),
            },
            "artifact_identities": identities,
            "boundary": {
                "child_environment": ["LANG"],
                "credentials": "not_available_to_packer_child",
                "network": "denied_by_cpython_audit_hook",
                "provider_calls": 0,
                "source_hydration": "forbidden",
            },
            "cells": all_cells,
            "factor_pairs": pairs,
            "limits": LIMITS,
            "prepared_unit_bindings": bindings,
            "preregistration_commit": PREREGISTRATION_COMMIT,
            "schema_version": CAPTURE_SCHEMA,
            "source_tasks": sorted(source_tasks, key=lambda item: str(item["task_id"])),
        }
        capture["capture_sha256"] = capture_identity(capture)
        validate_capture(capture, repo_root=repo_root)
        if len(private_prompts) != 96 or {
            sha256(raw) for raw in private_prompts.values()
        } != {cell["prompt_sha256"] for cell in all_cells}:
            fail("ephemeral provider input identity mismatch")
        # Scorer-only bytes are captured only after every provider input has
        # been built, sealed, and independently validated above.
        checkers, scorer_artifact = load_scorer_contract(capture, repo_root=repo_root)
        for task_id in sorted(task_contexts):
            context = task_contexts[task_id]
            checker_results.append(rehearse_historical_checker(
                task=context["task"],
                checker=checkers[task_id],
                repo=context["repo"],
                workspace=snapshots[task_id],
            ))
        if artifact_identities(repo_root) != identities:
            fail("frozen artifact changed during rehearsal")
    report = {
        "audit_boundary": audit,
        "execution_authorized": False,
        "historical_checker_rehearsal": {
            "failed_tasks": 0,
            "passed_tasks": len(checker_results),
            "results": checker_results,
        },
        "phase_order": [
            "all_96_provider_inputs_sealed",
            "scorer_artifact_captured",
            "12_historical_checkers_rehearsed",
        ],
        "producer": relative_identity(Path(__file__).resolve(), repo_root),
        "provider_evidence": {
            "cost": "unavailable_not_executed",
            "quality": "unavailable_not_executed",
            "savings": "unavailable_not_executed",
            "tokens": "unavailable_not_executed",
        },
        "provider_input_capture_sha256": sha256(canonical(capture)),
        "schedule_binding_set_sha256": sha256(canonical(bindings)),
        "schema_version": REPORT_SCHEMA,
        "scorer_artifact": scorer_artifact,
    }
    validate_report(report, capture=capture, repo_root=repo_root)
    return capture, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    capture, report = generate_evidence(repo_root=ROOT, corpus_root=args.corpus_root)
    if args.write:
        (V3 / "provider-input-freeze.json").write_bytes(canonical(capture))
        (V3 / "rehearsal-report.json").write_bytes(canonical(report))
    print(json.dumps({
        "cells": len(capture["cells"]),
        "provider_calls": 0,
        "scheduled_units": len(capture["prepared_unit_bindings"]),
        "status": "ok",
        "wrote": args.write,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
