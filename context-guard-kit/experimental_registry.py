#!/usr/bin/env python3
"""Default-off ContextGuard experimental feature registry.

The registry is intentionally passive: it records explicit project-local opt-in
state for experimental lanes, but it does not activate runtime behavior by
itself.  Individual helpers must still require their own explicit experimental
flags before changing stable behavior.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
from pathlib import Path
import stat
import sys
from typing import Any, NoReturn
import unicodedata
from urllib.parse import urlparse

TOOL_NAME = "context-guard-experiments"
CONFIG_SCHEMA_VERSION = "contextguard.experiments.v1"
DEFAULT_CONFIG = Path(".context-guard") / "experiments.json"
MAX_CONFIG_BYTES = 64_000
MAX_CONTEXT_DIFF_INPUT_BYTES = 256_000
MAX_CONTEXT_DIFF_REPLACEMENT_BYTES = 128_000
MAX_CONTEXT_DIFF_ARTIFACT_METADATA_BYTES = 64_000
DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR = Path(".context-guard") / "artifacts"
LEGACY_CONTEXT_DIFF_ARTIFACT_DIR = Path(".claude-token-optimizer") / "artifacts"
MAX_VISUAL_OCR_TEXT_BYTES = 64_000
MAX_LEARNED_COMPRESSION_INPUT_BYTES = 128_000
MAX_SELF_HOSTED_METRICS_INPUT_BYTES = 64_000
SELF_HOSTED_METRICS_SCHEMA_VERSION = "contextguard.bench.self-hosted-metrics.v1"
SELF_HOSTED_METRICS_KEY = "self_hosted_metrics"
SELF_HOSTED_METRICS_CLAIM_BOUNDARY = "self_hosted_metrics_only_not_hosted_api_token_or_cost_savings"
BENCH_RUN_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.run-evidence.v1"
MAX_SELF_HOSTED_LABEL_CHARS = 120
MAX_SELF_HOSTED_LATENCY_MS = 7 * 24 * 60 * 60 * 1000
MAX_SELF_HOSTED_MEMORY_MB = 10_000_000
MAX_SELF_HOSTED_ENERGY_WH = 1_000_000
MAX_SELF_HOSTED_LOCAL_COST_USD = 1_000_000
MAX_SELF_HOSTED_TOKENS_PER_SECOND = 10_000_000
TOKEN_PROXY_BYTES_PER_TOKEN = 4
MAX_SELF_HOSTED_JSON_DEPTH = 100
MAX_SELF_HOSTED_JSON_NODES = 10_000
LOCAL_PROXY_SCHEMA_VERSION = "contextguard.experiments.local-proxy-plan.v1"
LOCAL_PROXY_DEFAULT_BIND_HOST = "127.0.0.1"
LOCAL_PROXY_DEFAULT_BIND_PORT = 0
LOCAL_PROXY_DEFAULT_TARGET_HOST = "127.0.0.1"
LOCAL_PROXY_DEFAULT_TARGET_PORT = 0
LOCAL_PROXY_LOCALHOST_NAMES = {"localhost"}
ALLOWED_FIRST_COMPONENT_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
DIR_FD_OPEN_SUPPORTED = os.open in getattr(os, "supports_dir_fd", set())
DIR_FD_MKDIR_SUPPORTED = os.mkdir in getattr(os, "supports_dir_fd", set())
DIR_FD_STAT_NOFOLLOW_SUPPORTED = (
    os.stat in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_follow_symlinks", set())
)
NO_FOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")


@dataclass(frozen=True)
class Experiment:
    id: str
    name: str
    summary: str
    stability: str
    default_enabled: bool
    risk_level: str
    claim_boundary: str
    gate_requirements: tuple[str, ...]
    runtime_status: str = "metadata-only"
    commands: tuple[str, ...] = ()
    opt_in_flags: tuple[str, ...] = ()
    config_effect: str = (
        "Registry enablement records project-local intent only; helpers still require explicit experimental flags."
    )
    evidence_contract: str = "Evidence is local metadata only unless a later story adds a measured runtime gate."

    def to_json(self, *, enabled: bool = False) -> dict[str, Any]:
        data = asdict(self)
        for key in ("gate_requirements", "commands", "opt_in_flags"):
            data[key] = list(getattr(self, key))
        data["enabled"] = bool(enabled)
        return data


EXPERIMENTS: tuple[Experiment, ...] = (
    Experiment(
        id="output-receipt-trim",
        name="Receipt-backed output trimming",
        summary="Opt-in digest output with local artifact receipts and exact re-expand instructions.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Local output-size reduction only; no hosted API token/cost savings claim without provider-measured matched tasks.",
        gate_requirements=("explicit opt-in", "local artifact receipt", "exact re-expand command"),
        runtime_status="available-explicit-flags",
        commands=(
            "context-guard-trim-output --digest markdown --artifact-receipt -- <command>",
            "context-guard-trim-output --digest json --artifact-receipt -- <command>",
        ),
        opt_in_flags=("--digest markdown|json", "--artifact-receipt"),
        config_effect=(
            "Registry enablement records project-local intent only; output trimming still runs only when the helper is "
            "invoked with --digest markdown|json plus --artifact-receipt."
        ),
        evidence_contract=(
            "Stores the exact sanitized full output as a local context-guard-artifact receipt and emits an exact "
            "re-expand command before omitted details are relied on."
        ),
    ),
    Experiment(
        id="protected-zone-policy",
        name="Protected-zone transform policy",
        summary="Metadata policy that denies semantic rewrites for code, diffs, identifiers, hashes, paths, and other exact evidence.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Policy metadata only; it does not prove provider cache or token savings.",
        gate_requirements=("explicit opt-in", "protected-zone detection", "exact retrieval fallback"),
        runtime_status="available-explicit-flags",
        commands=(
            "context-guard-compress --json --protected-policy",
            "context-guard cost compile --json",
            "context-guard-cost compile --json",
        ),
        opt_in_flags=("--protected-policy", "protected=true manifest sections for cost compile"),
        config_effect=(
            "Registry enablement records project-local intent only; protected-zone policy metadata still appears only "
            "when explicit helper flags or protected manifest sections are used."
        ),
        evidence_contract=(
            "Denies semantic/paraphrase rewrites for protected classes and requires structural transforms plus exact "
            "artifact retrieval guidance for protected evidence."
        ),
    ),
    Experiment(
        id="context-diff-compaction",
        name="Reviewable context-diff compaction",
        summary="Explicit receipt-backed runtime for caller-supplied compact diff replacements with stable exact handles.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Smaller local diffs are proxy evidence only; hosted savings require provider-measured matched tasks.",
        gate_requirements=("explicit opt-in", "human-reviewable diff", "local receipt", "exact re-expand handle"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan context-diff-compaction",
            "context-guard experiments emit context-diff-compaction --receipt-id <id> --reexpand-command <cmd>",
        ),
        opt_in_flags=(
            "plan context-diff-compaction",
            "emit context-diff-compaction",
            "--receipt-id",
            "--reexpand-command",
            "--replacement-text|--replacement-file",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; context-diff replacement emits only through the "
            "explicit emit command with exact retrieval metadata and caller-supplied compact text."
        ),
        evidence_contract=(
            "Emitted replacements require human-reviewable hunks, caller-supplied compact text, and exact local "
            "artifact content that matches the input diff plus re-expand metadata; smaller local diffs remain proxy "
            "evidence only."
        ),
    ),
    Experiment(
        id="visual-crop-ocr",
        name="Visual crop/OCR evidence planning",
        summary="Dry-run fixture lane for comparing full visual evidence with cropped or OCR-derived evidence.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Image/OCR byte reductions are proxy evidence until provider image/text token fields are measured.",
        gate_requirements=("explicit opt-in", "original evidence preserved", "confidence/error notes", "missed-context guardrail"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan visual-crop-ocr",),
        opt_in_flags=(
            "plan visual-crop-ocr",
            "--full-evidence-receipt",
            "--crop-bounds",
            "--image-size",
            "--ocr-text|--ocr-text-file",
            "--ocr-confidence",
            "--ocr-error-note",
            "--missed-context-note",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; visual crop/OCR planning remains a dry-run "
            "metadata surface and does not run OCR, crop images, call providers, or change stable behavior."
        ),
        evidence_contract=(
            "Dry-run plans require retrievable full visual evidence plus crop/OCR confidence, error, and "
            "missed-context guardrails before human review."
        ),
    ),
    Experiment(
        id="learned-compression",
        name="Learned/synthetic compression safe gate",
        summary="Deny-by-default dry-run safety gate for already-sanitized unprotected prose only.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Semantic compression cannot claim savings or correctness without matched-task quality and provider token evidence.",
        gate_requirements=("explicit opt-in", "sanitized unprotected prose only", "protected-zone denial", "exact fallback or receipt"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan learned-compression",),
        opt_in_flags=("plan learned-compression", "--sanitized", "--trusted-source", "--exact-fallback-receipt", "--reexpand-command"),
        config_effect=(
            "Registry enablement records project-local intent only; learned compression remains a dry-run policy check "
            "and does not run learned compressors, embeddings, model calls, or replacements."
        ),
        evidence_contract=(
            "Dry-run eligibility requires caller-asserted sanitized trusted prose, exact local fallback handles, and "
            "denial of protected or prompt-like signals."
        ),
    ),
    Experiment(
        id="self-hosted-metrics-ledger",
        name="Self-hosted metrics ledger",
        summary="Explicit local ledger runtime for self-hosted/local metrics sidecars kept separate from hosted API claims.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Self-hosted memory/latency metrics must stay separate from hosted API token/cost claims.",
        gate_requirements=("explicit opt-in", "separate ledger fields", "shifted-cost accounting"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan self-hosted-metrics-ledger",
            "context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl <path>",
        ),
        opt_in_flags=(
            "plan self-hosted-metrics-ledger",
            "record self-hosted-metrics-ledger",
            "--ledger-jsonl",
            "--input",
            "--latency-ms",
            "--peak-memory-mb",
            "--quality-score",
            "--energy-wh",
            "--local-cost-usd",
            "--tokens-per-second",
            "--model-server",
            "--optimization",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; self-hosted metrics still write a ledger only "
            "when the explicit record command is invoked with --ledger-jsonl."
        ),
        evidence_contract=(
            "The explicit record command writes context-guard-bench JSONL ledger sidecars; self-hosted metrics "
            "remain separate from hosted API token/cost savings."
        ),
    ),
    Experiment(
        id="local-proxy",
        name="Local proxy advisory lane",
        summary="Dry-run localhost-only proxy advisory plan with no hidden forwarding or API-key persistence.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Proxy metrics are diagnostic only; no hosted savings claim without provider-measured evidence.",
        gate_requirements=("explicit opt-in", "localhost-only default", "no API-key persistence", "no hidden external forwarding"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan local-proxy",),
        opt_in_flags=(
            "plan local-proxy",
            "--bind-host",
            "--bind-port",
            "--target-host",
            "--target-port",
            "--upstream-url",
            "--runtime-gate-ack",
            "--external-forwarding-intent",
            "--persist-api-key",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; local proxy planning remains a dry-run advisory "
            "surface and does not bind sockets, forward traffic, persist API keys, or write ledgers."
        ),
        evidence_contract=(
            "Dry-run plans require localhost-only bind/target metadata, explicit runtime gate acknowledgement before "
            "any future forwarding, and no raw API-key persistence."
        ),
    ),
)

REGISTRY = {experiment.id: experiment for experiment in EXPERIMENTS}


class RegistryError(RuntimeError):
    pass


def fail(message: str, code: int = 2) -> NoReturn:
    print(f"{TOOL_NAME}: {message}", file=sys.stderr)
    raise SystemExit(code)


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


def _no_follow_flag(*, label: str) -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise RegistryError(f"{label} requires O_NOFOLLOW support")
    return os.O_NOFOLLOW


def _directory_open_flags(*, follow_final: bool = False, label: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_final:
        flags |= _no_follow_flag(label=label)
    return flags


def _file_open_flags(*, label: str, write: bool = False) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC if write else os.O_RDONLY
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _temp_file_open_flags(*, label: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _append_file_open_flags(*, label: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _leaf_name(path: Path, *, label: str) -> str:
    name = path.name
    if name in {"", ".", ".."}:
        raise RegistryError(f"{label} must name a regular file")
    return name


def _normalized_link_target(anchor: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if target.is_absolute():
        return Path(os.path.normpath(str(target)))
    return Path(os.path.normpath(str(anchor / target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    if not path.is_absolute():
        return path
    parts = path.parts
    if len(parts) < 2:
        return path
    first = parts[1]
    expected = ALLOWED_FIRST_COMPONENT_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if link.is_symlink() and _normalized_link_target(Path(path.anchor), os.readlink(link)) == expected:
            return expected.joinpath(*parts[2:])
    except OSError:
        return path
    return path


def normalize_local_path(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(path))))


def normalize_project_path(root: Path, candidate: Path, *, label: str) -> Path:
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    normalized = normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(candidate))))
    try:
        normalized.relative_to(root)
    except ValueError as exc:
        raise RegistryError(f"{label} must stay inside project root: {normalized}") from exc
    return normalized


def open_directory_no_follow(path: Path, *, label: str, create: bool = False, missing_ok: bool = False) -> int | None:
    path = normalize_allowed_first_absolute_symlink(path)
    if not DIR_FD_OPEN_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd open support")
    if create and not DIR_FD_MKDIR_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd mkdir support")
    flags = _directory_open_flags(label=label)
    if path.is_absolute():
        anchor = path.anchor or os.sep
        parts = path.parts[1:]
        try:
            current_fd = os.open(anchor, _directory_open_flags(follow_final=True, label=label))
        except OSError as exc:
            raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    else:
        parts = path.parts
        try:
            current_fd = os.open(".", flags)
        except OSError as exc:
            raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise RegistryError(f"{label} must not contain parent traversal")
            next_fd = -1
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if missing_ok:
                    os.close(current_fd)
                    current_fd = -1
                    return None
                if not create:
                    raise RegistryError(f"could not inspect {label}: missing directory component") from None
                try:
                    os.mkdir(part, mode=0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise RegistryError(f"could not create {label}: {os_error_detail(exc)}") from exc
                try:
                    next_fd = os.open(part, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
            except OSError as exc:
                raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise RegistryError(f"{label} must not traverse non-directory components")
            except Exception:
                if next_fd >= 0:
                    try:
                        os.close(next_fd)
                    except OSError:
                        pass
                raise
            try:
                os.close(current_fd)
            except OSError:
                pass
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    finally:
        if current_fd >= 0:
            try:
                os.close(current_fd)
            except OSError:
                pass


def _precheck_regular_leaf(parent_fd: int, leaf_name: str, *, label: str, missing_ok: bool = False) -> bool:
    if not DIR_FD_STAT_NOFOLLOW_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd stat support")
    try:
        st = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return False
        raise RegistryError(f"could not inspect {label}: missing file") from None
    except OSError as exc:
        raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise RegistryError(f"{label} must be a regular file")
    return True


def read_bounded_regular_file(path: Path, *, max_bytes: int, label: str, missing_ok: bool = False) -> tuple[bytes, bool] | None:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", missing_ok=missing_ok)
    if parent_fd is None:
        return None
    fd = -1
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=missing_ok)
        if not exists:
            return None
        fd = os.open(leaf, _file_open_flags(label=label), dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        truncated = len(raw) > max_bytes
        return raw[:max_bytes], truncated
    except OSError as exc:
        raise RegistryError(f"could not read {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def write_regular_file_no_follow(path: Path, data: bytes, *, label: str) -> None:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", create=True)
    if parent_fd is None:  # pragma: no cover - create=True never returns None.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    temp_leaf: str | None = None
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        mode = 0o644
        if exists:
            try:
                mode = stat.S_IMODE(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False).st_mode) or 0o644
            except OSError:
                mode = 0o644
        for _attempt in range(20):
            candidate = _leaf_name(Path(f".{leaf}.{os.getpid()}.{secrets.token_hex(8)}.tmp"), label=f"{label} temp")
            try:
                fd = os.open(candidate, _temp_file_open_flags(label=f"{label} temp"), mode, dir_fd=parent_fd)
                temp_leaf = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temp_leaf is None:
            raise RegistryError(f"could not create temporary {label}")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} temp must be a regular file")
        write_all_fd(fd, data)
        try:
            os.fsync(fd)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        fd = -1
        os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_leaf = None
    except OSError as exc:
        raise RegistryError(f"could not write {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_leaf is not None:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def append_jsonl_no_follow(path: Path, payload: dict[str, Any], *, label: str) -> int:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", create=True)
    if parent_fd is None:  # pragma: no cover - create=True never returns None.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    try:
        leaf = _leaf_name(path, label=label)
        _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        fd = os.open(leaf, _append_file_open_flags(label=label), 0o600, dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} must be a regular file")
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        write_all_fd(fd, data)
        try:
            os.fsync(fd)
        except OSError:
            pass
        return len(data)
    except OSError as exc:
        raise RegistryError(f"could not append {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def resolve_root(raw_root: str | None) -> Path:
    root = Path(raw_root) if raw_root else Path.cwd()
    try:
        return root.expanduser().resolve()
    except OSError as exc:
        raise RegistryError(f"could not resolve root: {root}: {exc}") from exc


def resolve_config_path(root: Path, raw_config: str | None) -> Path:
    if raw_config:
        candidate = Path(raw_config)
    else:
        candidate = DEFAULT_CONFIG
    return normalize_project_path(root, candidate, label="config path")


def load_config(path: Path) -> dict[str, Any]:
    loaded = read_bounded_regular_file(path, max_bytes=MAX_CONFIG_BYTES, label="config", missing_ok=True)
    if loaded is None:
        return {"schema_version": CONFIG_SCHEMA_VERSION, "enabled": []}
    raw, truncated = loaded
    if truncated:
        raise RegistryError("config exceeded max bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"could not decode config UTF-8: {path}: {exc.reason}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse config JSON: {path}: {exc.msg}") from exc
    except OSError as exc:
        raise RegistryError(f"could not read config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"config must be a JSON object: {path}")
    schema = data.get("schema_version")
    if schema not in (None, CONFIG_SCHEMA_VERSION):
        raise RegistryError(f"unsupported config schema_version: {schema!r}")
    enabled = data.get("enabled", [])
    if not isinstance(enabled, list) or not all(isinstance(item, str) for item in enabled):
        raise RegistryError("config enabled must be a list of experiment ids")
    return {"schema_version": CONFIG_SCHEMA_VERSION, "enabled": sorted(set(enabled))}


def write_config(path: Path, enabled: set[str]) -> dict[str, Any]:
    data = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "enabled": sorted(enabled),
    }
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_regular_file_no_follow(path, payload, label="config")
    return data


def configured_enabled_set(config: dict[str, Any]) -> set[str]:
    return set(config.get("enabled", []))


def enabled_set(config: dict[str, Any]) -> set[str]:
    return {item for item in configured_enabled_set(config) if item in REGISTRY}


def unknown_enabled(config: dict[str, Any]) -> list[str]:
    return sorted(item for item in set(config.get("enabled", [])) if item not in REGISTRY)


def registry_payload(*, config_path: Path, config: dict[str, Any], root: Path) -> dict[str, Any]:
    enabled = enabled_set(config)
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "root": str(root),
        "config_path": str(config_path),
        "default_off": True,
        "note": "Experiments are opt-in metadata gates; enabling an experiment does not activate stable runtime behavior by itself.",
        "unknown_enabled": unknown_enabled(config),
        "experiments": [experiment.to_json(enabled=experiment.id in enabled) for experiment in EXPERIMENTS],
    }


def emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def emit_human(payload: dict[str, Any], *, include_details: bool = False) -> None:
    print("ContextGuard experiments (default off; explicit opt-in required)")
    print(f"Config: {payload['config_path']}")
    print("Enabling an experiment records project-local intent only; helpers still require explicit experimental use.")
    for experiment in payload["experiments"]:
        state = "enabled" if experiment["enabled"] else "disabled"
        print(f"- {experiment['id']}: {state} [{experiment['stability']}, risk={experiment['risk_level']}]")
        if include_details:
            print(f"  {experiment['summary']}")
            print(f"  Runtime: {experiment['runtime_status']}")
            if experiment["commands"]:
                print("  Commands: " + "; ".join(experiment["commands"]))
            if experiment["opt_in_flags"]:
                print("  Opt-in flags: " + ", ".join(experiment["opt_in_flags"]))
            print(f"  Config effect: {experiment['config_effect']}")
            print(f"  Evidence contract: {experiment['evidence_contract']}")
            print(f"  Claim boundary: {experiment['claim_boundary']}")
    if payload["unknown_enabled"]:
        print("Unknown enabled ids in config: " + ", ".join(payload["unknown_enabled"]))


def require_known(experiment_id: str) -> Experiment:
    try:
        return REGISTRY[experiment_id]
    except KeyError:
        choices = ", ".join(sorted(REGISTRY))
        fail(f"unknown experiment id {experiment_id!r}; known ids: {choices}")


def command_list(args: argparse.Namespace) -> int:
    root, config_path, config = load_args_context(args)
    payload = registry_payload(config_path=config_path, config=config, root=root)
    if args.json:
        emit_json(payload)
    else:
        emit_human(payload, include_details=True)
    return 0


def command_status(args: argparse.Namespace) -> int:
    root, config_path, config = load_args_context(args)
    payload = registry_payload(config_path=config_path, config=config, root=root)
    if args.json:
        emit_json(payload)
    else:
        emit_human(payload, include_details=False)
    return 0


def command_enable(args: argparse.Namespace) -> int:
    require_known(args.experiment_id)
    root, config_path, config = load_args_context(args)
    enabled = configured_enabled_set(config)
    changed = args.experiment_id not in enabled
    enabled.add(args.experiment_id)
    written = write_config(config_path, enabled)
    payload = registry_payload(config_path=config_path, config=written, root=root)
    payload["changed"] = changed
    payload["experiment_id"] = args.experiment_id
    if args.json:
        emit_json(payload)
    else:
        print(f"enabled {args.experiment_id} in {config_path}")
    return 0


def command_disable(args: argparse.Namespace) -> int:
    require_known(args.experiment_id)
    root, config_path, config = load_args_context(args)
    enabled = configured_enabled_set(config)
    changed = args.experiment_id in enabled
    enabled.discard(args.experiment_id)
    written = write_config(config_path, enabled)
    payload = registry_payload(config_path=config_path, config=written, root=root)
    payload["changed"] = changed
    payload["experiment_id"] = args.experiment_id
    if args.json:
        emit_json(payload)
    else:
        print(f"disabled {args.experiment_id} in {config_path}")
    return 0



DIFF_GIT_RE = re.compile(r"^diff --git (?P<old>\S+) (?P<new>\S+)$")
HUNK_RE = re.compile(r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@(?P<section>.*)$")
CONTEXT_DIFF_ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")


def read_bounded_input(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    source_label = args.source_label
    if args.input:
        path = Path(args.input)
        source_label = source_label or str(path)
        loaded = read_bounded_regular_file(path, max_bytes=MAX_CONTEXT_DIFF_INPUT_BYTES, label="input")
        assert loaded is not None
        raw, truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_CONTEXT_DIFF_INPUT_BYTES + 1)
        truncated = len(raw) > MAX_CONTEXT_DIFF_INPUT_BYTES
        raw = raw[:MAX_CONTEXT_DIFF_INPUT_BYTES]
    if not raw:
        raise RegistryError("context-diff-compaction plan requires diff input on stdin or --input")
    text = raw.decode("utf-8", errors="replace")
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": truncated,
        "max_bytes": MAX_CONTEXT_DIFF_INPUT_BYTES,
    }
    return text, metadata


def strip_diff_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def summarize_diff(text: str, *, max_files: int = 50, max_hunks: int = 200) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_hunk: dict[str, Any] | None = None
    total_hunks = 0
    summarized_hunks = 0
    lines = text.splitlines()
    diff_header_count = 0
    for line_number, line in enumerate(lines, start=1):
        match = DIFF_GIT_RE.match(line)
        if match:
            diff_header_count += 1
            current_hunk = None
            if len(files) >= max_files:
                current = None
                continue
            current = {
                "old_path": strip_diff_prefix(match.group("old")),
                "new_path": strip_diff_prefix(match.group("new")),
                "diff_header_line": line_number,
                "hunks": [],
            }
            files.append(current)
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            total_hunks += 1
            if current is None:
                if len(files) >= max_files:
                    current_hunk = None
                    continue
                current = {"old_path": None, "new_path": None, "diff_header_line": None, "hunks": []}
                files.append(current)
            if len(current["hunks"]) < max_hunks:
                current_hunk = {
                    "line": line_number,
                    "old_start": int(hunk.group("old_start")),
                    "old_count": int(hunk.group("old_count") or "1"),
                    "new_start": int(hunk.group("new_start")),
                    "new_count": int(hunk.group("new_count") or "1"),
                    "section": hunk.group("section").strip()[:120],
                    "added_lines": 0,
                    "removed_lines": 0,
                    "context_lines": 0,
                    "body_lines": 0,
                    "reviewable": False,
                }
                current["hunks"].append(current_hunk)
                summarized_hunks += 1
            else:
                current_hunk = None
            continue
        if current_hunk is not None:
            changed = False
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk["added_lines"] += 1
                changed = True
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk["removed_lines"] += 1
                changed = True
            elif line.startswith(" "):
                current_hunk["context_lines"] += 1
            else:
                continue
            current_hunk["body_lines"] += 1
    reviewable_hunks = 0
    malformed_hunks = 0
    for file_summary in files:
        for hunk_summary in file_summary["hunks"]:
            old_body_lines = hunk_summary["removed_lines"] + hunk_summary["context_lines"]
            new_body_lines = hunk_summary["added_lines"] + hunk_summary["context_lines"]
            has_changes = bool(hunk_summary["added_lines"] or hunk_summary["removed_lines"])
            well_formed = (
                old_body_lines == hunk_summary["old_count"]
                and new_body_lines == hunk_summary["new_count"]
            )
            hunk_summary["old_body_lines"] = old_body_lines
            hunk_summary["new_body_lines"] = new_body_lines
            hunk_summary["has_changes"] = has_changes
            hunk_summary["well_formed"] = well_formed
            hunk_summary["reviewable"] = bool(has_changes and well_formed)
            if hunk_summary["reviewable"]:
                reviewable_hunks += 1
            elif not well_formed:
                malformed_hunks += 1
    return {
        "file_count": len(files),
        "hunk_count": total_hunks,
        "summarized_hunk_count": summarized_hunks,
        "reviewable_hunk_count": reviewable_hunks,
        "malformed_hunk_count": malformed_hunks,
        "truncated_files": max(0, diff_header_count - len(files)),
        "truncated_hunks": max(0, total_hunks - summarized_hunks),
        "files": files,
    }


def valid_context_diff_reexpand_command(receipt_id: str | None, command: str | None) -> tuple[bool, str | None]:
    if not receipt_id or not command:
        return False, "missing_exact_receipt_or_reexpand_command"
    if not CONTEXT_DIFF_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command"
    if any(token in command for token in (";", "|", "&", ">", "<", "`", "$", "\n", "\r")):
        return False, "invalid_reexpand_command"
    try:
        argv = shlex.split(command)
    except ValueError:
        return False, "invalid_reexpand_command"
    if argv == ["context-guard-artifact", "get", receipt_id, "--full"]:
        return True, None
    if argv == ["context-guard", "artifact", "get", receipt_id, "--full"]:
        return True, None
    return False, "invalid_reexpand_command"


def context_diff_artifact_read_dirs() -> list[Path]:
    return [DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR, LEGACY_CONTEXT_DIFF_ARTIFACT_DIR]


def context_diff_artifact_paths(directory: Path, receipt_id: str) -> tuple[Path, Path]:
    return directory / f"{receipt_id}.txt", directory / f"{receipt_id}.json"


def verify_context_diff_artifact(
    receipt_id: str | None,
    *,
    expected_sha256: str,
    expected_bytes: int,
) -> tuple[bool, str | None, dict[str, Any]]:
    if not receipt_id or not CONTEXT_DIFF_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command", {"checked": False, "read_directories": []}
    read_dirs = context_diff_artifact_read_dirs()
    details: dict[str, Any] = {
        "checked": True,
        "read_directories": [str(path) for path in read_dirs],
        "matched_directory": None,
        "content_sha256": None,
        "content_bytes": None,
    }
    for directory in read_dirs:
        content_path, meta_path = context_diff_artifact_paths(directory, receipt_id)
        meta_loaded = read_bounded_regular_file(
            meta_path,
            max_bytes=MAX_CONTEXT_DIFF_ARTIFACT_METADATA_BYTES,
            label="context-diff artifact metadata",
            missing_ok=True,
        )
        content_loaded = read_bounded_regular_file(
            content_path,
            max_bytes=max(MAX_CONTEXT_DIFF_INPUT_BYTES, expected_bytes),
            label="context-diff artifact content",
            missing_ok=True,
        )
        if meta_loaded is None and content_loaded is None:
            continue
        if meta_loaded is None or content_loaded is None:
            return False, "artifact_receipt_invalid", details
        meta_raw, meta_truncated = meta_loaded
        content_raw, content_truncated = content_loaded
        if meta_truncated or content_truncated:
            return False, "artifact_receipt_invalid", details
        try:
            metadata = json.loads(meta_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "artifact_receipt_invalid", details
        if not isinstance(metadata, dict) or metadata.get("artifact_id") != receipt_id:
            return False, "artifact_receipt_invalid", details
        stored = metadata.get("stored_output")
        stored_sha = stored.get("sha256") if isinstance(stored, dict) else None
        stored_bytes = stored.get("bytes") if isinstance(stored, dict) else None
        actual_sha = hashlib.sha256(content_raw).hexdigest()
        actual_bytes = len(content_raw)
        details.update({
            "matched_directory": str(directory),
            "content_sha256": actual_sha,
            "content_bytes": actual_bytes,
        })
        if stored_sha != actual_sha or stored_bytes != actual_bytes:
            return False, "artifact_receipt_invalid", details
        if actual_sha != expected_sha256 or actual_bytes != expected_bytes:
            return False, "artifact_content_mismatch", details
        return True, None, details
    return False, "artifact_receipt_not_found", details


def read_context_diff_replacement(args: argparse.Namespace) -> tuple[str | None, dict[str, Any]]:
    if args.replacement_text is not None and args.replacement_file:
        raise RegistryError("context-diff-compaction emit accepts only one of --replacement-text or --replacement-file")
    if args.replacement_text is not None:
        text = str(args.replacement_text)
        raw = text.encode("utf-8")
        truncated = len(raw) > MAX_CONTEXT_DIFF_REPLACEMENT_BYTES
        raw = raw[:MAX_CONTEXT_DIFF_REPLACEMENT_BYTES]
        text = raw.decode("utf-8", errors="replace")
        source_label = "inline"
    elif args.replacement_file:
        path = Path(args.replacement_file)
        loaded = read_bounded_regular_file(
            path,
            max_bytes=MAX_CONTEXT_DIFF_REPLACEMENT_BYTES,
            label="context-diff replacement",
        )
        assert loaded is not None
        raw, truncated = loaded
        text = raw.decode("utf-8", errors="replace")
        source_label = str(path)
    else:
        text = None
        raw = b""
        truncated = False
        source_label = None
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()) if text is not None else 0,
        "sha256": hashlib.sha256(raw).hexdigest() if text is not None else None,
        "truncated": truncated,
        "max_bytes": MAX_CONTEXT_DIFF_REPLACEMENT_BYTES,
    }
    return text, metadata


def context_diff_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    text, input_meta = read_bounded_input(args)
    summary = summarize_diff(text)
    receipt_id = args.receipt_id.strip() if args.receipt_id else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    has_exact_handle = bool(receipt_id and reexpand_command)
    readiness_blockers: list[str] = []
    if not has_exact_handle:
        readiness_blockers.append("missing_exact_receipt_or_reexpand_command")
    if input_meta["truncated"]:
        readiness_blockers.append("input_truncated")
    if summary.get("truncated_files", 0) or summary.get("truncated_hunks", 0):
        readiness_blockers.append("diff_summary_truncated")
    if summary.get("malformed_hunk_count", 0):
        readiness_blockers.append("malformed_diff_hunks")
    if summary["file_count"] == 0 or summary.get("reviewable_hunk_count", 0) == 0:
        readiness_blockers.append("no_reviewable_diff_hunks")
    status = (
        "ready_for_human_review"
        if not readiness_blockers
        else "blocked_until_reviewable_diff"
        if has_exact_handle
        else "blocked_until_exact_receipt"
    )
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "context-diff-compaction",
        "mode": "dry_run",
        "status": status,
        "input": input_meta,
        "transform_policy": {
            "automatic_compaction": False,
            "lossy_replacement_allowed": False,
            "semantic_rewrite_allowed": False,
            "human_review_required": True,
            "stable_runtime_behavior_changed": False,
        },
        "exact_retrieval": {
            "required": True,
            "available": has_exact_handle,
            "artifact_id": receipt_id,
            "cli": reexpand_command,
            "verified": False,
            "note": "Dry-run planning records user-supplied handles for human review only; it does not verify local receipt storage.",
        },
        "review_plan": {
            "summary": summary,
            "readiness_blockers": readiness_blockers,
            "bounded_loss_disclosure": (
                "No compacted replacement was produced. Any future lossy replacement must keep this diff reviewable "
                "and provide exact receipt/re-expand handles before use."
            ),
            "next_steps": [
                "Store exact original evidence with context-guard-artifact or another local receipt before compacting.",
                "Review file and hunk summaries against the original diff.",
                "Do not claim hosted token/cost savings from this dry-run plan.",
            ],
        },
        "claim_boundary": "Dry-run local planning only; no hosted API token/cost savings claim without provider-measured matched successful tasks.",
        "compacted_replacement": None,
    }


def command_plan_context_diff_compaction(args: argparse.Namespace) -> int:
    payload = context_diff_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard context-diff compaction plan (dry-run only)")
        print("No compaction was performed and no replacement text was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Input: {payload['input']['source_label']} lines={payload['input']['lines']} sha256={payload['input']['sha256']}")
        print(
            f"Review summary: files={payload['review_plan']['summary']['file_count']} "
            f"hunks={payload['review_plan']['summary']['hunk_count']}"
        )
        if not payload["exact_retrieval"]["available"]:
            print("Exact receipt/re-expand command required before any lossy replacement can be reviewed.")
        else:
            print("Exact retrieval handle supplied for human review only; verified=false.")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def context_diff_emit_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = context_diff_plan_payload(args)
    receipt_id = args.receipt_id.strip() if args.receipt_id else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, reexpand_blocker = valid_context_diff_reexpand_command(receipt_id, reexpand_command)
    replacement_text, replacement_meta = read_context_diff_replacement(args)
    artifact_verified = False
    artifact_blocker = None
    artifact_verification: dict[str, Any] = {"checked": False, "read_directories": []}
    if reexpand_valid:
        artifact_verified, artifact_blocker, artifact_verification = verify_context_diff_artifact(
            receipt_id,
            expected_sha256=payload["input"]["sha256"],
            expected_bytes=payload["input"]["bytes"],
        )

    blockers = list(payload["review_plan"]["readiness_blockers"])
    if reexpand_blocker:
        blockers.append(reexpand_blocker)
    if artifact_blocker:
        blockers.append(artifact_blocker)
    if replacement_text is None or not replacement_text.strip():
        blockers.append("missing_compacted_replacement")
    if replacement_meta["truncated"]:
        blockers.append("replacement_truncated")
    if (
        replacement_text is not None
        and not replacement_meta["truncated"]
        and replacement_meta["bytes"] >= payload["input"]["bytes"]
    ):
        blockers.append("replacement_not_smaller_than_input")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    replacement_record = None
    if ready and replacement_text is not None:
        replacement_record = {
            "text": replacement_text,
            "bytes": replacement_meta["bytes"],
            "lines": replacement_meta["lines"],
            "sha256": replacement_meta["sha256"],
            "source_label": replacement_meta["source_label"],
        }

    payload["mode"] = "emit"
    payload["status"] = "replacement_emitted" if ready else "blocked_until_emit_ready"
    payload["transform_policy"] = {
        "automatic_compaction": False,
        "lossy_replacement_allowed": ready,
        "semantic_rewrite_allowed": False,
        "caller_supplied_replacement_required": True,
        "human_review_required": True,
        "stable_runtime_behavior_changed": False,
    }
    payload["exact_retrieval"] = {
        "required": True,
        "available": bool(receipt_id and reexpand_command and reexpand_valid and artifact_verified),
        "artifact_id": receipt_id,
        "cli": reexpand_command,
        "verified": artifact_verified,
        "valid_command_shape": reexpand_valid,
        "verification": artifact_verification,
        "note": "Emit mode validates exact local artifact command shape and verifies local artifact content matches the input diff.",
    }
    payload["replacement"] = replacement_meta
    payload["review_plan"]["readiness_blockers"] = blockers
    payload["review_plan"]["bounded_loss_disclosure"] = (
        "Compacted replacement is caller supplied and lossy; use exact_retrieval.cli to recover the original diff "
        "before relying on omitted details."
    )
    payload["review_plan"]["next_steps"] = [
        "Human-review the compacted replacement against the original diff before use.",
        "Use exact_retrieval.cli to recover the original diff whenever omitted details matter.",
        "Treat bytes_before/bytes_after as local proxy evidence only; do not claim hosted token/cost savings.",
    ]
    payload["claim_boundary"] = (
        "Explicit local context-diff replacement emission only; smaller local diffs are proxy evidence and are not "
        "hosted API token or cost savings evidence."
    )
    bytes_after = replacement_meta["bytes"] if replacement_text is not None else 0
    payload["compaction_evidence"] = {
        "bytes_before": payload["input"]["bytes"],
        "bytes_after": bytes_after,
        "byte_reduction": max(0, payload["input"]["bytes"] - bytes_after),
        "byte_reduction_proxy_only": True,
        "hosted_api_token_savings_claim_allowed": False,
        "hosted_api_cost_savings_claim_allowed": False,
    }
    payload["compacted_replacement"] = replacement_record
    return payload


def command_emit_context_diff_compaction(args: argparse.Namespace) -> int:
    payload = context_diff_emit_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "replacement_emitted":
            print("ContextGuard context-diff compact replacement emitted")
            print(
                f"Replacement: bytes={payload['replacement']['bytes']} "
                f"sha256={payload['replacement']['sha256']}"
            )
            print(f"Exact re-expand: {payload['exact_retrieval']['cli']}")
        else:
            print("ContextGuard context-diff compact replacement blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "replacement_emitted" else 1


def clean_values(values: list[str] | None) -> list[str]:
    return [value.strip() for value in values or [] if value.strip()]


def parse_int_tuple(raw: str | None, *, count: int) -> tuple[int, ...] | None:
    if raw is None or not raw.strip():
        return None
    parts = [part.strip() for part in raw.split(",")]
    if len(parts) != count:
        return None
    try:
        return tuple(int(part, 10) for part in parts)
    except ValueError:
        return None


def crop_payload(bounds: tuple[int, ...] | None, image_size: tuple[int, ...] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    bounds_payload = None
    image_payload = None
    if bounds is not None:
        x, y, width, height = bounds
        bounds_payload = {"x": x, "y": y, "width": width, "height": height}
    if image_size is not None:
        width, height = image_size
        image_payload = {"width": width, "height": height}
    return bounds_payload, image_payload


def valid_crop_geometry(bounds: tuple[int, ...] | None, image_size: tuple[int, ...] | None) -> tuple[bool, bool]:
    if bounds is None or image_size is None:
        return False, False
    x, y, crop_width, crop_height = bounds
    image_width, image_height = image_size
    if x < 0 or y < 0 or crop_width <= 0 or crop_height <= 0 or image_width <= 0 or image_height <= 0:
        return False, False
    if x + crop_width > image_width or y + crop_height > image_height:
        return True, True
    return True, False


def parse_confidence(raw: str | None) -> tuple[float | None, str | None]:
    if raw is None or not raw.strip():
        return None, "missing"
    try:
        value = float(raw)
    except ValueError:
        return None, "invalid"
    if not (0.0 <= value <= 1.0):
        return None, "invalid"
    return value, None


def read_visual_ocr_text(args: argparse.Namespace) -> dict[str, Any]:
    if args.ocr_text is not None and args.ocr_text_file is not None:
        raise RegistryError("--ocr-text and --ocr-text-file are mutually exclusive")
    if args.ocr_text_file is not None:
        path = Path(args.ocr_text_file)
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else path.name
        loaded = read_bounded_regular_file(path, max_bytes=MAX_VISUAL_OCR_TEXT_BYTES, label="OCR text file")
        assert loaded is not None
        raw, truncated = loaded
        source_type = "file"
    elif args.ocr_text is not None:
        raw = args.ocr_text.encode("utf-8")
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else "inline"
        source_type = "inline"
        truncated = len(raw) > MAX_VISUAL_OCR_TEXT_BYTES
        raw = raw[:MAX_VISUAL_OCR_TEXT_BYTES]
    else:
        raw = b""
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else None
        source_type = None
        truncated = False
    try:
        text = raw.decode("utf-8")
        valid_encoding = True
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        valid_encoding = False
    return {
        "source_type": source_type,
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "truncated": truncated,
        "max_bytes": MAX_VISUAL_OCR_TEXT_BYTES,
        "valid_utf8": valid_encoding,
        "text_preview": text,
        "has_text": bool(text.strip()),
    }


def visual_crop_ocr_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    full_receipt = args.full_evidence_receipt.strip() if args.full_evidence_receipt else None
    full_label = args.full_evidence_label.strip() if args.full_evidence_label else None
    missed_context_notes = clean_values(args.missed_context_note)
    ocr_error_notes = clean_values(args.ocr_error_note)
    crop_label = args.crop_label.strip() if args.crop_label else None

    bounds = parse_int_tuple(args.crop_bounds, count=4)
    image_size = parse_int_tuple(args.image_size, count=2)
    bounds_payload, image_payload = crop_payload(bounds, image_size)
    crop_fields_present = any(value is not None and str(value).strip() for value in (args.crop_label, args.crop_bounds, args.image_size))
    crop_geometry_valid, crop_exceeds = valid_crop_geometry(bounds, image_size)
    crop_complete = bool(crop_label and crop_geometry_valid and not crop_exceeds)

    ocr_text = read_visual_ocr_text(args)
    confidence, confidence_error = parse_confidence(args.ocr_confidence)
    ocr_fields_present = any(
        [
            args.ocr_text is not None,
            args.ocr_text_file is not None,
            args.ocr_confidence is not None,
            bool(ocr_error_notes),
        ]
    )
    ocr_complete = bool(
        ocr_text["has_text"]
        and ocr_text["valid_utf8"]
        and not ocr_text["truncated"]
        and confidence_error is None
        and ocr_error_notes
    )

    blockers: list[str] = []
    if not full_receipt:
        blockers.append("missing_full_evidence_receipt")
    if not missed_context_notes:
        blockers.append("missing_missed_context_note")
    if not crop_complete and not ocr_complete:
        blockers.append("missing_derived_evidence")

    if crop_fields_present and (not crop_label or not crop_geometry_valid):
        blockers.append("invalid_crop_bounds")
    elif crop_fields_present and crop_exceeds:
        blockers.append("crop_exceeds_image_bounds")

    if ocr_fields_present:
        if confidence_error == "missing":
            blockers.append("missing_ocr_confidence")
        elif confidence_error == "invalid":
            blockers.append("invalid_ocr_confidence")
        if not ocr_error_notes:
            blockers.append("missing_ocr_error_note")
        if not ocr_text["has_text"]:
            blockers.append("missing_ocr_text")
        if not ocr_text["valid_utf8"]:
            blockers.append("invalid_ocr_text_encoding")
        if ocr_text["truncated"]:
            blockers.append("ocr_text_truncated")

    # Preserve stable ordering while avoiding duplicates when incomplete derived
    # evidence also contributed path-specific blockers.
    blockers = list(dict.fromkeys(blockers))
    status = "ready_for_human_review" if not blockers else "blocked_until_visual_evidence"

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "visual-crop-ocr",
        "mode": "dry_run",
        "status": status,
        "external_services": {
            "called": False,
            "ocr_service": None,
            "image_service": None,
            "network": False,
        },
        "full_visual_evidence": {
            "required": True,
            "available": bool(full_receipt),
            "receipt_id": full_receipt,
            "label": full_label,
            "verified": False,
            "note": "G004 records user-supplied full visual evidence handles only; it does not verify receipt storage.",
        },
        "derived_evidence": {
            "crop": {
                "available": crop_complete,
                "label": crop_label,
                "bounds": bounds_payload,
                "image_size": image_payload,
                "source": "user_supplied_metadata" if crop_fields_present else None,
            },
            "ocr": {
                "available": ocr_complete,
                "source_type": ocr_text["source_type"],
                "source_label": ocr_text["source_label"],
                "text_preview": ocr_text["text_preview"] if ocr_text["has_text"] else None,
                "metadata": {
                    "bytes": ocr_text["bytes"],
                    "lines": ocr_text["lines"],
                    "sha256": ocr_text["sha256"],
                    "truncated": ocr_text["truncated"],
                    "max_bytes": ocr_text["max_bytes"],
                    "valid_utf8": ocr_text["valid_utf8"],
                },
                "confidence": confidence,
                "error_notes": ocr_error_notes,
            },
        },
        "guardrails": {
            "original_evidence_required": True,
            "full_visual_evidence_must_remain_available": True,
            "external_ocr_service_allowed": False,
            "external_image_service_allowed": False,
            "human_review_required": True,
            "missed_context_review_required": True,
            "confidence_error_notes_required_for_ocr": True,
            "stable_runtime_behavior_changed": False,
            "candidate_replacement_allowed": False,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "missed_context_notes": missed_context_notes,
            "next_steps": [
                "Keep full visual evidence retrievable before relying on cropped or OCR-derived evidence.",
                "Review crop bounds and OCR text against the original evidence for missed context.",
                "Do not claim hosted image/text token or cost savings from this dry-run plan.",
            ],
        },
        "claim_boundary": (
            "Dry-run visual/OCR fixture planning only; no hosted visual/text token or cost savings claim without "
            "provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_visual_crop_ocr(args: argparse.Namespace) -> int:
    payload = visual_crop_ocr_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard visual crop/OCR plan (dry-run only)")
        print("No external OCR/image service was called and no replacement evidence was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Full evidence available: {payload['full_visual_evidence']['available']} verified=false")
        print(
            "Derived evidence: "
            f"crop={payload['derived_evidence']['crop']['available']} "
            f"ocr={payload['derived_evidence']['ocr']['available']}"
        )
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


SECRET_LABEL_KEY_RE = (
    r"[A-Za-z0-9_.-]*(?:"
    r"api[-_]?key|apikey|token|secret|password|passwd|pwd|client[-_]?secret|"
    r"auth|authorization|bearer|basic|pass|credential|credentials|signature|sig|"
    r"x[-_]?amz[-_]?[a-z0-9_.-]*|aws[a-z0-9_.-]*|(?:aws[-_]?)?access[-_]?key(?:[-_]?id)?|"
    r"private[-_]?key|privatekey|pgp[-_]?private[-_]?key|pgpprivatekey|ssh[-_]?key|sshkey"
    r")[A-Za-z0-9_.-]*"
)
SECRET_LABEL_VALUE_RE = r"(?:'[^']*'|\"[^\"]*\"|[^\s,}&#;]+)"
SECRET_LABEL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic|AWS|AWS4-HMAC-SHA256)\s+[^\s,}\]]+(?:\s+[A-Za-z0-9_-]+=[^\s,}\]]+)*"), "Authorization: [REDACTED]"),
    (re.compile(r"(?i)\b(?:Bearer|Basic)\s*(?:[:=]\s*)?[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\b(?:AWS|AWS4-HMAC-SHA256)\s+[A-Za-z0-9,=:/+._~%-]+"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;]({SECRET_LABEL_KEY_RE})=)[^\s?&#;]+"), r"\1[REDACTED]"),
    (
        re.compile(rf"(?i)(^|[\s{{,?&#;])([\"']?(?:{SECRET_LABEL_KEY_RE})[\"']?\s*[:=]\s*){SECRET_LABEL_VALUE_RE}"),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(rf"(?i)(^|[\s\"'])(--(?:{SECRET_LABEL_KEY_RE})(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?i)(^|[\s\"'])((?:-u|--user)(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(rf"(?i)(^|[/\\\s{{,?&#;\[\(<])({SECRET_LABEL_KEY_RE}(?:[:=][^\s,}}&#;\]\)\\/]*)?)"), r"\1[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "[REDACTED]"),
    (re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED]"),
    (re.compile(r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"npm_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED]"),
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s@]+@", re.IGNORECASE), r"\1[REDACTED]@"),
)


def sanitize_self_hosted_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in text)
    text = " ".join(text.split())
    for pattern, replacement in SECRET_LABEL_PATTERNS:
        text = pattern.sub(replacement, text)
    text = re.sub(r"\[REDACTED\]\]+", "[REDACTED]", text)
    text = re.sub(r"(?:\[REDACTED\]\s*){2,}", "[REDACTED]", text)
    if len(text) > MAX_SELF_HOSTED_LABEL_CHARS:
        text = text[: MAX_SELF_HOSTED_LABEL_CHARS - 12].rstrip() + "…[truncated]"
    return text


def sanitize_self_hosted_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = sanitize_self_hosted_text(value)
    if not text:
        return None
    return text


def sanitize_self_hosted_ignored_key(value: Any) -> str:
    if not isinstance(value, str):
        return "non_string_key"
    text = sanitize_self_hosted_text(value)
    if not text:
        return "empty_key"
    if "[REDACTED]" in text:
        return "redacted_key"
    return text


def normalize_self_hosted_metric(value: Any, *, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        return None
    return number


SELF_HOSTED_METRIC_LIMITS: dict[str, float] = {
    "latency_ms": MAX_SELF_HOSTED_LATENCY_MS,
    "peak_memory_mb": MAX_SELF_HOSTED_MEMORY_MB,
    "quality_score": 1.0,
    "energy_wh": MAX_SELF_HOSTED_ENERGY_WH,
    "local_cost_usd": MAX_SELF_HOSTED_LOCAL_COST_USD,
    "tokens_per_second": MAX_SELF_HOSTED_TOKENS_PER_SECOND,
}
SELF_HOSTED_LABEL_KEYS = ("model_server", "optimization", "quality_metric", "hardware", "runtime", "dataset")


def normalize_self_hosted_metrics(raw: Any, *, source: str) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    invalid_keys: list[str] = []
    ignored_keys: list[str] = []
    if not isinstance(raw, dict):
        return None, ["self_hosted_metrics_not_object"], ignored_keys
    metrics: dict[str, float] = {}
    labels: dict[str, str] = {}
    availability = {key: False for key in SELF_HOSTED_METRIC_LIMITS}
    for key, value in raw.items():
        if key in SELF_HOSTED_METRIC_LIMITS:
            metric = normalize_self_hosted_metric(value, maximum=SELF_HOSTED_METRIC_LIMITS[key])
            if metric is None:
                invalid_keys.append(key)
            else:
                metrics[key] = metric
                availability[key] = True
        elif key in SELF_HOSTED_LABEL_KEYS:
            label = sanitize_self_hosted_label(value)
            if label is not None:
                labels[key] = label
            elif value is not None:
                invalid_keys.append(key)
        else:
            ignored_keys.append(sanitize_self_hosted_ignored_key(key))
    if not metrics:
        return None, invalid_keys, ignored_keys
    return {
        "schema_version": SELF_HOSTED_METRICS_SCHEMA_VERSION,
        "source": source,
        "metrics": metrics,
        "labels": labels,
        "measurement_availability": availability,
        "claim_boundary": {
            "id": SELF_HOSTED_METRICS_CLAIM_BOUNDARY,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
            "requires_provider_measured_matched_tasks_for_hosted_claims": True,
            "reason": (
                "Self-hosted local/model-server latency, memory, quality, energy, and local cost metrics "
                "are not hosted API token or cost telemetry."
            ),
        },
    }, invalid_keys, ignored_keys


def cli_self_hosted_metrics(args: argparse.Namespace) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for arg_name, metric_name in (
        ("latency_ms", "latency_ms"),
        ("peak_memory_mb", "peak_memory_mb"),
        ("quality_score", "quality_score"),
        ("energy_wh", "energy_wh"),
        ("local_cost_usd", "local_cost_usd"),
        ("tokens_per_second", "tokens_per_second"),
    ):
        value = getattr(args, arg_name)
        if value is not None:
            raw[metric_name] = value
    for arg_name in SELF_HOSTED_LABEL_KEYS:
        value = getattr(args, arg_name)
        if value is not None:
            raw[arg_name] = value
    return raw


def reject_non_finite_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON value {value}")


def has_non_finite_json_number(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        if depth > MAX_SELF_HOSTED_JSON_DEPTH or visited > MAX_SELF_HOSTED_JSON_NODES:
            return True
        if isinstance(item, bool):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                return True
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
    return False


def read_self_hosted_payload(args: argparse.Namespace) -> tuple[Any, dict[str, Any]]:
    source_label = sanitize_self_hosted_text(args.source_label) if args.source_label else None
    if args.input:
        path = Path(args.input)
        source_label = source_label or sanitize_self_hosted_text(path)
        try:
            loaded = read_bounded_regular_file(path, max_bytes=MAX_SELF_HOSTED_METRICS_INPUT_BYTES, label=f"self-hosted metrics input: {source_label}")
        except RegistryError as exc:
            raise RegistryError(f"could not read self-hosted metrics input: {source_label}: {exc}") from exc
        assert loaded is not None
        raw, loaded_truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_SELF_HOSTED_METRICS_INPUT_BYTES + 1)
        loaded_truncated = len(raw) > MAX_SELF_HOSTED_METRICS_INPUT_BYTES
        raw = raw[:MAX_SELF_HOSTED_METRICS_INPUT_BYTES]
    if loaded_truncated:
        return None, {
            "source_label": source_label,
            "bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": True,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": None,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    if not raw.strip():
        return None, {
            "source_label": source_label,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": None,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    text = raw.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text, parse_constant=reject_non_finite_json_constant)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse self-hosted metrics JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise RegistryError(f"could not parse self-hosted metrics JSON: {exc}") from exc
    except RecursionError as exc:
        raise RegistryError("could not parse self-hosted metrics JSON: nesting too deep") from exc
    if has_non_finite_json_number(payload):
        raise RegistryError("could not parse self-hosted metrics JSON: non-finite JSON number")
    return payload, {
        "source_label": source_label,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": False,
        "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
        "envelope_source": None,
        "invalid_metric_keys": [],
        "ignored_keys": [],
    }


def select_self_hosted_envelope(payload: Any) -> tuple[Any, str | None, list[str]]:
    if not isinstance(payload, dict):
        return None, None, ["input_not_object"]
    ignored: list[str] = []
    if SELF_HOSTED_METRICS_KEY in payload:
        return payload.get(SELF_HOSTED_METRICS_KEY), f"explicit_provider_payload.{SELF_HOSTED_METRICS_KEY}", ignored
    metrics = payload.get("metrics")
    if isinstance(metrics, dict) and SELF_HOSTED_METRICS_KEY in metrics:
        return metrics.get(SELF_HOSTED_METRICS_KEY), f"explicit_provider_payload.metrics.{SELF_HOSTED_METRICS_KEY}", ignored
    if any(isinstance(key, str) and key.startswith("self_hosted_") for key in payload):
        ignored.append("incidental_self_hosted_keys")
    return None, None, ignored


def parse_optional_success(value: str | None) -> bool | None:
    if value is None or value == "unknown":
        return None
    return value == "true"


def self_hosted_metrics_ledger_row(
    sidecar: dict[str, Any],
    *,
    task_id: str = "self-hosted-metrics-manual",
    variant: str = "self-hosted-metrics-ledger",
    success: bool | None = None,
    notes: str = "explicit self-hosted metrics record; no hosted API savings claim",
    claude_version: str = "manual",
    wall_time_seconds: float = 0.0,
) -> dict[str, Any]:
    return {
        "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claude_version": sanitize_self_hosted_text(claude_version) or "manual",
        "task_id": sanitize_self_hosted_text(task_id) or "self-hosted-metrics-manual",
        "variant": sanitize_self_hosted_text(variant) or "self-hosted-metrics-ledger",
        "transform_id": "self-hosted-metrics-ledger",
        "success": success,
        "primary_tokens_measured": False,
        "primary_tokens": 0,
        "primary_cost_measured": False,
        "primary_cost_usd": 0.0,
        "provider_cached_tokens": None,
        "provider_cached_tokens_measured": False,
        "wall_time_seconds": wall_time_seconds,
        "external_tokens_measured": False,
        "external_tokens": 0,
        "external_cost_measured": False,
        "external_cost_usd": 0.0,
        "total_cost_with_shift_usd": None,
        "artifacts_used": 0,
        "bytes_before": 0,
        "bytes_after": 0,
        "hook_triggers": 0,
        "turns": 0,
        "notes": sanitize_self_hosted_text(notes)
        or "explicit self-hosted metrics record; no hosted API savings claim",
        "measurement_availability": {
            "primary_tokens": False,
            "primary_cost": False,
            "external_tokens": False,
            "external_cost": False,
            "shifted_cost": False,
            "provider_cache": False,
            "byte_metrics": False,
            "wall_time": False,
            "self_hosted_metrics": True,
        },
        "self_hosted_metrics": sidecar,
        "proxy_metrics": {
            "byte_metrics_observed": False,
            "token_proxy": "chars_div_4",
            "bytes_per_token": TOKEN_PROXY_BYTES_PER_TOKEN,
            "claim_boundary": "proxy_only_not_hosted_token_savings",
        },
    }


def self_hosted_metrics_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    cli_metrics = cli_self_hosted_metrics(args)
    if cli_metrics:
        raw_metrics = cli_metrics
        source = "cli_flags"
        ignored_envelope_keys = []
        input_meta = {
            "source_label": sanitize_self_hosted_text(args.source_label) if args.source_label else "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": source,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    elif args.input or not sys.stdin.isatty():
        raw_payload, input_meta = read_self_hosted_payload(args)
        raw_metrics, source, ignored_envelope_keys = select_self_hosted_envelope(raw_payload)
    else:
        raw_metrics = {}
        source = None
        ignored_envelope_keys = []
        input_meta = {
            "source_label": sanitize_self_hosted_text(args.source_label) if args.source_label else "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": source,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    if input_meta["truncated"]:
        sidecar = None
        invalid_keys: list[str] = []
        ignored_keys = ignored_envelope_keys
    elif raw_metrics is None:
        sidecar = None
        invalid_keys = []
        ignored_keys = ignored_envelope_keys
    else:
        sidecar, invalid_keys, ignored_keys = normalize_self_hosted_metrics(raw_metrics, source=source or "missing_explicit_envelope")
    input_meta["envelope_source"] = source
    input_meta["invalid_metric_keys"] = sorted(set(invalid_keys))
    input_meta["ignored_keys"] = sorted(set(ignored_keys + ignored_envelope_keys))
    blockers: list[str] = []
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if source is None:
        blockers.append("missing_explicit_self_hosted_metrics_envelope")
    if sidecar is None:
        blockers.append("missing_self_hosted_metrics")
    if invalid_keys:
        blockers.append("invalid_self_hosted_metrics")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    ledger_preview = None
    if sidecar is not None:
        ledger_preview = self_hosted_metrics_ledger_row(
            sidecar,
            task_id="self-hosted-metrics-dry-run",
            notes="dry-run preview; no ledger file written",
            claude_version="dry-run",
        )
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "self-hosted-metrics-ledger",
        "mode": "dry_run",
        "status": "ready_for_ledger_review" if ready else "blocked_until_metrics",
        "input": input_meta,
        "policy": {
            "default_off": True,
            "ledger_write_performed": False,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
            "stable_runtime_behavior_changed": False,
        },
        "self_hosted_metrics": sidecar,
        "ledger_preview": ledger_preview,
        "review_plan": {
            "readiness_blockers": blockers,
            "next_steps": [
                "Record real run evidence with context-guard-bench --ledger-jsonl when benchmark data exists.",
                "Keep self-hosted local metrics out of hosted API token/cost savings claims.",
                "Use provider-measured matched successful tasks for hosted API savings claims.",
            ],
        },
        "claim_boundary": (
            "Dry-run self-hosted metrics ledger preview only; local/model-server metrics are diagnostic sidecars "
            "and are not hosted API token or cost savings evidence."
        ),
    }


def command_plan_self_hosted_metrics_ledger(args: argparse.Namespace) -> int:
    payload = self_hosted_metrics_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard self-hosted metrics ledger preview (dry-run only)")
        print("No ledger file was written and no hosted API token/cost savings claim is allowed from these metrics.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def self_hosted_metrics_record_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = self_hosted_metrics_plan_payload(args)
    payload["mode"] = "record"
    payload["claim_boundary"] = (
        "Explicit local self-hosted metrics ledger record only; local/model-server metrics are diagnostic sidecars "
        "and are not hosted API token or cost savings evidence."
    )
    payload["policy"]["ledger_write_performed"] = False
    payload["policy"]["stable_runtime_behavior_changed"] = False
    payload["ledger_record"] = None
    payload["ledger_jsonl"] = {
        "path": sanitize_self_hosted_text(args.ledger_jsonl),
        "write_performed": False,
        "bytes_written": 0,
    }
    if payload["self_hosted_metrics"] is None or payload["review_plan"]["readiness_blockers"]:
        payload["status"] = "blocked_until_metrics"
        return payload

    row = self_hosted_metrics_ledger_row(
        payload["self_hosted_metrics"],
        task_id=args.task_id,
        variant=args.variant,
        success=parse_optional_success(args.success),
        notes=args.notes,
        claude_version="manual",
    )
    bytes_written = append_jsonl_no_follow(Path(args.ledger_jsonl), row, label="self-hosted metrics ledger")
    payload["status"] = "recorded"
    payload["ledger_preview"] = row
    payload["ledger_record"] = row
    payload["policy"]["ledger_write_performed"] = True
    payload["ledger_jsonl"]["write_performed"] = True
    payload["ledger_jsonl"]["bytes_written"] = bytes_written
    payload["review_plan"]["next_steps"] = [
        "Use this JSONL row only as self-hosted/local diagnostic evidence.",
        "Keep hosted API token/cost savings claims behind provider-measured matched successful tasks.",
        "Compare this sidecar with benchmark rows only through explicit shifted-cost accounting.",
    ]
    return payload


def command_record_self_hosted_metrics_ledger(args: argparse.Namespace) -> int:
    payload = self_hosted_metrics_record_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "recorded":
            print("ContextGuard self-hosted metrics ledger record written")
            print(f"Ledger: {payload['ledger_jsonl']['path']} bytes={payload['ledger_jsonl']['bytes_written']}")
        else:
            print("ContextGuard self-hosted metrics ledger record blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def sanitize_local_proxy_value(value: Any) -> str:
    return sanitize_self_hosted_text(value)


def local_proxy_secret_like(value: Any) -> bool:
    if value is None:
        return False
    return "[REDACTED]" in sanitize_local_proxy_value(value)


def is_localhost_host(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    host = value.strip().strip("[]").lower().rstrip(".")
    if host in LOCAL_PROXY_LOCALHOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_local_proxy_host(value: Any, *, default: str) -> tuple[str, bool, bool]:
    if value is None or str(value).strip() == "":
        host = default
    else:
        host = str(value).strip().strip("[]")
    sanitized = sanitize_local_proxy_value(host)
    return sanitized, is_localhost_host(host), "[REDACTED]" in sanitized


def normalize_local_proxy_port(value: Any, *, default: int) -> tuple[int, bool]:
    if value is None or value == "":
        return default, True
    if isinstance(value, bool):
        return default, False
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default, False
    return port, 0 <= port <= 65535


def read_local_proxy_payload(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    if not args.input:
        return {}, {
            "source_label": "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "ignored_keys": [],
        }
    path = Path(args.input)
    safe_path = sanitize_local_proxy_value(path)
    try:
        loaded = read_bounded_regular_file(path, max_bytes=MAX_SELF_HOSTED_METRICS_INPUT_BYTES, label=f"local-proxy input: {safe_path}")
    except RegistryError as exc:
        raise RegistryError(f"could not read local-proxy input: {safe_path}: {exc}") from exc
    assert loaded is not None
    raw, loaded_truncated = loaded
    if loaded_truncated:
        return {}, {
            "source_label": safe_path,
            "bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": True,
            "ignored_keys": [],
        }
    if not raw.strip():
        return {}, {
            "source_label": safe_path,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "ignored_keys": [],
        }
    text = raw.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text, parse_constant=reject_non_finite_json_constant)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse local-proxy JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise RegistryError(f"could not parse local-proxy JSON: {exc}") from exc
    except RecursionError as exc:
        raise RegistryError("could not parse local-proxy JSON: nesting too deep") from exc
    if has_non_finite_json_number(payload):
        raise RegistryError("could not parse local-proxy JSON: non-finite JSON number")
    if not isinstance(payload, dict):
        return {}, {
            "source_label": safe_path,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "ignored_keys": ["input_not_object"],
        }
    envelope = payload.get("local_proxy", payload)
    ignored = []
    if not isinstance(envelope, dict):
        envelope = {}
        ignored.append("local_proxy_not_object")
    allowed = {
        "bind_host",
        "bind_port",
        "target_host",
        "target_port",
        "upstream_url",
        "ledger_jsonl",
        "proxy_label",
        "api_key",
        "authorization_header",
        "persist_api_key",
        "external_forwarding_intent",
        "runtime_gate_ack",
    }
    ignored.extend(sanitize_self_hosted_ignored_key(key) for key in envelope if key not in allowed)
    return dict(envelope), {
        "source_label": safe_path,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": False,
        "ignored_keys": sorted(set(ignored)),
    }


def coalesce_local_proxy_value(args: argparse.Namespace, payload: dict[str, Any], attr: str, key: str) -> Any:
    value = getattr(args, attr)
    return value if value is not None else payload.get(key)


def coalesce_local_proxy_bool(args: argparse.Namespace, payload: dict[str, Any], attr: str, key: str) -> bool:
    if getattr(args, attr):
        return True
    return bool(payload.get(key))


def local_proxy_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    input_payload, input_meta = read_local_proxy_payload(args)
    bind_host_raw = coalesce_local_proxy_value(args, input_payload, "bind_host", "bind_host")
    bind_port_raw = coalesce_local_proxy_value(args, input_payload, "bind_port", "bind_port")
    target_host_raw = coalesce_local_proxy_value(args, input_payload, "target_host", "target_host")
    target_port_raw = coalesce_local_proxy_value(args, input_payload, "target_port", "target_port")
    upstream_url_raw = coalesce_local_proxy_value(args, input_payload, "upstream_url", "upstream_url")
    ledger_jsonl_raw = coalesce_local_proxy_value(args, input_payload, "ledger_jsonl", "ledger_jsonl")
    proxy_label_raw = coalesce_local_proxy_value(args, input_payload, "proxy_label", "proxy_label")
    api_key_raw = coalesce_local_proxy_value(args, input_payload, "api_key", "api_key")
    authorization_raw = coalesce_local_proxy_value(args, input_payload, "authorization_header", "authorization_header")
    persist_api_key = coalesce_local_proxy_bool(args, input_payload, "persist_api_key", "persist_api_key")
    external_forwarding_intent = coalesce_local_proxy_bool(
        args,
        input_payload,
        "external_forwarding_intent",
        "external_forwarding_intent",
    )
    runtime_gate_ack = coalesce_local_proxy_bool(args, input_payload, "runtime_gate_ack", "runtime_gate_ack")

    upstream_url = sanitize_local_proxy_value(upstream_url_raw) if upstream_url_raw else None
    upstream_host = None
    upstream_url_valid = True
    upstream_localhost = True
    upstream_secret_like = False
    if upstream_url_raw:
        upstream_secret_like = local_proxy_secret_like(upstream_url_raw)
        try:
            parsed = urlparse(str(upstream_url_raw))
            upstream_host = parsed.hostname
        except ValueError:
            upstream_url_valid = False
            upstream_host = None
        else:
            if upstream_host:
                upstream_localhost = is_localhost_host(upstream_host)
            else:
                upstream_url_valid = False
                upstream_localhost = False
            try:
                upstream_port = parsed.port
            except ValueError:
                upstream_url_valid = False
                upstream_port = None
            if upstream_port is not None and target_port_raw is None:
                target_port_raw = upstream_port
        if upstream_host and target_host_raw is None:
            target_host_raw = upstream_host

    bind_host, bind_localhost, bind_secret_like = normalize_local_proxy_host(
        bind_host_raw,
        default=LOCAL_PROXY_DEFAULT_BIND_HOST,
    )
    target_host, target_localhost, target_secret_like = normalize_local_proxy_host(
        target_host_raw,
        default=LOCAL_PROXY_DEFAULT_TARGET_HOST,
    )
    bind_port, bind_port_valid = normalize_local_proxy_port(bind_port_raw, default=LOCAL_PROXY_DEFAULT_BIND_PORT)
    target_port, target_port_valid = normalize_local_proxy_port(target_port_raw, default=LOCAL_PROXY_DEFAULT_TARGET_PORT)
    ledger_jsonl = sanitize_local_proxy_value(ledger_jsonl_raw) if ledger_jsonl_raw else None
    proxy_label = sanitize_local_proxy_value(proxy_label_raw) if proxy_label_raw else "local-proxy-dry-run"
    api_key_provided = api_key_raw is not None and str(api_key_raw).strip() != ""
    authorization_header_provided = authorization_raw is not None and str(authorization_raw).strip() != ""
    secret_like_fields: list[str] = []
    for field, raw in (
        ("bind_host", bind_host_raw),
        ("bind_port", bind_port_raw),
        ("target_host", target_host_raw),
        ("target_port", target_port_raw),
        ("upstream_url", upstream_url_raw),
        ("ledger_jsonl", ledger_jsonl_raw),
        ("proxy_label", proxy_label_raw),
        ("api_key", api_key_raw),
        ("authorization_header", authorization_raw),
    ):
        if raw is not None and local_proxy_secret_like(raw):
            secret_like_fields.append(field)
    if bind_secret_like and "bind_host" not in secret_like_fields:
        secret_like_fields.append("bind_host")
    if target_secret_like and "target_host" not in secret_like_fields:
        secret_like_fields.append("target_host")
    if upstream_secret_like and "upstream_url" not in secret_like_fields:
        secret_like_fields.append("upstream_url")

    blockers: list[str] = []
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if not bind_port_valid:
        blockers.append("invalid_bind_port")
    if not target_port_valid:
        blockers.append("invalid_target_port")
    if upstream_url_raw and not upstream_url_valid:
        blockers.append("invalid_upstream_url")
    if not bind_localhost:
        blockers.append("non_localhost_bind_host")
    if not target_localhost:
        blockers.append("non_localhost_target_host")
    if upstream_url_raw and not upstream_localhost:
        blockers.append("non_localhost_upstream_url")
    if api_key_provided or authorization_header_provided:
        blockers.append("api_key_material_provided")
    if persist_api_key:
        blockers.append("api_key_persistence_requested")
    if external_forwarding_intent:
        blockers.append("external_forwarding_intent_not_allowed")
        if not runtime_gate_ack:
            blockers.append("missing_runtime_gate_ack")
    if secret_like_fields:
        blockers.append("secret_like_proxy_metadata")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "local-proxy",
        "mode": "dry_run",
        "status": "ready_for_runtime_review" if ready else "blocked_until_local_proxy_constraints",
        "input": input_meta,
        "policy": {
            "default_off": True,
            "dry_run_only": True,
            "localhost_only": True,
            "runtime_gate_required_before_forwarding": True,
            "runtime_gate_acknowledged": runtime_gate_ack,
            "stable_runtime_behavior_changed": False,
        },
        "bind": {
            "host": bind_host,
            "port": bind_port,
            "localhost_only": bind_localhost,
        },
        "target": {
            "host": target_host,
            "port": target_port,
            "upstream_url": upstream_url,
            "localhost_only": target_localhost,
        },
        "network_actions": {
            "listener_started": False,
            "outbound_forwarding_attempted": False,
            "dns_lookup_attempted": False,
            "external_services_called": False,
        },
        "api_key_persistence": {
            "api_key_material_provided": api_key_provided,
            "authorization_header_provided": authorization_header_provided,
            "requested": persist_api_key,
            "performed": False,
            "allowed_by_default": False,
        },
        "ledger_preview": {
            "schema_version": LOCAL_PROXY_SCHEMA_VERSION,
            "ledger_jsonl": ledger_jsonl,
            "ledger_write_performed": False,
            "proxy_label": proxy_label,
            "claim_boundary": "local_proxy_advisory_only_not_hosted_token_or_cost_savings",
        },
        "forwarding": {
            "external_forwarding_intent": external_forwarding_intent,
            "hidden_external_forwarding": False,
            "runtime_gate_acknowledged": runtime_gate_ack,
            "future_runtime_gate_required": True,
        },
        "redaction": {
            "secret_like_fields": sorted(set(secret_like_fields)),
            "raw_api_key_output": False,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "next_steps": [
                "Keep any real proxy runtime behind a separate future runtime gate.",
                "Use localhost-only bind and target defaults for advisory review.",
                "Do not persist API keys or forward externally from this dry-run planner.",
            ],
        },
        "claim_boundary": (
            "Dry-run local proxy advisory preview only; no listener, forwarding, API-key persistence, ledger write, "
            "or hosted API token/cost savings claim is performed."
        ),
    }


def command_plan_local_proxy(args: argparse.Namespace) -> int:
    payload = local_proxy_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard local proxy plan (dry-run only)")
        print("No listener was started, no traffic was forwarded, no API key was persisted, and no ledger was written.")
        print(f"Status: {payload['status']}")
        print(f"Bind: {payload['bind']['host']}:{payload['bind']['port']} localhost_only={payload['bind']['localhost_only']}")
        print(
            f"Target: {payload['target']['host']}:{payload['target']['port']} "
            f"localhost_only={payload['target']['localhost_only']}"
        )
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


LEARNED_CODE_FENCE_RE = re.compile(r"(?m)^\s*(?:```|~~~)")
LEARNED_DIFF_RE = re.compile(r"(?m)^\s*(diff --git |@@\s+-|--- |\+\+\+ |[+-].*)")
LEARNED_IDENTIFIER_RE = re.compile(
    r"\b(?:"
    r"_*[A-Za-z]+_[A-Za-z0-9_]*"
    r"|_*[a-z]+[A-Z][A-Za-z0-9]*"
    r"|_*[A-Z][a-z]+[A-Z][A-Za-z0-9]*"
    r"|_*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r"|_*[A-Z][A-Z0-9_]{2,}"
    r")\b"
)
LEARNED_PATH_RE = re.compile(
    r"(?x)(?:"
    r"(?<![\w.-])/(?:[A-Za-z0-9._@%+=:-]+/)*[A-Za-z0-9._@%+=:-]+"
    r"|"
    r"\b[A-Za-z]:\\(?:[^\\\s:\"'<>|]+\\)*[^\\\s:\"'<>|]+"
    r"|"
    r"(?<![\w.-])(?:\.{1,2}/)+[A-Za-z0-9._@%+=:-]+(?:/[A-Za-z0-9._@%+=:-]+)*\b"
    r"|"
    r"\b(?:\.{1,2}/)?(?:[A-Za-z0-9._@%+=:-]+/)+[A-Za-z0-9._@%+=:-]+\b"
    r"|"
    r"\b[A-Za-z0-9._-]+\.(?:py|js|ts|tsx|jsx|go|rs|java|kt|swift|json|ya?ml|toml|md|txt|log|sh|bash|zsh|sql|html|css)\b"
    r")"
)
LEARNED_HASH_RE = re.compile(r"\b(?:sha256:[0-9a-fA-F]{32,64}|[0-9a-fA-F]{7,64})\b")
LEARNED_STACK_FRAME_RE = re.compile(
    r"(?m)^\s*(?:File\s+\"[^\"]+\",\s+line\s+\d+,\s+in\s+\S+|at\s+\S+.*\([^)]*:\d+(?::\d+)?\))"
)
LEARNED_JSON_KEY_RE = re.compile(r"""(?x)"(?:[^"\\]|\\.)*"\s*:|'(?:[^'\\]|\\.)*'\s*:""")
LEARNED_QUOTED_STRING_RE = re.compile(
    r'''(?x)"""(?:.|\n)*?"""|''' + r"""'''(?:.|\n)*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'"""
)
LEARNED_NUMERIC_CONSTANT_RE = re.compile(
    r"(?<![\w.])(?:[vV]?\d+(?:\.\d+)*|[-+]?0x[0-9A-Fa-f]+)(?![\w.])"
)
LEARNED_PROMPT_LIKE_RE = re.compile(
    r"(?imx)(?:"
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:above|earlier|previous|prior)\s+instructions?\b"
    r"|^\s*(?:system|developer|user|assistant)\s*:"
    r"|\b(?:system|developer|user|assistant)\s+instructions?\b"
    r"|\b(?:system|developer)\s+message\b"
    r"|\byou\s+are\s+(?:now\s+)?(?:chatgpt|a\s+\w+|\w+)\b"
    r"|\bact\s+as\b"
    r"|\bjailbreak\b"
    r"|\bdo\s+not\s+follow\b"
    r"|\boverride\s+instructions\b"
    r")"
)
LEARNED_URL_RE = re.compile(
    r"(?i)\b(?:https?://|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?:/|\b)"
)
LEARNED_CODE_LIKE_RE = re.compile(
    r"(?mx)^\s*(?:"
    r"(?:from\s+\S+\s+import\s+\S+|import\s+\S+|def\s+[A-Za-z_]\w*\s*\(|class\s+[A-Za-z_]\w*\s*(?:\(|:)|"
    r"function\s+[A-Za-z_$][\w$]*\s*\(|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=)"
    r"|(?:if|elif|else|for|while|try|except|finally|with)\b.*:"
    r"|(?:print|raise|return|yield|assert)\b(?:\s*\(|\s+\S+)"
    r"|[A-Za-z_][A-Za-z0-9_]*\s*(?:=|==|!=|<=|>=|\+=|-=|\*=|/=)\s*\S+"
    r"|.*[{};]\s*$"
    r"|(?:ls|cp|mv|rm|sudo|curl|wget|chmod|chown|git|npm|npx|pnpm|yarn|python3?|pip|node|bash|sh|zsh|cat|grep|sed|awk|make|cargo|pytest|tox|uv|ruff|mypy|pyright|docker|kubectl)(?:\s+(?:-\S+|\S+))*"
    r"|<[/!]?[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*)?>"
    r")"
)
LEARNED_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
LEARNED_NON_TEXT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]")
LEARNED_WORD_RE = re.compile(r"\b[\w.-]+\b")
LEARNED_ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")


def read_learned_input(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    source_label = args.source_label
    if args.input:
        path = Path(args.input)
        source_label = source_label or path.name
        loaded = read_bounded_regular_file(path, max_bytes=MAX_LEARNED_COMPRESSION_INPUT_BYTES, label="learned-compression input")
        assert loaded is not None
        raw, truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_LEARNED_COMPRESSION_INPUT_BYTES + 1)
        truncated = len(raw) > MAX_LEARNED_COMPRESSION_INPUT_BYTES
        raw = raw[:MAX_LEARNED_COMPRESSION_INPUT_BYTES]
    text = raw.decode("utf-8", errors="replace")
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "truncated": truncated,
        "max_bytes": MAX_LEARNED_COMPRESSION_INPUT_BYTES,
    }
    return text, metadata


def learned_content_type(text: str, counts: dict[str, int]) -> str:
    stripped = text.strip()
    if not stripped:
        return "empty"
    if counts["non_text_input"]:
        return "non_text"
    if counts["protected_json_key"]:
        return "json"
    if counts["protected_diff"]:
        return "diff"
    if counts["protected_code_fence"] or counts["protected_code_like"] or counts["protected_identifier"] >= 3:
        return "code"
    return "prose"


def learned_signal_counts(text: str) -> dict[str, int]:
    words = LEARNED_WORD_RE.findall(text)
    numeric_count = len(LEARNED_NUMERIC_CONSTANT_RE.findall(text))
    code_like_count = len(LEARNED_CODE_LIKE_RE.findall(text)) + len(LEARNED_INLINE_CODE_RE.findall(text))
    numeric_density_high = 1 if words and numeric_count >= 3 and numeric_count / len(words) >= 0.20 else 0
    return {
        "protected_code_fence": len(LEARNED_CODE_FENCE_RE.findall(text)),
        "protected_diff": len(LEARNED_DIFF_RE.findall(text)),
        "protected_identifier": len(LEARNED_IDENTIFIER_RE.findall(text)),
        "protected_path": len(LEARNED_PATH_RE.findall(text)),
        "protected_hash": len(LEARNED_HASH_RE.findall(text)),
        "protected_stack_frame": len(LEARNED_STACK_FRAME_RE.findall(text)),
        "protected_json_key": len(LEARNED_JSON_KEY_RE.findall(text)),
        "protected_numeric_constant": numeric_count,
        "protected_quoted_string": len(LEARNED_QUOTED_STRING_RE.findall(text)),
        "prompt_like_instruction": len(LEARNED_PROMPT_LIKE_RE.findall(text)),
        "url_or_endpoint": len(LEARNED_URL_RE.findall(text)),
        "protected_code_like": code_like_count,
        "non_text_input": len(LEARNED_NON_TEXT_RE.findall(text)),
        "numeric_density_high": numeric_density_high,
    }


def valid_learned_reexpand_command(receipt_id: str | None, command: str | None) -> tuple[bool, str | None]:
    if not receipt_id or not command:
        return False, "missing_exact_fallback"
    if not LEARNED_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command"
    if any(token in command for token in (";", "|", "&", ">", "<", "`", "$", "\n", "\r")):
        return False, "invalid_reexpand_command"
    try:
        argv = shlex.split(command)
    except ValueError:
        return False, "invalid_reexpand_command"
    if len(argv) < 4:
        return False, "invalid_reexpand_command"
    if argv == ["context-guard-artifact", "get", receipt_id, "--full"]:
        return True, None
    if argv == ["context-guard", "artifact", "get", receipt_id, "--full"]:
        return True, None
    return False, "invalid_reexpand_command"


def learned_compression_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    text, input_meta = read_learned_input(args)
    receipt_id = args.exact_fallback_receipt.strip() if args.exact_fallback_receipt else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, fallback_blocker = valid_learned_reexpand_command(receipt_id, reexpand_command)
    counts = learned_signal_counts(text)
    content_type = learned_content_type(text, counts)

    blockers: list[str] = []
    if not text.strip():
        blockers.append("missing_input")
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if not args.sanitized:
        blockers.append("missing_sanitized_assertion")
    if not args.trusted_source:
        blockers.append("untrusted_input")
    if fallback_blocker:
        blockers.append(fallback_blocker)
    if content_type != "prose" and text.strip():
        blockers.append("non_prose_input")
    for blocker, count in counts.items():
        if count:
            blockers.append(blocker)
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "learned-compression",
        "mode": "dry_run",
        "status": "ready_for_human_review" if ready else "blocked_until_safe_input",
        "input": input_meta,
        "policy": {
            "deny_by_default": True,
            "runtime_compression_allowed": False,
            "eligible_for_human_review": ready,
            "human_review_required": True,
            "stable_runtime_behavior_changed": False,
        },
        "sanitization": {
            "required": True,
            "caller_asserted": bool(args.sanitized),
            "verified": False,
        },
        "trust": {
            "required": True,
            "caller_asserted": bool(args.trusted_source),
            "verified": False,
        },
        "exact_fallback": {
            "required": True,
            "available": bool(receipt_id and reexpand_command and reexpand_valid),
            "receipt_id": receipt_id,
            "cli": reexpand_command,
            "verified": False,
        },
        "protected_signal_scan": {
            "content_type": content_type,
            "counts": counts,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "protected_signals": [name for name, count in counts.items() if count],
            "next_steps": [
                "Keep exact fallback receipt and re-expand command available before considering any future summary.",
                "Reject learned compression for protected, prompt-like, untrusted, or non-prose input.",
                "Do not claim hosted token/cost savings from this dry-run policy check.",
            ],
        },
        "claim_boundary": (
            "Dry-run learned-compression policy check only; no hosted token/cost savings claim without "
            "provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_learned_compression(args: argparse.Namespace) -> int:
    payload = learned_compression_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard learned/synthetic compression gate (dry-run only)")
        print("No learned compressor/model/provider was called and no replacement text was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Input: {payload['input']['source_label']} lines={payload['input']['lines']} sha256={payload['input']['sha256']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", help="Project root for default project-local experiment config (default: cwd).")
    parser.add_argument("--config", help="Project-local config path. Relative paths resolve under --root; absolute paths must stay inside --root.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")


def load_args_context(args: argparse.Namespace) -> tuple[Path, Path, dict[str, Any]]:
    root = resolve_root(args.root)
    config_path = resolve_config_path(root, args.config)
    return root, config_path, load_config(config_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Inspect and manage default-off ContextGuard experimental feature opt-ins.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List known experiments and metadata.")
    add_common_args(list_parser)
    list_parser.set_defaults(func=command_list)

    status_parser = sub.add_parser("status", help="Show project-local experiment enablement status.")
    add_common_args(status_parser)
    status_parser.set_defaults(func=command_status)

    enable_parser = sub.add_parser("enable", help="Enable one experiment in project-local config.")
    enable_parser.add_argument("experiment_id")
    add_common_args(enable_parser)
    enable_parser.set_defaults(func=command_enable)

    disable_parser = sub.add_parser("disable", help="Disable one experiment in project-local config.")
    disable_parser.add_argument("experiment_id")
    add_common_args(disable_parser)
    disable_parser.set_defaults(func=command_disable)

    plan_parser = sub.add_parser("plan", help="Run read-only dry-run planners for experimental lanes.")
    plan_sub = plan_parser.add_subparsers(dest="plan_command", required=True)

    context_diff = plan_sub.add_parser(
        "context-diff-compaction",
        help="Dry-run a reviewable context-diff compaction plan without emitting a replacement.",
    )
    context_diff.add_argument("--input", help="Read diff text from a file instead of stdin.")
    context_diff.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    context_diff.add_argument("--receipt-id", help="User-supplied exact receipt/artifact id for human review readiness.")
    context_diff.add_argument("--reexpand-command", help="User-supplied exact re-expand command for human review readiness.")
    context_diff.add_argument("--json", action="store_true", help="Emit JSON output.")
    context_diff.set_defaults(func=command_plan_context_diff_compaction)

    visual_ocr = plan_sub.add_parser(
        "visual-crop-ocr",
        help="Dry-run visual crop/OCR evidence metadata without calling OCR or image services.",
    )
    visual_ocr.add_argument("--full-evidence-receipt", help="User-supplied receipt/id for the original full visual evidence.")
    visual_ocr.add_argument("--full-evidence-label", help="Safe label for the full visual evidence.")
    visual_ocr.add_argument("--crop-label", help="Safe label for the cropped region or crop fixture.")
    visual_ocr.add_argument("--crop-bounds", help="Crop bounds as x,y,width,height integers.")
    visual_ocr.add_argument("--image-size", help="Original image size as width,height integers.")
    visual_ocr.add_argument("--ocr-text", help="Bounded OCR fixture text supplied inline.")
    visual_ocr.add_argument("--ocr-text-file", help="Read bounded OCR fixture text from a UTF-8 text file.")
    visual_ocr.add_argument("--ocr-source-label", help="Safe label for OCR text source; defaults to inline or file basename.")
    visual_ocr.add_argument("--ocr-confidence", help="OCR confidence as a finite decimal from 0.0 to 1.0.")
    visual_ocr.add_argument("--ocr-error-note", action="append", help="Known OCR error/uncertainty note. Repeatable.")
    visual_ocr.add_argument("--missed-context-note", action="append", help="Potential context outside crop/OCR text. Repeatable.")
    visual_ocr.add_argument("--json", action="store_true", help="Emit JSON output.")
    visual_ocr.set_defaults(func=command_plan_visual_crop_ocr)

    self_hosted = plan_sub.add_parser(
        "self-hosted-metrics-ledger",
        help="Dry-run self-hosted/local metrics ledger sidecar evidence without writing a ledger.",
    )
    self_hosted.add_argument("--input", help="Read an explicit self_hosted_metrics JSON envelope from a file instead of stdin.")
    self_hosted.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    self_hosted.add_argument("--latency-ms", type=float, default=None, help="Local/model-server latency in milliseconds.")
    self_hosted.add_argument("--peak-memory-mb", type=float, default=None, help="Peak local/model-server memory in MiB/MB.")
    self_hosted.add_argument("--quality-score", type=float, default=None, help="Quality score from 0.0 to 1.0.")
    self_hosted.add_argument("--energy-wh", type=float, default=None, help="Diagnostic local energy use in watt-hours.")
    self_hosted.add_argument("--local-cost-usd", type=float, default=None, help="Diagnostic local/self-hosted cost in USD.")
    self_hosted.add_argument("--tokens-per-second", type=float, default=None, help="Diagnostic local throughput.")
    self_hosted.add_argument("--model-server", help="Sanitized label for local model server/runtime.")
    self_hosted.add_argument("--optimization", help="Sanitized label for the local optimization under test.")
    self_hosted.add_argument("--quality-metric", help="Sanitized label for quality metric.")
    self_hosted.add_argument("--hardware", help="Sanitized local hardware label.")
    self_hosted.add_argument("--runtime", help="Sanitized local runtime label.")
    self_hosted.add_argument("--dataset", help="Sanitized dataset label.")
    self_hosted.add_argument("--json", action="store_true", help="Emit JSON output.")
    self_hosted.set_defaults(func=command_plan_self_hosted_metrics_ledger)

    local_proxy = plan_sub.add_parser(
        "local-proxy",
        help="Dry-run a localhost-only local proxy advisory plan without starting a proxy.",
    )
    local_proxy.add_argument("--input", help="Read a local_proxy JSON envelope from a file instead of CLI flags.")
    local_proxy.add_argument("--bind-host", help="Advisory bind host; must be localhost/loopback.")
    local_proxy.add_argument("--bind-port", default=None, help="Advisory bind port; 0 means unspecified/ephemeral.")
    local_proxy.add_argument("--target-host", help="Advisory target host; must be localhost/loopback.")
    local_proxy.add_argument("--target-port", default=None, help="Advisory target port; 0 means unspecified.")
    local_proxy.add_argument("--upstream-url", help="Advisory upstream URL; host must be localhost/loopback.")
    local_proxy.add_argument("--ledger-jsonl", help="Advisory ledger path preview; dry-run only, not written.")
    local_proxy.add_argument("--proxy-label", help="Safe label for this local proxy plan.")
    local_proxy.add_argument("--api-key", help="Blocked/redacted API key material; never persisted or emitted raw.")
    local_proxy.add_argument("--authorization-header", help="Blocked/redacted Authorization header; never persisted or emitted raw.")
    local_proxy.add_argument("--persist-api-key", action="store_true", help="Declare API-key persistence intent; blocked by default.")
    local_proxy.add_argument(
        "--external-forwarding-intent",
        action="store_true",
        help="Declare future external forwarding intent; blocked in this dry-run planner.",
    )
    local_proxy.add_argument(
        "--runtime-gate-ack",
        action="store_true",
        help="Acknowledge that any future forwarding needs a separate runtime gate.",
    )
    local_proxy.add_argument("--json", action="store_true", help="Emit JSON output.")
    local_proxy.set_defaults(func=command_plan_local_proxy)

    learned = plan_sub.add_parser(
        "learned-compression",
        help="Dry-run a deny-by-default learned/synthetic compression safety gate.",
    )
    learned.add_argument("--input", help="Read candidate prose from a text file instead of stdin.")
    learned.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    learned.add_argument("--sanitized", action="store_true", help="Assert input is already sanitized.")
    learned.add_argument("--trusted-source", action="store_true", help="Assert input came from a trusted source.")
    learned.add_argument("--exact-fallback-receipt", help="Local exact fallback receipt id for the original text.")
    learned.add_argument("--reexpand-command", help="Local exact re-expand command bound to the receipt id.")
    learned.add_argument("--json", action="store_true", help="Emit JSON output.")
    learned.set_defaults(func=command_plan_learned_compression)

    emit_parser = sub.add_parser("emit", help="Emit explicit local runtime outputs for experimental lanes.")
    emit_sub = emit_parser.add_subparsers(dest="emit_command", required=True)
    emit_context_diff = emit_sub.add_parser(
        "context-diff-compaction",
        help="Emit a caller-supplied compact diff replacement only with exact retrieval metadata.",
    )
    emit_context_diff.add_argument("--input", help="Read original diff text from a file instead of stdin.")
    emit_context_diff.add_argument("--source-label", help="Safe label to use for the diff input source in reports.")
    emit_context_diff.add_argument("--receipt-id", required=True, help="Exact local artifact receipt id for the original diff.")
    emit_context_diff.add_argument("--reexpand-command", required=True, help="Exact command that restores the original diff.")
    replacement_group = emit_context_diff.add_mutually_exclusive_group(required=True)
    replacement_group.add_argument("--replacement-text", help="Caller-supplied compact replacement text to emit.")
    replacement_group.add_argument("--replacement-file", help="Read caller-supplied compact replacement text from a file.")
    emit_context_diff.add_argument("--json", action="store_true", help="Emit JSON output.")
    emit_context_diff.set_defaults(func=command_emit_context_diff_compaction)

    record_parser = sub.add_parser("record", help="Run explicit local runtime recorders for experimental lanes.")
    record_sub = record_parser.add_subparsers(dest="record_command", required=True)
    record_self_hosted = record_sub.add_parser(
        "self-hosted-metrics-ledger",
        help="Append one self-hosted/local metrics sidecar row to a JSONL ledger.",
    )
    record_self_hosted.add_argument("--ledger-jsonl", required=True, help="Local JSONL ledger path to append.")
    record_self_hosted.add_argument("--input", help="Read an explicit self_hosted_metrics JSON envelope from a file instead of stdin.")
    record_self_hosted.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    record_self_hosted.add_argument("--latency-ms", type=float, default=None, help="Local/model-server latency in milliseconds.")
    record_self_hosted.add_argument("--peak-memory-mb", type=float, default=None, help="Peak local/model-server memory in MiB/MB.")
    record_self_hosted.add_argument("--quality-score", type=float, default=None, help="Quality score from 0.0 to 1.0.")
    record_self_hosted.add_argument("--energy-wh", type=float, default=None, help="Diagnostic local energy use in watt-hours.")
    record_self_hosted.add_argument("--local-cost-usd", type=float, default=None, help="Diagnostic local/self-hosted cost in USD.")
    record_self_hosted.add_argument("--tokens-per-second", type=float, default=None, help="Diagnostic local throughput.")
    record_self_hosted.add_argument("--model-server", help="Sanitized label for local model server/runtime.")
    record_self_hosted.add_argument("--optimization", help="Sanitized label for the local optimization under test.")
    record_self_hosted.add_argument("--quality-metric", help="Sanitized label for quality metric.")
    record_self_hosted.add_argument("--hardware", help="Sanitized local hardware label.")
    record_self_hosted.add_argument("--runtime", help="Sanitized local runtime label.")
    record_self_hosted.add_argument("--dataset", help="Sanitized dataset label.")
    record_self_hosted.add_argument("--task-id", default="self-hosted-metrics-manual", help="Sanitized task id for the ledger row.")
    record_self_hosted.add_argument("--variant", default="self-hosted-metrics-ledger", help="Sanitized variant label for the ledger row.")
    record_self_hosted.add_argument(
        "--success",
        choices=("true", "false", "unknown"),
        default="unknown",
        help="Optional success value for the local run; unknown writes JSON null.",
    )
    record_self_hosted.add_argument(
        "--notes",
        default="explicit self-hosted metrics record; no hosted API savings claim",
        help="Sanitized note for the ledger row.",
    )
    record_self_hosted.add_argument("--json", action="store_true", help="Emit JSON output.")
    record_self_hosted.set_defaults(func=command_record_self_hosted_metrics_ledger)

    return parser


def normalize_negative_csv_option_values(argv: list[str] | None) -> list[str] | None:
    """Keep negative comma-separated option values portable across Python versions.

    Python 3.11/3.12 argparse treats a value such as ``-1,0,20,10`` after an
    option as another option token rather than as the option's value.  Python
    3.14 accepts the same test input, so normalize the small set of CSV-valued
    options that intentionally accepts negative numbers for validation.
    """
    if argv is None:
        argv = sys.argv[1:]
    normalized: list[str] = []
    pending_csv_option: str | None = None
    csv_options = {"--crop-bounds"}
    for token in argv:
        if pending_csv_option is not None:
            normalized.append(f"{pending_csv_option}={token}")
            pending_csv_option = None
            continue
        if token in csv_options:
            pending_csv_option = token
            continue
        normalized.append(token)
    if pending_csv_option is not None:
        normalized.append(pending_csv_option)
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_negative_csv_option_values(argv))
    try:
        return int(args.func(args))
    except RegistryError as exc:
        fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
