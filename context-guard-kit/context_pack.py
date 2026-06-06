#!/usr/bin/env python3
"""Build a deterministic, budgeted local context pack from prioritized files.

The packer is local-only and intentionally conservative. It assembles selected
file slices into a Markdown body whose rendered UTF-8 byte length is bounded by
``--budget-bytes``. It redacts before building the pack/receipt, records why
lower-priority sources were omitted, and emits exact local slice commands for
retrieval when the path is safe to display.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

TOOL_NAME = "context-guard-pack"
VERSION = 1
DEFAULT_BUDGET_BYTES = 12_000
MIN_BUDGET_BYTES = 0
MAX_BUDGET_BYTES = 2_000_000
MAX_RECEIPT_BYTES = 64_000
MAX_MANIFEST_BYTES = 1_000_000
MAX_LABEL_CHARS = 160
MAX_REASON_CHARS = 120
TOKEN_PROXY_CHARS_PER_TOKEN = 4
SUGGEST_SCHEMA_VERSION = "contextguard.pack-suggest.v1"
DEFAULT_SUGGEST_TOP = 8
MAX_SUGGEST_TOP = 50
DEFAULT_SUGGEST_CONTEXT_LINES = 20
MAX_SUGGEST_CONTEXT_LINES = 120
SUGGEST_WHOLE_FILE_MAX_LINES = 120
MAX_SUGGEST_INPUT_BYTES = 256_000
MAX_QUERY_SCAN_FILES = 2_000
MAX_QUERY_SCAN_BYTES_PER_FILE = 200_000
PACK_DIR = ".context-guard/packs"
REDACTED_PATH_COMPONENT = "[REDACTED-PATH-COMPONENT]"
SECRET_CONTENT_RE = re.compile(
    r"(?is)("
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|"
    r"sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"(?i:Authorization)\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*[:=]\s*[^\s]+"
    r")"
)


@dataclass(frozen=True)
class LineRange:
    start: int
    end: int

    def as_dict(self) -> dict[str, int]:
        return {"start": self.start, "end": self.end}

    def identity(self) -> str:
        return f"{self.start}:{self.end}"


@dataclass
class SourceSpec:
    path: str
    priority: int = 0
    lines: LineRange | None = None
    label: str | None = None
    input_index: int = 0
    origin: str = "cli"


@dataclass
class ResolvedSource:
    spec: SourceSpec
    abs_path: Path
    display_path: str
    redacted_path: bool
    requested_lines: LineRange | None
    selected_lines: list[str]
    total_lines: int
    redacted_lines: int


@dataclass
class SuggestCandidate:
    path: str
    score: int
    reason: str
    lines: LineRange | None = None
    label: str | None = None
    input_index: int = 0


class PackError(ValueError):
    pass


class FallbackLineSanitizer:
    def __init__(self, *, show_paths: bool = False) -> None:
        self.show_paths = show_paths
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        def repl(match: re.Match[str]) -> str:
            text = match.group(0)
            if "=" in text:
                key = text.split("=", 1)[0]
                return key + "=[REDACTED]"
            if ":" in text and re.search(r"(?i)(api|token|secret|password|authorization)", text.split(":", 1)[0]):
                key = text.split(":", 1)[0]
                return key + ": [REDACTED]"
            return "[REDACTED]"

        line, count = SECRET_CONTENT_RE.subn(repl, raw_line)
        if count:
            self.redactions += 1
        return line, bool(count)


def load_line_sanitizer(show_paths: bool = False) -> object:
    script_dir = Path(__file__).resolve().parent
    for name in ("sanitize_output.py", "context-guard-sanitize-output", "claude-sanitize-output"):
        candidate = script_dir / name
        if not candidate.exists():
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_context_guard_pack_sanitize_{os.getpid()}", str(candidate))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            if spec is None:
                raise RuntimeError("import spec unavailable")
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module.LineSanitizer(show_paths=show_paths)
        except Exception as exc:
            raise RuntimeError(f"could not load sanitizer {candidate}: {exc}") from exc
    return FallbackLineSanitizer(show_paths=show_paths)


def sanitize_text(text: str, *, show_paths: bool = False) -> tuple[str, int]:
    sanitizer = load_line_sanitizer(show_paths)
    redacted = 0
    out: list[str] = []
    for line in text.splitlines(True):
        sanitized, did_redact = sanitizer.sanitize(line)  # type: ignore[attr-defined]
        out.append(sanitized)
        if did_redact:
            redacted += 1
    return "".join(out), redacted


def byte_len(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def token_proxy(text: str) -> int:
    if not text:
        return 0
    return max(1, round(len(text) / TOKEN_PROXY_CHARS_PER_TOKEN))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def path_hash(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:12]


def sanitize_path_component(component: str) -> tuple[str, bool]:
    if SECRET_CONTENT_RE.search(component):
        return REDACTED_PATH_COMPONENT, True
    return component, False


def display_root(root: Path) -> str:
    name, redacted = sanitize_path_component(root.name or "project")
    if redacted:
        name = "project"
    return f"{name}#path:{path_hash(root)}"


def display_rel_path(rel: str) -> tuple[str, bool]:
    parts: list[str] = []
    redacted = False
    for part in rel.replace("\\", "/").split("/"):
        if not part:
            continue
        safe, did = sanitize_path_component(part)
        parts.append(safe)
        redacted = redacted or did
    return "/".join(parts), redacted


def parse_line_range(value: object) -> LineRange | None:
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        try:
            start = int(value.get("start"))
            end = int(value.get("end"))
        except (TypeError, ValueError):
            raise PackError("invalid_lines")
    elif isinstance(value, str):
        if ":" not in value:
            raise PackError("invalid_lines")
        left, right = value.split(":", 1)
        try:
            start = int(left)
            end = int(right)
        except ValueError:
            raise PackError("invalid_lines")
    else:
        raise PackError("invalid_lines")
    if start < 1 or end < start:
        raise PackError("invalid_lines")
    return LineRange(start, end)


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def cap_label(value: object, default: str | None = None, limit: int = MAX_LABEL_CHARS) -> str | None:
    if value is None:
        return default
    text = " ".join(str(value).strip().split())
    text = SECRET_CONTENT_RE.sub("[REDACTED]", text)
    if not text:
        return default
    if len(text) > limit:
        text = text[: max(0, limit - 15)].rstrip() + " ...[truncated]"
    return text


def read_manifest(path: Path) -> list[SourceSpec]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PackError(f"could not read manifest: {exc.strerror or exc.__class__.__name__}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PackError(f"manifest exceeds trusted size cap: {len(raw)} > {MAX_MANIFEST_BYTES}")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackError(f"invalid manifest JSON: {exc}") from exc
    version = data.get("version", VERSION) if isinstance(data, dict) else None
    if version != VERSION:
        raise PackError(f"unsupported manifest version: {version}")
    sources = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, list):
        raise PackError("manifest sources must be a list")
    out: list[SourceSpec] = []
    for item in sources:
        if not isinstance(item, dict):
            raise PackError("manifest sources must be objects")
        if "path" not in item:
            raise PackError("manifest source missing path")
        try:
            lines = parse_line_range(item.get("lines"))
        except PackError:
            lines = LineRange(-1, -1)
        out.append(SourceSpec(
            path=str(item.get("path", "")),
            priority=bounded_int(item.get("priority"), 0, -1_000_000, 1_000_000),
            lines=lines,
            label=cap_label(item.get("label")),
            origin="manifest",
        ))
    return out


def parse_source_spec(raw: str) -> SourceSpec:
    raw = raw.strip()
    if not raw:
        raise PackError("empty --source")
    values: dict[str, str] = {}
    if "=" not in raw.split(",", 1)[0]:
        values["path"] = raw
    else:
        for part in raw.split(","):
            if not part:
                continue
            if "=" not in part:
                raise PackError(f"invalid --source part: {part}")
            key, value = part.split("=", 1)
            values[key.strip()] = value.strip()
    if "path" not in values or not values["path"]:
        raise PackError("--source missing path")
    try:
        lines = parse_line_range(values.get("lines"))
    except PackError:
        lines = LineRange(-1, -1)
    return SourceSpec(
        path=values["path"],
        priority=bounded_int(values.get("priority"), 0, -1_000_000, 1_000_000),
        lines=lines,
        label=cap_label(values.get("label")),
        origin="cli",
    )


def normalize_root(raw_root: Path) -> Path:
    expanded = raw_root.expanduser()
    try:
        if expanded.is_symlink():
            raise PackError("root must not be a symlink")
        root = expanded.resolve()
    except OSError as exc:
        raise PackError(f"could not resolve root: {exc.strerror or exc.__class__.__name__}") from exc
    if not root.is_dir():
        raise PackError("root must be a directory")
    return root


def omission(spec: SourceSpec, reason: str, *, path: str | None = None, redacted_path: bool = False) -> dict[str, Any]:
    item: dict[str, Any] = {
        "path": path if path is not None else safe_raw_path_label(spec.path),
        "status": "omitted",
        "priority": spec.priority,
        "reason": reason,
        "input_index": spec.input_index,
    }
    if spec.label:
        item["label"] = spec.label
    if spec.lines and spec.lines.start > 0:
        item["requested_lines"] = spec.lines.as_dict()
    if redacted_path:
        item["retrieval_omitted_reason"] = "redacted_path"
    return item


def safe_raw_path_label(raw: str) -> str:
    text = raw.replace("\\", "/")
    parts = []
    for part in text.split("/"):
        if part in {"", "."}:
            continue
        safe, _ = sanitize_path_component(part)
        parts.append(safe)
    return "/".join(parts) or "path"


def lexical_rel(raw_path: str) -> tuple[Path | None, str]:
    path = Path(raw_path)
    if path.is_absolute():
        return None, "outside_root"
    parts = path.parts
    if not parts or any(part in {"..", ""} for part in parts):
        return None, "outside_root"
    cleaned = Path(*[part for part in parts if part != "."])
    if not cleaned.parts:
        return None, "outside_root"
    return cleaned, ""


def open_dir_no_follow(path: Path | str, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if dir_fd is None:
        fd = os.open(path, flags)
    else:
        fd = os.open(path, flags, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise PackError("not a directory")
        return fd
    except Exception:
        os.close(fd)
        raise


def open_regular_under_root(root: Path, rel: Path) -> tuple[Any | None, str]:
    current_fd: int | None = None
    try:
        current_fd = open_dir_no_follow(root)
        for index, part in enumerate(rel.parts):
            if part in {"", ".", ".."}:
                return None, "outside_root"
            is_final = index == len(rel.parts) - 1
            if not is_final:
                try:
                    next_fd = open_dir_no_follow(part, dir_fd=current_fd)
                except FileNotFoundError:
                    return None, "missing"
                except NotADirectoryError:
                    return None, "missing"
                except OSError:
                    return None, "unsafe_path"
                os.close(current_fd)
                current_fd = next_fd
                continue
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            file_fd = -1
            try:
                file_fd = os.open(part, flags, dir_fd=current_fd)
                st = os.fstat(file_fd)
                if not stat.S_ISREG(st.st_mode):
                    os.close(file_fd)
                    file_fd = -1
                    return None, "empty_source"
                handle = os.fdopen(file_fd, "r", encoding="utf-8", errors="replace", newline="")
                file_fd = -1
                return handle, ""
            except FileNotFoundError:
                return None, "missing"
            except IsADirectoryError:
                return None, "empty_source"
            except NotADirectoryError:
                return None, "missing"
            except OSError:
                return None, "unsafe_path"
            finally:
                if file_fd >= 0:
                    try:
                        os.close(file_fd)
                    except OSError:
                        pass
    except OSError:
        return None, "unsafe_path"
    finally:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
    return None, "unsafe_path"


def resolve_source(root: Path, spec: SourceSpec) -> tuple[ResolvedSource | None, dict[str, Any] | None]:
    if spec.lines is not None and spec.lines.start < 1:
        return None, omission(spec, "invalid_lines")
    rel, reason = lexical_rel(spec.path)
    if rel is None:
        return None, omission(spec, reason)
    display, redacted_path = display_rel_path(rel.as_posix())
    handle, reason = open_regular_under_root(root, rel)
    if handle is None:
        return None, omission(spec, reason, path=display, redacted_path=redacted_path)
    try:
        with handle:
            raw_text = handle.read()
    except OSError:
        return None, omission(spec, "unsafe_path", path=display, redacted_path=redacted_path)
    sanitized, redacted_lines = sanitize_text(raw_text)
    all_lines = sanitized.splitlines(True)
    if not all_lines:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    total_lines = len(all_lines)
    requested = spec.lines or LineRange(1, total_lines)
    if requested.start > total_lines:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    end = min(requested.end, total_lines)
    selected = all_lines[requested.start - 1:end]
    if not selected:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    return ResolvedSource(
        spec=spec,
        abs_path=root / rel,
        display_path=display,
        redacted_path=redacted_path,
        requested_lines=requested,
        selected_lines=selected,
        total_lines=total_lines,
        redacted_lines=redacted_lines,
    ), None


def retrieval_cli(root_arg: str, display_path: str, lines: LineRange) -> str:
    return (
        f"context-guard-pack slice --root {shlex.quote(root_arg)} "
        f"--path {shlex.quote(display_path)} --lines {lines.start}:{lines.end} --json"
    )


def safe_root_arg_for_retrieval(root_arg: str) -> str | None:
    text = str(root_arg)
    if SECRET_CONTENT_RE.search(text):
        return None
    for part in text.replace("\\", "/").split("/"):
        if not part:
            continue
        _safe, redacted = sanitize_path_component(part)
        if redacted:
            return None
    return text


def retrieval_for(root_arg: str, display_path: str, lines: LineRange, *, redacted_path: bool) -> tuple[str | None, str | None]:
    if redacted_path:
        return None, "redacted_path"
    safe_root = safe_root_arg_for_retrieval(root_arg)
    if safe_root is None:
        return None, "unsafe_root_path"
    return retrieval_cli(safe_root, display_path, lines), None


def render_block(source: ResolvedSource, lines: list[str], *, root_arg: str, status: str, included: LineRange) -> str:
    title = source.spec.label or source.display_path
    requested = source.requested_lines or LineRange(1, source.total_lines)
    retrieval, retrieval_omitted_reason = retrieval_for(root_arg, source.display_path, included, redacted_path=source.redacted_path)
    header = [
        f"## {title}",
        f"Source: `{source.display_path}`",
        f"Priority: {source.spec.priority}",
        f"Status: {status}",
        f"Included lines: {included.start}:{included.end}",
        f"Requested lines: {requested.start}:{requested.end}",
    ]
    if retrieval:
        header.append(f"Retrieval: `{retrieval}`")
    elif retrieval_omitted_reason:
        header.append(f"Retrieval omitted: {retrieval_omitted_reason}")
    return "\n".join(header) + "\n\n```text\n" + "".join(lines) + ("" if not lines or lines[-1].endswith("\n") else "\n") + "```\n\n"


def source_metadata(source: ResolvedSource, *, status: str, lines: list[str], included: LineRange, root_arg: str) -> dict[str, Any]:
    requested = source.requested_lines or LineRange(1, source.total_lines)
    item: dict[str, Any] = {
        "path": source.display_path,
        "status": status,
        "priority": source.spec.priority,
        "input_index": source.spec.input_index,
        "requested_lines": requested.as_dict(),
        "included_lines": included.as_dict(),
        "bytes": byte_len("".join(lines)),
    }
    if source.spec.label:
        item["label"] = source.spec.label
    retrieval, retrieval_omitted_reason = retrieval_for(root_arg, source.display_path, included, redacted_path=source.redacted_path)
    if retrieval:
        item["retrieval_cli"] = retrieval
    elif retrieval_omitted_reason:
        item["retrieval_omitted_reason"] = retrieval_omitted_reason
    if status == "partial":
        item["reason"] = "budget_exhausted"
    return item


def budget_omission(source: ResolvedSource, *, root_arg: str) -> dict[str, Any]:
    requested = source.requested_lines or LineRange(1, source.total_lines)
    item = omission(source.spec, "budget_exhausted", path=source.display_path, redacted_path=source.redacted_path)
    item["requested_lines"] = requested.as_dict()
    item["total_lines"] = source.total_lines
    retrieval, retrieval_omitted_reason = retrieval_for(root_arg, source.display_path, requested, redacted_path=source.redacted_path)
    if retrieval:
        item["retrieval_cli"] = retrieval
        item.pop("retrieval_omitted_reason", None)
    elif retrieval_omitted_reason:
        item["retrieval_omitted_reason"] = retrieval_omitted_reason
    return item


def fit_partial_lines(source: ResolvedSource, remaining: int, *, root_arg: str) -> tuple[list[str], str | None, LineRange | None]:
    if remaining <= 0:
        return [], None, None
    picked: list[str] = []
    for line in source.selected_lines:
        candidate = picked + [line]
        included = LineRange(source.requested_lines.start if source.requested_lines else 1, (source.requested_lines.start if source.requested_lines else 1) + len(candidate) - 1)
        block = render_block(source, candidate, root_arg=root_arg, status="partial", included=included)
        if byte_len(block) <= remaining:
            picked = candidate
        else:
            break
    if not picked:
        return [], None, None
    included = LineRange(source.requested_lines.start if source.requested_lines else 1, (source.requested_lines.start if source.requested_lines else 1) + len(picked) - 1)
    return picked, render_block(source, picked, root_arg=root_arg, status="partial", included=included), included


def metadata_size(data: dict[str, Any]) -> int:
    return len(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8", errors="replace")) + 1


def artifact_failure(error: str, *, bytes_count: int = 0, capped: bool = False) -> dict[str, Any]:
    return {
        "stored": False,
        "path": None,
        "bytes": bytes_count,
        "capped": capped,
        "error": error,
        "cap_bytes": MAX_RECEIPT_BYTES,
    }


def ensure_private_pack_dir(root: Path) -> tuple[Path | None, int | None, str | None]:
    """Create/verify the receipt directory by walking from a no-follow root fd."""
    current_fd: int | None = None
    try:
        current_fd = open_dir_no_follow(root)
        for part in (".context-guard", "packs"):
            while True:
                try:
                    next_fd = open_dir_no_follow(part, dir_fd=current_fd)
                    break
                except FileNotFoundError:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current_fd)
                    except FileExistsError:
                        continue
                    except (OSError, NotImplementedError):
                        return None, None, "artifact_dir_unavailable"
                except NotADirectoryError:
                    return None, None, "unsafe_artifact_dir"
                except (OSError, NotImplementedError):
                    return None, None, "unsafe_artifact_dir"
            try:
                os.fchmod(next_fd, 0o700)
            except (AttributeError, OSError):
                pass
            os.close(current_fd)
            current_fd = next_fd
        dir_fd = current_fd
        current_fd = None
        return root / PACK_DIR, dir_fd, None
    except OSError:
        return None, None, "unsafe_artifact_dir"
    finally:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass


def write_private_json_at(dir_fd: int, filename: str, data: dict[str, Any]) -> None:
    if "/" in filename or filename in {"", ".", ".."}:
        raise PackError("unsafe_artifact_path")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(filename, flags, 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        os.chmod(filename, 0o600, dir_fd=dir_fd, follow_symlinks=False)
    except (OSError, TypeError, NotImplementedError):
        pass


def finalize_receipt_size(receipt: dict[str, Any]) -> int:
    artifact = receipt.setdefault("artifact", {})
    size = metadata_size(receipt)
    for _ in range(4):
        artifact["bytes"] = size
        next_size = metadata_size(receipt)
        if next_size == size:
            return size
        size = next_size
    artifact["bytes"] = size
    return metadata_size(receipt)


def shrink_receipt_for_write(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    receipt = copy.deepcopy(data)
    capped = False
    if metadata_size(receipt) <= MAX_RECEIPT_BYTES:
        return receipt, capped
    capped = True
    receipt.setdefault("artifact", {})["capped"] = True
    receipt.setdefault("artifact", {})["cap_bytes"] = MAX_RECEIPT_BYTES
    for item in receipt.get("omitted_sources", []):
        if isinstance(item, dict):
            item.pop("preview", None)
            if "label" in item:
                item["label"] = cap_label(item.get("label"), limit=80)
            if "reason" in item:
                item["reason"] = cap_label(item.get("reason"), default=str(item.get("reason")), limit=MAX_REASON_CHARS)
    if metadata_size(receipt) <= MAX_RECEIPT_BYTES:
        return receipt, capped
    for item in receipt.get("included_sources", []):
        if isinstance(item, dict):
            item.pop("preview", None)
            if "label" in item:
                item["label"] = cap_label(item.get("label"), limit=80)
    if metadata_size(receipt) <= MAX_RECEIPT_BYTES:
        return receipt, capped
    # The stdout payload remains authoritative for the full pack body. Receipts may omit it to stay readable.
    receipt["pack_omitted_from_receipt"] = True
    receipt.pop("pack", None)
    return receipt, capped


def store_receipt(root: Path, result: dict[str, Any]) -> dict[str, Any]:
    out_dir, dir_fd, dir_error = ensure_private_pack_dir(root)
    if out_dir is None or dir_fd is None:
        return artifact_failure(dir_error or "unsafe_artifact_dir")
    size = 0
    capped = False
    try:
        receipt, capped = shrink_receipt_for_write(result)
        size = metadata_size(receipt)
        if size > MAX_RECEIPT_BYTES:
            return artifact_failure("receipt_metadata_too_large", bytes_count=size, capped=True)
        pack_id = str(result["pack_id"])
        filename = f"{pack_id}.json"
        receipt.setdefault("artifact", {})["stored"] = True
        receipt.setdefault("artifact", {})["path"] = f"{PACK_DIR}/{pack_id}.json"
        receipt.setdefault("artifact", {})["capped"] = capped
        size = finalize_receipt_size(receipt)
        if size > MAX_RECEIPT_BYTES:
            return artifact_failure("receipt_metadata_too_large", bytes_count=size, capped=True)
        write_private_json_at(dir_fd, filename, receipt)
    except (OSError, PackError, NotImplementedError):
        return artifact_failure("artifact_write_failed", bytes_count=size, capped=capped)
    finally:
        try:
            os.close(dir_fd)
        except OSError:
            pass
    return {
        "stored": True,
        "path": f"{PACK_DIR}/{pack_id}.json",
        "bytes": size,
        "capped": capped,
        "cap_bytes": MAX_RECEIPT_BYTES,
    }


def build_pack(root: Path, specs: list[SourceSpec], *, budget_bytes: int, root_arg: str, store_artifact: bool) -> dict[str, Any]:
    seen: set[tuple[str, str]] = set()
    resolved: list[ResolvedSource] = []
    omitted: list[dict[str, Any]] = []
    canonical_specs: list[dict[str, Any]] = []
    for spec in specs:
        rel, reason = lexical_rel(spec.path)
        if spec.lines is not None and spec.lines.start < 1:
            omitted_item = omission(spec, "invalid_lines")
            omitted.append(omitted_item)
            canonical_specs.append({"path": omitted_item.get("path"), "priority": spec.priority, "lines": "invalid", "status": "invalid_lines"})
            continue
        if rel is not None and spec.lines is not None and spec.lines.start > 0:
            identity_lines = spec.lines.identity()
        elif rel is not None:
            identity_lines = "all"
        else:
            identity_lines = "invalid"
        identity = (rel.as_posix() if rel is not None else spec.path, identity_lines)
        if rel is not None and identity in seen:
            display, redacted = display_rel_path(rel.as_posix())
            omitted.append(omission(spec, "duplicate_source", path=display, redacted_path=redacted))
            canonical_specs.append({"path": display, "priority": spec.priority, "lines": identity_lines, "status": "duplicate_source"})
            continue
        if rel is not None:
            seen.add(identity)
        source, omitted_item = resolve_source(root, spec)
        if omitted_item is not None:
            omitted.append(omitted_item)
            canonical_specs.append({"path": omitted_item.get("path"), "priority": spec.priority, "lines": identity_lines, "status": omitted_item.get("reason")})
            continue
        assert source is not None
        resolved.append(source)
        canonical_specs.append({"path": source.display_path, "priority": spec.priority, "lines": identity_lines, "status": "candidate"})
    resolved.sort(key=lambda item: (-item.spec.priority, item.spec.input_index, item.display_path))
    header = "# Context Pack\n\nGenerated by context-guard-pack. Token counts are estimated proxies; byte counts are observed.\n\n"
    parts: list[str] = []
    included: list[dict[str, Any]] = []
    current_pack_bytes = 0
    header_bytes = byte_len(header)
    if header_bytes <= budget_bytes:
        parts.append(header)
        current_pack_bytes += header_bytes
    for source in resolved:
        start_line = source.requested_lines.start if source.requested_lines else 1
        included_range = LineRange(start_line, start_line + len(source.selected_lines) - 1)
        full_block = render_block(source, source.selected_lines, root_arg=root_arg, status="included", included=included_range)
        full_block_bytes = byte_len(full_block)
        remaining = budget_bytes - current_pack_bytes
        if full_block_bytes <= remaining:
            parts.append(full_block)
            current_pack_bytes += full_block_bytes
            included.append(source_metadata(source, status="included", lines=source.selected_lines, included=included_range, root_arg=root_arg))
            continue
        partial_lines, partial_block, partial_range = fit_partial_lines(source, remaining, root_arg=root_arg)
        if partial_block is not None and partial_range is not None:
            parts.append(partial_block)
            current_pack_bytes += byte_len(partial_block)
            included.append(source_metadata(source, status="partial", lines=partial_lines, included=partial_range, root_arg=root_arg))
        else:
            omitted.append(budget_omission(source, root_arg=root_arg))
    pack = "".join(parts)
    pack_bytes = current_pack_bytes
    redacted_lines = sum(source.redacted_lines for source in resolved)
    partial_count = sum(1 for item in included if item.get("status") == "partial")
    omitted_sorted = sorted(omitted, key=lambda item: (item.get("input_index", 0), str(item.get("path", "")), str(item.get("reason", ""))))
    canonical = {
        "version": VERSION,
        "root": display_root(root),
        "budget_bytes": budget_bytes,
        "sources": canonical_specs,
        "pack_sha256": sha256_text(pack),
        "omission_summary": sorted({str(item.get("reason")) for item in omitted_sorted}),
    }
    pack_id = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:20]
    result: dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "pack_id": pack_id,
        "root": display_root(root),
        "budget_bytes": budget_bytes,
        "pack_bytes": pack_bytes,
        "pack": pack,
        "token_proxy": {"measurement": "estimated", "method": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}", "pack": token_proxy(pack)},
        "sources": {"total": len(specs), "included": len(included) - partial_count, "partial": partial_count, "omitted": len(omitted_sorted)},
        "included_sources": included,
        "omitted_sources": omitted_sorted,
        "redaction": {"redacted_lines": redacted_lines, "redacted_before_pack": True},
        "artifact": {"stored": False, "path": None, "bytes": 0, "capped": False, "cap_bytes": MAX_RECEIPT_BYTES},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if store_artifact:
        artifact = store_receipt(root, result)
        result["artifact"] = artifact
    return result


def parse_all_sources(args: argparse.Namespace) -> list[SourceSpec]:
    specs: list[SourceSpec] = []
    if args.manifest:
        specs.extend(read_manifest(Path(args.manifest)))
    for raw in args.source or []:
        specs.append(parse_source_spec(raw))
    for index, spec in enumerate(specs):
        spec.input_index = index
    return specs


def slice_source(root: Path, *, raw_path: str, lines: LineRange) -> tuple[dict[str, Any], int]:
    spec = SourceSpec(path=raw_path, lines=lines)
    source, omitted_item = resolve_source(root, spec)
    if omitted_item is not None:
        payload = {"tool": TOOL_NAME, "status": "error", "reason": omitted_item.get("reason"), "path": omitted_item.get("path")}
        return payload, 1
    assert source is not None
    content = "".join(source.selected_lines)
    payload = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "status": "ok",
        "path": source.display_path,
        "query": {"type": "lines", "start": lines.start, "end": min(lines.end, source.total_lines), "returned_lines": len(source.selected_lines)},
        "content": content,
        "bytes": byte_len(content),
        "redaction": {"redacted_lines": source.redacted_lines, "redacted_before_pack": True},
    }
    return payload, 0


def suggest_tokens(text: str) -> set[str]:
    sanitized = SECRET_CONTENT_RE.sub(" ", text.lower())
    return {part for part in re.findall(r"[a-z0-9_][a-z0-9_.-]{1,}", sanitized) if len(part) >= 2}


def suggest_score_path(path: str, query_terms: set[str]) -> int:
    lowered = path.lower()
    score = 0
    for term in query_terms:
        if term in lowered:
            score += 120
    return score


def suggest_reason(*parts: str) -> str:
    return cap_label("; ".join(part for part in parts if part), default="local heuristic", limit=MAX_REASON_CHARS) or "local heuristic"


def split_suggest_files(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            text = part.strip()
            if text:
                out.append(text)
    return out


def line_window(line_number: int, total_lines: int | None, context_lines: int) -> LineRange:
    start = max(1, line_number - context_lines)
    if total_lines is None:
        end = max(start, line_number + context_lines)
    else:
        end = min(max(start, line_number + context_lines), max(1, total_lines))
    return LineRange(start, end)


def merge_line_window(existing: LineRange | None, line_number: int, context_lines: int) -> LineRange:
    window = line_window(line_number, None, context_lines)
    if existing is None:
        return window
    return LineRange(min(existing.start, window.start), max(existing.end, window.end))


def add_suggest_candidate(
    candidates: list[SuggestCandidate],
    *,
    path: str,
    score: int,
    reason: str,
    lines: LineRange | None = None,
    label: str | None = None,
) -> None:
    candidates.append(
        SuggestCandidate(
            path=path,
            score=score,
            reason=suggest_reason(reason),
            lines=lines,
            label=cap_label(label),
            input_index=len(candidates),
        )
    )


def run_git_diff(root: Path, diff_ref: str) -> str:
    ref = diff_ref.strip()
    if not ref:
        raise PackError("empty --diff")
    command = ["git", "-C", str(root), "diff", "--no-ext-diff", "--no-textconv", "--unified=3"]
    if ref in {"staged", "--staged", "cached", "--cached"}:
        command.extend(["--cached"])
    elif ref in {"worktree", "unstaged", "working-tree"}:
        pass
    elif ref.startswith("-"):
        raise PackError("invalid --diff: revision must not start with '-'")
    else:
        command.append(ref)
    try:
        proc = subprocess.run(command, text=True, errors="replace", capture_output=True, timeout=10, check=False)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise PackError(f"could not read diff: {exc.__class__.__name__}") from exc
    if proc.returncode != 0:
        detail = sanitize_text(proc.stderr or proc.stdout or "git diff failed")[0].strip().splitlines()
        message = detail[0] if detail else "git diff failed"
        raise PackError(f"could not read diff: {cap_label(message, default='git diff failed', limit=160)}")
    return sanitize_text(proc.stdout[:MAX_SUGGEST_INPUT_BYTES])[0]


def collect_diff_candidates(root: Path, diff_ref: str, query_terms: set[str], context_lines: int) -> list[SuggestCandidate]:
    diff_text = run_git_diff(root, diff_ref)
    candidates: list[SuggestCandidate] = []
    current_path: str | None = None
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            match = re.match(r"^diff --git a/(.+?) b/(.+)$", line)
            current_path = None
            if match:
                left, right = match.groups()
                current_path = right if right != "/dev/null" else left
            continue
        if current_path is None:
            continue
        hunk = hunk_re.match(line)
        if hunk:
            start = int(hunk.group(1))
            count = int(hunk.group(2) or "1")
            end_line = max(start, start + max(1, count) - 1)
            start_line = max(1, start - context_lines)
            window = LineRange(start_line, max(start_line, end_line + context_lines))
            score = 7_000 + suggest_score_path(current_path, query_terms)
            add_suggest_candidate(
                candidates,
                path=current_path,
                score=score,
                reason="changed diff hunk",
                lines=window,
                label=f"diff:{current_path}",
            )
    return candidates


OUTPUT_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?P<path>(?:\.\/)?(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\."
    r"(?:py|js|jsx|ts|tsx|mjs|cjs|md|json|yml|yaml|toml|sh|css|html|txt|rb|go|rs|java|kt|swift|c|cc|cpp|h|hpp))"
    r"(?::(?P<line>\d+))?"
)


def read_text_input_under_root(root: Path, raw_path: str) -> tuple[str | None, dict[str, Any] | None]:
    rel, reason = lexical_rel(raw_path)
    display = safe_raw_path_label(raw_path)
    if rel is None:
        return None, {"path": display, "status": "omitted", "reason": reason}
    display, redacted = display_rel_path(rel.as_posix())
    if redacted:
        return None, {"path": display, "status": "omitted", "reason": "redacted_path", "retrieval_omitted_reason": "redacted_path"}
    handle, reason = open_regular_under_root(root, rel)
    if handle is None:
        return None, {"path": display, "status": "omitted", "reason": reason}
    try:
        with handle:
            text = handle.read(MAX_SUGGEST_INPUT_BYTES + 1)
    except OSError:
        return None, {"path": display, "status": "omitted", "reason": "unsafe_path"}
    if len(text.encode("utf-8", errors="replace")) > MAX_SUGGEST_INPUT_BYTES:
        text = text[:MAX_SUGGEST_INPUT_BYTES]
    sanitized, _redacted = sanitize_text(text)
    return sanitized, None


def collect_output_candidates(
    root: Path,
    raw_paths: list[str] | None,
    query_terms: set[str],
    context_lines: int,
    *,
    origin: str,
) -> tuple[list[SuggestCandidate], list[dict[str, Any]]]:
    candidates: list[SuggestCandidate] = []
    omitted: list[dict[str, Any]] = []
    for raw in raw_paths or []:
        text, omission_item = read_text_input_under_root(root, raw)
        if omission_item is not None:
            omission_item["origin"] = origin
            omitted.append(omission_item)
            continue
        assert text is not None
        by_path: dict[str, LineRange | None] = {}
        for match in OUTPUT_PATH_RE.finditer(text):
            path = match.group("path")
            if path.startswith("./"):
                path = path[2:]
            line_text = match.group("line")
            if line_text:
                try:
                    line_number = int(line_text)
                except ValueError:
                    line_number = 1
                by_path[path] = merge_line_window(by_path.get(path), line_number, context_lines)
            else:
                by_path.setdefault(path, None)
        for path, lines in sorted(by_path.items()):
            score = 5_000 + suggest_score_path(path, query_terms)
            add_suggest_candidate(
                candidates,
                path=path,
                score=score,
                reason=f"{origin} referenced path",
                lines=lines,
                label=f"{origin}:{path}",
            )
    return candidates, omitted


def git_ls_files(root: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            text=False,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if proc is not None and proc.returncode == 0:
        raw = proc.stdout[: MAX_QUERY_SCAN_FILES * 512]
        return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part][:MAX_QUERY_SCAN_FILES]
    out: list[str] = []
    skip_dirs = {".git", ".omx", ".context-guard", "node_modules", "dist", "build", "__pycache__"}
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in skip_dirs and not name.startswith(".pytest")]
        current_path = Path(current)
        for name in files:
            rel = (current_path / name).relative_to(root).as_posix()
            out.append(rel)
            if len(out) >= MAX_QUERY_SCAN_FILES:
                return out
    return out


def collect_query_candidates(root: Path, query_terms: set[str], context_lines: int) -> list[SuggestCandidate]:
    if not query_terms:
        return []
    candidates: list[SuggestCandidate] = []
    for rel_path in git_ls_files(root):
        rel, reason = lexical_rel(rel_path)
        if rel is None or reason:
            continue
        display, redacted = display_rel_path(rel.as_posix())
        if redacted:
            continue
        path_score = suggest_score_path(display, query_terms)
        handle, open_reason = open_regular_under_root(root, rel)
        if handle is None:
            continue
        first_match_line: int | None = None
        content_score = 0
        try:
            with handle:
                scanned_bytes = 0
                for index, raw_line in enumerate(handle, start=1):
                    scanned_bytes += byte_len(raw_line)
                    if scanned_bytes > MAX_QUERY_SCAN_BYTES_PER_FILE:
                        break
                    if index > SUGGEST_WHOLE_FILE_MAX_LINES and content_score == 0 and path_score == 0:
                        break
                    lowered = raw_line.lower()
                    hits = sum(1 for term in query_terms if term in lowered)
                    if hits:
                        content_score += 250 * hits
                        if first_match_line is None:
                            first_match_line = index
        except (OSError, UnicodeError):
            _ = open_reason
            continue
        if path_score == 0 and content_score == 0:
            continue
        if first_match_line is not None:
            lines = line_window(first_match_line, None, context_lines)
            reason = "query matched file content"
        else:
            lines = None
            reason = "query matched file path"
        add_suggest_candidate(
            candidates,
            path=display,
            score=3_000 + path_score + content_score,
            reason=reason,
            lines=lines,
            label=f"query:{display}",
        )
    return candidates


def source_selected_range(source: ResolvedSource) -> LineRange:
    start = source.requested_lines.start if source.requested_lines else 1
    return LineRange(start, start + len(source.selected_lines) - 1)


def resolved_block_bytes(source: ResolvedSource, *, root_arg: str) -> int:
    included = source_selected_range(source)
    return byte_len(render_block(source, source.selected_lines, root_arg=root_arg, status="included", included=included))


def manifest_source_for_candidate(source: ResolvedSource, *, priority: int, label: str | None) -> dict[str, Any]:
    item: dict[str, Any] = {"path": source.display_path, "priority": priority}
    if label:
        item["label"] = label
    if source.requested_lines is not None:
        item["lines"] = source_selected_range(source).as_dict()
    return item


def suggested_source_payload(source: ResolvedSource, candidate: SuggestCandidate, *, root_arg: str) -> dict[str, Any]:
    included = source_selected_range(source)
    payload: dict[str, Any] = {
        "path": source.display_path,
        "priority": candidate.score,
        "score": candidate.score,
        "reason": candidate.reason,
        "lines": included.as_dict(),
        "bytes": byte_len("".join(source.selected_lines)),
    }
    if candidate.label:
        payload["label"] = candidate.label
    retrieval, retrieval_omitted_reason = retrieval_for(root_arg, source.display_path, included, redacted_path=source.redacted_path)
    if retrieval:
        payload["retrieval_cli"] = retrieval
    elif retrieval_omitted_reason:
        payload["retrieval_omitted_reason"] = retrieval_omitted_reason
    return payload


def normalize_suggest_source(root: Path, candidate: SuggestCandidate) -> tuple[ResolvedSource | None, dict[str, Any] | None]:
    spec = SourceSpec(
        path=candidate.path,
        priority=candidate.score,
        lines=candidate.lines,
        label=candidate.label,
        input_index=candidate.input_index,
        origin="suggest",
    )
    source, omitted_item = resolve_source(root, spec)
    if omitted_item is not None:
        omitted_item["reason"] = omitted_item.get("reason") or candidate.reason
        omitted_item["suggest_reason"] = candidate.reason
        return None, omitted_item
    assert source is not None
    if source.redacted_path:
        return None, omission(spec, "redacted_path", path=source.display_path, redacted_path=True)
    if spec.lines is None and source.total_lines > SUGGEST_WHOLE_FILE_MAX_LINES:
        capped = SourceSpec(
            path=candidate.path,
            priority=candidate.score,
            lines=LineRange(1, min(SUGGEST_WHOLE_FILE_MAX_LINES, source.total_lines)),
            label=candidate.label,
            input_index=candidate.input_index,
            origin="suggest",
        )
        source, omitted_item = resolve_source(root, capped)
        if omitted_item is not None:
            omitted_item["suggest_reason"] = candidate.reason
            return None, omitted_item
        assert source is not None
    return source, None


def write_manifest_under_root(root: Path, raw_path: str, manifest: dict[str, Any]) -> str:
    rel, reason = lexical_rel(raw_path)
    if rel is None:
        raise PackError(f"invalid --manifest-out: {reason}")
    display, redacted = display_rel_path(rel.as_posix())
    if redacted:
        raise PackError("invalid --manifest-out: redacted_path")
    parent_parts = rel.parts[:-1]
    filename = rel.parts[-1]
    current_fd: int | None = None
    file_fd = -1
    try:
        current_fd = open_dir_no_follow(root)
        for part in parent_parts:
            next_fd = open_dir_no_follow(part, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        file_fd = os.open(filename, flags, 0o600, dir_fd=current_fd)
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise PackError("invalid --manifest-out: unsafe_path")
        with os.fdopen(file_fd, "w", encoding="utf-8") as handle:
            file_fd = -1
            json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
    except PackError:
        raise
    except FileNotFoundError as exc:
        raise PackError("invalid --manifest-out: missing") from exc
    except OSError as exc:
        raise PackError(f"invalid --manifest-out: {exc.strerror or exc.__class__.__name__}") from exc
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
    return display


def build_suggest_manifest(sources: list[dict[str, Any]]) -> dict[str, Any]:
    manifest_sources: list[dict[str, Any]] = []
    for item in sources:
        source: dict[str, Any] = {"path": item["path"], "priority": item["priority"]}
        if "label" in item:
            source["label"] = item["label"]
        if "lines" in item:
            source["lines"] = item["lines"]
        manifest_sources.append(source)
    return {"version": VERSION, "sources": manifest_sources}


def suggest_build_hint(root_arg: str, manifest_path: str | None, budget: int) -> tuple[str | None, str | None]:
    safe_root = safe_root_arg_for_retrieval(root_arg)
    if safe_root is None:
        return None, "unsafe_root_path"
    manifest_arg = manifest_path or "<manifest.json>"
    command_parts = ["context-guard-pack", "build", "--root", ".", "--manifest", manifest_arg, "--budget-bytes", str(budget), "--json"]
    command = " ".join(shlex.quote(part) for part in command_parts)
    if safe_root in {".", ""}:
        return command, None
    return f"cd {shlex.quote(safe_root)} && {command}", None


def suggest_pack(root: Path, args: argparse.Namespace, *, root_arg: str) -> tuple[dict[str, Any], int]:
    query_text, _query_redactions = sanitize_text(args.query or "")
    query = " ".join(query_text.split())
    query_terms = suggest_tokens(query)
    context_lines = bounded_int(args.context_lines, DEFAULT_SUGGEST_CONTEXT_LINES, 0, MAX_SUGGEST_CONTEXT_LINES)
    top = bounded_int(args.top, DEFAULT_SUGGEST_TOP, 1, MAX_SUGGEST_TOP)
    budget = bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES)
    candidates: list[SuggestCandidate] = []
    omitted: list[dict[str, Any]] = []

    for raw_path in split_suggest_files(args.files):
        add_suggest_candidate(
            candidates,
            path=raw_path,
            score=9_000 + suggest_score_path(raw_path, query_terms),
            reason="explicit file request",
            label=f"file:{safe_raw_path_label(raw_path)}",
        )
    if args.diff:
        candidates.extend(collect_diff_candidates(root, args.diff, query_terms, context_lines))
    output_candidates, output_omitted = collect_output_candidates(root, args.output, query_terms, context_lines, origin="output")
    test_candidates, test_omitted = collect_output_candidates(root, args.test_output, query_terms, context_lines, origin="test-output")
    candidates.extend(output_candidates)
    candidates.extend(test_candidates)
    omitted.extend(output_omitted)
    omitted.extend(test_omitted)
    candidates.extend(collect_query_candidates(root, query_terms, context_lines))

    if not candidates:
        raise PackError("provide --query, --files, --diff, --output, or --test-output")

    candidates.sort(key=lambda item: (-item.score, item.input_index, item.path, item.lines.identity() if item.lines else "all"))
    seen: set[tuple[str, str]] = set()
    final_seen: set[tuple[str, str]] = set()
    selected: list[dict[str, Any]] = []
    manifest_seed: list[dict[str, Any]] = []
    current_bytes = byte_len("# Context Pack\n\nGenerated by context-guard-pack. Token counts are estimated proxies; byte counts are observed.\n\n")
    for candidate in candidates:
        rel, reason = lexical_rel(candidate.path)
        identity_path = rel.as_posix() if rel is not None else safe_raw_path_label(candidate.path)
        identity_lines = candidate.lines.identity() if candidate.lines else "all"
        identity = (identity_path, identity_lines)
        if rel is not None and identity in seen:
            display, redacted = display_rel_path(rel.as_posix())
            omitted.append({
                "path": display,
                "status": "omitted",
                "reason": "duplicate_source",
                "suggest_reason": candidate.reason,
                "priority": candidate.score,
                "retrieval_omitted_reason": "redacted_path" if redacted else None,
            })
            continue
        if rel is not None:
            seen.add(identity)
        source, omitted_item = normalize_suggest_source(root, candidate)
        if omitted_item is not None:
            omitted_item["priority"] = candidate.score
            omitted_item["suggest_reason"] = candidate.reason
            omitted.append({key: value for key, value in omitted_item.items() if value is not None})
            continue
        assert source is not None
        final_identity = (source.display_path, source_selected_range(source).identity() if source.requested_lines is not None else "all")
        if final_identity in final_seen:
            omitted.append({
                "path": source.display_path,
                "status": "omitted",
                "reason": "duplicate_source",
                "suggest_reason": candidate.reason,
                "priority": candidate.score,
            })
            continue
        final_seen.add(final_identity)
        source_bytes = resolved_block_bytes(source, root_arg=root_arg)
        remaining = budget - current_bytes
        if source_bytes > remaining:
            if not selected and remaining > 0:
                partial_lines, _partial_block, partial_range = fit_partial_lines(source, remaining, root_arg=root_arg)
                if partial_range is not None and partial_lines:
                    partial_spec = SourceSpec(
                        path=candidate.path,
                        priority=candidate.score,
                        lines=partial_range,
                        label=candidate.label,
                        input_index=candidate.input_index,
                        origin="suggest",
                    )
                    source, omitted_item = resolve_source(root, partial_spec)
                    if omitted_item is not None:
                        omitted_item["priority"] = candidate.score
                        omitted_item["suggest_reason"] = candidate.reason
                        omitted.append(omitted_item)
                        continue
                    assert source is not None
                    source_bytes = resolved_block_bytes(source, root_arg=root_arg)
                else:
                    omitted.append({"path": source.display_path, "status": "omitted", "reason": "budget_exhausted", "priority": candidate.score})
                    continue
            else:
                omitted.append({"path": source.display_path, "status": "omitted", "reason": "budget_exhausted", "priority": candidate.score})
                continue
        payload = suggested_source_payload(source, candidate, root_arg=root_arg)
        selected.append(payload)
        manifest_seed.append(manifest_source_for_candidate(source, priority=candidate.score, label=candidate.label))
        current_bytes += source_bytes
        if len(selected) >= top:
            break

    manifest = build_suggest_manifest(manifest_seed)
    estimated_pack_bytes = current_bytes if selected else 0
    manifest_path: str | None = None
    if args.manifest_out:
        manifest_path = write_manifest_under_root(root, args.manifest_out, manifest)
    build_hint, build_hint_omitted_reason = suggest_build_hint(root_arg, manifest_path, budget)
    payload: dict[str, Any] = {
        "tool": TOOL_NAME,
        "schema_version": SUGGEST_SCHEMA_VERSION,
        "version": VERSION,
        "mode": "suggest",
        "root": display_root(root),
        "query": query,
        "budget_bytes": budget,
        "estimated_pack_bytes": estimated_pack_bytes,
        "token_proxy": {
            "measurement": "estimated",
            "method": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}",
            "estimated_pack": estimated_pack_bytes // TOKEN_PROXY_CHARS_PER_TOKEN,
        },
        "sources": selected,
        "omitted_sources": sorted(omitted, key=lambda item: (str(item.get("path", "")), str(item.get("reason", "")), int(item.get("priority", 0) or 0))),
        "manifest": manifest,
        "manifest_path": manifest_path,
        "build_hint": build_hint,
        "caveats": [
            "Deterministic local heuristics only; no model, network, embedding, or provider-cost estimate is used.",
            "Byte and token values are pack-size proxies, not billing claims.",
        ],
    }
    if build_hint_omitted_reason:
        payload["build_hint_omitted_reason"] = build_hint_omitted_reason
    return payload, 0


def print_suggest_text(payload: dict[str, Any]) -> None:
    print(
        f"context-guard-pack suggest: {len(payload['sources'])} source(s), "
        f"estimated {payload['estimated_pack_bytes']}/{payload['budget_bytes']} bytes"
    )
    for item in payload["sources"]:
        lines = item.get("lines")
        line_text = f":{lines['start']}:{lines['end']}" if isinstance(lines, dict) else ""
        print(f"- {item['path']}{line_text} priority={item['priority']} reason={item['reason']}")
    if payload.get("manifest_path"):
        print(f"manifest: {payload['manifest_path']}")
    if payload.get("build_hint"):
        print(f"build: {payload['build_hint']}")
    elif payload.get("build_hint_omitted_reason"):
        print(f"build hint omitted: {payload['build_hint_omitted_reason']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build budgeted local context packs with exact retrieval hints.")
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="assemble a prioritized context pack")
    build.add_argument("--root", default=".", help="project root; must not be a symlink")
    build.add_argument("--manifest", help="JSON manifest with version/sources")
    build.add_argument("--source", action="append", help="source spec: path=REL[,priority=N][,lines=A:B][,label=TEXT]")
    build.add_argument("--budget-bytes", type=int, default=DEFAULT_BUDGET_BYTES)
    build.add_argument("--json", action="store_true", help="emit JSON payload")
    build.add_argument("--no-artifact", action="store_true", help="do not write .context-guard/packs receipt")
    slice_cmd = sub.add_parser("slice", help="retrieve an exact sanitized file slice")
    slice_cmd.add_argument("--root", default=".", help="project root; must not be a symlink")
    slice_cmd.add_argument("--path", required=True, help="relative file path under root")
    slice_cmd.add_argument("--lines", required=True, help="inclusive 1-indexed START:END")
    slice_cmd.add_argument("--json", action="store_true", help="emit JSON payload")
    suggest = sub.add_parser("suggest", help="suggest a build-compatible context pack manifest from local signals")
    suggest.add_argument("--root", default=".", help="project root; must not be a symlink")
    suggest.add_argument("--query", default="", help="task or question to match against local files")
    suggest.add_argument("--diff", help="git diff range, or staged/worktree, to seed changed-file ranges")
    suggest.add_argument("--files", "--file", dest="files", action="append", help="explicit relative file path(s), comma-separated or repeated")
    suggest.add_argument("--output", action="append", help="relative path to sanitized command output text under root")
    suggest.add_argument("--test-output", action="append", help="relative path to sanitized test output text under root")
    suggest.add_argument("--budget-bytes", type=int, default=DEFAULT_BUDGET_BYTES)
    suggest.add_argument("--top", type=int, default=DEFAULT_SUGGEST_TOP, help="maximum suggested sources")
    suggest.add_argument("--context-lines", type=int, default=DEFAULT_SUGGEST_CONTEXT_LINES, help="line context around diff/output hits")
    suggest.add_argument("--manifest-out", help="write the suggested build manifest to this relative path under root")
    suggest.add_argument("--json", action="store_true", help="emit JSON payload")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = normalize_root(Path(args.root))
        if args.command == "build":
            specs = parse_all_sources(args)
            if not specs:
                raise PackError("provide --manifest or --source")
            budget = bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES)
            result = build_pack(root, specs, budget_bytes=budget, root_arg=str(args.root), store_artifact=not args.no_artifact)
            if args.json:
                json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                sys.stdout.write(str(result["pack"]))
                print(
                    f"[context-guard-pack] pack_id={result['pack_id']} bytes={result['pack_bytes']}/{result['budget_bytes']} "
                    f"included={result['sources']['included']} partial={result['sources']['partial']} omitted={result['sources']['omitted']}",
                    file=sys.stderr,
                )
            return 0
        if args.command == "slice":
            lines = parse_line_range(args.lines)
            if lines is None:
                raise PackError("invalid_lines")
            payload, rc = slice_source(root, raw_path=args.path, lines=lines)
            if args.json:
                json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            elif rc == 0:
                sys.stdout.write(str(payload.get("content", "")))
            else:
                print(f"context-guard-pack: {payload.get('reason')}", file=sys.stderr)
            return rc
        if args.command == "suggest":
            payload, rc = suggest_pack(root, args, root_arg=str(args.root))
            if args.json:
                json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                print_suggest_text(payload)
            return rc
        raise PackError("unknown command")
    except PackError as exc:
        print(f"context-guard-pack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
