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


def reject_symlink_components(root: Path, rel: Path) -> tuple[Path | None, str]:
    current = root
    for part in rel.parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return None, "missing"
        except OSError:
            return None, "unsafe_path"
        if stat.S_ISLNK(st.st_mode):
            return None, "unsafe_path"
        if current != root / rel and not stat.S_ISDIR(st.st_mode):
            return None, "missing"
    try:
        st = os.lstat(current)
    except OSError:
        return None, "missing"
    if not stat.S_ISREG(st.st_mode):
        return None, "empty_source"
    return current, ""


def open_regular_no_follow(path: Path):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PackError("source is not a regular file")
        return os.fdopen(fd, "r", encoding="utf-8", errors="replace", newline="")
    except Exception:
        os.close(fd)
        raise


def resolve_source(root: Path, spec: SourceSpec) -> tuple[ResolvedSource | None, dict[str, Any] | None]:
    if spec.lines is not None and spec.lines.start < 1:
        return None, omission(spec, "invalid_lines")
    rel, reason = lexical_rel(spec.path)
    if rel is None:
        return None, omission(spec, reason)
    abs_path, reason = reject_symlink_components(root, rel)
    display, redacted_path = display_rel_path(rel.as_posix())
    if abs_path is None:
        return None, omission(spec, reason, path=display, redacted_path=redacted_path)
    try:
        # The no-symlink lexical check above lets resolve act as a final containment assertion.
        abs_path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None, omission(spec, "outside_root", path=display, redacted_path=redacted_path)
    try:
        with open_regular_no_follow(abs_path) as handle:
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
        abs_path=abs_path,
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


def render_block(source: ResolvedSource, lines: list[str], *, root_arg: str, status: str, included: LineRange) -> str:
    title = source.spec.label or source.display_path
    requested = source.requested_lines or LineRange(1, source.total_lines)
    retrieval = None if source.redacted_path else retrieval_cli(root_arg, source.display_path, requested)
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
    elif source.redacted_path:
        header.append("Retrieval omitted: redacted_path")
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
    if source.redacted_path:
        item["retrieval_omitted_reason"] = "redacted_path"
    else:
        item["retrieval_cli"] = retrieval_cli(root_arg, source.display_path, requested)
    if status == "partial":
        item["reason"] = "budget_exhausted"
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
    return len(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8", errors="replace"))


def artifact_failure(error: str, *, bytes_count: int = 0, capped: bool = False) -> dict[str, Any]:
    return {
        "stored": False,
        "path": None,
        "bytes": bytes_count,
        "capped": capped,
        "error": error,
        "cap_bytes": MAX_RECEIPT_BYTES,
    }


def ensure_private_pack_dir(root: Path) -> tuple[Path | None, str | None]:
    """Create/verify the receipt directory without following symlink components."""
    current = root
    for part in (".context-guard", "packs"):
        current = current / part
        while True:
            try:
                st = os.lstat(current)
                break
            except FileNotFoundError:
                try:
                    os.mkdir(current, 0o700)
                except FileExistsError:
                    continue
                except OSError:
                    return None, "artifact_dir_unavailable"
            except OSError:
                return None, "artifact_dir_unavailable"
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            return None, "unsafe_artifact_dir"
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
    try:
        current.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None, "unsafe_artifact_dir"
    return current, None


def open_private_dir_fd(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise PackError("unsafe_artifact_dir")
        return fd
    except Exception:
        os.close(fd)
        raise


def write_private_json(path: Path, data: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
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
        os.chmod(path, 0o600)
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
    out_dir, dir_error = ensure_private_pack_dir(root)
    if out_dir is None:
        return artifact_failure(dir_error or "unsafe_artifact_dir")
    receipt, capped = shrink_receipt_for_write(result)
    size = metadata_size(receipt)
    if size > MAX_RECEIPT_BYTES:
        return artifact_failure("receipt_metadata_too_large", bytes_count=size, capped=True)
    pack_id = str(result["pack_id"])
    filename = f"{pack_id}.json"
    receipt.setdefault("artifact", {})["stored"] = True
    receipt.setdefault("artifact", {})["path"] = f"{PACK_DIR}/{pack_id}.json"
    receipt.setdefault("artifact", {})["capped"] = capped
    size = metadata_size(receipt)
    receipt.setdefault("artifact", {})["bytes"] = size
    if size > MAX_RECEIPT_BYTES:
        return artifact_failure("receipt_metadata_too_large", bytes_count=size, capped=True)
    dir_fd: int | None = None
    try:
        dir_fd = open_private_dir_fd(out_dir)
        write_private_json_at(dir_fd, filename, receipt)
    except (OSError, PackError):
        return artifact_failure("artifact_write_failed", bytes_count=size, capped=capped)
    finally:
        if dir_fd is not None:
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
    pack = ""
    if byte_len(header) <= budget_bytes:
        parts.append(header)
        pack = header
    for source in resolved:
        start_line = source.requested_lines.start if source.requested_lines else 1
        included_range = LineRange(start_line, start_line + len(source.selected_lines) - 1)
        full_block = render_block(source, source.selected_lines, root_arg=root_arg, status="included", included=included_range)
        remaining = budget_bytes - byte_len("".join(parts))
        if byte_len(full_block) <= remaining:
            parts.append(full_block)
            included.append(source_metadata(source, status="included", lines=source.selected_lines, included=included_range, root_arg=root_arg))
            continue
        partial_lines, partial_block, partial_range = fit_partial_lines(source, remaining, root_arg=root_arg)
        if partial_block is not None and partial_range is not None:
            parts.append(partial_block)
            included.append(source_metadata(source, status="partial", lines=partial_lines, included=partial_range, root_arg=root_arg))
        else:
            omitted.append(omission(source.spec, "budget_exhausted", path=source.display_path, redacted_path=source.redacted_path))
    pack = "".join(parts)
    pack_bytes = byte_len(pack)
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
        raise PackError("unknown command")
    except PackError as exc:
        print(f"context-guard-pack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
