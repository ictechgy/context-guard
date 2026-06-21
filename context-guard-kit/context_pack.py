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
import ast
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import threading
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
AUTO_SCHEMA_VERSION = "contextguard.pack-auto.v1"
AUTO_EXPLAIN_SCHEMA_VERSION = "contextguard.pack-auto-explain.v1"
REPO_MAP_SCHEMA_VERSION = "contextguard.pack-repo-map.v1"
ADAPTIVE_K_SCHEMA_VERSION = "contextguard.pack-adaptive-k.v1"
SYMBOL_MEMORY_SCHEMA_VERSION = "contextguard.pack-symbol-memory.v1"
DEFAULT_SUGGEST_TOP = 8
MAX_SUGGEST_TOP = 50
DEFAULT_SUGGEST_CONTEXT_LINES = 20
MAX_SUGGEST_CONTEXT_LINES = 120
SUGGEST_WHOLE_FILE_MAX_LINES = 120
MAX_SUGGEST_INPUT_BYTES = 256_000
MAX_QUERY_SCAN_FILES = 2_000
MAX_QUERY_SCAN_BYTES_PER_FILE = 200_000
MAX_GIT_LS_FILES_OUTPUT_BYTES = MAX_QUERY_SCAN_FILES * 512
GIT_LS_FILES_READ_CHUNK_BYTES = 64 * 1024
MAX_REPO_MAP_FILES = 1_000
MAX_REPO_MAP_SCAN_FILES = 160
MAX_REPO_MAP_BYTES_PER_FILE = 120_000
MAX_REPO_MAP_TREE_ENTRIES = 30
MAX_REPO_MAP_SIGNATURE_ENTRIES = 40
MAX_REPO_MAP_GRAPH_RANK_ENTRIES = 30
MAX_REPO_MAP_RETRIEVAL_HINTS = 30
MAX_REPO_MAP_SECRET_RISK_FILES = 20
MAX_ADAPTIVE_K_SCORE_SAMPLES = 200
MAX_ADAPTIVE_K_SELECTED_EVIDENCE = 12
MAX_ADAPTIVE_K_OMITTED_EVIDENCE = 12
MAX_ADAPTIVE_K_REASON_COUNTS = 12
MAX_ADAPTIVE_K_VERIFICATION_HINTS = 12
ADAPTIVE_K_POLICIES = ("balanced", "recall", "precision")
MAX_SYMBOL_MEMORY_ITEMS = 12
MAX_SYMBOL_MEMORY_GRAPH_ITEMS = 12
PACK_DIR = ".context-guard/packs"
REDACTED_PATH_COMPONENT = "[REDACTED-PATH-COMPONENT]"
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
SECRET_CONTENT_RE = re.compile(
    r"(?is)("
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|"
    r"sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"npm_[A-Za-z0-9]{20,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"(?i:Authorization)\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*[:=]\s*[^\s]+"
    r")"
)
SECRET_PATH_COMPONENT_RE = re.compile(
    r"(?i)("
    r"SG\.[A-Za-z0-9_-]{16,256}\.[A-Za-z0-9_-]{16,512}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}|"
    r"[a-z][a-z0-9+.-]{0,31}:/+(?:[^/\s:@]{0,256}:[^/\s@]{0,2048}|[^/\s@]{1,2048})@"
    r")"
)
SECRET_RISK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key_block", re.compile(r"(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{12,}")),
    ("provider_api_key", re.compile(r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_\-]{20,}")),
    ("authorization_header", re.compile(r"(?i)Authorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")),
    ("generic_secret_assignment", re.compile(r"(?i)(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*[:=]\s*[^\s]+")),
)
REPO_MAP_TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".md", ".mdx", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".css", ".html",
}
SYMBOL_HINT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"}
SIGNATURE_LINE_RE = re.compile(
    r"^\s*(?:export\s+)?(?:(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|class\s+([A-Za-z_$][\w$]*)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>|"
    r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(|(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*\()"
)
IMPORT_PATH_RE = re.compile(
    r"(?:from\s+['\"](?P<jsfrom>[^'\"]+)['\"]|"
    r"import(?:\s+[^;\n'\"]+?\s+from)?\s+['\"](?P<jsimport>[^'\"]+)['\"]|"
    r"from\s+(?P<pyfrom>\.*[A-Za-z_][\w.]*|\.+)\s+import|"
    r"import\s+(?P<pyimport>[A-Za-z_][\w.]*))"
)
PY_FROM_IMPORT_LINE_RE = re.compile(r"^\s*from\s+(?P<module>\.*[A-Za-z_][\w.]*|\.+)\s+import\s+(?P<names>[^\n#;]+)")


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


# Process-static cache: CLI invocations should not re-import the sanitizer for
# every file, while each sanitize_text() call still gets a fresh stateful
# sanitizer instance.
_LINE_SANITIZER_FACTORY_CACHE: Any | None = None
_LINE_SANITIZER_FACTORY_LOCK = threading.Lock()


def load_line_sanitizer_factory() -> Any:
    global _LINE_SANITIZER_FACTORY_CACHE
    if _LINE_SANITIZER_FACTORY_CACHE is not None:
        return _LINE_SANITIZER_FACTORY_CACHE
    with _LINE_SANITIZER_FACTORY_LOCK:
        if _LINE_SANITIZER_FACTORY_CACHE is not None:
            return _LINE_SANITIZER_FACTORY_CACHE
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
                _LINE_SANITIZER_FACTORY_CACHE = module.LineSanitizer
                return _LINE_SANITIZER_FACTORY_CACHE
            except Exception as exc:
                raise RuntimeError(f"could not load sanitizer {candidate}: {exc}") from exc
        _LINE_SANITIZER_FACTORY_CACHE = FallbackLineSanitizer
        return _LINE_SANITIZER_FACTORY_CACHE


def load_line_sanitizer(show_paths: bool = False) -> object:
    sanitizer_factory = load_line_sanitizer_factory()
    return sanitizer_factory(show_paths=show_paths)


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


def sanitize_source_lines(handle: Any, requested: LineRange | None) -> tuple[list[str], int, int]:
    """Sanitize a source stream while retaining only the requested line window.

    Explicit line-window retrieval still scans the complete file so global
    redaction counts and total line counts stay compatible with previous
    outputs, but it no longer materializes a sanitized all-lines list before
    slicing.
    """
    sanitizer = load_line_sanitizer()
    selected: list[str] = []
    redacted = 0
    total_lines = 0
    collect_all = requested is None
    start = requested.start if requested is not None else 1
    end = requested.end if requested is not None else 0
    for total_lines, raw_line in enumerate(handle, start=1):
        sanitized, did_redact = sanitizer.sanitize(raw_line)  # type: ignore[attr-defined]
        if did_redact:
            redacted += 1
        if collect_all or start <= total_lines <= end:
            selected.append(sanitized)
    return selected, total_lines, redacted


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
    normalized = rel.replace("\\", "/")
    parts: list[str] = []
    redacted = False
    for part in normalized.split("/"):
        if not part:
            continue
        safe, did = sanitize_path_component(part)
        parts.append(safe)
        redacted = redacted or did
    return "/".join(parts), redacted


def repo_map_path_has_sensitive_evidence(value: str) -> bool:
    return bool(CONTROL_CHAR_RE.search(value) or SECRET_PATH_COMPONENT_RE.search(value))


def repo_map_display_rel_path(rel: str) -> tuple[str, bool]:
    normalized = rel.replace("\\", "/")
    if repo_map_path_has_sensitive_evidence(normalized):
        return f"redacted-path#path:{sha256_text(normalized)[:12]}", True
    return display_rel_path(normalized)


def repo_map_safe_raw_path_label(raw: str) -> str:
    normalized = raw.replace("\\", "/")
    if repo_map_path_has_sensitive_evidence(normalized):
        return f"redacted-path#path:{sha256_text(normalized)[:12]}"
    return safe_raw_path_label(normalized)


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


def adaptive_k_threshold(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError("adaptive-k threshold must be a number between 0.0 and 1.0") from exc
    if not 0.0 <= number <= 1.0:
        raise argparse.ArgumentTypeError("adaptive-k threshold must be between 0.0 and 1.0")
    return number


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


def normalized_link_target(anchor: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = anchor / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    """Normalize common macOS absolute path aliases before no-follow traversal."""

    if not path.is_absolute() or len(path.parts) < 2:
        return path
    first = path.parts[1]
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if not stat.S_ISLNK(os.lstat(link).st_mode):
            return path
        if normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def manifest_safe_read_supported() -> bool:
    return hasattr(os, "O_NOFOLLOW") and os.open in getattr(os, "supports_dir_fd", set())


def manifest_directory_open_flags(*, follow_final: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if not follow_final:
        flags |= os.O_NOFOLLOW
    return flags


def manifest_file_open_flags() -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    for name in ("O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"):
        flags |= getattr(os, name, 0)
    return flags


def manifest_leaf_name(path: Path) -> str:
    name = path.name
    if name in {"", ".", ".."}:
        raise PackError("manifest path must name a regular file")
    return name


def open_manifest_parent_no_follow(path: Path) -> int:
    if not manifest_safe_read_supported():
        raise PackError("safe manifest reads require O_NOFOLLOW and dir_fd support")
    path = path.expanduser()
    if any(part == ".." for part in path.parts):
        raise PackError("manifest path must not contain parent traversal")
    if path.is_absolute():
        path = normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(path))))
        current_fd = os.open(path.anchor or os.sep, manifest_directory_open_flags(follow_final=True))
        parts = path.parts[1:-1]
    else:
        path = Path(os.path.normpath(str(path)))
        current_fd = os.open(".", manifest_directory_open_flags())
        parts = path.parts[:-1]
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise PackError("manifest path must not contain parent traversal")
            next_fd = -1
            try:
                next_fd = os.open(part, manifest_directory_open_flags(), dir_fd=current_fd)
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise PackError("manifest path must not traverse non-directory components")
            except (OSError, PackError):
                if next_fd >= 0:
                    try:
                        os.close(next_fd)
                    except OSError:
                        pass
                raise
            os.close(current_fd)
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


def read_manifest_bytes_no_follow(path: Path) -> bytes:
    parent_fd = -1
    fd = -1
    try:
        leaf = manifest_leaf_name(path.expanduser())
        parent_fd = open_manifest_parent_no_follow(path)
        fd = os.open(leaf, manifest_file_open_flags(), dir_fd=parent_fd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PackError("manifest must be a regular file")
        if st.st_size > MAX_MANIFEST_BYTES:
            raise PackError(f"manifest exceeds trusted size cap: {st.st_size} > {MAX_MANIFEST_BYTES}")
        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise PackError(f"manifest exceeds trusted size cap: {len(raw)} > {MAX_MANIFEST_BYTES}")
        return raw
    except PackError:
        raise
    except OSError as exc:
        raise PackError(f"could not read manifest: {exc.strerror or exc.__class__.__name__}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError:
                pass


def read_manifest(path: Path) -> list[SourceSpec]:
    raw = read_manifest_bytes_no_follow(path)
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


def file_open_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"):
        flags |= getattr(os, name, 0)
    return flags


def stat_leaf_no_follow(name: str, *, dir_fd: int) -> os.stat_result | None:
    supports_dir_fd = os.stat in getattr(os, "supports_dir_fd", set())
    supports_no_follow = os.stat in getattr(os, "supports_follow_symlinks", set())
    if not supports_dir_fd or not supports_no_follow:
        return None
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


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
            try:
                pre_st = stat_leaf_no_follow(part, dir_fd=current_fd)
            except FileNotFoundError:
                return None, "missing"
            except NotADirectoryError:
                return None, "missing"
            except OSError:
                return None, "unsafe_path"
            if pre_st is not None:
                if stat.S_ISLNK(pre_st.st_mode):
                    return None, "unsafe_path"
                if not stat.S_ISREG(pre_st.st_mode):
                    return None, "empty_source"
            flags = file_open_flags()
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
            requested = spec.lines
            selected, total_lines, redacted_lines = sanitize_source_lines(handle, requested)
    except OSError:
        return None, omission(spec, "unsafe_path", path=display, redacted_path=redacted_path)
    if total_lines <= 0:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    requested = requested or LineRange(1, total_lines)
    if requested.start > total_lines:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
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
    if CONTROL_CHAR_RE.search(text) or SECRET_CONTENT_RE.search(text) or SECRET_PATH_COMPONENT_RE.search(text):
        return None
    for part in text.replace("\\", "/").split("/"):
        if not part:
            continue
        _safe, redacted = sanitize_path_component(part)
        if redacted:
            return None
    return text


def safe_repo_map_root_arg_for_retrieval(root_arg: str) -> str | None:
    text = str(root_arg)
    if repo_map_path_has_sensitive_evidence(text):
        return None
    return safe_root_arg_for_retrieval(text)


def retrieval_for(root_arg: str, display_path: str, lines: LineRange, *, redacted_path: bool) -> tuple[str | None, str | None]:
    if redacted_path:
        return None, "redacted_path"
    safe_root = safe_root_arg_for_retrieval(root_arg)
    if safe_root is None:
        return None, "unsafe_root_path"
    return retrieval_cli(safe_root, display_path, lines), None


BLOCK_OPEN = "\n\n```text\n"
BLOCK_CLOSE = "```\n\n"


def render_block_header(source: ResolvedSource, *, root_arg: str, status: str, included: LineRange) -> str:
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
    return "\n".join(header)


def render_block(source: ResolvedSource, lines: list[str], *, root_arg: str, status: str, included: LineRange) -> str:
    return render_block_header(source, root_arg=root_arg, status=status, included=included) + BLOCK_OPEN + "".join(lines) + ("" if not lines or lines[-1].endswith("\n") else "\n") + BLOCK_CLOSE


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


def included_range_for_line_count(source: ResolvedSource, line_count: int) -> LineRange:
    start = source.requested_lines.start if source.requested_lines else 1
    return LineRange(start, start + line_count - 1)


def line_byte_prefixes(lines: list[str]) -> list[int]:
    prefixes = [0]
    total = 0
    for line in lines:
        total += byte_len(line)
        prefixes.append(total)
    return prefixes


def render_block_byte_len(
    source: ResolvedSource,
    line_count: int,
    line_prefixes: list[int],
    *,
    root_arg: str,
    status: str,
    included: LineRange,
) -> int:
    body_bytes = line_prefixes[line_count]
    if line_count > 0 and not source.selected_lines[line_count - 1].endswith("\n"):
        body_bytes += 1
    return byte_len(render_block_header(source, root_arg=root_arg, status=status, included=included)) + byte_len(BLOCK_OPEN) + body_bytes + byte_len(BLOCK_CLOSE)


def fit_partial_lines(
    source: ResolvedSource,
    remaining: int,
    *,
    root_arg: str,
    line_prefixes: list[int] | None = None,
) -> tuple[list[str], str | None, LineRange | None]:
    if remaining <= 0:
        return [], None, None
    if not source.selected_lines:
        return [], None, None
    prefixes = line_prefixes if line_prefixes is not None else line_byte_prefixes(source.selected_lines)
    best = 0
    low = 1
    high = len(source.selected_lines)
    while low <= high:
        mid = (low + high) // 2
        included = included_range_for_line_count(source, mid)
        block_bytes = render_block_byte_len(source, mid, prefixes, root_arg=root_arg, status="partial", included=included)
        if block_bytes <= remaining:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    if best <= 0:
        return [], None, None
    picked = source.selected_lines[:best]
    included = included_range_for_line_count(source, best)
    return picked, render_block(source, picked, root_arg=root_arg, status="partial", included=included), included


def metadata_size(data: dict[str, Any]) -> int:
    return len(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8", errors="replace")) + 1


def receipt_working_copy(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Copy receipt metadata without deep-copying or serializing an oversized pack body.

    The pack body is already an immutable string in normal builds and stdout remains
    authoritative for it.  When it cannot possibly fit under the receipt cap by
    itself, omit it before the first receipt-size probe so capping work only touches
    metadata previews.
    """
    receipt: dict[str, Any] = {}
    pack_omitted = False
    for key, value in data.items():
        if key == "pack" and isinstance(value, str):
            if len(value.encode("utf-8", errors="replace")) > MAX_RECEIPT_BYTES:
                pack_omitted = True
                continue
            receipt[key] = value
            continue
        receipt[key] = copy.deepcopy(value)
    if pack_omitted:
        receipt["pack_omitted_from_receipt"] = True
    return receipt, pack_omitted


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


def atomic_write_ops_supported() -> bool:
    return (
        os.open in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
    )


def fsync_dir_fd(dir_fd: int) -> None:
    os.fsync(dir_fd)


def validate_existing_output_target_at(dir_fd: int, filename: str, option_name: str) -> None:
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    file_fd = -1
    try:
        file_fd = os.open(filename, flags, dir_fd=dir_fd)
        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise PackError(f"invalid {option_name}: unsafe_path")
    except FileNotFoundError:
        return
    except IsADirectoryError as exc:
        raise PackError(f"invalid {option_name}: unsafe_path") from exc
    except OSError as exc:
        raise PackError(f"invalid {option_name}: {exc.strerror or exc.__class__.__name__}") from exc
    finally:
        if file_fd >= 0:
            try:
                os.close(file_fd)
            except OSError:
                pass


def write_text_atomic_at(dir_fd: int, filename: str, content: str, *, mode: int, option_name: str) -> None:
    if "/" in filename or filename in {"", ".", ".."}:
        raise PackError(f"invalid {option_name}: unsafe_path")
    if not atomic_write_ops_supported():
        raise PackError(f"invalid {option_name}: atomic_write_unsupported")
    validate_existing_output_target_at(dir_fd, filename, option_name)
    digest = hashlib.sha256(f"{filename}:{os.getpid()}:{time.time_ns()}".encode("utf-8", "replace")).hexdigest()[:16]
    temp_name = f".context-guard-pack-{digest}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = -1
    temp_created = False
    try:
        fd = os.open(temp_name, flags, mode, dir_fd=dir_fd)
        temp_created = True
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        fsync_dir_fd(dir_fd)
        os.rename(temp_name, filename, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_created = False
        try:
            os.chmod(filename, mode, dir_fd=dir_fd, follow_symlinks=False)
        except (OSError, TypeError, NotImplementedError):
            pass
        fsync_dir_fd(dir_fd)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except OSError:
                pass


def write_private_json_at(dir_fd: int, filename: str, data: dict[str, Any]) -> None:
    if "/" in filename or filename in {"", ".", ".."}:
        raise PackError("unsafe_artifact_path")
    content = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    write_text_atomic_at(dir_fd, filename, content, mode=0o600, option_name="artifact receipt")


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
    receipt, pack_omitted = receipt_working_copy(data)
    capped = pack_omitted
    if pack_omitted:
        receipt.setdefault("artifact", {})["capped"] = True
        receipt.setdefault("artifact", {})["cap_bytes"] = MAX_RECEIPT_BYTES
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
        line_prefixes = line_byte_prefixes(source.selected_lines)
        included_range = included_range_for_line_count(source, len(source.selected_lines))
        full_block_bytes = render_block_byte_len(source, len(source.selected_lines), line_prefixes, root_arg=root_arg, status="included", included=included_range)
        remaining = budget_bytes - current_pack_bytes
        if full_block_bytes <= remaining:
            full_block = render_block(source, source.selected_lines, root_arg=root_arg, status="included", included=included_range)
            parts.append(full_block)
            current_pack_bytes += full_block_bytes
            included.append(source_metadata(source, status="included", lines=source.selected_lines, included=included_range, root_arg=root_arg))
            continue
        partial_lines, partial_block, partial_range = fit_partial_lines(source, remaining, root_arg=root_arg, line_prefixes=line_prefixes)
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
                label=f"diff:{safe_raw_path_label(current_path)}",
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
    except (OSError, UnicodeError):
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
                label=f"{origin}:{safe_raw_path_label(path)}",
            )
    return candidates, omitted


def git_ls_files(root: Path) -> list[str]:
    def read_stdout_capped(proc: subprocess.Popen[bytes], limit: int, timeout_seconds: float) -> tuple[bytes, bool]:
        if proc.stdout is None:
            return b"", False
        chunks: list[bytes] = []
        total = 0
        capped = False
        timed_out = False

        def reader() -> None:
            nonlocal total, capped
            try:
                while total <= limit:
                    chunk = proc.stdout.read(min(GIT_LS_FILES_READ_CHUNK_BYTES, limit + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > limit:
                        capped = True
                        break
            finally:
                if capped and proc.poll() is None:
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                try:
                    proc.stdout.close()
                except OSError:
                    pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive() and proc.poll() is None:
            timed_out = True
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        thread.join(0.2)
        raw_output = b"".join(chunks)[:limit]
        complete = proc.returncode == 0 and not capped and not timed_out and raw_output.endswith(b"\0")
        return raw_output, complete

    raw = b""
    git_returncode: int | None = None
    try:
        proc = subprocess.Popen(
            ["git", "-C", str(root), "ls-files", "-z"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
        )
        raw, _git_complete = read_stdout_capped(proc, MAX_GIT_LS_FILES_OUTPUT_BYTES, 10)
        git_returncode = proc.returncode
    except (OSError, subprocess.TimeoutExpired):
        proc = None
    if raw:
        if not raw.endswith(b"\0"):
            raw = raw.rsplit(b"\0", 1)[0] if b"\0" in raw else b""
        return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part][:MAX_QUERY_SCAN_FILES]
    if git_returncode == 0 or (git_returncode is not None and git_returncode < 0):
        return []
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
    return LineRange(start, start + max(len(source.selected_lines), 1) - 1)


def resolved_block_bytes(source: ResolvedSource, *, root_arg: str) -> int:
    included = source_selected_range(source)
    line_prefixes = line_byte_prefixes(source.selected_lines)
    return render_block_byte_len(source, len(source.selected_lines), line_prefixes, root_arg=root_arg, status="included", included=included)


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
    content = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return write_text_under_root(root, raw_path, content, "--manifest-out")


def validate_output_path_under_root(root: Path, raw_path: str, option_name: str) -> str:
    rel, reason = lexical_rel(raw_path)
    if rel is None:
        raise PackError(f"invalid {option_name}: {reason}")
    display, redacted = display_rel_path(rel.as_posix())
    if redacted:
        raise PackError(f"invalid {option_name}: redacted_path")
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
        flags = os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            file_fd = os.open(filename, flags, dir_fd=current_fd)
            st = os.fstat(file_fd)
            if not stat.S_ISREG(st.st_mode):
                raise PackError(f"invalid {option_name}: unsafe_path")
        except FileNotFoundError:
            temp_fd = -1
            temp_name = f".context-guard-pack-preflight-{os.getpid()}-{hashlib.sha256(raw_path.encode('utf-8', 'replace')).hexdigest()[:10]}"
            try:
                create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    create_flags |= os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    create_flags |= os.O_CLOEXEC
                if hasattr(os, "O_NONBLOCK"):
                    create_flags |= os.O_NONBLOCK
                temp_fd = os.open(temp_name, create_flags, 0o600, dir_fd=current_fd)
            except OSError as exc:
                raise PackError(f"invalid {option_name}: {exc.strerror or exc.__class__.__name__}") from exc
            finally:
                if temp_fd >= 0:
                    try:
                        os.close(temp_fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(temp_name, dir_fd=current_fd)
                    except OSError:
                        pass
        except IsADirectoryError as exc:
            raise PackError(f"invalid {option_name}: unsafe_path") from exc
        except OSError as exc:
            raise PackError(f"invalid {option_name}: {exc.strerror or exc.__class__.__name__}") from exc
    except PackError:
        raise
    except FileNotFoundError as exc:
        raise PackError(f"invalid {option_name}: missing") from exc
    except OSError as exc:
        raise PackError(f"invalid {option_name}: {exc.strerror or exc.__class__.__name__}") from exc
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


def output_rel_for_collision_check(raw_path: str, option_name: str) -> Path:
    rel, reason = lexical_rel(raw_path)
    if rel is None:
        raise PackError(f"invalid {option_name}: {reason}")
    _display, redacted = display_rel_path(rel.as_posix())
    if redacted:
        raise PackError(f"invalid {option_name}: redacted_path")
    return rel


def existing_output_identity_under_root(root: Path, rel: Path) -> tuple[int, int] | None:
    current_fd: int | None = None
    try:
        current_fd = open_dir_no_follow(root)
        for part in rel.parts[:-1]:
            next_fd = open_dir_no_follow(part, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        st = os.stat(rel.parts[-1], dir_fd=current_fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            return None
        return int(st.st_dev), int(st.st_ino)
    except (FileNotFoundError, OSError, NotImplementedError):
        return None
    finally:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass


def reject_matching_output_targets(
    root: Path,
    *,
    first_rel: Path,
    second_rel: Path,
    second_option: str,
    reason: str,
) -> None:
    first_identity = existing_output_identity_under_root(root, first_rel)
    second_identity = existing_output_identity_under_root(root, second_rel)
    same_existing_target = first_identity is not None and first_identity == second_identity
    same_lexical_target = first_rel == second_rel or first_rel.as_posix().casefold() == second_rel.as_posix().casefold()
    if same_lexical_target or same_existing_target:
        raise PackError(f"invalid {second_option}: {reason}")


def write_text_under_root(root: Path, raw_path: str, content: str, option_name: str) -> str:
    rel, reason = lexical_rel(raw_path)
    if rel is None:
        raise PackError(f"invalid {option_name}: {reason}")
    display, redacted = display_rel_path(rel.as_posix())
    if redacted:
        raise PackError(f"invalid {option_name}: redacted_path")
    parent_parts = rel.parts[:-1]
    filename = rel.parts[-1]
    current_fd: int | None = None
    try:
        current_fd = open_dir_no_follow(root)
        for part in parent_parts:
            next_fd = open_dir_no_follow(part, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        write_text_atomic_at(current_fd, filename, content, mode=0o600, option_name=option_name)
    except PackError:
        raise
    except FileNotFoundError as exc:
        raise PackError(f"invalid {option_name}: missing") from exc
    except OSError as exc:
        raise PackError(f"invalid {option_name}: {exc.strerror or exc.__class__.__name__}") from exc
    finally:
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass
    return display


def manifest_to_source_specs(manifest: dict[str, Any]) -> list[SourceSpec]:
    version = manifest.get("version", VERSION)
    if version != VERSION:
        raise PackError(f"unsupported manifest version: {version}")
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        raise PackError("manifest sources must be a list")
    specs: list[SourceSpec] = []
    for index, item in enumerate(sources):
        if not isinstance(item, dict):
            raise PackError("manifest sources must be objects")
        if "path" not in item:
            raise PackError("manifest source missing path")
        try:
            lines = parse_line_range(item.get("lines"))
        except PackError:
            lines = LineRange(-1, -1)
        specs.append(SourceSpec(
            path=str(item.get("path", "")),
            priority=bounded_int(item.get("priority"), 0, -1_000_000, 1_000_000),
            lines=lines,
            label=cap_label(item.get("label")),
            input_index=index,
            origin="auto",
        ))
    return specs


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


def percentile_int(values: list[int], numerator: int, denominator: int) -> int:
    if not values:
        return 0
    if denominator <= 0:
        return values[0]
    index = min(len(values) - 1, max(0, (len(values) - 1) * numerator // denominator))
    return values[index]


def score_gap_advice(scores: list[int], requested_top: int) -> tuple[int, dict[str, Any], list[str]]:
    if not scores:
        return 0, {"after_rank": 0, "delta": 0, "ratio": 0.0}, ["no_candidates"]
    if len(scores) == 1:
        return 1, {"after_rank": 1, "delta": 0, "ratio": 0.0}, ["single_candidate"]
    gaps = [max(0, scores[index] - scores[index + 1]) for index in range(len(scores) - 1)]
    max_gap = max(gaps)
    gap_index = gaps.index(max_gap)
    top_score = max(1, scores[0])
    ratio = round(max_gap / top_score, 4)
    if max_gap >= max(250, top_score // 5):
        elbow_k = gap_index + 1
        reasons = ["score_elbow"] if elbow_k <= requested_top else ["score_elbow_after_requested_top"]
    else:
        elbow_k = min(MAX_SUGGEST_TOP, len(scores))
        reasons = ["no_strong_score_elbow"]
    return max(1, elbow_k), {"after_rank": gap_index + 1, "delta": max_gap, "ratio": ratio}, reasons


def clamp_proxy(value: float) -> float:
    return min(1.0, max(0.0, round(value, 4)))


def adaptive_policy_recommended_k(
    *,
    policy: str,
    requested_top: int,
    score_elbow_k: int,
    budget_fit_k: int,
    candidate_count: int,
) -> int:
    candidate_limit = min(max(0, candidate_count), MAX_SUGGEST_TOP)
    if candidate_limit == 0 or budget_fit_k <= 0:
        return 0
    if policy == "recall":
        policy_k = max(requested_top, score_elbow_k)
    elif policy == "precision":
        policy_k = min(score_elbow_k, requested_top)
    else:
        policy_k = score_elbow_k
    return min(max(0, policy_k), max(0, budget_fit_k), candidate_limit)


def adaptive_path_label(value: object) -> str:
    raw = "" if value is None else str(value)
    if CONTROL_CHAR_RE.search(raw) or SECRET_CONTENT_RE.search(raw) or SECRET_PATH_COMPONENT_RE.search(raw):
        return f"redacted-path#path:{sha256_text(raw)[:12]}"
    rel, _reason = lexical_rel(raw)
    if rel is None:
        return safe_raw_path_label(raw)
    display, _redacted = display_rel_path(rel.as_posix())
    return display


def actionable_adaptive_path(value: object) -> tuple[str | None, str | None]:
    raw = "" if value is None else str(value)
    if not raw:
        return None, "missing_path"
    if REDACTED_PATH_COMPONENT in raw or "[REDACTED" in raw:
        return None, "redacted_path"
    if CONTROL_CHAR_RE.search(raw) or SECRET_CONTENT_RE.search(raw) or SECRET_PATH_COMPONENT_RE.search(raw):
        return None, "unsafe_path"
    rel, reason = lexical_rel(raw)
    if rel is None:
        return None, reason or "unsafe_path"
    return rel.as_posix(), None


def adaptive_lines(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    try:
        start = int(value.get("start"))
        end = int(value.get("end"))
    except (TypeError, ValueError, OverflowError):
        return None
    if start < 1 or end < start:
        return None
    return {"start": start, "end": end}


def adaptive_retrieval_hint(item: dict[str, Any]) -> dict[str, Any]:
    path, path_reason = actionable_adaptive_path(item.get("path"))
    lines = adaptive_lines(item.get("lines") or item.get("included_lines") or item.get("requested_lines"))
    omitted_reason = item.get("retrieval_omitted_reason")
    if path_reason:
        return {"type": "slice", "available": False, "reason": str(omitted_reason or path_reason)}
    if lines is None:
        return {"type": "slice", "available": False, "reason": "missing_lines"}
    if not item.get("retrieval_cli"):
        return {"type": "slice", "available": False, "reason": str(omitted_reason or "missing_retrieval_hint")}
    return {"type": "slice", "available": True, "path": path, "lines": lines}


def adaptive_selected_evidence(selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for rank, item in enumerate(selected[:MAX_ADAPTIVE_K_SELECTED_EVIDENCE], start=1):
        entry: dict[str, Any] = {
            "rank": rank,
            "path": adaptive_path_label(item.get("path")),
            "score": max(0, int(item.get("score", item.get("priority", 0)) or 0)),
            "reason": cap_label(item.get("reason"), default="local heuristic", limit=MAX_REASON_CHARS),
            "retrieval_hint": adaptive_retrieval_hint(item),
        }
        lines = adaptive_lines(item.get("lines"))
        if lines is not None:
            entry["lines"] = lines
        evidence.append(entry)
    return evidence


def adaptive_omitted_evidence(omitted: list[dict[str, Any]]) -> dict[str, Any]:
    reason_counts: dict[str, int] = {}
    sources: list[dict[str, Any]] = []
    for item in omitted:
        reason = cap_label(item.get("reason"), default="unknown", limit=MAX_REASON_CHARS) or "unknown"
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if len(sources) >= MAX_ADAPTIVE_K_OMITTED_EVIDENCE:
            continue
        source: dict[str, Any] = {
            "path": adaptive_path_label(item.get("path")),
            "reason": reason,
            "priority": max(0, int(item.get("priority", 0) or 0)),
        }
        lines = adaptive_lines(item.get("requested_lines") or item.get("lines"))
        if lines is not None:
            source["lines"] = lines
        hint = adaptive_retrieval_hint(item)
        if hint.get("available") or hint.get("reason") in {"redacted_path", "unsafe_root_path", "unsafe_path"}:
            source["retrieval_hint"] = hint
        sources.append(source)
    counts = [
        {"reason": reason, "count": count}
        for reason, count in sorted(reason_counts.items(), key=lambda pair: (-pair[1], pair[0]))[:MAX_ADAPTIVE_K_REASON_COUNTS]
    ]
    return {
        "omitted_count": len(omitted),
        "sources_capped": len(omitted) > len(sources),
        "sources": sources,
        "reason_counts": counts,
    }


def adaptive_source_verification(selected: list[dict[str, Any]]) -> dict[str, Any]:
    hints: list[dict[str, Any]] = []
    available = 0
    for rank, item in enumerate(selected[:MAX_ADAPTIVE_K_VERIFICATION_HINTS], start=1):
        hint = adaptive_retrieval_hint(item)
        if hint.get("available"):
            available += 1
        record: dict[str, Any] = {
            "rank": rank,
            "path": adaptive_path_label(item.get("path")),
            "retrieval_hint": hint,
        }
        hints.append(record)
    return {
        "requires_exact_source_before_edits": True,
        "format": "structured_relative_slice_hints",
        "selected_count": len(selected),
        "hint_count": len(hints),
        "hints_capped": len(selected) > len(hints),
        "available_hint_count": available,
        "omitted_hint_count": len(hints) - available,
        "hints": hints,
    }


def build_adaptive_k_advisory(
    *,
    candidates: list[SuggestCandidate],
    selected: list[dict[str, Any]],
    omitted: list[dict[str, Any]],
    requested_top: int,
    budget_bytes: int,
    estimated_pack_bytes: int,
    policy: str = "balanced",
    min_recall_proxy: float = 0.0,
    min_precision_proxy: float = 0.0,
) -> dict[str, Any]:
    if policy not in ADAPTIVE_K_POLICIES:
        policy = "balanced"
    sampled_candidates = candidates[:MAX_ADAPTIVE_K_SCORE_SAMPLES]
    scores = [max(0, int(candidate.score)) for candidate in sampled_candidates]
    score_elbow_k, max_gap_details, reason_codes = score_gap_advice(scores, requested_top)
    selected_count = len(selected)
    selected_scores = [max(0, int(item.get("score", item.get("priority", 0)) or 0)) for item in selected]
    selected_score_mass = sum(selected_scores)
    analyzed_score_mass = sum(scores)
    budget_omitted_count = sum(1 for item in omitted if item.get("reason") == "budget_exhausted")
    budget_limited = bool(budget_omitted_count or estimated_pack_bytes > budget_bytes)
    remaining_bytes = budget_bytes - estimated_pack_bytes
    average_selected_bytes = int(estimated_pack_bytes / selected_count) if selected_count else 0
    if budget_limited:
        reason_codes.append("budget_limited")
    if len(candidates) > len(sampled_candidates):
        reason_codes.append("candidate_sample_capped")
    if selected_count < min(requested_top, len(candidates)):
        reason_codes.append("selected_below_requested_top")
    if selected_count == 0:
        budget_fit_k = 0
        if candidates:
            reason_codes.append("no_budget_fit" if budget_limited else "no_selected_sources")
    elif budget_limited:
        budget_fit_k = selected_count
    else:
        additional_by_budget = max(0, remaining_bytes // max(1, average_selected_bytes))
        budget_fit_k = min(MAX_SUGGEST_TOP, len(candidates), selected_count + additional_by_budget)
        if budget_fit_k > requested_top:
            reason_codes.append("budget_headroom_expand")
    if not candidates:
        recommended_k = 0
    else:
        recommended_k = adaptive_policy_recommended_k(
            policy=policy,
            requested_top=requested_top,
            score_elbow_k=score_elbow_k,
            budget_fit_k=budget_fit_k,
            candidate_count=len(candidates),
        )
    score_values_asc = sorted(scores)
    top_score = score_values_asc[-1] if score_values_asc else 0
    recall_proxy = clamp_proxy(selected_score_mass / analyzed_score_mass) if analyzed_score_mass else 0.0
    precision_proxy = (
        clamp_proxy((selected_score_mass / max(1, selected_count)) / max(1, top_score))
        if selected_count
        else 0.0
    )
    recall_gate_passed = recall_proxy >= min_recall_proxy
    precision_gate_passed = precision_proxy >= min_precision_proxy
    gate_status = "pass" if recall_gate_passed and precision_gate_passed else "failed"
    return {
        "schema_version": ADAPTIVE_K_SCHEMA_VERSION,
        "mode": "advisory",
        "requested_top": requested_top,
        "recommended_k": recommended_k,
        "policy": {
            "name": policy,
            "available_policies": list(ADAPTIVE_K_POLICIES),
            "changes_manifest_or_pack": False,
            "measurement_basis": "current_selected_sources_not_policy_applied_rebuild",
            "status": "evaluated",
        },
        "recommendation": {
            "apply": False,
            "reason_codes": sorted(set(reason_codes)),
            "next_step": "rerun with --top recommended_k if you accept this local proxy advisory",
        },
        "score_distribution": {
            "candidate_count": len(candidates),
            "analyzed_candidate_count": len(sampled_candidates),
            "sample_capped": len(candidates) > len(sampled_candidates),
            "top_score": top_score,
            "p50_score": percentile_int(score_values_asc, 1, 2),
            "p90_score": percentile_int(score_values_asc, 9, 10),
            "min_score": score_values_asc[0] if score_values_asc else 0,
            "max_gap_details": max_gap_details,
            "score_elbow_k": score_elbow_k,
        },
        "budget_fit": {
            "budget_bytes": budget_bytes,
            "estimated_pack_bytes": estimated_pack_bytes,
            "remaining_bytes": remaining_bytes,
            "selected_count": selected_count,
            "budget_omitted_count": budget_omitted_count,
            "budget_limited": budget_limited,
            "average_selected_bytes": average_selected_bytes,
            "budget_fit_k": budget_fit_k,
        },
        "regression_gates": {
            "status": gate_status,
            "measurement_basis": "current_selected_sources_not_policy_applied_rebuild",
            "comparison": "observed_greater_than_or_equal_threshold",
            "recall_proxy": {
                "observed": recall_proxy,
                "minimum": min_recall_proxy,
                "passed": recall_gate_passed,
            },
            "precision_proxy": {
                "observed": precision_proxy,
                "minimum": min_precision_proxy,
                "passed": precision_gate_passed,
            },
        },
        "recall_precision_proxy": {
            "measurement": "local_score_mass_proxy",
            "range": "clamped_0_1",
            "measurement_basis": "current_selected_sources_not_policy_applied_rebuild",
            "selected_score_mass": selected_score_mass,
            "analyzed_score_mass": analyzed_score_mass,
            "recall_proxy": recall_proxy,
            "precision_proxy": precision_proxy,
            "selected_count": selected_count,
            "candidate_count": len(candidates),
        },
        "selected_evidence": {
            "selected_count": selected_count,
            "items_capped": selected_count > MAX_ADAPTIVE_K_SELECTED_EVIDENCE,
            "items": adaptive_selected_evidence(selected),
        },
        "omitted_evidence": adaptive_omitted_evidence(omitted),
        "source_verification": adaptive_source_verification(selected),
        "claim_boundary": {
            "deterministic_local_only": True,
            "no_model_network_or_embedding": True,
            "token_counts_are_estimated_proxies": True,
            "provider_token_or_cost_savings_claim_allowed": False,
            "advisory_does_not_change_manifest_or_pack": True,
            "selectable_policy_changes_manifest_or_pack": False,
        },
    }


def suggest_pack(root: Path, args: argparse.Namespace, *, root_arg: str) -> tuple[dict[str, Any], int]:
    query_text, _query_redactions = sanitize_text(args.query or "")
    query = " ".join(query_text.split())
    query_terms = suggest_tokens(query)
    context_lines = bounded_int(args.context_lines, DEFAULT_SUGGEST_CONTEXT_LINES, 0, MAX_SUGGEST_CONTEXT_LINES)
    top = bounded_int(args.top, DEFAULT_SUGGEST_TOP, 1, MAX_SUGGEST_TOP)
    budget = bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES)
    candidates: list[SuggestCandidate] = []
    omitted: list[dict[str, Any]] = []
    file_inputs = split_suggest_files(args.files)
    has_signal = bool(query or file_inputs or args.diff or args.output or args.test_output)
    if not has_signal:
        raise PackError("provide --query, --files, --diff, --output, or --test-output")

    for raw_path in file_inputs:
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

    candidates.sort(key=lambda item: (-item.score, item.input_index, item.path, item.lines.identity() if item.lines else "0:0"))
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
            duplicate_item = {
                "path": display,
                "status": "omitted",
                "reason": "duplicate_source",
                "suggest_reason": candidate.reason,
                "priority": candidate.score,
                "retrieval_omitted_reason": "redacted_path" if redacted else None,
            }
            omitted.append({key: value for key, value in duplicate_item.items() if value is not None})
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
        line_prefixes = line_byte_prefixes(source.selected_lines)
        source_bytes = render_block_byte_len(
            source,
            len(source.selected_lines),
            line_prefixes,
            root_arg=root_arg,
            status="included",
            included=source_selected_range(source),
        )
        remaining = budget - current_bytes
        if source_bytes > remaining:
            if not selected and remaining > 0:
                partial_lines, _partial_block, partial_range = fit_partial_lines(source, remaining, root_arg=root_arg, line_prefixes=line_prefixes)
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
                    partial_prefixes = line_byte_prefixes(source.selected_lines)
                    source_bytes = render_block_byte_len(
                        source,
                        len(source.selected_lines),
                        partial_prefixes,
                        root_arg=root_arg,
                        status="included",
                        included=source_selected_range(source),
                    )
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
    if getattr(args, "adaptive_k", False):
        payload["adaptive_k"] = build_adaptive_k_advisory(
            candidates=candidates,
            selected=selected,
            omitted=omitted,
            requested_top=top,
            budget_bytes=budget,
            estimated_pack_bytes=estimated_pack_bytes,
            policy=getattr(args, "adaptive_k_policy", "balanced"),
            min_recall_proxy=float(getattr(args, "adaptive_k_min_recall_proxy", 0.0) or 0.0),
            min_precision_proxy=float(getattr(args, "adaptive_k_min_precision_proxy", 0.0) or 0.0),
        )
    return payload, 0


def line_range_identity(value: object) -> str:
    if isinstance(value, dict):
        return f"{value.get('start')}:{value.get('end')}"
    if value is None:
        return "all"
    return str(value)


def copy_explain_fields(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for field in fields:
        if field in item and item[field] is not None:
            out[field] = copy.deepcopy(item[field])
    return out


def build_source_matches_exact(suggest_item: dict[str, Any], build_item: dict[str, Any]) -> bool:
    if build_item.get("path") != suggest_item.get("path"):
        return False
    if build_item.get("priority") != suggest_item.get("priority"):
        return False
    lines = line_range_identity(suggest_item.get("lines"))
    requested = line_range_identity(build_item.get("requested_lines"))
    included = line_range_identity(build_item.get("included_lines"))
    return lines in {requested, included, "all"}


def find_exact_build_source_for_explain(
    suggest_item: dict[str, Any],
    build_sources: list[dict[str, Any]],
    used_indexes: set[int],
) -> dict[str, Any] | None:
    for index, item in enumerate(build_sources):
        if index in used_indexes:
            continue
        if build_source_matches_exact(suggest_item, item):
            used_indexes.add(index)
            return item
    return None


def find_fallback_build_source_for_explain(
    suggest_item: dict[str, Any],
    build_sources: list[dict[str, Any]],
    used_indexes: set[int],
) -> dict[str, Any] | None:
    path = suggest_item.get("path")
    for index, item in enumerate(build_sources):
        if index in used_indexes or item.get("path") != path:
            continue
        used_indexes.add(index)
        return item
    return None


def explain_omission_key(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        str(item.get("phase", "")),
        str(item.get("path", "")),
        str(item.get("reason", "")),
        str(item.get("suggest_reason", "")),
        json.dumps(item.get("requested_lines", item.get("lines", "")), ensure_ascii=False, sort_keys=True),
    )


def sanitize_explain_text(value: str, *, limit: int = MAX_LABEL_CHARS) -> str:
    sanitized, _redacted = sanitize_text(str(value))
    return cap_label(sanitized, default="", limit=limit) or ""


def is_repo_map_text_path(path: str) -> bool:
    name = Path(path).name.lower()
    if name in {"readme", "license", "dockerfile", "makefile"}:
        return True
    return Path(path).suffix.lower() in REPO_MAP_TEXT_EXTENSIONS


def read_repo_map_text(root: Path, rel_path: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    rel, reason = lexical_rel(rel_path)
    if rel is None:
        return None, {"path": repo_map_safe_raw_path_label(rel_path), "reason": reason}
    display, redacted_path = repo_map_display_rel_path(rel.as_posix())
    if not is_repo_map_text_path(display):
        return None, {"path": display, "reason": "unsupported_file_type"}
    handle, open_reason = open_regular_under_root(root, rel)
    if handle is None:
        return None, {"path": display, "reason": open_reason, "retrieval_omitted_reason": "redacted_path" if redacted_path else None}
    try:
        with handle:
            text = handle.read(MAX_REPO_MAP_BYTES_PER_FILE + 1)
    except (OSError, UnicodeError):
        return None, {"path": display, "reason": "unsafe_path", "retrieval_omitted_reason": "redacted_path" if redacted_path else None}
    capped = byte_len(text) > MAX_REPO_MAP_BYTES_PER_FILE
    if capped:
        text = text.encode("utf-8", errors="replace")[:MAX_REPO_MAP_BYTES_PER_FILE].decode("utf-8", errors="ignore")
    risk_counts = secret_risk_counts(text)
    sanitized_text, redacted_lines = sanitize_text(text)
    return {
        "path": display,
        "raw_path": rel.as_posix(),
        "redacted_path": redacted_path,
        "text": sanitized_text,
        "bytes": byte_len(sanitized_text),
        "bytes_capped": capped,
        "line_count": len(sanitized_text.splitlines()) or (1 if sanitized_text else 0),
        "redacted_lines": redacted_lines,
        "secret_risk_counts": risk_counts,
    }, None


def repo_map_path_scan_priority(rel_path: str, *, seed_paths: set[str], query_terms: set[str], input_index: int) -> tuple[int, int, str]:
    rel, reason = lexical_rel(rel_path)
    display = repo_map_safe_raw_path_label(rel_path)
    redacted = False
    if rel is not None and not reason:
        display, redacted = repo_map_display_rel_path(rel.as_posix())
    score = 0
    if not redacted and display in seed_paths:
        score += 1_000_000
    if is_repo_map_text_path(display):
        score += 10_000
    score += suggest_score_path(display, query_terms)
    if Path(display).name.lower() in {"readme", "readme.md", "readme.mdx"}:
        score += 250
    return (-score, input_index, display)


def repo_map_scan_paths(paths: list[str], *, seed_paths: set[str], query_terms: set[str]) -> list[str]:
    ranked = sorted(
        enumerate(paths[:MAX_REPO_MAP_FILES]),
        key=lambda item: repo_map_path_scan_priority(item[1], seed_paths=seed_paths, query_terms=query_terms, input_index=item[0]),
    )
    return [path for _index, path in ranked[:MAX_REPO_MAP_SCAN_FILES]]


def repo_map_records(root: Path, *, seed_paths: set[str], query_terms: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    paths = git_ls_files(root)
    candidate_paths = paths[:MAX_REPO_MAP_FILES]
    path_cap_reached = len(paths) > MAX_REPO_MAP_FILES
    scan_paths = repo_map_scan_paths(candidate_paths, seed_paths=seed_paths, query_terms=query_terms)
    scan_cap_reached = len(candidate_paths) > len(scan_paths)
    records: list[dict[str, Any]] = []
    omitted: list[dict[str, Any]] = []
    for rel_path in scan_paths:
        record, omission_item = read_repo_map_text(root, rel_path)
        if record is not None:
            records.append(record)
        elif omission_item is not None and omission_item.get("reason") != "unsupported_file_type":
            omitted.append({key: value for key, value in omission_item.items() if value is not None})
    caps = {
        "max_files": MAX_REPO_MAP_SCAN_FILES,
        "files_capped": path_cap_reached or scan_cap_reached,
        "max_candidate_files": MAX_REPO_MAP_FILES,
        "candidate_files": len(candidate_paths),
        "candidate_files_capped": path_cap_reached,
        "scan_files": len(scan_paths),
        "scan_files_capped": scan_cap_reached,
        "max_bytes_per_file": MAX_REPO_MAP_BYTES_PER_FILE,
        "bytes_per_file_capped_count": sum(1 for item in records if item.get("bytes_capped")),
        "max_tree_entries": MAX_REPO_MAP_TREE_ENTRIES,
        "max_signature_entries": MAX_REPO_MAP_SIGNATURE_ENTRIES,
        "max_graph_rank_entries": MAX_REPO_MAP_GRAPH_RANK_ENTRIES,
        "max_retrieval_hints": MAX_REPO_MAP_RETRIEVAL_HINTS,
        "max_secret_risk_files": MAX_REPO_MAP_SECRET_RISK_FILES,
    }
    return records, omitted, caps


def secret_risk_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name, pattern in SECRET_RISK_PATTERNS:
        found = len(pattern.findall(text))
        if found:
            counts[name] = found
    return counts


def build_secret_scan(records: list[dict[str, Any]]) -> dict[str, Any]:
    risk_counts: dict[str, int] = {}
    files: list[dict[str, Any]] = []
    for record in records:
        counts = dict(record.get("secret_risk_counts", {}) if isinstance(record.get("secret_risk_counts"), dict) else {})
        if not counts:
            continue
        for name, count in counts.items():
            risk_counts[name] = risk_counts.get(name, 0) + count
        files.append({
            "path": record["path"],
            "counts": counts,
            "redacted_path": bool(record.get("redacted_path")),
        })
    files.sort(key=lambda item: (-sum(item["counts"].values()), item["path"]))
    return {
        "risk_counts": dict(sorted(risk_counts.items())),
        "files_with_risks": files[:MAX_REPO_MAP_SECRET_RISK_FILES],
        "files_omitted_by_cap": max(0, len(files) - MAX_REPO_MAP_SECRET_RISK_FILES),
        "caveat": "Counts are local best-effort secret-pattern risk signals; raw matched values are never emitted.",
    }


def build_token_tree(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    directory_totals: dict[str, dict[str, int]] = {}
    file_entries: list[dict[str, Any]] = []
    for record in records:
        path = str(record["path"])
        bytes_count = int(record.get("bytes", 0) or 0)
        file_entries.append({
            "kind": "file",
            "path": path,
            "bytes": bytes_count,
            "token_proxy": token_proxy(str(record.get("text", ""))),
            "line_count": int(record.get("line_count", 0) or 0),
            "bytes_capped": bool(record.get("bytes_capped")),
        })
        parts = path.split("/")
        if len(parts) > 1:
            prefix = ""
            for part in parts[:-1]:
                prefix = part if not prefix else f"{prefix}/{part}"
                bucket = directory_totals.setdefault(prefix, {"bytes": 0, "file_count": 0})
                bucket["bytes"] += bytes_count
                bucket["file_count"] += 1
    directory_entries = [
        {
            "kind": "directory",
            "path": path,
            "bytes": data["bytes"],
            "token_proxy": max(0, round(data["bytes"] / TOKEN_PROXY_CHARS_PER_TOKEN)),
            "file_count": data["file_count"],
        }
        for path, data in directory_totals.items()
    ]
    entries = directory_entries + file_entries
    entries.sort(key=lambda item: (-int(item.get("bytes", 0) or 0), str(item.get("path", ""))))
    return entries[:MAX_REPO_MAP_TREE_ENTRIES]


def signature_range(line_number: int, total_lines: int) -> LineRange:
    return LineRange(max(1, line_number), min(max(1, total_lines), max(1, line_number) + 24))


def signature_entry(record: dict[str, Any], *, kind: str, name: str, raw_signature: str, line_number: int) -> dict[str, Any]:
    total_lines = int(record.get("line_count", 0) or 1)
    line_range = signature_range(line_number, total_lines)
    return {
        "path": record["path"],
        "kind": kind,
        "name": sanitize_explain_text(name, limit=80),
        "signature": sanitize_explain_text(raw_signature, limit=180),
        "line": line_number,
        "lines": line_range.as_dict(),
    }


def python_signatures(record: dict[str, Any], text: str) -> list[dict[str, Any]]:
    try:
        module = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = text.splitlines()
    out: list[dict[str, Any]] = []
    for node in module.body:
        if isinstance(node, ast.ClassDef):
            raw = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else f"class {node.name}"
            out.append(signature_entry(record, kind="class", name=node.name, raw_signature=raw, line_number=node.lineno))
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    raw_child = lines[child.lineno - 1].strip() if 0 < child.lineno <= len(lines) else f"def {child.name}"
                    out.append(signature_entry(record, kind="method", name=child.name, raw_signature=raw_child, line_number=child.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            raw = lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else f"def {node.name}"
            out.append(signature_entry(record, kind="function", name=node.name, raw_signature=raw, line_number=node.lineno))
    return out


def regex_signatures(record: dict[str, Any], text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    suffix = Path(str(record.get("path", ""))).suffix.lower()
    for index, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if suffix in {".md", ".mdx"}:
            heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
            if heading:
                out.append(signature_entry(record, kind="heading", name=heading.group(2), raw_signature=stripped, line_number=index))
            continue
        match = SIGNATURE_LINE_RE.match(raw)
        if not match:
            continue
        name = next((group for group in match.groups() if group), "signature")
        kind = "class" if re.search(r"\bclass\s+" + re.escape(name), raw) else "function"
        out.append(signature_entry(record, kind=kind, name=name, raw_signature=stripped, line_number=index))
    return out


def extract_signatures(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signatures: list[dict[str, Any]] = []
    for record in records:
        text = str(record.get("text", ""))
        suffix = Path(str(record.get("path", ""))).suffix.lower()
        if suffix == ".py":
            parsed = python_signatures(record, text)
            if parsed:
                signatures.extend(parsed)
                continue
        signatures.extend(regex_signatures(record, text))
    signatures.sort(key=lambda item: (str(item.get("path", "")), int(item.get("line", 0) or 0), str(item.get("name", ""))))
    return signatures[:MAX_REPO_MAP_SIGNATURE_ENTRIES]


def normalize_repo_map_candidate(path: str) -> str:
    normalized = posixpath.normpath(path.replace("\\", "/"))
    if normalized == ".":
        return ""
    return normalized.lstrip("/")


def resolve_import_target(raw_target: str, source_path: str, known_paths: set[str]) -> str | None:
    target = raw_target.strip()
    if not target:
        return None
    candidates: list[str] = []
    source_dir = Path(source_path).parent.as_posix()
    if target.startswith("."):
        if target.startswith("./") or target.startswith("../"):
            base = normalize_repo_map_candidate(posixpath.join(source_dir, target))
        else:
            leading = len(target) - len(target.lstrip("."))
            remainder = target[leading:].replace(".", "/")
            base_dir = source_dir
            for _ in range(max(0, leading - 1)):
                base_dir = posixpath.dirname(base_dir)
            base = normalize_repo_map_candidate(posixpath.join(base_dir, remainder)) if remainder else normalize_repo_map_candidate(base_dir)
        candidates.extend([base, f"{base}.py", f"{base}.ts", f"{base}.tsx", f"{base}.js", f"{base}.jsx", f"{base}/index.ts", f"{base}/index.js"])
    else:
        module_path = target.replace(".", "/")
        candidates.extend([f"{module_path}.py", f"{module_path}.ts", f"{module_path}.tsx", f"{module_path}.js", f"{module_path}.jsx", f"{module_path}/index.ts", f"{module_path}/index.js"])
    for candidate in candidates:
        normalized = normalize_repo_map_candidate(candidate)
        if normalized in known_paths:
            return normalized
    return None


def python_from_import_targets(module_name: str, imported_names: str) -> list[str]:
    targets = [module_name]
    if module_name.strip("."):
        return targets
    for raw_name in imported_names.replace("(", " ").replace(")", " ").split(","):
        name = raw_name.strip().split(" as ", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue
        targets.append(f"{module_name}{name}")
    return targets


def collect_import_edges(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    known = {str(record.get("path", "")) for record in records}
    edges: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        source = str(record.get("path", ""))
        for line in str(record.get("text", "")).splitlines():
            py_from_match = PY_FROM_IMPORT_LINE_RE.match(line)
            if py_from_match:
                raw_targets = python_from_import_targets(py_from_match.group("module"), py_from_match.group("names"))
            else:
                raw_targets = [next((value for value in match.groupdict().values() if value), "") for match in IMPORT_PATH_RE.finditer(line)]
            for raw_target in raw_targets:
                target = resolve_import_target(raw_target, source, known)
                if target is None or target == source:
                    continue
                edge = (source, target)
                if edge in seen:
                    continue
                seen.add(edge)
                edges.append({"from": source, "to": target})
                if len(edges) >= MAX_REPO_MAP_FILES:
                    return edges
    return edges


def repo_map_seed_paths(args: argparse.Namespace, suggest_payload: dict[str, Any], build_payload: dict[str, Any]) -> set[str]:
    seeds: set[str] = set()
    for raw in split_suggest_files(getattr(args, "files", None)):
        rel, _reason = lexical_rel(raw)
        if rel is not None:
            display, redacted = repo_map_display_rel_path(rel.as_posix())
            if not redacted:
                seeds.add(display)
    for source in suggest_payload.get("sources", []):
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            seeds.add(source["path"])
    for source in build_payload.get("included_sources", []):
        if isinstance(source, dict) and isinstance(source.get("path"), str):
            seeds.add(source["path"])
    return seeds


def build_graph_rank(
    records: list[dict[str, Any]],
    signatures: list[dict[str, Any]],
    edges: list[dict[str, str]],
    *,
    query_terms: set[str],
    seed_paths: set[str],
    secret_scan: dict[str, Any],
) -> list[dict[str, Any]]:
    signature_paths = {str(item.get("path", "")) for item in signatures}
    secret_paths = {str(item.get("path", "")) for item in secret_scan.get("files_with_risks", []) if isinstance(item, dict)}
    degree: dict[str, int] = {}
    for edge in edges:
        degree[edge["from"]] = degree.get(edge["from"], 0) + 1
        degree[edge["to"]] = degree.get(edge["to"], 0) + 1
    ranked: list[dict[str, Any]] = []
    for record in records:
        path = str(record.get("path", ""))
        text = str(record.get("text", "")).lower()
        components = {
            "seed": 1000 if path in seed_paths else 0,
            "query_path": suggest_score_path(path, query_terms),
            "query_content": min(500, 25 * sum(text.count(term) for term in query_terms)),
            "signature": 80 if path in signature_paths else 0,
            "graph_degree": 25 * degree.get(path, 0),
            "secret_risk_penalty": -25 if path in secret_paths else 0,
        }
        score = sum(components.values())
        if score <= 0:
            continue
        ranked.append({
            "path": path,
            "score": score,
            "components": components,
            "explain_only": True,
            "line_count": int(record.get("line_count", 0) or 0),
        })
    ranked.sort(key=lambda item: (-int(item["score"]), str(item["path"])))
    return ranked[:MAX_REPO_MAP_GRAPH_RANK_ENTRIES]


def repo_map_retrieval_for(root_arg: str, display_path: str, lines: LineRange, *, redacted_path: bool) -> tuple[str | None, str | None]:
    if redacted_path:
        return None, "redacted_path"
    safe_root = safe_repo_map_root_arg_for_retrieval(root_arg)
    if safe_root is None:
        return None, "unsafe_root_path"
    return retrieval_cli(safe_root, display_path, lines), None


def repo_map_retrieval(
    record_by_path: dict[str, dict[str, Any]],
    signatures: list[dict[str, Any]],
    graph_rank: list[dict[str, Any]],
    *,
    root_arg: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(path: str, line_range: LineRange, source: str, name: str | None = None) -> None:
        record = record_by_path.get(path)
        if record is None:
            return
        retrieval, reason = repo_map_retrieval_for(root_arg, path, line_range, redacted_path=bool(record.get("redacted_path")))
        key = (path, line_range.identity(), source)
        if key in seen:
            return
        seen.add(key)
        item: dict[str, Any] = {"path": path, "source": source, "lines": line_range.as_dict()}
        if retrieval:
            item["slice_cli"] = retrieval
        elif reason:
            item["retrieval_omitted_reason"] = reason
        if name and retrieval and Path(path).suffix.lower() in SYMBOL_HINT_EXTENSIONS:
            item["symbol_cli"] = " ".join(shlex.quote(part) for part in ["context-guard-read-symbol", "--json", path, name])
        out.append(item)

    for signature in signatures:
        lines = signature.get("lines")
        if isinstance(lines, dict):
            try:
                line_range = LineRange(int(lines.get("start")), int(lines.get("end")))
            except (TypeError, ValueError):
                continue
            add(str(signature.get("path", "")), line_range, "signature", str(signature.get("name", "")) or None)
        if len(out) >= MAX_REPO_MAP_RETRIEVAL_HINTS:
            return out[:MAX_REPO_MAP_RETRIEVAL_HINTS]
    for item in graph_rank:
        path = str(item.get("path", ""))
        record = record_by_path.get(path)
        if record is None:
            continue
        total = int(record.get("line_count", 0) or 1)
        add(path, LineRange(1, min(total, 80)), "graph_rank")
        if len(out) >= MAX_REPO_MAP_RETRIEVAL_HINTS:
            break
    return out[:MAX_REPO_MAP_RETRIEVAL_HINTS]


def build_repo_map_payload(
    root: Path,
    args: argparse.Namespace,
    suggest_payload: dict[str, Any],
    build_payload: dict[str, Any],
    *,
    root_arg: str,
) -> dict[str, Any]:
    query_terms = suggest_tokens(str(suggest_payload.get("query", "")))
    seed_paths = repo_map_seed_paths(args, suggest_payload, build_payload)
    records, omitted, caps = repo_map_records(root, seed_paths=seed_paths, query_terms=query_terms)
    record_by_path = {str(record["path"]): record for record in records}
    signatures = extract_signatures(records)
    secret_scan = build_secret_scan(records)
    edges = collect_import_edges(records)
    graph_rank = build_graph_rank(
        records,
        signatures,
        edges,
        query_terms=query_terms,
        seed_paths=seed_paths,
        secret_scan=secret_scan,
    )
    retrieval = repo_map_retrieval(record_by_path, signatures, graph_rank, root_arg=root_arg)
    tree = build_token_tree(records)
    total_bytes = sum(int(record.get("bytes", 0) or 0) for record in records)
    return {
        "schema_version": REPO_MAP_SCHEMA_VERSION,
        "summary": {
            "files_scanned": len(records),
            "files_capped": bool(caps["files_capped"]),
            "bytes_per_file_capped_count": int(caps["bytes_per_file_capped_count"]),
            "tree_bytes": total_bytes,
            "tree_token_proxy": sum(int(item.get("token_proxy", 0) or 0) for item in tree),
            "signature_files": len({str(item.get("path", "")) for item in signatures}),
            "signature_count": len(signatures),
            "secret_risk_files": len(secret_scan.get("files_with_risks", [])),
            "graph_edges": len(edges),
        },
        "caps": caps,
        "token_tree": tree,
        "secret_scan": secret_scan,
        "signature_index": signatures,
        "graph": {
            "edges": edges[:MAX_REPO_MAP_GRAPH_RANK_ENTRIES],
            "edges_omitted_by_cap": max(0, len(edges) - MAX_REPO_MAP_GRAPH_RANK_ENTRIES),
        },
        "graph_rank": graph_rank,
        "retrieval": retrieval,
        "omitted_files": omitted[:MAX_REPO_MAP_TREE_ENTRIES],
        "safety": {
            "deterministic_local_only": True,
            "no_network": True,
            "no_model_or_embedding": True,
            "explain_only": True,
            "redacted_before_output": True,
            "tree_sitter": {"status": "unavailable_without_optional_dependency", "fallback": "python_ast_and_regex_signatures"},
            "caveats": [
                "Repo-map bytes are local sampled UTF-8 bytes and estimated chars_div_4 token proxies, not provider-token or savings claims.",
                "Graph ranking is deterministic explain metadata only; it does not change pack selection in this stage.",
            ],
        },
    }


def line_identity_from_dict(value: object) -> str:
    if not isinstance(value, dict):
        return "all"
    return f"{value.get('start')}:{value.get('end')}"


def build_symbol_memory_payload(repo_map: dict[str, Any]) -> dict[str, Any]:
    retrieval_by_path_lines: dict[tuple[str, str], dict[str, Any]] = {}
    for item in repo_map.get("retrieval", []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", ""))
        retrieval_by_path_lines[(path, line_identity_from_dict(item.get("lines")))] = item

    symbols: list[dict[str, Any]] = []
    for signature in repo_map.get("signature_index", []):
        if not isinstance(signature, dict):
            continue
        path = str(signature.get("path", ""))
        lines = copy.deepcopy(signature.get("lines"))
        retrieval = retrieval_by_path_lines.get((path, line_identity_from_dict(lines)))
        symbol: dict[str, Any] = {
            "path": path,
            "kind": signature.get("kind"),
            "name": signature.get("name"),
            "signature": signature.get("signature"),
            "line": signature.get("line"),
            "lines": lines,
            "source": "repo_map.signature_index",
            "exact_source_verification_required": True,
        }
        if isinstance(retrieval, dict):
            for key in ("slice_cli", "symbol_cli", "retrieval_omitted_reason"):
                if retrieval.get(key):
                    symbol[key] = retrieval[key]
        symbols.append({key: value for key, value in symbol.items() if value is not None})
        if len(symbols) >= MAX_SYMBOL_MEMORY_ITEMS:
            break

    graph_context: list[dict[str, Any]] = []
    for item in repo_map.get("graph_rank", []):
        if not isinstance(item, dict):
            continue
        graph_context.append({
            "path": item.get("path"),
            "score": item.get("score"),
            "components": copy.deepcopy(item.get("components", {})),
            "line_count": item.get("line_count"),
            "exact_source_verification_required": True,
        })
        if len(graph_context) >= MAX_SYMBOL_MEMORY_GRAPH_ITEMS:
            break

    summary = repo_map.get("summary", {}) if isinstance(repo_map.get("summary"), dict) else {}
    retrieval = repo_map.get("retrieval", []) if isinstance(repo_map.get("retrieval"), list) else []
    return {
        "schema_version": SYMBOL_MEMORY_SCHEMA_VERSION,
        "mode": "advisory",
        "source": "contextguard.pack-repo-map.v1",
        "summary": {
            "symbols": len(symbols),
            "graph_context": len(graph_context),
            "files_scanned": int(summary.get("files_scanned", 0) or 0),
            "graph_edges": int(summary.get("graph_edges", 0) or 0),
            "retrieval_hints": len(retrieval),
        },
        "symbols": symbols,
        "graph_context": graph_context,
        "source_verification": {
            "requires_exact_source_before_edits": True,
            "verified_by": ["slice_cli", "symbol_cli"],
            "retrieval_hint_count": len(retrieval),
            "missing_retrieval_hint_count": max(0, len(symbols) - sum(1 for item in symbols if item.get("slice_cli") or item.get("symbol_cli"))),
        },
        "claim_boundary": {
            "deterministic_local_only": True,
            "no_network_model_embedding_lsp_or_tree_sitter_dependency": True,
            "advisory_does_not_change_manifest_pack_or_receipt": True,
            "graph_rank_is_explain_only": True,
            "provider_token_or_cost_savings_claim_allowed": False,
        },
    }


def build_auto_explain_payload(
    args: argparse.Namespace,
    suggest_payload: dict[str, Any],
    build_payload: dict[str, Any],
    payload: dict[str, Any],
    *,
    root: Path | None = None,
    root_arg: str = ".",
    repo_map_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    build_sources = [
        item
        for item in build_payload.get("included_sources", [])
        if isinstance(item, dict)
    ]
    used_build_indexes: set[int] = set()
    suggest_sources = [
        item
        for item in suggest_payload.get("sources", [])
        if isinstance(item, dict)
    ]
    exact_matches: dict[int, dict[str, Any]] = {}
    for index, item in enumerate(suggest_sources):
        build_item = find_exact_build_source_for_explain(item, build_sources, used_build_indexes)
        if build_item is not None:
            exact_matches[index] = build_item

    selection: list[dict[str, Any]] = []
    for index, item in enumerate(suggest_sources):
        entry = copy_explain_fields(
            item,
            ("path", "score", "priority", "reason", "label", "lines", "bytes", "retrieval_cli", "retrieval_omitted_reason"),
        )
        build_item = exact_matches.get(index)
        if build_item is None:
            build_item = find_fallback_build_source_for_explain(item, build_sources, used_build_indexes)
        if build_item is not None:
            entry["build_status"] = build_item.get("status", "included")
            for key in ("requested_lines", "included_lines"):
                if key in build_item:
                    entry[key] = copy.deepcopy(build_item[key])
            if "bytes" in build_item:
                entry["build_bytes"] = build_item["bytes"]
        else:
            entry["build_status"] = "not_built"
        selection.append(entry)

    omissions: list[dict[str, Any]] = []
    seen_omissions: set[tuple[str, str, str, str, str]] = set()
    omission_fields = (
        "path",
        "status",
        "reason",
        "suggest_reason",
        "priority",
        "label",
        "requested_lines",
        "included_lines",
        "lines",
        "total_lines",
        "retrieval_cli",
        "retrieval_omitted_reason",
        "input_index",
    )
    for phase, source in (("suggest", suggest_payload), ("build", build_payload)):
        for item in source.get("omitted_sources", []):
            if not isinstance(item, dict):
                continue
            entry = copy_explain_fields(item, omission_fields)
            entry["phase"] = phase
            key = explain_omission_key(entry)
            if key in seen_omissions:
                continue
            seen_omissions.add(key)
            omissions.append(entry)
    omissions.sort(key=explain_omission_key)

    build_source_counts = build_payload.get("sources", {}) if isinstance(build_payload.get("sources"), dict) else {}
    auto_source_counts = payload.get("sources", {}) if isinstance(payload.get("sources"), dict) else {}
    artifact = build_payload.get("artifact", {}) if isinstance(build_payload.get("artifact"), dict) else {}
    pack_bytes = int(payload.get("pack_bytes", build_payload.get("pack_bytes", 0)) or 0)
    budget_bytes = int(payload.get("budget_bytes", build_payload.get("budget_bytes", 0)) or 0)
    budget_omitted_count = sum(1 for item in omissions if item.get("reason") == "budget_exhausted")
    explicit_files = split_suggest_files(args.files)
    query = str(suggest_payload.get("query", ""))
    diff_label = cap_label(args.diff) if getattr(args, "diff", None) else None
    explain = {
        "schema_version": AUTO_EXPLAIN_SCHEMA_VERSION,
        "summary": {
            "suggested": int(auto_source_counts.get("suggested", len(selection)) or 0),
            "included": int(auto_source_counts.get("included", build_source_counts.get("included", 0)) or 0),
            "partial": int(auto_source_counts.get("partial", build_source_counts.get("partial", 0)) or 0),
            "omitted": int(auto_source_counts.get("omitted", build_source_counts.get("omitted", 0)) or 0),
            "suggest_omitted": len([item for item in suggest_payload.get("omitted_sources", []) if isinstance(item, dict)]),
            "explain_omissions": len(omissions),
            "pack_bytes": pack_bytes,
            "budget_bytes": budget_bytes,
            "manifest_written": bool(payload.get("manifest_path")),
            "pack_written": bool(payload.get("pack_path")),
            "artifact_stored": bool(artifact.get("stored")),
            "artifact_capped": bool(artifact.get("capped")),
        },
        "inputs": {
            "query": query,
            "query_present": bool(query),
            "diff": diff_label,
            "diff_present": bool(diff_label),
            "explicit_file_count": len(explicit_files),
            "output_count": len(args.output or []),
            "test_output_count": len(args.test_output or []),
            "top": bounded_int(args.top, DEFAULT_SUGGEST_TOP, 1, MAX_SUGGEST_TOP),
            "context_lines": bounded_int(args.context_lines, DEFAULT_SUGGEST_CONTEXT_LINES, 0, MAX_SUGGEST_CONTEXT_LINES),
            "no_artifact": bool(args.no_artifact),
            "manifest_path": payload.get("manifest_path"),
            "pack_path": payload.get("pack_path"),
        },
        "selection": selection,
        "omissions": omissions,
        "budget": {
            "pack_bytes": pack_bytes,
            "budget_bytes": budget_bytes,
            "remaining_bytes": budget_bytes - pack_bytes,
            "partial_count": int(build_source_counts.get("partial", 0) or 0),
            "budget_omitted_count": budget_omitted_count,
            "token_proxy": copy.deepcopy(payload.get("token_proxy", {})),
            "measurement": "observed_bytes_estimated_tokens",
            "caveat": "Byte counts are observed pack bytes; token counts are estimated chars_div_4 proxies, not provider-token savings.",
        },
        "safety": {
            "redaction": copy.deepcopy(build_payload.get("redaction", {})),
            "caveats": copy.deepcopy(payload.get("caveats", [])),
            "deterministic_local_only": True,
            "raw_output_embedded": False,
            "raw_test_output_embedded": False,
        },
    }
    if repo_map_payload is not None:
        explain["repo_map"] = copy.deepcopy(repo_map_payload)
    elif root is not None:
        explain["repo_map"] = build_repo_map_payload(root, args, suggest_payload, build_payload, root_arg=root_arg)
    return explain


def auto_pack(root: Path, args: argparse.Namespace, *, root_arg: str) -> tuple[dict[str, Any], int]:
    manifest_rel = output_rel_for_collision_check(args.manifest_out, "--manifest-out") if args.manifest_out else None
    pack_rel = output_rel_for_collision_check(args.pack_out, "--pack-out") if args.pack_out else None
    if manifest_rel is not None and pack_rel is not None:
        reject_matching_output_targets(
            root,
            first_rel=manifest_rel,
            second_rel=pack_rel,
            second_option="--pack-out",
            reason="same_as_manifest_out",
        )
    if args.manifest_out:
        validate_output_path_under_root(root, args.manifest_out, "--manifest-out")
    if args.pack_out:
        validate_output_path_under_root(root, args.pack_out, "--pack-out")
    suggest_args = copy.copy(args)
    suggest_args.manifest_out = None
    suggest_payload, rc = suggest_pack(root, suggest_args, root_arg=root_arg)
    manifest = suggest_payload["manifest"]
    specs = manifest_to_source_specs(manifest)
    budget = bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES)
    build_payload = build_pack(root, specs, budget_bytes=budget, root_arg=root_arg, store_artifact=False)
    if not args.no_artifact:
        receipt_rel = Path(PACK_DIR) / f"{build_payload['pack_id']}.json"
        if manifest_rel is not None:
            reject_matching_output_targets(
                root,
                first_rel=receipt_rel,
                second_rel=manifest_rel,
                second_option="--manifest-out",
                reason="same_as_artifact_receipt",
            )
        if pack_rel is not None:
            reject_matching_output_targets(
                root,
                first_rel=receipt_rel,
                second_rel=pack_rel,
                second_option="--pack-out",
                reason="same_as_artifact_receipt",
            )
    manifest_path: str | None = None
    pack_path: str | None = None
    if args.pack_out:
        pack_path = write_text_under_root(root, args.pack_out, str(build_payload["pack"]), "--pack-out")
    if args.manifest_out:
        manifest_path = write_manifest_under_root(root, args.manifest_out, manifest)
    if not args.no_artifact:
        build_payload["artifact"] = store_receipt(root, build_payload)
    build_hint, build_hint_omitted_reason = suggest_build_hint(root_arg, manifest_path, budget)
    suggest_payload["manifest_path"] = manifest_path
    suggest_payload["build_hint"] = build_hint
    suggest_payload.pop("build_hint_omitted_reason", None)
    if build_hint_omitted_reason:
        suggest_payload["build_hint_omitted_reason"] = build_hint_omitted_reason
    payload: dict[str, Any] = {
        "tool": TOOL_NAME,
        "schema_version": AUTO_SCHEMA_VERSION,
        "version": VERSION,
        "mode": "auto",
        "root": display_root(root),
        "query": suggest_payload.get("query", ""),
        "budget_bytes": budget,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "pack_path": pack_path,
        "suggest": suggest_payload,
        "build": build_payload,
        "sources": {
            "suggested": len(suggest_payload.get("sources", [])),
            "included": build_payload.get("sources", {}).get("included", 0),
            "partial": build_payload.get("sources", {}).get("partial", 0),
            "omitted": build_payload.get("sources", {}).get("omitted", 0),
        },
        "pack_bytes": build_payload.get("pack_bytes", 0),
        "token_proxy": build_payload.get("token_proxy", {}),
        "caveats": [
            "Deterministic local heuristics only; no model, network, embedding, or provider-cost estimate is used.",
            "Byte and token values are pack-size proxies, not billing claims.",
        ],
    }
    if build_hint_omitted_reason:
        payload["build_hint_omitted_reason"] = build_hint_omitted_reason
    if getattr(args, "adaptive_k", False) and isinstance(suggest_payload.get("adaptive_k"), dict):
        payload["adaptive_k"] = copy.deepcopy(suggest_payload["adaptive_k"])
    repo_map_payload: dict[str, Any] | None = None
    if getattr(args, "symbol_memory", False) or args.explain:
        repo_map_payload = build_repo_map_payload(root, args, suggest_payload, build_payload, root_arg=root_arg)
    if getattr(args, "symbol_memory", False) and isinstance(repo_map_payload, dict):
        payload["symbol_memory"] = build_symbol_memory_payload(repo_map_payload)
    if args.explain:
        payload["explain"] = build_auto_explain_payload(
            args,
            suggest_payload,
            build_payload,
            payload,
            root=root,
            root_arg=root_arg,
            repo_map_payload=repo_map_payload,
        )
    return payload, rc


def print_adaptive_k_text(payload: dict[str, Any]) -> None:
    adaptive = payload.get("adaptive_k")
    if not isinstance(adaptive, dict):
        return
    recommendation = (
        adaptive.get("recommendation", {})
        if isinstance(adaptive.get("recommendation"), dict)
        else {}
    )
    score_distribution = (
        adaptive.get("score_distribution", {})
        if isinstance(adaptive.get("score_distribution"), dict)
        else {}
    )
    budget_fit = adaptive.get("budget_fit", {}) if isinstance(adaptive.get("budget_fit"), dict) else {}
    policy = adaptive.get("policy", {}) if isinstance(adaptive.get("policy"), dict) else {}
    regression_gates = adaptive.get("regression_gates", {}) if isinstance(adaptive.get("regression_gates"), dict) else {}
    reason_codes = recommendation.get("reason_codes", [])
    if isinstance(reason_codes, list):
        reason_text = ",".join(str(item) for item in reason_codes[:5])
    else:
        reason_text = str(reason_codes)
    print(
        "adaptive-k: "
        f"recommended={adaptive.get('recommended_k', 0)}/{adaptive.get('requested_top', 0)} "
        f"policy={policy.get('name', 'balanced')} "
        f"gates={regression_gates.get('status', 'pass')} "
        f"candidates={score_distribution.get('candidate_count', 0)} "
        f"budget_limited={budget_fit.get('budget_limited', False)} "
        f"apply=false reasons={reason_text or 'none'}"
    )


def print_symbol_memory_text(payload: dict[str, Any]) -> None:
    symbol_memory = payload.get("symbol_memory")
    if not isinstance(symbol_memory, dict):
        return
    summary = symbol_memory.get("summary", {}) if isinstance(symbol_memory.get("summary"), dict) else {}
    verification = symbol_memory.get("source_verification", {}) if isinstance(symbol_memory.get("source_verification"), dict) else {}
    print(
        "symbol-memory: "
        f"symbols={summary.get('symbols', 0)} "
        f"graph_context={summary.get('graph_context', 0)} "
        f"retrieval_hints={summary.get('retrieval_hints', 0)} "
        f"verify_before_edits={str(verification.get('requires_exact_source_before_edits', True)).lower()}"
    )


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
    print_adaptive_k_text(payload)


def print_auto_text(payload: dict[str, Any]) -> None:
    print(
        f"context-guard-pack auto: {payload['sources']['suggested']} suggested source(s), "
        f"pack {payload['pack_bytes']}/{payload['budget_bytes']} bytes"
    )
    explain = payload.get("explain")
    if isinstance(explain, dict):
        summary = explain.get("summary", {}) if isinstance(explain.get("summary"), dict) else {}
        budget = explain.get("budget", {}) if isinstance(explain.get("budget"), dict) else {}
        print(
            "explain: "
            f"selected={summary.get('suggested', 0)} "
            f"included={summary.get('included', 0)} "
            f"partial={summary.get('partial', 0)} "
            f"omitted={summary.get('omitted', 0)} "
            f"budget={budget.get('pack_bytes', payload.get('pack_bytes', 0))}/{budget.get('budget_bytes', payload.get('budget_bytes', 0))} "
            "heuristic=local"
        )
        for item in (explain.get("selection", []) if isinstance(explain.get("selection"), list) else [])[:5]:
            if not isinstance(item, dict):
                continue
            lines = item.get("included_lines") or item.get("lines")
            if isinstance(lines, dict):
                line_text = f":{lines.get('start')}:{lines.get('end')}"
            else:
                line_text = ""
            print(
                f"- {item.get('path')}{line_text} "
                f"status={item.get('build_status', 'unknown')} "
                f"score={item.get('score', item.get('priority', 0))} "
                f"reason={item.get('reason', 'local heuristic')}"
            )
        omissions = explain.get("omissions", []) if isinstance(explain.get("omissions"), list) else []
        if omissions:
            reason_counts: dict[str, int] = {}
            for item in omissions:
                if not isinstance(item, dict):
                    continue
                reason = str(item.get("reason", "unknown"))
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
            reason_text = ", ".join(f"{reason}={count}" for reason, count in sorted(reason_counts.items()))
            print(f"omitted reasons: {reason_text}")
    print_adaptive_k_text(payload)
    print_symbol_memory_text(payload)
    if payload.get("manifest_path"):
        print(f"manifest: {payload['manifest_path']}")
    if payload.get("pack_path"):
        print(f"pack: {payload['pack_path']}")
    else:
        print()
        sys.stdout.write(str(payload["build"]["pack"]))


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
    suggest.add_argument("--adaptive-k", action="store_true", help="include local score/budget top-k advisory metadata without changing the manifest")
    suggest.add_argument("--adaptive-k-policy", choices=ADAPTIVE_K_POLICIES, default="balanced", help="local adaptive-k recommendation policy used when --adaptive-k is set")
    suggest.add_argument("--adaptive-k-min-recall-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum recall proxy gate for --adaptive-k")
    suggest.add_argument("--adaptive-k-min-precision-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum precision proxy gate for --adaptive-k")
    suggest.add_argument("--json", action="store_true", help="emit JSON payload")
    auto = sub.add_parser("auto", help="suggest a context pack manifest and build the budgeted pack in one local step")
    auto.add_argument("--root", default=".", help="project root; must not be a symlink")
    auto.add_argument("--query", default="", help="task or question to match against local files")
    auto.add_argument("--diff", help="git diff range, or staged/worktree, to seed changed-file ranges")
    auto.add_argument("--files", "--file", dest="files", action="append", help="explicit relative file path(s), comma-separated or repeated")
    auto.add_argument("--output", action="append", help="relative path to sanitized command output text under root")
    auto.add_argument("--test-output", action="append", help="relative path to sanitized test output text under root")
    auto.add_argument("--budget-bytes", type=int, default=DEFAULT_BUDGET_BYTES)
    auto.add_argument("--top", type=int, default=DEFAULT_SUGGEST_TOP, help="maximum suggested sources")
    auto.add_argument("--context-lines", type=int, default=DEFAULT_SUGGEST_CONTEXT_LINES, help="line context around diff/output hits")
    auto.add_argument("--manifest-out", help="write the suggested build manifest to this relative path under root")
    auto.add_argument("--pack-out", help="write the built Markdown pack to this relative path under root")
    auto.add_argument("--json", action="store_true", help="emit JSON payload")
    auto.add_argument("--no-artifact", action="store_true", help="do not write .context-guard/packs receipt")
    auto.add_argument("--explain", action="store_true", help="include deterministic local selection/build explanation metadata")
    auto.add_argument("--adaptive-k", action="store_true", help="include local score/budget top-k advisory metadata without changing the manifest or pack")
    auto.add_argument("--adaptive-k-policy", choices=ADAPTIVE_K_POLICIES, default="balanced", help="local adaptive-k recommendation policy used when --adaptive-k is set")
    auto.add_argument("--adaptive-k-min-recall-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum recall proxy gate for --adaptive-k")
    auto.add_argument("--adaptive-k-min-precision-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum precision proxy gate for --adaptive-k")
    auto.add_argument("--symbol-memory", action="store_true", help="include repo-map derived symbol/graph advisory metadata with exact source verification hints")
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
        if args.command == "auto":
            payload, rc = auto_pack(root, args, root_arg=str(args.root))
            if args.json:
                json.dump(payload, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                print_auto_text(payload)
            return rc
        raise PackError("unknown command")
    except PackError as exc:
        print(f"context-guard-pack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
