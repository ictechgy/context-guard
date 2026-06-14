#!/usr/bin/env python3
"""Store large sanitized command output outside Claude context and query slices later."""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import sys
import time
from typing import Iterable

DEFAULT_ARTIFACT_DIR = ".context-guard/artifacts"
LEGACY_ARTIFACT_DIR = ".claude-token-optimizer/artifacts"
DEFAULT_MAX_BYTES = 10_000_000
MAX_MAX_BYTES = 100_000_000
MAX_METADATA_BYTES = 64_000
DEFAULT_MAX_LINES = 80
DEFAULT_MAX_CHARS = 20_000
MAX_QUERY_LINES = 5_000
MAX_LINE_CHARS = 2_000
MAX_DIGEST_TEXT_CHARS = 360
MAX_DIGEST_TEXT_BYTES = 512
MAX_COMMAND_PREVIEW_BYTES = 2_048
MAX_TOP_ERROR_RECEIPTS = 12
MAX_DUPLICATE_GROUPS = 12
MAX_SUGGESTED_QUERIES = 12
SEARCH_SCHEMA_VERSION = "contextguard.artifact.search.v1"
OUTPUT_SANDBOX_SCHEMA_VERSION = "contextguard.artifact.output-sandbox.v1"
DEFAULT_SEARCH_MAX_ARTIFACTS = 100
MAX_SEARCH_MAX_ARTIFACTS = 1_000
DEFAULT_SEARCH_MAX_MATCHES = 40
MAX_SEARCH_MAX_MATCHES = 1_000
DEFAULT_SEARCH_CONTEXT_LINES = 1
MAX_SEARCH_CONTEXT_LINES = 20
DEFAULT_SEARCH_SNIPPET_CHARS = 360
MAX_SEARCH_SNIPPET_CHARS = 2_000
MAX_SEARCH_PATTERN_BYTES = 512
SEARCH_TRUNCATED_COUNT_UNKNOWN = "lower_bound"
ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
ERROR_RE = re.compile(
    r"(FAIL|FAILED|ERROR|Error:|Exception|Traceback|AssertionError|panic:|fatal:|"
    r"segmentation fault|not ok|\bE\s+assert|\[ERROR\]|✗|✖)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(Bearer\s+\S+|Basic\s+\S+|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd)[A-Za-z0-9_.-]*\s*[:=]\s*)\S+)"
)


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def cap_line(line: str, limit: int = MAX_LINE_CHARS) -> str:
    if len(line) <= limit:
        return line
    marker = f"...[line trimmed: {len(line)} chars]"
    return line[: max(0, limit - len(marker))] + marker


def cap_utf8_bytes(text: str, limit: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    marker = f"...[line trimmed: {len(text)} chars/{len(encoded)} bytes]"
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= limit:
        return marker_bytes[:limit].decode("utf-8", errors="ignore")
    keep = limit - len(marker_bytes)
    out: list[str] = []
    used = 0
    for char in text:
        char_bytes = char.encode("utf-8", errors="replace")
        if used + len(char_bytes) > keep:
            break
        out.append(char)
        used += len(char_bytes)
    return "".join(out) + marker


def cap_digest_text(text: str) -> str:
    return cap_utf8_bytes(cap_line(text, limit=MAX_DIGEST_TEXT_CHARS), MAX_DIGEST_TEXT_BYTES)


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
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


def compact_items(lines: Iterable[str], *, limit: int, max_chars: int = MAX_LINE_CHARS, max_bytes: int | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        item = cap_line(line.strip(), limit=max_chars)
        if max_bytes is not None:
            item = cap_utf8_bytes(item, max_bytes)
        if not item or item in seen:
            continue
        out.append(item)
        seen.add(item)
        if len(out) >= limit:
            break
    return out


class FallbackLineSanitizer:
    def __init__(self, *, show_paths: bool = False) -> None:
        self.show_paths = show_paths
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        def repl(match: re.Match[str]) -> str:
            groups = match.groups()
            if len(groups) >= 2 and groups[1]:
                return groups[1] + "[REDACTED]"
            return "[REDACTED]"

        line, count = SECRET_VALUE_RE.subn(repl, raw_line)
        if count:
            self.redactions += 1
        return line, bool(count)


def load_line_sanitizer(show_paths: bool) -> object:
    script_dir = Path(__file__).resolve().parent
    for name in ("sanitize_output.py", "context-guard-sanitize-output", "claude-sanitize-output"):
        candidate = script_dir / name
        if not candidate.exists():
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_claude_token_sanitize_{os.getpid()}", str(candidate))
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


def sanitize_one_line(text: str, *, show_paths: bool = False) -> str:
    sanitized, _ = sanitize_text(text + "\n", show_paths=show_paths)
    return cap_utf8_bytes(cap_line(" ".join(sanitized.strip().split())), MAX_COMMAND_PREVIEW_BYTES)


NO_FOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")
DIR_FD_OPEN_SUPPORTED = bool(os.supports_dir_fd and os.open in os.supports_dir_fd)
DIR_FD_MKDIR_SUPPORTED = bool(os.supports_dir_fd and os.mkdir in os.supports_dir_fd)
DIR_FD_STAT_SUPPORTED = bool(os.supports_dir_fd and os.stat in os.supports_dir_fd)
DIR_FD_UNLINK_SUPPORTED = bool(os.supports_dir_fd and os.unlink in os.supports_dir_fd)


def dir_fd_replace_supported() -> bool:
    # Some Python builds support src_dir_fd/dst_dir_fd for os.replace without
    # listing os.replace in os.supports_dir_fd, so use a signature/probe-light
    # check instead of os.supports_dir_fd membership.
    try:
        import inspect

        signature = inspect.signature(os.replace)
    except (TypeError, ValueError):
        return True
    return "src_dir_fd" in signature.parameters and "dst_dir_fd" in signature.parameters


DIR_FD_REPLACE_SUPPORTED = dir_fd_replace_supported()


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or str(exc) or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


def reject_parent_traversal(path: Path, *, label: str) -> None:
    if any(part == ".." for part in path.expanduser().parts):
        raise ValueError(f"{label} must not contain parent traversal")


def ensure_private_dir(path: Path) -> None:
    fd = open_private_directory_no_follow(path, label="artifact directory", create=True)
    try:
        try:
            os.fchmod(fd, 0o700)
        except OSError:
            pass
    finally:
        os.close(fd)


def reject_symlink_components(path: Path) -> None:
    path = normalize_allowed_first_absolute_symlink(path)
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise RuntimeError(f"refusing artifact path with symlink component: {current}")
        if not stat.S_ISDIR(st.st_mode) and current != path:
            raise RuntimeError(f"refusing artifact path through non-directory component: {current}")


def regular_private_file_size(path: Path) -> int:
    path = normalize_allowed_first_absolute_symlink(path)
    reject_symlink_components(path.parent)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"artifact file must not be a symlink: {path.name}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"artifact file must be a regular file: {path.name}")
    return int(st.st_size)


def read_bounded_private_text(path: Path, max_bytes: int) -> str:
    path = normalize_allowed_first_absolute_symlink(path)
    size = regular_private_file_size(path)
    if size > max_bytes:
        raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: {size} > {max_bytes}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"artifact file must be a regular file: {path.name}")
        if st.st_size > max_bytes:
            raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: {st.st_size} > {max_bytes}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"artifact file exceeds trusted size cap: {path.name}: > {max_bytes}")
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def no_follow_dir_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise RuntimeError("artifact writes require O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def temp_file_flags() -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise RuntimeError("artifact writes require O_NOFOLLOW support")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def open_private_directory_no_follow(path: Path, *, label: str, create: bool) -> int:
    reject_parent_traversal(path, label=label)
    path = normalize_allowed_first_absolute_symlink(path.expanduser())
    if not DIR_FD_OPEN_SUPPORTED:
        raise RuntimeError(f"{label} requires dir_fd open support")
    if create and not DIR_FD_MKDIR_SUPPORTED:
        raise RuntimeError(f"{label} requires dir_fd mkdir support")
    flags = no_follow_dir_flags()
    if path.is_absolute():
        current_fd = os.open(path.anchor or os.sep, os.O_RDONLY | (os.O_CLOEXEC if hasattr(os, "O_CLOEXEC") else 0))
        parts = path.parts[1:]
    else:
        current_fd = os.open(".", flags)
        parts = path.parts
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise RuntimeError(f"{label} must not contain parent traversal")
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=current_fd)
                next_fd = os.open(part, flags, dir_fd=current_fd)
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise RuntimeError(f"{label} must not traverse non-directory components")
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    except OSError as exc:
        raise RuntimeError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def precheck_artifact_leaf(parent_fd: int, leaf: str, *, label: str) -> None:
    if not DIR_FD_STAT_SUPPORTED:
        raise RuntimeError(f"{label} requires dir_fd stat support")
    try:
        st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError(f"{label} must be missing or a regular file")


def write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def fsync_required(fd: int, *, label: str, committed: bool = False) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        if committed:
            raise RuntimeError(f"committed_but_parent_fsync_failed: {os_error_detail(exc)}") from exc
        raise RuntimeError(f"could not fsync {label}: {os_error_detail(exc)}") from exc


def write_private_text(path: Path, text: str) -> None:
    reject_parent_traversal(path, label="artifact file")
    path = normalize_allowed_first_absolute_symlink(path.expanduser())
    if not DIR_FD_REPLACE_SUPPORTED:
        raise RuntimeError("artifact writes require dir_fd replace support")
    if not DIR_FD_UNLINK_SUPPORTED:
        raise RuntimeError("artifact writes require dir_fd unlink support")
    parent_fd = open_private_directory_no_follow(path.parent, label="artifact directory", create=True)
    try:
        os.fchmod(parent_fd, 0o700)
    except OSError:
        pass
    fd = -1
    temp_leaf: str | None = None
    try:
        leaf = path.name
        if leaf in {"", ".", ".."}:
            raise RuntimeError("artifact file must name a regular file")
        precheck_artifact_leaf(parent_fd, leaf, label="artifact file")
        for _attempt in range(20):
            candidate = f".{leaf}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(candidate, temp_file_flags(), 0o600, dir_fd=parent_fd)
                temp_leaf = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temp_leaf is None:
            raise RuntimeError("could not create temporary artifact file")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError("temporary artifact file must be a regular file")
        os.fchmod(fd, 0o600)
        write_all_fd(fd, text.encode("utf-8"))
        fsync_required(fd, label="artifact temp file")
        os.close(fd)
        fd = -1
        fsync_required(parent_fd, label="artifact directory before replace")
        os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_leaf = None
        fsync_required(parent_fd, label="artifact directory after replace", committed=True)
    except OSError as exc:
        raise RuntimeError(f"could not write artifact file: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temp_leaf is not None:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def read_bounded_stdin(max_bytes: int) -> tuple[str, bool, int]:
    data = sys.stdin.buffer.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated, len(data)


def artifact_paths(directory: Path, artifact_id: str) -> tuple[Path, Path]:
    if not ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError("artifact id must be 16-64 lowercase hex chars")
    reject_parent_traversal(directory, label="artifact directory")
    directory = normalize_allowed_first_absolute_symlink(directory)
    return directory / f"{artifact_id}.txt", directory / f"{artifact_id}.json"


def artifact_read_directories(raw_dir: str) -> list[Path]:
    """Return primary plus legacy read fallback for the default artifact dir.

    Rebranded ContextGuard stores new artifacts under `.context-guard/artifacts`,
    but users may still have receipts from the old `.claude-token-optimizer`
    default. Reads and listings include that legacy default so old receipts keep
    working; stores intentionally continue to use only the new path.
    """
    raw_path = Path(raw_dir).expanduser()
    reject_parent_traversal(raw_path, label="artifact directory")
    primary = normalize_allowed_first_absolute_symlink(raw_path)
    directories = [primary]
    if default_artifact_dir_requested(raw_dir):
        legacy = normalize_allowed_first_absolute_symlink(Path(LEGACY_ARTIFACT_DIR).expanduser())
        if legacy != primary:
            directories.append(legacy)
    return directories


def default_artifact_dir_requested(raw_dir: str) -> bool:
    return Path(raw_dir).expanduser() == Path(DEFAULT_ARTIFACT_DIR)


CONTENT_TYPE_VALUES = ("json", "diff", "log", "search", "code", "prose", "text")
# Recommended retrieval strategy per content type. Pattern-oriented payloads
# (logs, search hits, diffs) are best sliced by `--pattern`; structured or
# narrative payloads (json, code, prose) read best by `--lines`. Unknown/empty
# content falls back to a bounded `head` read.
STRATEGY_BY_CONTENT_TYPE = {
    "json": "lines",
    "code": "lines",
    "prose": "lines",
    "diff": "pattern",
    "log": "pattern",
    "search": "pattern",
    "text": "head",
}
_SEARCH_HIT_RE = re.compile(r"^[^\s:]+:\d+:")
_LOG_LINE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}|"
    r"\[(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\]|"
    r"(?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b)",
    re.IGNORECASE,
)
_CODE_LINE_RE = re.compile(
    r"^\s*(def |class |import |from \S+ import |function |const |let |var |"
    r"public |private |protected |#include|package |func |fn |impl |"
    r"return\b|if\s*\(|for\s*\(|while\s*\()"
)


def classify_content_type(text: str) -> str:
    """Classify stored content into one of CONTENT_TYPE_VALUES (advisory only).

    The classification is dependency-free and deterministic: identical input
    always yields the same label. It never influences redaction or storage; it
    only drives retrieval-strategy hints, so a wrong guess degrades to a less
    ergonomic (but still correct) retrieval suggestion. Empty input is "text".
    """
    stripped = text.strip()
    if not stripped:
        return "text"
    if stripped[0] in "{[":
        try:
            json.loads(stripped)
            return "json"
        except (ValueError, RecursionError):
            pass
    lines = stripped.splitlines()
    line_count = len(lines)
    majority = max(1, line_count // 2)
    diff_hits = sum(1 for line in lines if line.startswith(("diff --git ", "@@ ", "+++ ", "--- ", "index ")))
    if diff_hits and (lines[0].startswith(("diff --git ", "--- ", "@@ ")) or diff_hits >= 2):
        return "diff"
    # Log is checked before search because timestamps (HH:MM:SS) and bracketed
    # levels can superficially resemble the `path:line:` search shape.
    if sum(1 for line in lines if _LOG_LINE_RE.match(line)) >= majority:
        return "log"
    if sum(1 for line in lines if _SEARCH_HIT_RE.match(line)) >= majority:
        return "search"
    code_hits = sum(1 for line in lines if _CODE_LINE_RE.match(line))
    brace_lines = sum(1 for line in lines if line.rstrip().endswith(("{", "}", ";", "):")))
    if code_hits >= 2 or (code_hits >= 1 and brace_lines >= max(2, line_count // 3)):
        return "code"
    return "prose"


def recommended_strategy(content_type: str) -> str:
    """Map a content type to its default retrieval strategy hint (advisory)."""
    return STRATEGY_BY_CONTENT_TYPE.get(content_type, "head")


def first_error_anchor(text: str) -> str | None:
    """Return the first literal error token in text for a pattern hint, or None.

    The returned token is taken verbatim from ERROR_RE's match, so it is
    guaranteed to be an exact substring of the stored content. This makes the
    derived `--pattern` retrieval hint deterministic and exactly round-trippable.
    """
    for line in text.splitlines():
        match = ERROR_RE.search(line)
        if match:
            token = match.group(0).strip()
            if token:
                return token
    return None


def build_retrieval_hints(
    artifact_id: str,
    sanitized_text: str,
    *,
    content_type: str,
    strategy: str,
    total_lines: int,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> list[dict[str, object]]:
    """Build deterministic, machine-readable retrieval hints for bounded round-trip.

    Each hint pairs a `selector` (consumable by `query_content` / the `get` CLI)
    with the exact CLI invocation for that selector. The line-range hint spans
    the full stored content when it fits the query cap, otherwise it advertises
    the first bounded chunk only. The pattern hint, when present, targets a
    literal token guaranteed to exist, so retrieval is reproducible. Order is
    fixed (lines, pattern, head) for determinism; callers pick the hint whose
    `type` matches `strategy`.
    """
    hints: list[dict[str, object]] = []
    if total_lines >= 1:
        end_line = min(total_lines, MAX_QUERY_LINES)
        lines_hint: dict[str, object] = {
            "type": "lines",
            "selector": {"start": 1, "end": end_line},
            "cli": line_query_cli(artifact_id, 1, end_line, raw_dir=raw_dir, show_paths=show_paths),
            "exact": total_lines <= MAX_QUERY_LINES and artifact_dir_cli_is_exact(raw_dir, show_paths=show_paths),
        }
        if end_line > DEFAULT_MAX_LINES:
            lines_hint["max_lines"] = end_line
            lines_hint["max_lines_required"] = True
            lines_hint["note"] = (
                "`--max-lines` in this suggested query is only the returned-line cap for the selected "
                "`--lines` range; the explicit line range remains the selector."
            )
        if total_lines > MAX_QUERY_LINES:
            lines_hint["note"] = (
                f"first {MAX_QUERY_LINES} lines only; request later ranges for the full artifact. "
                "`--max-lines` is only the returned-line cap for the selected range."
            )
            lines_hint["total_lines"] = total_lines
        hints.append(lines_hint)
    anchor = first_error_anchor(sanitized_text)
    if anchor is not None:
        hints.append(
            {
                "type": "pattern",
                "selector": {"pattern": anchor},
                "cli": f"{artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)} get {artifact_id} --pattern {shlex.quote(anchor)}",
            }
        )
    hints.append(
        {
            "type": "head",
            "selector": {"max_lines": DEFAULT_MAX_LINES},
            "cli": f"{artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)} get {artifact_id} --max-lines {DEFAULT_MAX_LINES}",
        }
    )
    return hints


def artifact_dir_cli_prefix(raw_dir: str | None, *, show_paths: bool = False) -> str:
    if not raw_dir or default_artifact_dir_requested(raw_dir):
        return "context-guard-artifact"
    if not show_paths:
        return "context-guard-artifact --dir <artifact_dir>"
    return f"context-guard-artifact --dir {shlex.quote(raw_dir)}"


def artifact_dir_cli_is_exact(raw_dir: str | None, *, show_paths: bool = False) -> bool:
    return not raw_dir or default_artifact_dir_requested(raw_dir) or show_paths


def line_query_cli(
    artifact_id: str,
    start: int,
    end: int,
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> str:
    cli = f"{artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)} get {artifact_id} --lines {start}:{end}"
    requested_lines = end - start + 1
    if requested_lines > DEFAULT_MAX_LINES:
        cli += f" --max-lines {min(requested_lines, MAX_QUERY_LINES)}"
    return cli


def line_receipt(
    artifact_id: str,
    line_number: int,
    text: str,
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> dict[str, object]:
    return {
        "line": line_number,
        "text": cap_digest_text(text.strip()),
        "selector": {"type": "lines", "start": line_number, "end": line_number},
        "cli": line_query_cli(artifact_id, line_number, line_number, raw_dir=raw_dir, show_paths=show_paths),
    }


def build_top_error_receipts(
    artifact_id: str,
    lines: list[str],
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> list[dict[str, object]]:
    receipts: list[dict[str, object]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not ERROR_RE.search(line):
            continue
        text = cap_digest_text(line.strip())
        if not text or text in seen:
            continue
        receipt = line_receipt(artifact_id, line_number, text, raw_dir=raw_dir, show_paths=show_paths)
        receipts.append(receipt)
        seen.add(text)
        if len(receipts) >= MAX_TOP_ERROR_RECEIPTS:
            break
    return receipts


def build_duplicate_line_groups(
    artifact_id: str,
    lines: list[str],
    *,
    limit: int = MAX_DUPLICATE_GROUPS,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    first_line: dict[str, int] = {}
    for line_number, line in enumerate(lines, start=1):
        text = cap_digest_text(line.strip())
        if not text:
            continue
        if text not in counts:
            first_line[text] = line_number
            counts[text] = 0
        counts[text] += 1
    groups: list[dict[str, object]] = []
    for text, count in sorted(
        ((text, count) for text, count in counts.items() if count > 1),
        key=lambda item: (-item[1], first_line[item[0]], item[0]),
    )[:limit]:
        line_number = first_line[text]
        groups.append(
            {
                "count": count,
                "first_line": line_number,
                "text": text,
                "selector": {"type": "lines", "start": line_number, "end": line_number},
                "cli": line_query_cli(artifact_id, line_number, line_number, raw_dir=raw_dir, show_paths=show_paths),
            }
        )
    return groups


def build_digest(
    sanitized_text: str,
    *,
    artifact_id: str,
    redacted_lines: int,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> dict[str, object]:
    lines = sanitized_text.splitlines()
    top_errors = compact_items(
        (line for line in lines if ERROR_RE.search(line)),
        limit=12,
        max_chars=MAX_DIGEST_TEXT_CHARS,
        max_bytes=MAX_DIGEST_TEXT_BYTES,
    )
    return {
        "status": "has_errors" if top_errors else "stored",
        "redacted_lines": redacted_lines,
        "redaction_counts": {
            "lines": redacted_lines,
            "markers": sanitized_text.count("[REDACTED]"),
        },
        "top_error_lines": top_errors,
        "top_error_receipts": build_top_error_receipts(artifact_id, lines, raw_dir=raw_dir, show_paths=show_paths),
        "duplicate_line_groups": build_duplicate_line_groups(artifact_id, lines, raw_dir=raw_dir, show_paths=show_paths),
        "representative_head": compact_items(
            lines,
            limit=8,
            max_chars=MAX_DIGEST_TEXT_CHARS,
            max_bytes=MAX_DIGEST_TEXT_BYTES,
        ),
        "representative_tail": compact_items(
            lines[-8:],
            limit=8,
            max_chars=MAX_DIGEST_TEXT_CHARS,
            max_bytes=MAX_DIGEST_TEXT_BYTES,
        ),
    }


def suggested_queries_for(metadata: dict[str, object]) -> list[str]:
    queries: list[str] = []

    def add(value: object) -> None:
        if isinstance(value, str) and value and value not in queries:
            queries.append(value)

    digest = metadata.get("digest")
    if isinstance(digest, dict):
        for key in ("top_error_receipts", "duplicate_line_groups"):
            items = digest.get(key)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        add(item.get("cli"))

    retrieval = metadata.get("retrieval")
    if isinstance(retrieval, dict):
        hints = retrieval.get("hints")
        if isinstance(hints, list):
            for hint in hints:
                if isinstance(hint, dict):
                    add(hint.get("cli"))

    return queries[:MAX_SUGGESTED_QUERIES]


def artifact_handle(artifact_id: str) -> str:
    return f"contextguard-artifact:{artifact_id}"


def compact_stored_output(metadata: dict[str, object]) -> dict[str, object]:
    stored = metadata.get("stored_output")
    if not isinstance(stored, dict):
        return {}
    compact: dict[str, object] = {}
    for key in ("scope", "bytes", "lines", "sha256", "content_file", "metadata_file"):
        if key in stored:
            compact[key] = stored[key]
    content_type = metadata.get("content_type")
    if isinstance(content_type, str):
        compact["content_type"] = content_type
    return compact


def digest_count(digest: dict[str, object], key: str) -> int:
    value = digest.get(key)
    return len(value) if isinstance(value, list) else 0


def build_output_sandbox_summary(metadata: dict[str, object]) -> dict[str, object]:
    digest = metadata.get("digest")
    if not isinstance(digest, dict):
        return {"status": "stored"}
    summary: dict[str, object] = {
        "status": digest.get("status") or "stored",
        "top_error_count": digest_count(digest, "top_error_lines"),
        "top_error_receipt_count": digest_count(digest, "top_error_receipts"),
        "duplicate_line_group_count": digest_count(digest, "duplicate_line_groups"),
        "representative_head_count": digest_count(digest, "representative_head"),
        "representative_tail_count": digest_count(digest, "representative_tail"),
    }
    redaction_counts = digest.get("redaction_counts")
    if isinstance(redaction_counts, dict):
        summary["redaction_counts"] = {
            str(key): value
            for key, value in redaction_counts.items()
            if isinstance(value, (int, float, str, bool)) or value is None
        }
    elif "redacted_lines" in digest:
        summary["redacted_lines"] = digest.get("redacted_lines")
    capped = digest.get("capped_for_metadata")
    if isinstance(capped, bool):
        summary["capped_for_metadata"] = capped
    return summary


def rehydration_command_record(
    *,
    kind: str,
    cli: str,
    selector: dict[str, object],
    exact: bool,
    note: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "type": kind,
        "selector": selector,
        "cli": cli,
        "exact": exact,
    }
    if note:
        record["note"] = note
    return record


def build_output_sandbox_rehydration(
    metadata: dict[str, object],
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> dict[str, object]:
    artifact_id = str(metadata["artifact_id"])
    cli_exact = artifact_dir_cli_is_exact(raw_dir, show_paths=show_paths)
    prefix = artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)
    note = (
        None
        if cli_exact
        else "custom artifact directory is redacted; rerun with the same --dir value or pass --show-paths for a directly executable local command"
    )
    commands: list[dict[str, object]] = [
        rehydration_command_record(
            kind="metadata",
            selector={"type": "receipt"},
            cli=f"{prefix} receipt {artifact_id} --json",
            exact=cli_exact,
            note=note,
        )
    ]

    retrieval = metadata.get("retrieval")
    hints = retrieval.get("hints") if isinstance(retrieval, dict) else None
    if isinstance(hints, list):
        for hint in hints:
            if not isinstance(hint, dict):
                continue
            hint_type = hint.get("type")
            selector = hint.get("selector")
            if not isinstance(selector, dict):
                selector = {}
            cli: str | None = None
            exact = bool(hint.get("exact", True)) and cli_exact
            if hint_type == "lines":
                start = selector.get("start")
                end = selector.get("end")
                if isinstance(start, int) and isinstance(end, int):
                    cli = line_query_cli(artifact_id, start, end, raw_dir=raw_dir, show_paths=show_paths)
            elif hint_type == "pattern":
                pattern = selector.get("pattern")
                if isinstance(pattern, str) and pattern:
                    cli = f"{prefix} get {artifact_id} --pattern {shlex.quote(pattern)}"
            elif hint_type == "head":
                max_lines = selector.get("max_lines")
                if isinstance(max_lines, int) and max_lines > 0:
                    cli = f"{prefix} get {artifact_id} --max-lines {max_lines}"
            if cli is None:
                raw_cli = hint.get("cli")
                cli = raw_cli if isinstance(raw_cli, str) and raw_cli else None
            if cli:
                commands.append(
                    rehydration_command_record(
                        kind=str(hint_type or "query"),
                        selector=selector,
                        cli=cli,
                        exact=exact,
                        note=note if not cli_exact else str(hint.get("note") or "") or None,
                    )
                )
            if len(commands) >= 5:
                break

    digest = metadata.get("digest")
    top_error_lines = digest.get("top_error_lines") if isinstance(digest, dict) else None
    if isinstance(top_error_lines, list):
        anchor = first_error_anchor("\n".join(str(line) for line in top_error_lines))
        if anchor and len(commands) < 5:
            commands.append(
                rehydration_command_record(
                    kind="search",
                    selector={"type": "literal", "pattern": anchor},
                    cli=f"{prefix} search {shlex.quote(anchor)} --json",
                    exact=cli_exact,
                    note=note,
                )
            )

    return {
        "commands": commands,
        "dir_argument": "default" if default_artifact_dir_requested(raw_dir or DEFAULT_ARTIFACT_DIR) else ("included" if show_paths else "redacted"),
        "exact_commands": cli_exact,
        "note": note,
    }


def build_output_sandbox_envelope(
    metadata: dict[str, object],
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> dict[str, object]:
    artifact_id = str(metadata["artifact_id"])
    return {
        "schema_version": OUTPUT_SANDBOX_SCHEMA_VERSION,
        "mode": "local_artifact_receipt",
        "handle": artifact_handle(artifact_id),
        "artifact_id": artifact_id,
        "stored_output": compact_stored_output(metadata),
        "summary": build_output_sandbox_summary(metadata),
        "rehydration": build_output_sandbox_rehydration(metadata, raw_dir=raw_dir, show_paths=show_paths),
        "agent_guidance": [
            "Keep this compact receipt in agent context instead of pasting the full output.",
            "Before relying on omitted details, rehydrate the exact sanitized slice with one of rehydration.commands[].cli.",
            "For repeated diagnostics, query narrower lines or literal matches instead of rerunning broad commands unchanged.",
        ],
        "claim_boundary": {
            "local_only": True,
            "stored_content_is_sanitized_copy": True,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
            "exact_rehydration_required_before_relying_on_omitted_detail": True,
        },
    }


def receipt_for(
    metadata: dict[str, object],
    *,
    raw_dir: str | None = None,
    show_paths: bool = False,
) -> dict[str, object]:
    artifact_id = str(metadata["artifact_id"])
    return {
        "artifact_id": artifact_id,
        "stored": True,
        "created_at": metadata.get("created_at"),
        "command_preview": metadata.get("command_preview"),
        "content_type": metadata.get("content_type"),
        "input": metadata.get("input"),
        "stored_output": metadata.get("stored_output"),
        "digest": metadata.get("digest"),
        "retrieval": metadata.get("retrieval"),
        "available_queries": [
            line_query_cli(artifact_id, 1, 80, raw_dir=raw_dir, show_paths=show_paths),
            f"{artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)} get {artifact_id} --pattern ERROR --max-lines 40",
            f"{artifact_dir_cli_prefix(raw_dir, show_paths=show_paths)} get {artifact_id} --json --lines 1:20",
        ],
        "suggested_queries": suggested_queries_for(metadata),
        "output_sandbox": build_output_sandbox_envelope(metadata, raw_dir=raw_dir, show_paths=show_paths),
    }


def metadata_json_text(metadata: dict[str, object]) -> str:
    return json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def metadata_size_bytes(metadata: dict[str, object]) -> int:
    return len(metadata_json_text(metadata).encode("utf-8", errors="replace"))


def metadata_cap_diagnostic(metadata: dict[str, object], *, stage: str) -> str:
    digest = metadata.get("digest")
    digest_counts: dict[str, int] = {}
    if isinstance(digest, dict):
        for key in (
            "representative_tail",
            "representative_head",
            "duplicate_line_groups",
            "top_error_lines",
            "top_error_receipts",
        ):
            value = digest.get(key)
            if isinstance(value, list):
                digest_counts[key] = len(value)
    counts_text = ",".join(f"{key}={value}" for key, value in digest_counts.items()) or "none"
    return (
        "artifact metadata exceeds trusted size cap before write: "
        f"metadata_bytes={metadata_size_bytes(metadata)} "
        f"metadata_cap_bytes={MAX_METADATA_BYTES} "
        f"stage={stage} "
        f"remaining_digest_items={counts_text}; "
        "authoritative artifact content was not written because the receipt would be unreadable"
    )


def shrink_digest_for_metadata_cap(metadata: dict[str, object]) -> None:
    """Keep stored metadata inside the trusted read cap before writing it.

    Digest fields are advisory receipts over the authoritative `.txt` artifact.
    If future fields or multi-byte text push metadata near the hard read cap,
    prefer dropping low-priority digest examples over writing a file that `get`
    and `list` will later reject as untrusted.
    """
    digest = metadata.get("digest")
    if not isinstance(digest, dict):
        if metadata_size_bytes(metadata) > MAX_METADATA_BYTES:
            raise ValueError(metadata_cap_diagnostic(metadata, stage="no_digest"))
        return
    if metadata_size_bytes(metadata) <= MAX_METADATA_BYTES:
        return

    digest["capped_for_metadata"] = True
    digest["metadata_cap_bytes"] = MAX_METADATA_BYTES
    shrink_order = (
        "representative_tail",
        "representative_head",
        "duplicate_line_groups",
        "top_error_lines",
        "top_error_receipts",
    )
    while metadata_size_bytes(metadata) > MAX_METADATA_BYTES:
        for key in shrink_order:
            items = digest.get(key)
            if isinstance(items, list) and items:
                items.pop()
                break
        else:
            raise ValueError(metadata_cap_diagnostic(metadata, stage="digest_shrink_exhausted"))


def store_command(args: argparse.Namespace) -> int:
    directory = normalize_allowed_first_absolute_symlink(Path(args.dir).expanduser())
    max_bytes = bounded_int(args.max_bytes, DEFAULT_MAX_BYTES, 1, MAX_MAX_BYTES)
    raw_text, input_truncated, input_bytes = read_bounded_stdin(max_bytes)
    sanitized_text, redacted_lines = sanitize_text(raw_text, show_paths=args.show_paths)
    content_bytes = len(sanitized_text.encode("utf-8", errors="replace"))
    content_sha = hashlib.sha256(sanitized_text.encode("utf-8", errors="replace")).hexdigest()
    command_preview = sanitize_one_line(args.command or "", show_paths=args.show_paths) if args.command else None
    id_basis = json.dumps(
        {
            "content_sha256": content_sha,
            "command_preview": command_preview,
            "input_truncated": input_truncated,
        },
        sort_keys=True,
    )
    artifact_id = hashlib.sha256(id_basis.encode("utf-8")).hexdigest()[:20]
    content_path, meta_path = artifact_paths(directory, artifact_id)
    total_lines = sanitized_text.count("\n") + (1 if sanitized_text and not sanitized_text.endswith("\n") else 0)
    content_type = classify_content_type(sanitized_text)
    strategy = recommended_strategy(content_type)
    metadata: dict[str, object] = {
        "artifact_id": artifact_id,
        "created_at": int(time.time()),
        "command_preview": command_preview,
        "content_type": content_type,
        "input": {
            "bytes_read": input_bytes,
            "truncated": input_truncated,
            "max_bytes": max_bytes,
        },
        "stored_output": {
            "bytes": content_bytes,
            "lines": total_lines,
            "sha256": content_sha,
            "content_file": content_path.name,
            "metadata_file": meta_path.name,
        },
        "digest": build_digest(
            sanitized_text,
            artifact_id=artifact_id,
            redacted_lines=redacted_lines,
            raw_dir=args.dir,
            show_paths=args.show_paths,
        ),
        "retrieval": {
            "strategy": strategy,
            "deterministic": True,
            "hints": build_retrieval_hints(
                artifact_id,
                sanitized_text,
                content_type=content_type,
                strategy=strategy,
                total_lines=total_lines,
                raw_dir=args.dir,
                show_paths=args.show_paths,
            ),
        },
    }
    shrink_digest_for_metadata_cap(metadata)
    write_private_text(content_path, sanitized_text)
    write_private_text(meta_path, metadata_json_text(metadata))
    receipt = receipt_for(metadata, raw_dir=args.dir, show_paths=args.show_paths)
    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"artifact_id={artifact_id}")
        sandbox = receipt.get("output_sandbox")
        handle = sandbox.get("handle") if isinstance(sandbox, dict) else artifact_handle(artifact_id)
        print(f"handle={handle}")
        stored = receipt["stored_output"]
        if isinstance(stored, dict):
            print(f"stored_output={stored.get('lines')} lines/{stored.get('bytes')} bytes")
        digest = receipt.get("digest")
        if isinstance(digest, dict) and digest.get("top_error_lines"):
            print("top_error_lines:")
            for line in digest["top_error_lines"]:  # type: ignore[index]
                print(f"- {line}")
        available_queries = receipt.get("available_queries")
        if isinstance(available_queries, list) and available_queries:
            print(f"query={available_queries[0]}")
        rehydration = sandbox.get("rehydration") if isinstance(sandbox, dict) else None
        commands = rehydration.get("commands") if isinstance(rehydration, dict) else None
        if isinstance(commands, list):
            for command in commands:
                if isinstance(command, dict) and command.get("type") != "metadata" and isinstance(command.get("cli"), str):
                    print(f"rehydrate={command['cli']}")
                    break
    return 0


def load_metadata(directory: Path, artifact_id: str) -> dict[str, object]:
    content_path, meta_path = artifact_paths(directory, artifact_id)
    try:
        regular_private_file_size(content_path)
        meta_text = read_bounded_private_text(meta_path, MAX_METADATA_BYTES)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"artifact not found: {artifact_id}")
    data = json.loads(meta_text)
    if not isinstance(data, dict) or data.get("artifact_id") != artifact_id:
        raise ValueError(f"artifact metadata mismatch: {artifact_id}")
    return data


def load_verified_artifact(directory: Path, artifact_id: str) -> tuple[dict[str, object], Path, str]:
    metadata = load_metadata(directory, artifact_id)
    content_path, _meta_path = artifact_paths(directory, artifact_id)
    stored_output = metadata.get("stored_output")
    expected_sha = stored_output.get("sha256") if isinstance(stored_output, dict) else None
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
        raise ValueError(f"artifact metadata missing stored_output sha256: {artifact_id}")
    expected_bytes = stored_output.get("bytes") if isinstance(stored_output, dict) else None
    if not isinstance(expected_bytes, int) or expected_bytes < 0 or expected_bytes > MAX_MAX_BYTES:
        raise ValueError(f"artifact metadata has invalid stored_output bytes: {artifact_id}")
    actual_size = regular_private_file_size(content_path)
    if actual_size != expected_bytes:
        raise ValueError(f"artifact content checksum mismatch: {artifact_id}")
    content = read_bounded_private_text(content_path, expected_bytes)
    actual_sha = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    if actual_sha != expected_sha:
        raise ValueError(f"artifact content checksum mismatch: {artifact_id}")
    return metadata, content_path, content


def parse_line_range(value: str | None) -> tuple[int, int] | None:
    if not value:
        return None
    match = re.fullmatch(r"(\d+)(?::(\d+))?", value.strip())
    if not match:
        raise ValueError("--lines must be START or START:END using 1-based inclusive line numbers")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start < 1 or end < start:
        raise ValueError("--lines must satisfy 1 <= START <= END")
    return start, end


def cap_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    marker = f"\n[context-guard-kit] artifact query capped: {len(text)} chars total\n"
    keep = max(0, max_chars - len(marker))
    return text[:keep].rstrip() + marker, True


def search_literal(value: str) -> str:
    if not value:
        raise ValueError("search pattern must not be empty")
    if "\x00" in value:
        raise ValueError("search pattern must not contain NUL bytes")
    size = len(value.encode("utf-8", errors="replace"))
    if size > MAX_SEARCH_PATTERN_BYTES:
        raise ValueError(f"search pattern exceeds {MAX_SEARCH_PATTERN_BYTES} bytes")
    return value


def safe_query_label(value: str) -> str:
    return sanitize_one_line(value, show_paths=False)


def artifact_dir_label(raw_dir: str) -> str:
    if default_artifact_dir_requested(raw_dir):
        return "default"
    return sanitize_one_line(raw_dir, show_paths=False)


def metadata_text_field(metadata: dict[str, object], key: str) -> str | None:
    value = metadata.get(key)
    if not isinstance(value, str):
        return None
    return sanitize_one_line(value, show_paths=False)


def metadata_content_type(metadata: dict[str, object]) -> str:
    value = metadata.get("content_type")
    return value if isinstance(value, str) and value in CONTENT_TYPE_VALUES else "text"


def metadata_candidate_paths(directory: Path, limit: int) -> tuple[list[Path], int, int]:
    candidates: list[Path] = []
    skipped = 0
    truncated_lower_bound = 0
    if limit <= 0:
        return candidates, skipped, 0
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                name = entry.name
                if not name.endswith(".json"):
                    continue
                if not ARTIFACT_ID_RE.fullmatch(name[:-5]):
                    skipped += 1
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
                if len(candidates) >= limit:
                    truncated_lower_bound += 1
                    break
                candidates.append(directory / name)
    except OSError:
        return candidates, skipped + 1, truncated_lower_bound
    return sorted(candidates), skipped, truncated_lower_bound


def search_match_record(
    *,
    artifact_id: str,
    line_number: int,
    lines: list[str],
    context_lines: int,
    snippet_chars: int,
    metadata: dict[str, object],
    raw_dir: str,
    show_paths: bool,
) -> dict[str, object]:
    start = max(1, line_number - context_lines)
    end = min(len(lines), line_number + context_lines)
    cli_exact = artifact_dir_cli_is_exact(raw_dir, show_paths=show_paths)

    def line_item(number: int) -> dict[str, object]:
        return {"line": number, "text": cap_line(lines[number - 1].rstrip("\n"), limit=snippet_chars)}

    return {
        "artifact_id": artifact_id,
        "line": line_number,
        "text": cap_line(lines[line_number - 1].rstrip("\n"), limit=snippet_chars),
        "context_before": [line_item(number) for number in range(start, line_number)],
        "context_after": [line_item(number) for number in range(line_number + 1, end + 1)],
        "content_type": metadata_content_type(metadata),
        "command_preview": metadata_text_field(metadata, "command_preview"),
        "retrieval": {
            "selector": {"type": "lines", "start": start, "end": end},
            "cli": line_query_cli(artifact_id, start, end, raw_dir=raw_dir, show_paths=show_paths),
            "exact": cli_exact,
            "dir_argument": "default" if default_artifact_dir_requested(raw_dir) else ("included" if show_paths else "redacted"),
            "note": (
                None
                if cli_exact
                else "custom artifact directory is redacted; rerun with the same --dir used for search, or pass search --show-paths to emit a directly executable local CLI"
            ),
        },
    }


def search_artifact_content(
    *,
    artifact_id: str,
    metadata: dict[str, object],
    content: str,
    literal: str,
    ignore_case: bool,
    context_lines: int,
    snippet_chars: int,
    remaining_matches: int,
    raw_dir: str,
    show_paths: bool,
) -> tuple[list[dict[str, object]], int]:
    lines = content.splitlines()
    needle = literal.casefold() if ignore_case else literal
    matches: list[dict[str, object]] = []
    matched_lines = 0
    for line_number, line in enumerate(lines, start=1):
        haystack = line.casefold() if ignore_case else line
        if needle not in haystack:
            continue
        matched_lines += 1
        if len(matches) >= remaining_matches:
            continue
        matches.append(
            search_match_record(
                artifact_id=artifact_id,
                line_number=line_number,
                lines=lines,
                context_lines=context_lines,
                snippet_chars=snippet_chars,
                metadata=metadata,
                raw_dir=raw_dir,
                show_paths=show_paths,
            )
        )
    return matches, matched_lines


def query_content(
    content: str,
    *,
    line_range: tuple[int, int] | None,
    pattern: str | None,
    max_lines: int,
    full: bool = False,
) -> tuple[str, dict[str, object]]:
    lines = content.splitlines(True)
    selected: list[tuple[int, str]] = []
    if full:
        selected = list(enumerate(lines, start=1))
        selector = {"type": "full"}
    elif line_range is not None:
        start, end = line_range
        selected = list(enumerate(lines[start - 1 : end], start=start))
        selector = {"type": "lines", "start": start, "end": end}
    elif pattern:
        selected = [(idx, line) for idx, line in enumerate(lines, start=1) if pattern in line]
        selector = {"type": "pattern", "pattern": pattern}
    else:
        selected = list(enumerate(lines[:max_lines], start=1))
        selector = {"type": "head", "max_lines": max_lines}
    total_matches = len(selected)
    if not full:
        selected = selected[:max_lines]
    text = "".join(line for _idx, line in selected)
    return text, {"selector": selector, "returned_lines": len(selected), "matched_lines": total_matches, "total_lines": len(lines)}


def get_command(args: argparse.Namespace) -> int:
    artifact_id = args.artifact_id
    full = bool(getattr(args, "full", False))
    try:
        if full and (args.lines or args.pattern or args.max_lines is not None):
            raise ValueError("--full cannot be combined with --lines, --pattern, or --max-lines")
        last_missing: FileNotFoundError | None = None
        for directory in artifact_read_directories(args.dir):
            try:
                metadata, _content_path, content = load_verified_artifact(directory, artifact_id)
                break
            except FileNotFoundError as exc:
                last_missing = exc
        else:
            if last_missing is not None:
                raise last_missing
            raise FileNotFoundError(f"artifact not found: {artifact_id}")
        stored_output = metadata.get("stored_output")
        expected_bytes = stored_output.get("bytes") if isinstance(stored_output, dict) else None
        if not isinstance(expected_bytes, int):
            raise ValueError(f"artifact metadata has invalid stored_output bytes: {artifact_id}")
        default_max_chars = max(DEFAULT_MAX_CHARS, expected_bytes) if full else DEFAULT_MAX_CHARS
        max_chars = bounded_int(args.max_chars, default_max_chars, 1, MAX_MAX_BYTES)
        line_range = parse_line_range(args.lines)
        if line_range is not None and args.max_lines is None:
            max_lines = min(line_range[1] - line_range[0] + 1, MAX_QUERY_LINES)
        else:
            max_lines = bounded_int(args.max_lines, DEFAULT_MAX_LINES, 1, MAX_QUERY_LINES)
        selected, query = query_content(content, line_range=line_range, pattern=args.pattern, max_lines=max_lines, full=full)
        selected, capped = cap_text(selected, max_chars)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1
    if args.json:
        payload = {
            "artifact_id": artifact_id,
            "content_type": metadata.get("content_type"),
            "query": query,
            "capped": capped,
            "content": selected,
            "stored_output": metadata.get("stored_output"),
            "retrieval": metadata.get("retrieval"),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        sys.stdout.write(selected)
    return 0


def receipt_command(args: argparse.Namespace) -> int:
    artifact_id = args.artifact_id
    try:
        last_missing: FileNotFoundError | None = None
        for directory in artifact_read_directories(args.dir):
            try:
                metadata, _content_path, _content = load_verified_artifact(directory, artifact_id)
                break
            except FileNotFoundError as exc:
                last_missing = exc
        else:
            if last_missing is not None:
                raise last_missing
            raise FileNotFoundError(f"artifact not found: {artifact_id}")
        receipt = receipt_for(metadata, raw_dir=args.dir, show_paths=bool(getattr(args, "show_paths", False)))
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        sandbox = receipt.get("output_sandbox")
        handle = sandbox.get("handle") if isinstance(sandbox, dict) else artifact_handle(artifact_id)
        print(f"artifact_id={artifact_id}")
        print(f"handle={handle}")
        stored = receipt.get("stored_output")
        if isinstance(stored, dict):
            print(f"stored_output={stored.get('lines')} lines/{stored.get('bytes')} bytes")
        rehydration = sandbox.get("rehydration") if isinstance(sandbox, dict) else None
        commands = rehydration.get("commands") if isinstance(rehydration, dict) else None
        if isinstance(commands, list):
            for command in commands[:4]:
                if isinstance(command, dict) and command.get("cli"):
                    print(f"rehydrate={command.get('cli')}")
        print("claim_boundary=local sanitized artifact; no hosted token/cost savings claim")
    return 0


def search_command(args: argparse.Namespace) -> int:
    try:
        literal = search_literal(args.pattern)
        max_artifacts = bounded_int(args.max_artifacts, DEFAULT_SEARCH_MAX_ARTIFACTS, 1, MAX_SEARCH_MAX_ARTIFACTS)
        max_matches = bounded_int(args.max_matches, DEFAULT_SEARCH_MAX_MATCHES, 1, MAX_SEARCH_MAX_MATCHES)
        context_lines = bounded_int(args.context_lines, DEFAULT_SEARCH_CONTEXT_LINES, 0, MAX_SEARCH_CONTEXT_LINES)
        snippet_chars = bounded_int(args.max_snippet_chars, DEFAULT_SEARCH_SNIPPET_CHARS, 1, MAX_SEARCH_SNIPPET_CHARS)
        ignore_case = bool(args.ignore_case)
        matches: list[dict[str, object]] = []
        seen: set[str] = set()
        scanned_artifacts = 0
        skipped_artifacts = 0
        total_matched_lines = 0
        meta_candidates_seen = 0
        scan_truncated = False
        scan_truncated_count = 0
        matched_artifact_ids: set[str] = set()

        for directory in artifact_read_directories(args.dir):
            remaining_candidates = max_artifacts - meta_candidates_seen
            if remaining_candidates <= 0:
                scan_truncated = True
                break
            try:
                reject_symlink_components(directory)
                directory_is_safe = directory.is_dir() and not directory.is_symlink()
            except RuntimeError:
                directory_is_safe = False
            if not directory_is_safe:
                continue
            meta_paths, skipped_candidates, truncated_candidates = metadata_candidate_paths(directory, remaining_candidates)
            skipped_artifacts += skipped_candidates
            if truncated_candidates:
                scan_truncated = True
                scan_truncated_count += truncated_candidates
            for meta_path in meta_paths:
                meta_candidates_seen += 1
                try:
                    data = json.loads(read_bounded_private_text(meta_path, MAX_METADATA_BYTES))
                except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                    skipped_artifacts += 1
                    continue
                artifact_id = str(data.get("artifact_id", "")) if isinstance(data, dict) else ""
                if not (isinstance(data, dict) and ARTIFACT_ID_RE.fullmatch(artifact_id)) or artifact_id in seen:
                    skipped_artifacts += 1
                    continue
                seen.add(artifact_id)
                if scanned_artifacts >= max_artifacts:
                    scan_truncated = True
                    scan_truncated_count += 1
                    continue
                try:
                    metadata, _content_path, content = load_verified_artifact(directory, artifact_id)
                except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                    skipped_artifacts += 1
                    continue
                scanned_artifacts += 1
                remaining = max(0, max_matches - len(matches))
                artifact_matches, artifact_match_count = search_artifact_content(
                    artifact_id=artifact_id,
                    metadata=metadata,
                    content=content,
                    literal=literal,
                    ignore_case=ignore_case,
                    context_lines=context_lines,
                    snippet_chars=snippet_chars,
                    remaining_matches=remaining,
                    raw_dir=args.dir,
                    show_paths=bool(getattr(args, "show_paths", False)),
                )
                if artifact_match_count:
                    matched_artifact_ids.add(artifact_id)
                total_matched_lines += artifact_match_count
                matches.extend(artifact_matches)
        payload = {
            "tool": "context-guard-artifact",
            "schema_version": SEARCH_SCHEMA_VERSION,
            "mode": "search",
            "query": {
                "label": safe_query_label(literal),
                "raw_pattern_stored": False,
                "literal": True,
                "ignore_case": ignore_case,
            },
            "artifact_dir": artifact_dir_label(args.dir),
            "scanned_artifacts": scanned_artifacts,
            "skipped_artifacts": skipped_artifacts,
            "matched_artifacts": len(matched_artifact_ids),
            "matched_lines": total_matched_lines,
            "metadata_candidates_scanned": meta_candidates_seen,
            "matches": matches,
            "matches_truncated_count": max(0, total_matched_lines - max_matches),
            "artifact_scan_truncated": scan_truncated,
            "artifact_scan_truncated_count": scan_truncated_count,
            "artifact_scan_truncated_count_mode": SEARCH_TRUNCATED_COUNT_UNKNOWN if scan_truncated else "exact",
            "limits": {
                "max_artifacts": max_artifacts,
                "max_matches": max_matches,
                "context_lines": context_lines,
                "max_snippet_chars": snippet_chars,
            },
            "sandbox": {
                "local_only": True,
                "workflow": ["store", "search", "get"],
                "exact_rehydration": "use matches[].retrieval.cli when exact=true; for redacted custom dirs, reuse the same --dir or opt into --show-paths",
            },
            "claim_boundary": {
                "local_only": True,
                "stored_content_is_sanitized_copy": True,
                "hosted_api_token_or_cost_savings_claim_allowed": False,
                "exact_rehydration_required_before_relying_on_omitted_detail": True,
            },
        }
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for item in payload["matches"]:
            if isinstance(item, dict):
                print(f"{item.get('artifact_id')}:{item.get('line')}: {item.get('text')}")
                retrieval = item.get("retrieval")
                if isinstance(retrieval, dict):
                    print(f"  rehydrate={retrieval.get('cli')}")
        if not payload["matches"]:
            print("no matches")
        elif payload["matches_truncated_count"]:
            print(f"matches_truncated_count={payload['matches_truncated_count']}")
    return 0


def list_command(args: argparse.Namespace) -> int:
    items: list[dict[str, object]] = []
    seen: set[str] = set()
    for directory in artifact_read_directories(args.dir):
        try:
            reject_symlink_components(directory)
            directory_is_safe = directory.is_dir() and not directory.is_symlink()
        except RuntimeError:
            directory_is_safe = False
        if not directory_is_safe:
            continue
        for meta_path in sorted(directory.glob("*.json")):
            try:
                data = json.loads(read_bounded_private_text(meta_path, MAX_METADATA_BYTES))
            except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
                continue
            artifact_id = str(data.get("artifact_id", "")) if isinstance(data, dict) else ""
            if isinstance(data, dict) and ARTIFACT_ID_RE.fullmatch(artifact_id) and artifact_id not in seen:
                items.append(receipt_for(data, raw_dir=args.dir, show_paths=False))
                seen.add(artifact_id)
    items.sort(key=lambda item: str(item.get("artifact_id", "")))
    if args.json:
        print(json.dumps({"artifacts": items}, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for item in items:
            stored = item.get("stored_output")
            if isinstance(stored, dict):
                print(f"{item['artifact_id']}\t{stored.get('lines')} lines\t{stored.get('bytes')} bytes")
            else:
                print(item["artifact_id"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Store sanitized large outputs as queryable local artifacts.")
    parser.add_argument("--dir", default=DEFAULT_ARTIFACT_DIR, help=f"artifact directory (default: {DEFAULT_ARTIFACT_DIR})")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    store = subparsers.add_parser("store", help="store stdin as a sanitized artifact and print a compact receipt")
    store.add_argument("--command", help="optional command label to sanitize into the receipt")
    store.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="maximum stdin bytes to read before truncating")
    store.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths instead of path hashes; local debugging only because private paths may be exposed",
    )
    store.add_argument("--json", action="store_true", help="emit receipt JSON")
    store.set_defaults(func=store_command)

    get = subparsers.add_parser("get", help="query a stored artifact")
    get.add_argument("artifact_id")
    get.add_argument("--lines", help="1-based inclusive line range, e.g. 10:40")
    get.add_argument("--pattern", help="literal substring filter")
    get.add_argument("--max-lines", type=int, default=None)
    get.add_argument("--full", action="store_true", help="return full stored artifact content; cannot be combined with selectors")
    get.add_argument("--max-chars", type=int, default=None)
    get.add_argument("--json", action="store_true", help="emit query JSON with content")
    get.set_defaults(func=get_command)

    receipt = subparsers.add_parser("receipt", help="print metadata-only receipt and rehydration handle for a stored artifact")
    receipt.add_argument("artifact_id")
    receipt.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw custom --dir values in rehydration commands; local debugging only because private paths may be exposed",
    )
    receipt.add_argument("--json", action="store_true", help="emit receipt JSON without artifact content")
    receipt.set_defaults(func=receipt_command)

    list_parser = subparsers.add_parser("list", help="list stored artifacts")
    list_parser.add_argument("--json", action="store_true", help="emit list JSON")
    list_parser.set_defaults(func=list_command)

    search = subparsers.add_parser("search", help="search stored sanitized artifacts by literal text")
    search.add_argument("pattern", help=f"literal substring to search for (max {MAX_SEARCH_PATTERN_BYTES} UTF-8 bytes)")
    search.add_argument("--ignore-case", action="store_true", help="case-insensitive literal search")
    search.add_argument("--context-lines", type=int, default=DEFAULT_SEARCH_CONTEXT_LINES, help=f"context lines around each match (default: {DEFAULT_SEARCH_CONTEXT_LINES})")
    search.add_argument("--max-artifacts", type=int, default=DEFAULT_SEARCH_MAX_ARTIFACTS, help=f"maximum artifacts to scan (default: {DEFAULT_SEARCH_MAX_ARTIFACTS})")
    search.add_argument("--max-matches", type=int, default=DEFAULT_SEARCH_MAX_MATCHES, help=f"maximum match records to return (default: {DEFAULT_SEARCH_MAX_MATCHES})")
    search.add_argument("--max-snippet-chars", type=int, default=DEFAULT_SEARCH_SNIPPET_CHARS, help=f"maximum characters per displayed line (default: {DEFAULT_SEARCH_SNIPPET_CHARS})")
    search.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw custom --dir values in rehydration commands; local debugging only because private paths may be exposed",
    )
    search.add_argument("--json", action="store_true", help="emit sandbox search JSON")
    search.set_defaults(func=search_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except (RuntimeError, ValueError) as exc:
        print(f"context-guard-artifact: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
