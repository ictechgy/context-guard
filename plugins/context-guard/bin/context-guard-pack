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
from collections import Counter, deque
import copy
import hashlib
import heapq
import importlib.machinery
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import shlex
import signal
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
ROLLING_DELTA_SAMPLE_BYTES = 65_536
ROLLING_DELTA_WINDOW_BYTES = 64
MAX_MANIFEST_BYTES = 1_000_000
MAX_LABEL_CHARS = 160
MAX_REASON_CHARS = 120
TOKEN_PROXY_CHARS_PER_TOKEN = 4
SUGGEST_SCHEMA_VERSION = "contextguard.pack-suggest.v1"
AUTO_SCHEMA_VERSION = "contextguard.pack-auto.v1"
AUTO_EXPLAIN_SCHEMA_VERSION = "contextguard.pack-auto-explain.v1"
REPO_MAP_SCHEMA_VERSION = "contextguard.pack-repo-map.v1"
ADAPTIVE_K_SCHEMA_VERSION = "contextguard.pack-adaptive-k.v1"
ADAPTIVE_K_APPLICATION_SCHEMA_VERSION = "contextguard.pack-adaptive-k-application.v1"
SYMBOL_MEMORY_SCHEMA_VERSION = "contextguard.pack-symbol-memory.v1"
GRAPH_APPLICATION_SCHEMA_VERSION = "contextguard.pack-graph-application.v1"
SELF_FINANCING_SELECTION_SCHEMA_VERSION = "contextguard.pack-self-financing-selection.v1"
SELECTION_PLAN_SCHEMA_VERSION = "contextguard.pack-selection-plan.v1"
CONTENT_ADDRESS_SCHEMA_VERSION = "contextguard.pack-content-address.v1"
ROLLING_DELTA_SCHEMA_VERSION = "contextguard.pack-rolling-delta.v1"
SKETCH_DUPLICATE_SHINGLE_WIDTH = 5
SKETCH_DUPLICATE_RETAINED_DIGESTS = 64
SKETCH_DUPLICATE_MIN_CARDINALITY = 12
SKETCH_DUPLICATE_THRESHOLD_NUMERATOR = 9
SKETCH_DUPLICATE_THRESHOLD_DENOMINATOR = 10
SKETCH_DUPLICATE_COMPARISON_CAP = 100_000
SKETCH_DUPLICATE_SHINGLE_DOMAIN = b"context-guard-pack/sketch-duplicate-veto/shingle/v1\x00"
SKETCH_DUPLICATE_TOKEN_RE = re.compile(r"\w+")
DEFAULT_SUGGEST_TOP = 8
MAX_SUGGEST_TOP = 50
DEFAULT_SUGGEST_CONTEXT_LINES = 20
MAX_SUGGEST_CONTEXT_LINES = 120
SUGGEST_WHOLE_FILE_MAX_LINES = 120
MAX_SUGGEST_INPUT_BYTES = 256_000
MAX_GIT_DIFF_STDERR_BYTES = 16_000
GIT_DIFF_TIMEOUT_SECONDS = 10.0
MAX_QUERY_SCAN_FILES = 2_000
MAX_QUERY_SCAN_BYTES_PER_FILE = 200_000
MAX_GIT_LS_FILES_OUTPUT_BYTES = MAX_QUERY_SCAN_FILES * 512
GIT_LS_FILES_READ_CHUNK_BYTES = 64 * 1024
MAX_GIT_ATTR_INPUT_BYTES = MAX_GIT_LS_FILES_OUTPUT_BYTES
MAX_GIT_ATTR_OUTPUT_BYTES = MAX_GIT_ATTR_INPUT_BYTES * 2
GIT_ATTR_TIMEOUT_SECONDS = 10.0
MAX_QUERY_WALK_DIRS = 2_000
MAX_QUERY_WALK_ENTRIES = 10_000
MAX_QUERY_WALK_DEPTH = 32
MAX_QUERY_WALK_SECONDS = 2.0
MAX_SOURCE_INPUT_BYTES = 4_000_000
MAX_SOURCE_INPUT_LINES = 100_000
MAX_SOURCE_LINE_BYTES = 256_000
MAX_TOTAL_SOURCE_INPUT_BYTES = 16_000_000
MAX_TOTAL_SOURCE_INPUT_LINES = 400_000
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
MAX_GRAPH_APPLICATION_SOURCES = 4
MAX_GRAPH_APPLICATION_LINES = 80
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
    sanitization_context: str = "source_code"


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
    total_lines_exact: bool = True
    input_bytes_read: int = 0
    input_lines_read: int = 0
    sanitized_through_line: int = 0
    input_limit_reason: str | None = None
    redacted_lines_exact: bool = True


@dataclass(frozen=True)
class _SourceScanResult:
    selected_lines: tuple[str, ...]
    total_lines: int
    redacted_lines: int
    total_lines_exact: bool
    input_bytes_read: int
    input_lines_read: int
    sanitized_through_line: int
    limit_reason: str | None
    selection_complete: bool
    redacted_lines_exact: bool


@dataclass(frozen=True)
class _SourceSnapshot:
    identity: tuple[int, int, int, int, int, int, int, int]
    display_path: str
    redacted_path: bool
    requested_lines: LineRange
    selected_lines: tuple[str, ...]
    total_lines: int
    redacted_lines: int
    total_lines_exact: bool
    input_bytes_read: int
    input_lines_read: int
    sanitized_through_line: int
    input_limit_reason: str | None
    redacted_lines_exact: bool


class _SourceInputBudget:
    def __init__(self) -> None:
        self.bytes_read = 0
        self.lines_read = 0
        self.bytes_attempted = 0
        self.lines_attempted = 0
        self.bytes_charged = 0
        self.lines_charged = 0
        self.capped = (
            MAX_TOTAL_SOURCE_INPUT_BYTES <= 0
            or MAX_TOTAL_SOURCE_INPUT_LINES <= 0
        )

    def remaining_bytes(self) -> int:
        return max(0, MAX_TOTAL_SOURCE_INPUT_BYTES - self.bytes_charged)

    def remaining_lines(self) -> int:
        return max(0, MAX_TOTAL_SOURCE_INPUT_LINES - self.lines_charged)

    def record_read(self, bytes_count: int) -> str | None:
        bytes_remaining = self.remaining_bytes()
        lines_remaining = self.remaining_lines()
        self.bytes_read += bytes_count
        self.lines_read += 1
        self.bytes_attempted += bytes_count
        self.lines_attempted += 1
        self.bytes_charged = min(
            MAX_TOTAL_SOURCE_INPUT_BYTES,
            self.bytes_charged + bytes_count,
        )
        self.lines_charged = min(
            MAX_TOTAL_SOURCE_INPUT_LINES,
            self.lines_charged + 1,
        )
        self.capped = (
            self.bytes_charged >= MAX_TOTAL_SOURCE_INPUT_BYTES
            or self.lines_charged >= MAX_TOTAL_SOURCE_INPUT_LINES
        )
        if lines_remaining <= 0:
            return "cumulative_input_lines_exceeded"
        if bytes_count > bytes_remaining:
            return "cumulative_input_bytes_exceeded"
        return None


class _SourceSnapshotCache:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, str, str], _SourceSnapshot] = {}

    @staticmethod
    def key(rel: Path, requested: LineRange | None, context: str) -> tuple[str, str, str]:
        return (rel.as_posix(), requested.identity() if requested is not None else "all", context)


@dataclass
class _PairedCandidate:
    source: ResolvedSource
    canonical: dict[str, Any]


@dataclass(frozen=True)
class _DuplicateSignature:
    exact_digest: bytes
    sketch: frozenset[bytes] | None


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


SANITIZATION_CONTEXTS = frozenset(
    {
        "unknown_text",
        "command_search_diff",
        "filesystem_listing",
        "source_code",
    }
)


def parse_sanitization_context(value: object) -> str:
    context = str(value or "unknown_text")
    if context not in SANITIZATION_CONTEXTS:
        raise PackError(f"unsupported sanitization context: {context}")
    return context


class FallbackLineSanitizer:
    def __init__(
        self,
        *,
        show_paths: bool = False,
        context: str = "unknown_text",
    ) -> None:
        self.show_paths = show_paths
        self.context = context
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
                sys.modules[loader.name] = module
                try:
                    loader.exec_module(module)
                except Exception:
                    sys.modules.pop(loader.name, None)
                    raise
                _LINE_SANITIZER_FACTORY_CACHE = module.LineSanitizer
                return _LINE_SANITIZER_FACTORY_CACHE
            except Exception as exc:
                raise RuntimeError(f"could not load sanitizer {candidate}: {exc}") from exc
        _LINE_SANITIZER_FACTORY_CACHE = FallbackLineSanitizer
        return _LINE_SANITIZER_FACTORY_CACHE


def instantiate_line_sanitizer(
    factory: Any,
    *,
    show_paths: bool,
    context: str,
    private_roots: tuple[str, ...] = (),
) -> object:
    try:
        return factory(
            show_paths=show_paths,
            context=context,
            private_roots=private_roots,
        )
    except TypeError:
        if context != "unknown_text" or private_roots:
            raise RuntimeError(
                "adjacent sanitizer does not support required explicit context"
            )
        return factory(show_paths=show_paths)


def load_line_sanitizer(
    show_paths: bool = False,
    context: str = "unknown_text",
    private_roots: tuple[str, ...] = (),
) -> object:
    sanitizer_factory = load_line_sanitizer_factory()
    return instantiate_line_sanitizer(
        sanitizer_factory,
        show_paths=show_paths,
        context=context,
        private_roots=private_roots,
    )


def sanitize_text(
    text: str,
    *,
    show_paths: bool = False,
    context: str = "unknown_text",
    private_roots: tuple[str, ...] = (),
) -> tuple[str, int]:
    sanitizer = load_line_sanitizer(
        show_paths,
        context=context,
        private_roots=private_roots,
    )
    redacted = 0
    out: list[str] = []
    for line in text.splitlines(True):
        sanitized, did_redact = sanitizer.sanitize(line)  # type: ignore[attr-defined]
        out.append(sanitized)
        if did_redact:
            redacted += 1
    return "".join(out), redacted


def sanitize_source_lines(
    handle: Any,
    requested: LineRange | None,
    *,
    context: str = "source_code",
    private_roots: tuple[str, ...] = (),
) -> tuple[list[str], int, int]:
    """Compatibility wrapper for the bounded source scanner."""
    scan = _scan_source_lines(
        handle,
        requested,
        context=context,
        private_roots=private_roots,
        input_budget=_SourceInputBudget(),
    )
    return list(scan.selected_lines), scan.total_lines, scan.redacted_lines


def _scan_source_lines(
    handle: Any,
    requested: LineRange | None,
    *,
    context: str,
    private_roots: tuple[str, ...],
    input_budget: _SourceInputBudget,
    expected_size_bytes: int | None = None,
) -> _SourceScanResult:
    """Read with byte/line caps and sanitize only the required prefix.

    Stateful sanitizers still see every line through ``requested.end``. The
    remaining tail is counted without invoking the sanitizer so range requests
    do not pay sanitizer cost for irrelevant content. If counting reaches a
    cap, the selected range remains usable and the total is explicitly marked
    as a lower bound.
    """
    sanitizer = load_line_sanitizer(
        context=context,
        private_roots=private_roots,
    )
    selected: list[str] = []
    redacted = 0
    total_lines = 0
    input_bytes = 0
    input_lines = 0
    collect_all = requested is None
    start = requested.start if requested is not None else 1
    end = requested.end if requested is not None else 0
    total_lines_exact = False
    limit_reason: str | None = None
    redacted_lines_exact = True
    iterator = None if callable(getattr(handle, "readline", None)) else iter(handle)

    while True:
        boundary_reason: str | None = None
        if total_lines >= MAX_SOURCE_INPUT_LINES:
            boundary_reason = "source_input_lines_exceeded"
        elif input_budget.remaining_lines() <= 0:
            boundary_reason = "cumulative_input_lines_exceeded"
        source_remaining = MAX_SOURCE_INPUT_BYTES - input_bytes
        cumulative_remaining = input_budget.remaining_bytes()
        if boundary_reason is None and source_remaining <= 0:
            boundary_reason = "source_input_bytes_exceeded"
        elif boundary_reason is None and cumulative_remaining <= 0:
            boundary_reason = "cumulative_input_bytes_exceeded"
        if boundary_reason is not None:
            if expected_size_bytes is not None:
                try:
                    if handle.tell() == expected_size_bytes:
                        total_lines_exact = True
                        break
                except (AttributeError, OSError):
                    pass
            limit_reason = boundary_reason
            break
        read_char_cap = min(MAX_SOURCE_LINE_BYTES, source_remaining, cumulative_remaining)
        try:
            if iterator is None:
                raw_line = handle.readline(read_char_cap + 1)
            else:
                raw_line = next(iterator, "")
        except (OSError, UnicodeError):
            limit_reason = "unsafe_path"
            break
        if raw_line == "":
            total_lines_exact = True
            break
        raw_bytes = byte_len(raw_line)
        cumulative_reason = input_budget.record_read(raw_bytes)
        input_bytes += raw_bytes
        input_lines += 1
        if len(raw_line) > MAX_SOURCE_LINE_BYTES or raw_bytes > MAX_SOURCE_LINE_BYTES:
            limit_reason = "source_line_bytes_exceeded"
            break
        if raw_bytes > source_remaining:
            limit_reason = "source_input_bytes_exceeded"
            break
        if cumulative_reason is not None:
            limit_reason = cumulative_reason
            break
        total_lines += 1

        must_sanitize = collect_all or total_lines <= end
        if must_sanitize:
            sanitized, did_redact = sanitizer.sanitize(raw_line)  # type: ignore[attr-defined]
            if did_redact:
                redacted += 1
            if collect_all or start <= total_lines <= end:
                selected.append(sanitized)
        else:
            redacted_lines_exact = False
            if SECRET_CONTENT_RE.search(raw_line):
                redacted += 1

    selection_complete = (
        total_lines_exact
        if collect_all
        else total_lines >= end or (total_lines_exact and total_lines >= start)
    )
    sanitized_through = total_lines if collect_all else min(total_lines, end)
    return _SourceScanResult(
        selected_lines=tuple(selected),
        total_lines=total_lines,
        redacted_lines=redacted,
        total_lines_exact=total_lines_exact,
        input_bytes_read=input_bytes,
        input_lines_read=input_lines,
        sanitized_through_line=sanitized_through,
        limit_reason=limit_reason,
        selection_complete=selection_complete,
        redacted_lines_exact=redacted_lines_exact,
    )


def byte_len(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def token_proxy(text: str) -> int:
    if not text:
        return 0
    return max(1, round(len(text) / TOKEN_PROXY_CHARS_PER_TOKEN))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sketch_duplicate_shingle_digest(tokens: tuple[str, ...]) -> bytes:
    if len(tokens) != SKETCH_DUPLICATE_SHINGLE_WIDTH:
        raise ValueError("sketch duplicate shingles require exactly five tokens")
    digest = hashlib.sha256()
    digest.update(SKETCH_DUPLICATE_SHINGLE_DOMAIN)
    for token in tokens:
        encoded = token.encode("utf-8", errors="strict")
        digest.update(len(encoded).to_bytes(8, "big", signed=False))
        digest.update(encoded)
    return digest.digest()


def _retain_bottom_sketch_digest(heap: list[tuple[int, bytes]], retained: set[bytes], digest: bytes) -> None:
    if digest in retained:
        return
    number = int.from_bytes(digest, "big", signed=False)
    if len(heap) < SKETCH_DUPLICATE_RETAINED_DIGESTS:
        heapq.heappush(heap, (-number, digest))
        retained.add(digest)
        return
    largest = heap[0][1]
    if digest >= largest:
        return
    _negative, removed = heapq.heapreplace(heap, (-number, digest))
    retained.remove(removed)
    retained.add(digest)


def _sketch_duplicate_signature(lines: list[str], *, include_sketch: bool) -> _DuplicateSignature:
    exact = hashlib.sha256()
    if not include_sketch:
        for line in lines:
            exact.update(line.encode("utf-8", errors="replace"))
        return _DuplicateSignature(exact.digest(), None)

    token_window: deque[str] = deque(maxlen=SKETCH_DUPLICATE_SHINGLE_WIDTH)
    heap: list[tuple[int, bytes]] = []
    retained: set[bytes] = set()
    for line in lines:
        exact.update(line.encode("utf-8", errors="replace"))
        for match in SKETCH_DUPLICATE_TOKEN_RE.finditer(line.casefold()):
            token_window.append(match.group(0))
            if len(token_window) == SKETCH_DUPLICATE_SHINGLE_WIDTH:
                digest = _sketch_duplicate_shingle_digest(tuple(token_window))
                _retain_bottom_sketch_digest(heap, retained, digest)
    return _DuplicateSignature(exact.digest(), frozenset(retained))


def _sanitized_source_bytes_equal(left: ResolvedSource, right: ResolvedSource) -> bool:
    if len(left.selected_lines) != len(right.selected_lines):
        return False
    return all(
        left_line.encode("utf-8", errors="replace") == right_line.encode("utf-8", errors="replace")
        for left_line, right_line in zip(left.selected_lines, right.selected_lines)
    )


def _sketch_sets_match(left: frozenset[bytes], right: frozenset[bytes]) -> bool:
    intersection = len(left & right)
    union = len(left) + len(right) - intersection
    return (
        union > 0
        and SKETCH_DUPLICATE_THRESHOLD_DENOMINATOR * intersection
        >= SKETCH_DUPLICATE_THRESHOLD_NUMERATOR * union
    )


def _ordered_sketch_winner_ids(
    sketch: frozenset[bytes],
    postings: dict[bytes, list[int]],
) -> Any:
    heap: list[tuple[int, int, int, list[int]]] = []
    for ordinal, digest in enumerate(sorted(sketch)):
        winner_ids = postings.get(digest)
        if winner_ids:
            heapq.heappush(heap, (winner_ids[0], ordinal, 0, winner_ids))
    last_yielded: int | None = None
    while heap:
        winner_id, ordinal, index, winner_ids = heapq.heappop(heap)
        next_index = index + 1
        if next_index < len(winner_ids):
            heapq.heappush(heap, (winner_ids[next_index], ordinal, next_index, winner_ids))
        if winner_id != last_yielded:
            last_yielded = winner_id
            yield winner_id


def _sketch_duplicate_omission(source: ResolvedSource, *, root_arg: str) -> dict[str, Any]:
    requested = source.requested_lines or LineRange(1, source.total_lines)
    item = omission(
        source.spec,
        "sketch_duplicate_source",
        path=source.display_path,
        redacted_path=source.redacted_path,
    )
    item["requested_lines"] = requested.as_dict()
    retrieval, retrieval_omitted_reason = retrieval_for(
        root_arg,
        source.display_path,
        requested,
        redacted_path=source.redacted_path,
    )
    if retrieval:
        item["retrieval_cli"] = retrieval
        item.pop("retrieval_omitted_reason", None)
    elif retrieval_omitted_reason:
        item["retrieval_omitted_reason"] = retrieval_omitted_reason
    return item


def _apply_sketch_duplicate_veto(
    candidates: list[_PairedCandidate],
    omitted: list[dict[str, Any]],
    *,
    root_arg: str,
) -> tuple[list[ResolvedSource], bool]:
    winners: list[_PairedCandidate] = []
    exact_winners: dict[bytes, list[int]] = {}
    winner_sketches: dict[int, frozenset[bytes]] = {}
    postings: dict[bytes, list[int]] = {}
    comparisons_remaining = SKETCH_DUPLICATE_COMPARISON_CAP
    comparison_cap_reached = False

    for candidate in candidates:
        signature = _sketch_duplicate_signature(
            candidate.source.selected_lines,
            include_sketch=not comparison_cap_reached,
        )
        duplicate = False
        for winner_id in exact_winners.get(signature.exact_digest, ()):
            if _sanitized_source_bytes_equal(candidate.source, winners[winner_id].source):
                duplicate = True
                break

        skipped_pair = False
        sketch = signature.sketch
        if (
            not duplicate
            and not comparison_cap_reached
            and sketch is not None
            and len(sketch) >= SKETCH_DUPLICATE_MIN_CARDINALITY
        ):
            for winner_id in _ordered_sketch_winner_ids(sketch, postings):
                if comparisons_remaining == 0:
                    comparison_cap_reached = True
                    skipped_pair = True
                    sketch = None
                    break
                comparisons_remaining -= 1
                if _sketch_sets_match(sketch, winner_sketches[winner_id]):
                    duplicate = True
                    break

        if duplicate:
            candidate.canonical["status"] = "sketch_duplicate_source"
            omitted.append(_sketch_duplicate_omission(candidate.source, root_arg=root_arg))
            continue

        winner_id = len(winners)
        winners.append(candidate)
        exact_winners.setdefault(signature.exact_digest, []).append(winner_id)
        if (
            not skipped_pair
            and not comparison_cap_reached
            and sketch is not None
            and len(sketch) >= SKETCH_DUPLICATE_MIN_CARDINALITY
        ):
            winner_sketches[winner_id] = sketch
            for digest in sketch:
                postings.setdefault(digest, []).append(winner_id)

    return [candidate.source for candidate in winners], comparison_cap_reached


def pack_id_arg(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{20}", value) is None:
        raise argparse.ArgumentTypeError("PACK_ID must be exactly 20 lowercase hexadecimal characters")
    return value


def content_address(digest: str, bytes_count: int) -> dict[str, Any]:
    return {
        "schema_version": CONTENT_ADDRESS_SCHEMA_VERSION,
        "id": f"sha256:{digest}",
        "algorithm": "sha256",
        "digest": digest,
        "bytes": bytes_count,
    }


def rolling_sample_metadata(body: bytes) -> dict[str, Any]:
    sampled_bytes = min(len(body), ROLLING_DELTA_SAMPLE_BYTES)
    if sampled_bytes == 0:
        window_count = 0
    elif sampled_bytes < ROLLING_DELTA_WINDOW_BYTES:
        window_count = 1
    else:
        window_count = sampled_bytes - ROLLING_DELTA_WINDOW_BYTES + 1
    return {
        "total_bytes": len(body),
        "sampled_bytes": sampled_bytes,
        "window_count": window_count,
        "truncated": len(body) > ROLLING_DELTA_SAMPLE_BYTES,
    }


def rolling_window_multiset(body: bytes) -> Counter[bytes]:
    sample = body[:ROLLING_DELTA_SAMPLE_BYTES]
    if not sample:
        return Counter()
    if len(sample) < ROLLING_DELTA_WINDOW_BYTES:
        return Counter((hashlib.sha256(sample).digest(),))
    return Counter(
        hashlib.sha256(sample[index:index + ROLLING_DELTA_WINDOW_BYTES]).digest()
        for index in range(len(sample) - ROLLING_DELTA_WINDOW_BYTES + 1)
    )


def rolling_delta_algorithm() -> dict[str, Any]:
    return {
        "name": "sha256_sliding_window_multiset",
        "window_bytes": ROLLING_DELTA_WINDOW_BYTES,
        "stride_bytes": 1,
        "max_sample_bytes_per_pack": ROLLING_DELTA_SAMPLE_BYTES,
    }


def rolling_delta_claim_boundary() -> dict[str, bool]:
    return {
        "diagnostic_only": True,
        "changes_manifest_selection_or_pack": False,
        "provider_token_or_cost_savings_claim_allowed": False,
    }


def build_rolling_delta(
    current_pack: str,
    previous_pack: str,
    previous_pack_id: str,
    current_address: str,
) -> dict[str, Any]:
    current_body = current_pack.encode("utf-8")
    previous_body = previous_pack.encode("utf-8")
    current_meta = rolling_sample_metadata(current_body)
    previous_meta = rolling_sample_metadata(previous_body)
    current_windows = rolling_window_multiset(current_body)
    previous_windows = rolling_window_multiset(previous_body)
    matched = sum((current_windows & previous_windows).values())
    current_count = current_meta["window_count"]
    previous_count = previous_meta["window_count"]
    both_empty = current_count == 0 and previous_count == 0
    if both_empty:
        current_ratio = 1.0
        previous_ratio = 1.0
    else:
        current_ratio = round(matched / current_count, 6) if current_count else 0.0
        previous_ratio = round(matched / previous_count, 6) if previous_count else 0.0
    return {
        "schema_version": ROLLING_DELTA_SCHEMA_VERSION,
        "status": "partial" if current_meta["truncated"] or previous_meta["truncated"] else "available",
        "previous_pack_id": previous_pack_id,
        "current_content_address": current_address,
        "previous_content_address": f"sha256:{hashlib.sha256(previous_body).hexdigest()}",
        "algorithm": rolling_delta_algorithm(),
        "current": current_meta,
        "previous": previous_meta,
        "matched_window_count": matched,
        "current_reuse_ratio_proxy": current_ratio,
        "previous_retention_ratio_proxy": previous_ratio,
        "reason": None,
        "claim_boundary": rolling_delta_claim_boundary(),
    }


def unavailable_rolling_delta(
    current_pack: str,
    previous_pack_id: str,
    current_address: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": ROLLING_DELTA_SCHEMA_VERSION,
        "status": "unavailable",
        "previous_pack_id": previous_pack_id,
        "current_content_address": current_address,
        "previous_content_address": None,
        "algorithm": rolling_delta_algorithm(),
        "current": rolling_sample_metadata(current_pack.encode("utf-8")),
        "previous": {"total_bytes": 0, "sampled_bytes": 0, "window_count": 0, "truncated": False},
        "matched_window_count": 0,
        "current_reuse_ratio_proxy": 0.0,
        "previous_retention_ratio_proxy": 0.0,
        "reason": reason,
        "claim_boundary": rolling_delta_claim_boundary(),
    }


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
            sanitization_context=parse_sanitization_context(
                item.get("sanitization_context", item.get("context"))
            ),
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
        sanitization_context=parse_sanitization_context(
            values.get("sanitization_context", values.get("context"))
        ),
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


def _open_source_identity(handle: Any) -> tuple[int, int, int, int, int, int, int, int] | None:
    try:
        st = os.fstat(handle.fileno())
    except (AttributeError, OSError):
        return None
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_uid,
        st.st_nlink,
        st.st_size,
        int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        int(getattr(st, "st_ctime_ns", int(st.st_ctime * 1_000_000_000))),
    )


def _input_limit_metadata(reason: str) -> dict[str, Any]:
    caps = {
        "source_line_bytes_exceeded": ("source_line_bytes", MAX_SOURCE_LINE_BYTES),
        "source_input_bytes_exceeded": ("source_bytes", MAX_SOURCE_INPUT_BYTES),
        "source_input_lines_exceeded": ("source_lines", MAX_SOURCE_INPUT_LINES),
        "cumulative_input_bytes_exceeded": ("cumulative_bytes", MAX_TOTAL_SOURCE_INPUT_BYTES),
        "cumulative_input_lines_exceeded": ("cumulative_lines", MAX_TOTAL_SOURCE_INPUT_LINES),
    }
    kind, cap = caps.get(reason, ("unknown", 0))
    return {"kind": kind, "cap_bytes" if "bytes" in kind else "cap_lines": cap}


def _snapshot_to_source(
    snapshot: _SourceSnapshot,
    *,
    root: Path,
    rel: Path,
    spec: SourceSpec,
) -> ResolvedSource:
    return ResolvedSource(
        spec=spec,
        abs_path=root / rel,
        display_path=snapshot.display_path,
        redacted_path=snapshot.redacted_path,
        requested_lines=spec.lines or snapshot.requested_lines,
        selected_lines=list(snapshot.selected_lines),
        total_lines=snapshot.total_lines,
        redacted_lines=snapshot.redacted_lines,
        total_lines_exact=snapshot.total_lines_exact,
        input_bytes_read=snapshot.input_bytes_read,
        input_lines_read=snapshot.input_lines_read,
        sanitized_through_line=snapshot.sanitized_through_line,
        input_limit_reason=snapshot.input_limit_reason,
        redacted_lines_exact=snapshot.redacted_lines_exact,
    )


def resolve_source(
    root: Path,
    spec: SourceSpec,
    *,
    source_cache: _SourceSnapshotCache | None = None,
    input_budget: _SourceInputBudget | None = None,
    expected_identity: tuple[int, int, int, int, int, int, int, int] | None = None,
    require_cached: bool = False,
) -> tuple[ResolvedSource | None, dict[str, Any] | None]:
    if spec.lines is not None and spec.lines.start < 1:
        return None, omission(spec, "invalid_lines")
    rel, reason = lexical_rel(spec.path)
    if rel is None:
        return None, omission(spec, reason)
    display, redacted_path = display_rel_path(rel.as_posix())
    handle, reason = open_regular_under_root(root, rel)
    if handle is None:
        return None, omission(spec, reason, path=display, redacted_path=redacted_path)
    scan_budget = input_budget if input_budget is not None else _SourceInputBudget()
    requested = spec.lines
    cache_key = _SourceSnapshotCache.key(rel, requested, spec.sanitization_context)
    try:
        with handle:
            before_identity = _open_source_identity(handle)
            if expected_identity is not None and before_identity != expected_identity:
                return None, omission(
                    spec,
                    "graph_source_changed_since_repo_map_snapshot",
                    path=display,
                    redacted_path=redacted_path,
                )
            cached = source_cache.entries.get(cache_key) if source_cache is not None else None
            if require_cached and cached is None:
                return None, omission(
                    spec,
                    "graph_source_snapshot_unavailable",
                    path=display,
                    redacted_path=redacted_path,
                )
            if cached is not None:
                if before_identity != cached.identity:
                    return None, omission(
                        spec,
                        "source_changed_during_auto",
                        path=display,
                        redacted_path=redacted_path,
                    )
                source = _snapshot_to_source(cached, root=root, rel=rel, spec=spec)
                if _open_source_identity(handle) != before_identity:
                    return None, omission(
                        spec,
                        "source_changed_during_auto",
                        path=display,
                        redacted_path=redacted_path,
                    )
                return source, None
            scan = _scan_source_lines(
                handle,
                requested,
                context=spec.sanitization_context,
                private_roots=(
                    (str(root),)
                    if spec.sanitization_context == "filesystem_listing"
                    else ()
                ),
                input_budget=scan_budget,
                expected_size_bytes=before_identity[5] if before_identity is not None else None,
            )
            after_identity = _open_source_identity(handle)
    except OSError:
        return None, omission(spec, "unsafe_path", path=display, redacted_path=redacted_path)
    if before_identity is not None and after_identity != before_identity:
        return None, omission(spec, "source_changed_during_read", path=display, redacted_path=redacted_path)
    if scan.limit_reason == "unsafe_path":
        return None, omission(spec, "unsafe_path", path=display, redacted_path=redacted_path)
    if scan.limit_reason is not None and not scan.selection_complete:
        item = omission(spec, scan.limit_reason, path=display, redacted_path=redacted_path)
        item["input_limit"] = _input_limit_metadata(scan.limit_reason)
        item["input_observed"] = {
            "bytes": scan.input_bytes_read,
            "lines": scan.input_lines_read,
            "bytes_attempted": scan.input_bytes_read,
            "lines_attempted": scan.input_lines_read,
            "capped": True,
        }
        return None, item
    selected = list(scan.selected_lines)
    total_lines = scan.total_lines
    redacted_lines = scan.redacted_lines
    if total_lines <= 0:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    requested = requested or LineRange(1, total_lines)
    if scan.total_lines_exact and requested.start > total_lines:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    if not selected:
        return None, omission(spec, "empty_source", path=display, redacted_path=redacted_path)
    source = ResolvedSource(
        spec=spec,
        abs_path=root / rel,
        display_path=display,
        redacted_path=redacted_path,
        requested_lines=requested,
        selected_lines=selected,
        total_lines=total_lines,
        redacted_lines=redacted_lines,
        total_lines_exact=scan.total_lines_exact,
        input_bytes_read=scan.input_bytes_read,
        input_lines_read=scan.input_lines_read,
        sanitized_through_line=scan.sanitized_through_line,
        input_limit_reason=scan.limit_reason,
        redacted_lines_exact=scan.redacted_lines_exact,
    )
    if source_cache is not None and before_identity is not None:
        snapshot = _SourceSnapshot(
            identity=before_identity,
            display_path=display,
            redacted_path=redacted_path,
            requested_lines=requested,
            selected_lines=tuple(selected),
            total_lines=total_lines,
            redacted_lines=redacted_lines,
            total_lines_exact=scan.total_lines_exact,
            input_bytes_read=scan.input_bytes_read,
            input_lines_read=scan.input_lines_read,
            sanitized_through_line=scan.sanitized_through_line,
            input_limit_reason=scan.limit_reason,
            redacted_lines_exact=scan.redacted_lines_exact,
        )
        source_cache.entries[cache_key] = snapshot
        canonical_key = _SourceSnapshotCache.key(rel, source_selected_range(source), spec.sanitization_context)
        source_cache.entries[canonical_key] = snapshot
    return source, None


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


def markdown_metadata_text(value: object) -> str:
    out: list[str] = []
    for char in str(value):
        code = ord(char)
        if not char.isprintable():
            out.append(f"\\u{code:04X}" if code <= 0xFFFF else f"\\U{code:08X}")
        elif char == "&":
            out.append("&amp;")
        elif char == "<":
            out.append("&lt;")
        elif char == ">":
            out.append("&gt;")
        elif char in {"[", "]", "(", ")", "!"}:
            out.append("\\" + char)
        elif char in {"`", "\\"}:
            out.append("\\" + char)
        else:
            out.append(char)
    return "".join(out)


def markdown_inline_code(value: object) -> str:
    text = "".join(
        (f"\\u{ord(char):04X}" if ord(char) <= 0xFFFF else f"\\U{ord(char):08X}")
        if not char.isprintable()
        else char
        for char in str(value)
    )
    max_run = max((len(match.group(0)) for match in re.finditer(r"`+", text)), default=0)
    delimiter = "`" * max(1, max_run + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"


def markdown_block_delimiters(lines: list[str]) -> tuple[str, str]:
    max_run = 0
    for line in lines:
        line_max = max((len(match.group(0)) for match in re.finditer(r"`+", line)), default=0)
        max_run = max(max_run, line_max)
    fence = "`" * max(3, max_run + 1)
    return f"\n\n{fence}text\n", f"{fence}\n\n"


def render_block_header(source: ResolvedSource, *, root_arg: str, status: str, included: LineRange) -> str:
    title = markdown_metadata_text(source.spec.label or source.display_path)
    requested = source.requested_lines or LineRange(1, source.total_lines)
    retrieval, retrieval_omitted_reason = retrieval_for(root_arg, source.display_path, included, redacted_path=source.redacted_path)
    header = [
        f"## {title}",
        f"Source: {markdown_inline_code(source.display_path)}",
        f"Priority: {source.spec.priority}",
        f"Status: {status}",
        f"Included lines: {included.start}:{included.end}",
        f"Requested lines: {requested.start}:{requested.end}",
    ]
    if retrieval:
        header.append(f"Retrieval: {markdown_inline_code(retrieval)}")
    elif retrieval_omitted_reason:
        header.append(f"Retrieval omitted: {retrieval_omitted_reason}")
    return "\n".join(header)


def render_block(source: ResolvedSource, lines: list[str], *, root_arg: str, status: str, included: LineRange) -> str:
    block_open, block_close = markdown_block_delimiters(lines)
    return render_block_header(source, root_arg=root_arg, status=status, included=included) + block_open + "".join(lines) + ("" if not lines or lines[-1].endswith("\n") else "\n") + block_close


def source_input_metadata(source: ResolvedSource) -> dict[str, Any]:
    item: dict[str, Any] = {
        "bytes_read": source.input_bytes_read,
        "lines_read": source.input_lines_read,
        "bytes_attempted": source.input_bytes_read,
        "lines_attempted": source.input_lines_read,
        "capped": source.input_limit_reason is not None,
        "total_lines_exact": source.total_lines_exact,
        "truncated": not source.total_lines_exact,
        "sanitized_through_line": source.sanitized_through_line,
        "redacted_lines_exact": source.redacted_lines_exact,
        "limits": {
            "source_bytes": MAX_SOURCE_INPUT_BYTES,
            "source_lines": MAX_SOURCE_INPUT_LINES,
            "source_line_bytes": MAX_SOURCE_LINE_BYTES,
            "cumulative_bytes": MAX_TOTAL_SOURCE_INPUT_BYTES,
            "cumulative_lines": MAX_TOTAL_SOURCE_INPUT_LINES,
        },
    }
    if source.total_lines_exact:
        item["total_lines"] = source.total_lines
    else:
        item["total_lines_lower_bound"] = source.total_lines
    if source.input_limit_reason is not None:
        item["limit_reason"] = source.input_limit_reason
    return item


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
    item["input"] = source_input_metadata(source)
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
    if source.total_lines_exact:
        item["total_lines"] = source.total_lines
    else:
        item["total_lines_lower_bound"] = source.total_lines
    item["input"] = source_input_metadata(source)
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
    block_open, block_close = markdown_block_delimiters(source.selected_lines[:line_count])
    return byte_len(render_block_header(source, root_arg=root_arg, status=status, included=included)) + byte_len(block_open) + body_bytes + byte_len(block_close)


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


class ReceiptJSONError(ValueError):
    pass


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptJSONError("duplicate key")
        result[key] = value
    return result


def reject_json_constant(_value: str) -> Any:
    raise ReceiptJSONError("non-finite number")


def parse_receipt_int(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > 20:
        raise ReceiptJSONError("integer too large")
    return int(value)


def json_depth(value: Any, depth: int = 1) -> int:
    if depth > 100:
        raise ReceiptJSONError("maximum depth exceeded")
    if isinstance(value, dict):
        for item in value.values():
            json_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            json_depth(item, depth + 1)
    return depth


def prior_read_capabilities_available() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "geteuid")
        and os.open in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_follow_symlinks", set())
    )


def private_receipt_stat_safe(st: os.stat_result, *, directory: bool) -> bool:
    expected_mode = 0o700 if directory else 0o600
    expected_type = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    return (
        expected_type
        and st.st_uid == os.geteuid()
        and stat.S_IMODE(st.st_mode) == expected_mode
        and (directory or st.st_nlink == 1)
    )


def stat_identity(st: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size)


def read_previous_receipt(root: Path, requested_id: str) -> tuple[str | None, str | None]:
    if not prior_read_capabilities_available():
        return None, "previous_receipt_unsafe"
    current_fd: int | None = None
    file_fd: int | None = None
    parent_stats: list[os.stat_result] = []
    try:
        current_fd = open_dir_no_follow(root)
        for part in (".context-guard", "packs"):
            try:
                next_fd = open_dir_no_follow(part, dir_fd=current_fd)
            except FileNotFoundError:
                return None, "previous_receipt_not_found"
            except (OSError, PackError, NotImplementedError):
                return None, "previous_receipt_unsafe"
            os.close(current_fd)
            current_fd = next_fd
            try:
                parent_stat = os.fstat(current_fd)
            except OSError:
                return None, "previous_receipt_unsafe"
            parent_stats.append(parent_stat)

        filename = f"{requested_id}.json"
        try:
            before = os.stat(filename, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, "previous_receipt_not_found"
        except (OSError, NotImplementedError):
            return None, "previous_receipt_unsafe"
        unsafe_parent = any(not private_receipt_stat_safe(item, directory=True) for item in parent_stats)
        if unsafe_parent or not private_receipt_stat_safe(before, directory=False):
            return None, "previous_receipt_unsafe"
        if before.st_size > MAX_RECEIPT_BYTES:
            return None, "previous_receipt_too_large"

        flags = os.O_RDONLY | os.O_NOFOLLOW
        for name in ("O_CLOEXEC", "O_NONBLOCK", "O_NOCTTY"):
            flags |= getattr(os, name, 0)
        try:
            file_fd = os.open(filename, flags, dir_fd=current_fd)
        except FileNotFoundError:
            return None, "previous_receipt_invalid"
        except (OSError, NotImplementedError):
            return None, "previous_receipt_unsafe"
        opened = os.fstat(file_fd)
        if not private_receipt_stat_safe(opened, directory=False):
            return None, "previous_receipt_unsafe"
        if opened.st_size > MAX_RECEIPT_BYTES:
            return None, "previous_receipt_too_large"
        chunks: list[bytes] = []
        observed = 0
        while observed < MAX_RECEIPT_BYTES + 1:
            chunk = os.read(file_fd, min(16 * 1024, MAX_RECEIPT_BYTES + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        try:
            path_after = os.stat(filename, dir_fd=current_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None, "previous_receipt_invalid"
        except (OSError, NotImplementedError):
            return None, "previous_receipt_unsafe"
        if not private_receipt_stat_safe(after, directory=False) or not private_receipt_stat_safe(path_after, directory=False):
            return None, "previous_receipt_unsafe"
        if len(raw) > MAX_RECEIPT_BYTES or after.st_size > MAX_RECEIPT_BYTES or path_after.st_size > MAX_RECEIPT_BYTES:
            return None, "previous_receipt_too_large"
        identities = (stat_identity(before), stat_identity(opened), stat_identity(after), stat_identity(path_after))
        if len(set(identities)) != 1 or len(raw) != after.st_size:
            return None, "previous_receipt_invalid"
    except OSError:
        return None, "previous_receipt_unsafe"
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if current_fd is not None:
            try:
                os.close(current_fd)
            except OSError:
                pass

    try:
        receipt = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=strict_json_object,
            parse_constant=reject_json_constant,
            parse_int=parse_receipt_int,
        )
        json_depth(receipt)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "previous_receipt_invalid"
    if not isinstance(receipt, dict):
        return None, "previous_receipt_invalid"
    prior_id = receipt.get("pack_id")
    prior_bytes = receipt.get("pack_bytes")
    pack_present = "pack" in receipt
    address_present = "content_address" in receipt
    prior_pack = receipt.get("pack")
    prior_address = receipt.get("content_address")
    if not isinstance(prior_id, str) or re.fullmatch(r"[0-9a-f]{20}", prior_id) is None:
        return None, "previous_receipt_invalid"
    if not isinstance(prior_bytes, int) or isinstance(prior_bytes, bool) or prior_bytes < 0:
        return None, "previous_receipt_invalid"
    if pack_present and not isinstance(prior_pack, str):
        return None, "previous_receipt_invalid"
    if address_present and not isinstance(prior_address, dict):
        return None, "previous_receipt_invalid"
    if prior_id != requested_id:
        return None, "previous_pack_integrity_mismatch"
    if not pack_present:
        if receipt.get("pack_omitted_from_receipt") is True:
            return None, "previous_pack_body_unavailable"
        return None, "previous_receipt_invalid"
    assert isinstance(prior_pack, str)
    try:
        prior_body = prior_pack.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None, "previous_receipt_invalid"
    digest = hashlib.sha256(prior_body).hexdigest()
    if len(prior_body) != prior_bytes:
        return None, "previous_pack_integrity_mismatch"
    if address_present and prior_address != content_address(digest, prior_bytes):
        return None, "previous_pack_integrity_mismatch"
    return prior_pack, None


def rolling_delta_from_receipt(
    root: Path,
    current_pack: str,
    previous_pack_id: str,
    current_address: str,
) -> dict[str, Any]:
    previous_pack, reason = read_previous_receipt(root, previous_pack_id)
    if reason is not None or previous_pack is None:
        return unavailable_rolling_delta(current_pack, previous_pack_id, current_address, reason or "previous_receipt_invalid")
    return build_rolling_delta(current_pack, previous_pack, previous_pack_id, current_address)


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


def build_pack(
    root: Path,
    specs: list[SourceSpec],
    *,
    budget_bytes: int,
    root_arg: str,
    store_artifact: bool,
    delta_from_pack_id: str | None = None,
    sketch_duplicate_veto: bool = False,
    _source_cache: _SourceSnapshotCache | None = None,
    _input_budget: _SourceInputBudget | None = None,
    _required_snapshot_sources: set[tuple[str, str]] | None = None,
    _expected_source_identities: dict[str, tuple[int, int, int, int, int, int, int, int]] | None = None,
    _snapshot_rejections: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    input_budget = _input_budget if _input_budget is not None else _SourceInputBudget()
    seen: set[tuple[str, str]] = set()
    resolved: list[ResolvedSource] = []
    paired_candidates: list[_PairedCandidate] = []
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
        rel_path = rel.as_posix() if rel is not None else ""
        require_cached = bool(
            _required_snapshot_sources
            and (rel_path, identity_lines) in _required_snapshot_sources
        )
        expected_identity = (
            _expected_source_identities.get(rel_path)
            if require_cached and _expected_source_identities is not None
            else None
        )
        if require_cached and expected_identity is None:
            display, redacted = display_rel_path(rel_path)
            omitted_item = omission(
                spec,
                "graph_source_not_in_repo_map_snapshot",
                path=display,
                redacted_path=redacted,
            )
            omitted.append(omitted_item)
            canonical_specs.append({
                "path": display,
                "priority": spec.priority,
                "lines": identity_lines,
                "status": omitted_item.get("reason"),
            })
            continue
        cached_rejection = (
            _snapshot_rejections.get((rel_path, identity_lines))
            if require_cached and _snapshot_rejections is not None
            else None
        )
        if cached_rejection is not None:
            omitted_item = copy.deepcopy(cached_rejection)
            omitted.append(omitted_item)
            canonical_specs.append({
                "path": omitted_item.get("path"),
                "priority": spec.priority,
                "lines": identity_lines,
                "status": omitted_item.get("reason"),
            })
            continue
        source, omitted_item = resolve_source(
            root,
            spec,
            source_cache=_source_cache,
            input_budget=input_budget,
            expected_identity=expected_identity,
            require_cached=require_cached,
        )
        if omitted_item is not None:
            omitted.append(omitted_item)
            canonical_specs.append({"path": omitted_item.get("path"), "priority": spec.priority, "lines": identity_lines, "status": omitted_item.get("reason")})
            continue
        assert source is not None
        resolved.append(source)
        canonical = {"path": source.display_path, "priority": spec.priority, "lines": identity_lines, "status": "candidate"}
        canonical_specs.append(canonical)
        paired_candidates.append(_PairedCandidate(source, canonical))
    paired_candidates.sort(key=lambda item: (-item.source.spec.priority, item.source.spec.input_index, item.source.display_path))
    all_resolved = resolved
    comparison_cap_reached = False
    if sketch_duplicate_veto:
        resolved, comparison_cap_reached = _apply_sketch_duplicate_veto(
            paired_candidates,
            omitted,
            root_arg=root_arg,
        )
    else:
        resolved = [item.source for item in paired_candidates]
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
    pack_digest = sha256_text(pack)
    redacted_lines = sum(source.redacted_lines for source in all_resolved)
    partial_count = sum(1 for item in included if item.get("status") == "partial")
    omitted_sorted = sorted(omitted, key=lambda item: (item.get("input_index", 0), str(item.get("path", "")), str(item.get("reason", ""))))
    canonical = {
        "version": VERSION,
        "root": display_root(root),
        "budget_bytes": budget_bytes,
        "sources": canonical_specs,
        "pack_sha256": pack_digest,
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
        "content_address": content_address(pack_digest, pack_bytes),
        "token_proxy": {"measurement": "estimated", "method": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}", "pack": token_proxy(pack)},
        "sources": {"total": len(specs), "included": len(included) - partial_count, "partial": partial_count, "omitted": len(omitted_sorted)},
        "included_sources": included,
        "omitted_sources": omitted_sorted,
        "redaction": {
            "redacted_lines": redacted_lines,
            "redacted_lines_exact": all(source.redacted_lines_exact for source in all_resolved),
            "redacted_before_pack": True,
        },
        "input": {
            "bytes_read": input_budget.bytes_read,
            "lines_read": input_budget.lines_read,
            "bytes_attempted": input_budget.bytes_attempted,
            "lines_attempted": input_budget.lines_attempted,
            "bytes_charged": input_budget.bytes_charged,
            "lines_charged": input_budget.lines_charged,
            "capped": input_budget.capped,
            "limits": {
                "source_bytes": MAX_SOURCE_INPUT_BYTES,
                "source_lines": MAX_SOURCE_INPUT_LINES,
                "source_line_bytes": MAX_SOURCE_LINE_BYTES,
                "cumulative_bytes": MAX_TOTAL_SOURCE_INPUT_BYTES,
                "cumulative_lines": MAX_TOTAL_SOURCE_INPUT_LINES,
            },
        },
        "artifact": {"stored": False, "path": None, "bytes": 0, "capped": False, "cap_bytes": MAX_RECEIPT_BYTES},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if sketch_duplicate_veto:
        result["sketch_duplicate_veto"] = {"comparison_cap_reached": comparison_cap_reached}
    if delta_from_pack_id is not None:
        result["rolling_delta"] = rolling_delta_from_receipt(
            root,
            pack,
            delta_from_pack_id,
            result["content_address"]["id"],
        )
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
        "redaction": {
            "redacted_lines": source.redacted_lines,
            "redacted_lines_exact": source.redacted_lines_exact,
            "redacted_before_pack": True,
        },
        "input": source_input_metadata(source),
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


def trusted_git_executable() -> str:
    if os.name != "posix":
        raise OSError("Git execution is unavailable on this platform")
    executable_names = ("git",)
    for directory in os.defpath.split(os.pathsep):
        if not directory:
            continue
        for name in executable_names:
            candidate = Path(directory) / name
            try:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
            except OSError:
                continue
    raise OSError("trusted system git executable unavailable")


def guarded_git_environment() -> dict[str, str]:
    return {
        "PATH": os.defpath,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
        "SSH_ASKPASS": os.devnull,
        "GCM_INTERACTIVE": "Never",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
    }


def guarded_git_command(root: Path, *args: str) -> list[str]:
    return [
        trusted_git_executable(),
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "-c",
        "credential.interactive=never",
        "-c",
        "filter.unset.clean=",
        "-c",
        "filter.unset.process=",
        "-c",
        "filter.unset.required=false",
        "-c",
        "filter.unspecified.clean=",
        "-c",
        "filter.unspecified.process=",
        "-c",
        "filter.unspecified.required=false",
        "-C",
        str(root),
        *args,
    ]


def _signal_process_group(proc: subprocess.Popen[Any], *, force: bool) -> None:
    requested_signal = getattr(signal, "SIGKILL", signal.SIGTERM) if force else signal.SIGTERM
    if os.name == "posix" and hasattr(os, "killpg"):
        try:
            os.killpg(proc.pid, requested_signal)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    if proc.poll() is not None:
        return
    try:
        if force:
            proc.kill()
        else:
            proc.terminate()
    except OSError:
        pass


def _run_process_capped(
    command: list[str],
    *,
    stdout_cap: int,
    stderr_cap: int,
    timeout_seconds: float,
    environment: dict[str, str] | None = None,
    stdin_data: bytes | None = None,
    stdin_cap_bytes: int | None = None,
) -> tuple[int, bytes, bytes, bool, bool]:
    if stdin_data is not None and (
        stdin_cap_bytes is None or len(stdin_data) > stdin_cap_bytes
    ):
        raise PackError("process stdin exceeds cap")
    proc = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        start_new_session=os.name == "posix",
        env=environment,
    )
    buffers: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    capped = {"stdout": False, "stderr": False}
    stop = threading.Event()

    def drain(name: str, stream: Any, cap: int) -> None:
        total = 0
        try:
            while not stop.is_set() and total <= cap:
                chunk = stream.read(min(64 * 1024, cap + 1 - total))
                if not chunk:
                    break
                buffers[name].append(chunk)
                total += len(chunk)
                if total > cap:
                    capped[name] = True
                    stop.set()
                    _signal_process_group(proc, force=False)
                    break
        finally:
            try:
                stream.close()
            except OSError:
                pass

    threads = [
        threading.Thread(target=drain, args=("stdout", proc.stdout, stdout_cap), daemon=True),
        threading.Thread(target=drain, args=("stderr", proc.stderr, stderr_cap), daemon=True),
    ]
    if stdin_data is not None:
        def write_stdin() -> None:
            try:
                assert proc.stdin is not None
                view = memoryview(stdin_data)
                for offset in range(0, len(view), 64 * 1024):
                    if stop.is_set():
                        break
                    proc.stdin.write(view[offset : offset + 64 * 1024])
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                if proc.stdin is not None:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass

        threads.append(threading.Thread(target=write_stdin, daemon=True))
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop.set()
        _signal_process_group(proc, force=False)
        try:
            proc.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            _signal_process_group(proc, force=True)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    if capped["stdout"] or capped["stderr"] or timed_out:
        _signal_process_group(proc, force=True)
    for thread in threads:
        thread.join(0.5)
    if any(thread.is_alive() for thread in threads):
        stop.set()
        _signal_process_group(proc, force=True)
        for thread in threads:
            thread.join(0.2)
    stdout = b"".join(buffers["stdout"])[:stdout_cap]
    stderr = b"".join(buffers["stderr"])[:stderr_cap]
    return proc.returncode if proc.returncode is not None else -1, stdout, stderr, capped["stdout"], capped["stderr"] or timed_out


def run_git_diff(root: Path, diff_ref: str) -> str:
    ref = diff_ref.strip()
    if not ref:
        raise PackError("empty --diff")
    git_args = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=all",
        "--unified=3",
    ]
    if ref in {"staged", "--staged", "cached", "--cached"}:
        git_args.append("--cached")
    elif ref in {"worktree", "unstaged", "working-tree"}:
        pass
    elif ref.startswith("-"):
        raise PackError("invalid --diff: revision must not start with '-'")
    else:
        git_args.append(ref)
    try:
        reject_configured_git_filters(root)
        command = guarded_git_command(root, *git_args)
        returncode, stdout, stderr, stdout_capped, stderr_capped_or_timeout = _run_process_capped(
            command,
            stdout_cap=MAX_SUGGEST_INPUT_BYTES,
            stderr_cap=MAX_GIT_DIFF_STDERR_BYTES,
            timeout_seconds=GIT_DIFF_TIMEOUT_SECONDS,
            environment=guarded_git_environment(),
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise PackError(f"could not read diff: {exc.__class__.__name__}") from exc
    if stdout_capped:
        raise PackError(f"could not read diff: diff output exceeds cap ({MAX_SUGGEST_INPUT_BYTES} bytes)")
    if stderr_capped_or_timeout:
        raise PackError("could not read diff: stderr cap or timeout exceeded")
    stdout_text = stdout.decode("utf-8", "replace")
    stderr_text = stderr.decode("utf-8", "replace")
    if returncode != 0:
        detail = sanitize_text(
            stderr_text or stdout_text or "git diff failed",
            context="command_search_diff",
        )[0].strip().splitlines()
        message = detail[0] if detail else "git diff failed"
        raise PackError(f"could not read diff: {cap_label(message, default='git diff failed', limit=160)}")
    return sanitize_text(
        stdout_text,
        context="command_search_diff",
    )[0]


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


def _read_git_stdout_capped(
    proc: subprocess.Popen[bytes],
    limit: int,
    timeout_seconds: float,
) -> tuple[bytes, bool]:
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
            if capped:
                _signal_process_group(proc, force=False)
            try:
                proc.stdout.close()
            except OSError:
                pass

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    thread.join(timeout_seconds)
    if thread.is_alive():
        timed_out = True
        _signal_process_group(proc, force=False)
    try:
        proc.wait(timeout=0.2 if timed_out else 2)
    except subprocess.TimeoutExpired:
        _signal_process_group(proc, force=True)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if capped or timed_out:
        _signal_process_group(proc, force=True)
    thread.join(0.5)
    raw_output = b"".join(chunks)[:limit]
    complete = (
        proc.returncode == 0
        and not capped
        and not timed_out
        and (not raw_output or raw_output.endswith(b"\0"))
    )
    return raw_output, complete


def _git_ls_files_raw(root: Path) -> tuple[bytes, bool, int | None]:
    try:
        proc = subprocess.Popen(
            guarded_git_command(root, "ls-files", "-z"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=False,
            start_new_session=os.name == "posix",
            env=guarded_git_environment(),
        )
        raw, complete = _read_git_stdout_capped(
            proc,
            MAX_GIT_LS_FILES_OUTPUT_BYTES,
            10,
        )
        return raw, complete, proc.returncode
    except (OSError, subprocess.TimeoutExpired):
        return b"", False, None


def _iter_nul_fields(raw: bytes):
    view = memoryview(raw)
    start = 0
    while start < len(raw):
        end = raw.find(b"\0", start)
        if end < 0:
            return
        yield view[start:end]
        start = end + 1


def git_ls_files(root: Path, diagnostics: dict[str, Any] | None = None) -> list[str]:
    raw, git_complete, git_returncode = _git_ls_files_raw(root)
    if raw:
        if not raw.endswith(b"\0"):
            raw = raw.rsplit(b"\0", 1)[0] if b"\0" in raw else b""
        retained_parts: list[bytes] = []
        file_cap_reached = False
        for part_view in _iter_nul_fields(raw):
            if not part_view:
                continue
            if len(retained_parts) >= MAX_QUERY_SCAN_FILES:
                file_cap_reached = True
                break
            retained_parts.append(bytes(part_view))
        if diagnostics is not None:
            diagnostics.update({
                "mode": "git",
                "truncated": not git_complete or file_cap_reached,
                "truncation_reason": (
                    "git_output_cap_or_timeout"
                    if not git_complete
                    else "file_cap" if file_cap_reached else None
                ),
            })
        return [part.decode("utf-8", "replace") for part in retained_parts]
    if git_returncode == 0:
        if diagnostics is not None:
            diagnostics.update({"mode": "git", "truncated": False, "truncation_reason": None})
        return []
    if git_returncode is not None and git_returncode < 0:
        if diagnostics is not None:
            diagnostics.update({
                "mode": "git",
                "truncated": True,
                "truncation_reason": "git_output_cap_or_timeout",
            })
        return []
    out: list[str] = []
    skip_dirs = {".git", ".omx", ".context-guard", "node_modules", "dist", "build", "__pycache__"}
    started = time.monotonic()
    visited_dirs = 0
    visited_entries = 0
    truncation_reason: str | None = None
    pending: deque[tuple[Path, int]] = deque([(root, 0)])
    while pending:
        if time.monotonic() - started > MAX_QUERY_WALK_SECONDS:
            truncation_reason = "time_cap"
            break
        if visited_dirs >= MAX_QUERY_WALK_DIRS:
            truncation_reason = "directory_cap"
            break
        current_path, depth = pending.popleft()
        visited_dirs += 1
        try:
            iterator = os.scandir(current_path)
        except OSError:
            truncation_reason = "unsafe_path"
            break
        child_dirs: list[Path] = []
        try:
            with iterator:
                for entry in iterator:
                    if time.monotonic() - started > MAX_QUERY_WALK_SECONDS:
                        truncation_reason = "time_cap"
                        break
                    if visited_entries >= MAX_QUERY_WALK_ENTRIES:
                        truncation_reason = "entry_cap"
                        break
                    visited_entries += 1
                    name = entry.name
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        is_file = entry.is_file(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        if name in skip_dirs or name.startswith(".pytest"):
                            continue
                        if depth >= MAX_QUERY_WALK_DEPTH:
                            truncation_reason = truncation_reason or "depth_cap"
                            continue
                        child_dirs.append(current_path / name)
                    elif is_file:
                        try:
                            rel = (current_path / name).relative_to(root).as_posix()
                        except ValueError:
                            truncation_reason = "unsafe_path"
                            break
                        out.append(rel)
                        if len(out) >= MAX_QUERY_SCAN_FILES:
                            truncation_reason = "file_cap"
                            break
        except OSError:
            truncation_reason = "unsafe_path"
            break
        if truncation_reason in {"time_cap", "entry_cap", "file_cap", "unsafe_path"}:
            break
        for child in reversed(sorted(child_dirs, key=lambda path: path.name)):
            pending.appendleft((child, depth + 1))
    if diagnostics is not None:
        diagnostics.update({
            "mode": "walk",
            "truncated": truncation_reason is not None,
            "truncation_reason": truncation_reason,
            "visited_dirs": min(visited_dirs, MAX_QUERY_WALK_DIRS),
            "visited_entries": min(visited_entries, MAX_QUERY_WALK_ENTRIES),
        })
    return out


def reject_configured_git_filters(root: Path) -> None:
    raw_paths, complete, returncode = _git_ls_files_raw(root)
    if returncode != 0 or not complete:
        raise PackError("could not verify git filters: tracked path scan failed or truncated")
    if not raw_paths:
        return
    if len(raw_paths) > MAX_GIT_ATTR_INPUT_BYTES:
        raise PackError("could not verify git filters: tracked path input exceeds cap")

    try:
        command = guarded_git_command(
            root,
            "check-attr",
            "-z",
            "--stdin",
            "filter",
        )
        returncode, stdout, _stderr, stdout_capped, failed_or_timed_out = _run_process_capped(
            command,
            stdout_cap=MAX_GIT_ATTR_OUTPUT_BYTES,
            stderr_cap=MAX_GIT_DIFF_STDERR_BYTES,
            timeout_seconds=GIT_ATTR_TIMEOUT_SECONDS,
            environment=guarded_git_environment(),
            stdin_data=raw_paths,
            stdin_cap_bytes=MAX_GIT_ATTR_INPUT_BYTES,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise PackError(f"could not verify git filters: {exc.__class__.__name__}") from exc
    if stdout_capped or failed_or_timed_out or returncode != 0:
        raise PackError("could not verify git filters: check-attr failed or exceeded cap")
    if not stdout.endswith(b"\0"):
        raise PackError("could not verify git filters: malformed check-attr output")
    output_fields = iter(_iter_nul_fields(stdout))
    for expected_path in _iter_nul_fields(raw_paths):
        try:
            path = next(output_fields)
            attribute = next(output_fields)
            value = next(output_fields)
        except StopIteration as exc:
            raise PackError("could not verify git filters: incomplete check-attr output") from exc
        if path != expected_path or bytes(attribute) != b"filter":
            raise PackError("could not verify git filters: mismatched check-attr output")
        if bytes(value) not in {b"unspecified", b"unset"}:
            raise PackError("git diff blocked: configured filter attribute")
    try:
        next(output_fields)
    except StopIteration:
        return
    raise PackError("could not verify git filters: excess check-attr output")


def collect_query_candidates(
    root: Path,
    query_terms: set[str],
    context_lines: int,
    *,
    diagnostics: dict[str, Any] | None = None,
) -> list[SuggestCandidate]:
    if not query_terms:
        return []
    candidates: list[SuggestCandidate] = []
    for rel_path in git_ls_files(root, diagnostics):
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


def normalize_suggest_source(
    root: Path,
    candidate: SuggestCandidate,
    *,
    source_cache: _SourceSnapshotCache | None = None,
    input_budget: _SourceInputBudget | None = None,
) -> tuple[ResolvedSource | None, dict[str, Any] | None]:
    effective_lines = candidate.lines or LineRange(1, SUGGEST_WHOLE_FILE_MAX_LINES)
    spec = SourceSpec(
        path=candidate.path,
        priority=candidate.score,
        lines=effective_lines,
        label=candidate.label,
        input_index=candidate.input_index,
        origin="suggest",
    )
    source, omitted_item = resolve_source(
        root,
        spec,
        source_cache=source_cache,
        input_budget=input_budget,
    )
    if omitted_item is not None:
        omitted_item["reason"] = omitted_item.get("reason") or candidate.reason
        omitted_item["suggest_reason"] = candidate.reason
        return None, omitted_item
    assert source is not None
    if source.redacted_path:
        return None, omission(spec, "redacted_path", path=source.display_path, redacted_path=True)
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


def suggest_pack(
    root: Path,
    args: argparse.Namespace,
    *,
    root_arg: str,
    _source_cache: _SourceSnapshotCache | None = None,
    _input_budget: _SourceInputBudget | None = None,
) -> tuple[dict[str, Any], int]:
    input_budget = _input_budget if _input_budget is not None else _SourceInputBudget()
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
    query_scan: dict[str, Any] = {}
    candidates.extend(
        collect_query_candidates(
            root,
            query_terms,
            context_lines,
            diagnostics=query_scan,
        )
    )
    if query_scan.get("truncated"):
        omitted.append({
            "path": "repository",
            "status": "omitted",
            "reason": "query_scan_truncated",
            "scan_truncation_reason": query_scan.get("truncation_reason"),
            "priority": 0,
        })

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
        source, omitted_item = normalize_suggest_source(
            root,
            candidate,
            source_cache=_source_cache,
            input_budget=input_budget,
        )
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
                    source, omitted_item = resolve_source(
                        root,
                        partial_spec,
                        source_cache=_source_cache,
                        input_budget=input_budget,
                    )
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
    if query_scan:
        payload["query_scan"] = {
            **query_scan,
            "limits": {
                "files": MAX_QUERY_SCAN_FILES,
                "directories": MAX_QUERY_WALK_DIRS,
                "entries": MAX_QUERY_WALK_ENTRIES,
                "depth": MAX_QUERY_WALK_DEPTH,
                "seconds": MAX_QUERY_WALK_SECONDS,
            },
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


def apply_adaptive_k_manifest(
    manifest: dict[str, Any],
    advisory: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_sources = manifest.get("sources", [])
    sources = copy.deepcopy(raw_sources) if isinstance(raw_sources, list) else []
    gates = advisory.get("regression_gates", {})
    gates_passed = isinstance(gates, dict) and gates.get("status") == "pass"
    recommended_k = max(0, int(advisory.get("recommended_k", 0) or 0))
    protected_prefixes = ("file:", "output:", "test-output:", "diff:")
    protected_indexes = {
        index
        for index, item in enumerate(sources)
        if isinstance(item, dict)
        and str(item.get("label", "")).startswith(protected_prefixes)
    }
    retained: list[dict[str, Any]] = []
    if gates_passed:
        target_count = max(recommended_k, len(protected_indexes))
        for index, item in enumerate(sources):
            if not isinstance(item, dict):
                continue
            if index in protected_indexes or len(retained) < target_count:
                retained.append(item)
    else:
        retained = [item for item in sources if isinstance(item, dict)]
    omitted_count = len(sources) - len(retained)
    status = "applied" if gates_passed and omitted_count else "no_change"
    if not gates_passed:
        status = "gate_failed"
    applied_manifest = {"version": 1, "sources": retained}
    return applied_manifest, {
        "schema_version": ADAPTIVE_K_APPLICATION_SCHEMA_VERSION,
        "mode": "explicit_opt_in",
        "status": status,
        "recommended_k": recommended_k,
        "input_source_count": len(sources),
        "applied_source_count": len(retained),
        "omitted_source_count": omitted_count,
        "regression_gates_passed": gates_passed,
        "explicit_sources_retained": all(
            sources[index] in retained for index in protected_indexes
        ),
        "claim_boundary": {
            "deterministic_local_only": True,
            "exact_source_fallback_retained": True,
            "provider_token_or_cost_savings_claim_allowed": False,
        },
    }


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


def read_repo_map_text(
    root: Path,
    rel_path: str,
    *,
    source_identities_out: dict[str, tuple[int, int, int, int, int, int, int, int]] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
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
            before_identity = _open_source_identity(handle)
            text = handle.read(MAX_REPO_MAP_BYTES_PER_FILE + 1)
            after_identity = _open_source_identity(handle)
    except (OSError, UnicodeError):
        return None, {"path": display, "reason": "unsafe_path", "retrieval_omitted_reason": "redacted_path" if redacted_path else None}
    if before_identity is None or after_identity != before_identity:
        return None, {
            "path": display,
            "reason": "source_changed_during_repo_map",
            "retrieval_omitted_reason": "redacted_path" if redacted_path else None,
        }
    capped = byte_len(text) > MAX_REPO_MAP_BYTES_PER_FILE
    if capped:
        text = text.encode("utf-8", errors="replace")[:MAX_REPO_MAP_BYTES_PER_FILE].decode("utf-8", errors="ignore")
    risk_counts = secret_risk_counts(text)
    sanitized_text, redacted_lines = sanitize_text(text)
    if source_identities_out is not None:
        source_identities_out[rel.as_posix()] = before_identity
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


def repo_map_records(
    root: Path,
    *,
    seed_paths: set[str],
    query_terms: set[str],
    source_identities_out: dict[str, tuple[int, int, int, int, int, int, int, int]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    paths = git_ls_files(root)
    candidate_paths = paths[:MAX_REPO_MAP_FILES]
    path_cap_reached = len(paths) > MAX_REPO_MAP_FILES
    scan_paths = repo_map_scan_paths(candidate_paths, seed_paths=seed_paths, query_terms=query_terms)
    scan_cap_reached = len(candidate_paths) > len(scan_paths)
    records: list[dict[str, Any]] = []
    omitted: list[dict[str, Any]] = []
    for rel_path in scan_paths:
        if source_identities_out is None:
            record, omission_item = read_repo_map_text(root, rel_path)
        else:
            record, omission_item = read_repo_map_text(
                root,
                rel_path,
                source_identities_out=source_identities_out,
            )
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
    complete_secret_paths: set[str] | None = None,
) -> list[dict[str, Any]]:
    signature_paths = {str(item.get("path", "")) for item in signatures}
    secret_paths = (
        complete_secret_paths
        if complete_secret_paths is not None
        else {
            str(item.get("path", ""))
            for item in secret_scan.get("files_with_risks", [])
            if isinstance(item, dict)
        }
    )
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
    complete_secret_paths_out: set[str] | None = None,
    source_identities_out: dict[str, tuple[int, int, int, int, int, int, int, int]] | None = None,
) -> dict[str, Any]:
    query_terms = suggest_tokens(str(suggest_payload.get("query", "")))
    seed_paths = repo_map_seed_paths(args, suggest_payload, build_payload)
    records, omitted, caps = repo_map_records(
        root,
        seed_paths=seed_paths,
        query_terms=query_terms,
        source_identities_out=source_identities_out,
    )
    record_by_path = {str(record["path"]): record for record in records}
    signatures = extract_signatures(records)
    secret_scan = build_secret_scan(records)
    complete_secret_paths = {
        str(record.get("path", ""))
        for record in records
        if record.get("secret_risk_counts")
    }
    if complete_secret_paths_out is not None:
        complete_secret_paths_out.update(complete_secret_paths)
    edges = collect_import_edges(records)
    graph_rank = build_graph_rank(
        records,
        signatures,
        edges,
        query_terms=query_terms,
        seed_paths=seed_paths,
        secret_scan=secret_scan,
        complete_secret_paths=complete_secret_paths,
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


def frozen_source_content_sha256(
    path: str,
    lines: object,
    source_cache: _SourceSnapshotCache,
) -> str | None:
    rel, _reason = lexical_rel(path)
    if rel is None:
        return None
    snapshot = source_cache.entries.get(
        (rel.as_posix(), line_identity_from_dict(lines), "source_code")
    )
    if snapshot is None:
        return None
    return sha256_text("".join(snapshot.selected_lines))


def frozen_source_identity(
    path: str,
    lines: object,
    identities: dict[str, tuple[int, int, int, int, int, int, int, int]],
    source_cache: _SourceSnapshotCache,
) -> str:
    identity = identities.get(path)
    content_sha256 = frozen_source_content_sha256(path, lines, source_cache)
    material = json.dumps(
        {
            "content_sha256": content_sha256,
            "lines": line_identity_from_dict(lines),
            "path": path,
            "stat": identity,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{sha256_text(material)}"


def exact_source_fallback(
    root_arg: str,
    path: str,
    lines: object,
    *,
    expected_content_sha256: str | None,
    unavailable_reason: str | None = None,
) -> dict[str, Any]:
    if unavailable_reason is not None:
        return {"kind": "unavailable", "reason": unavailable_reason}
    rel, _reason = lexical_rel(path)
    safe_root = safe_root_arg_for_retrieval(root_arg)
    if (
        rel is None
        or safe_root is None
        or repo_map_path_has_sensitive_evidence(path)
        or not isinstance(lines, dict)
        or not isinstance(lines.get("start"), int)
        or isinstance(lines.get("start"), bool)
        or not isinstance(lines.get("end"), int)
        or isinstance(lines.get("end"), bool)
        or lines["start"] < 1
        or lines["end"] < lines["start"]
        or expected_content_sha256 is None
    ):
        return {"kind": "unavailable", "reason": "exact_snapshot_unavailable"}
    line_identity = line_identity_from_dict(lines)
    args = [
        "context-guard-pack", "slice", "--root", safe_root,
        "--path", rel.as_posix(), "--lines", line_identity, "--json",
    ]
    return {
        "kind": "exact_source_slice",
        "command": " ".join(shlex.quote(part) for part in args),
        "expected_content_sha256": expected_content_sha256,
        "path": rel.as_posix(),
        "lines": copy.deepcopy(lines),
    }


def self_financing_candidate_receipt(
    *, phase: str, source: dict[str, Any], reason: str, status: str,
    secret_decision: str, identities: dict[str, tuple[int, int, int, int, int, int, int, int]],
    root_arg: str, source_cache: _SourceSnapshotCache, byte_delta: int = 0,
    removed_sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    path = str(source.get("path", ""))
    content_sha256 = frozen_source_content_sha256(
        path, source.get("lines"), source_cache
    )
    return {
        "phase": phase,
        "status": status,
        "path": path,
        "lines": copy.deepcopy(source.get("lines")),
        "reason": reason,
        "hop_count": 1 if phase == "graph" else 0,
        "frozen_identity": frozen_source_identity(
            path, source.get("lines"), identities, source_cache
        ),
        "byte_delta": byte_delta,
        "secret_risk": {"decision": secret_decision, "signal": "bounded_local_pattern_scan"},
        "exact_fallback": exact_source_fallback(
            root_arg,
            path,
            source.get("lines"),
            expected_content_sha256=content_sha256,
            unavailable_reason="secret_risk" if secret_decision == "reject" else None,
        ),
        "removed_sources": copy.deepcopy(removed_sources or []),
    }


def selection_plan_source(
    item: dict[str, Any], identities: dict[str, tuple[int, int, int, int, int, int, int, int]],
    source_cache: _SourceSnapshotCache, root_arg: str,
) -> dict[str, Any]:
    path = str(item.get("path", ""))
    lines = copy.deepcopy(item.get("requested_lines", item.get("lines")))
    content_sha256 = frozen_source_content_sha256(path, lines, source_cache)
    fallback = exact_source_fallback(
        root_arg, path, lines, expected_content_sha256=content_sha256
    )
    if fallback.get("kind") != "exact_source_slice":
        raise PackError("selection plan missing exact recovery")
    return {
        "path": path,
        "lines": lines,
        "identity": frozen_source_identity(path, lines, identities, source_cache),
        "content_sha256": content_sha256,
        "exact_fallback": fallback,
    }


def build_selection_plan(
    args: argparse.Namespace, ordinary_build: dict[str, Any], selected_build: dict[str, Any],
    receipt: dict[str, Any], repo_map: dict[str, Any], suggest_payload: dict[str, Any],
    identities: dict[str, tuple[int, int, int, int, int, int, int, int]],
    source_cache: _SourceSnapshotCache, *, root_arg: str,
) -> dict[str, Any]:
    if getattr(args, "selection_plan", False) and (args.manifest_out or args.pack_out):
        raise PackError("selection planning is read-only; output paths are unsupported")
    if not args.json:
        raise PackError("selection planning requires --json")
    if getattr(args, "selection_plan", False) and getattr(args, "apply_selection_plan", None):
        raise PackError("selection plan and apply are mutually exclusive")
    if args.delta_from_pack_id:
        raise PackError("selection plan does not cross private receipt boundaries")
    explicit_paths = split_suggest_files(args.files) + list(args.output or []) + list(args.test_output or [])
    if any(repo_map_path_has_sensitive_evidence(path) or re.search(r"(?i)(?:^|[-_/.])(scorer|private)(?:[-_/.]|$)", path) for path in explicit_paths):
        raise PackError("selection plan refuses scorer/private data")
    if any(
        isinstance(item, dict) and str(item.get("path", "")).startswith("redacted-path#")
        for item in repo_map.get("token_tree", [])
    ):
        raise PackError("selection plan refuses scorer/private data")
    caps = repo_map.get("caps", {}) if isinstance(repo_map.get("caps"), dict) else {}
    summary = repo_map.get("summary", {}) if isinstance(repo_map.get("summary"), dict) else {}
    graph = repo_map.get("graph", {}) if isinstance(repo_map.get("graph"), dict) else {}
    if SECRET_CONTENT_RE.search(str(args.query)):
        raise PackError("selection plan refuses secret-risk input")
    if (
        any(bool(caps.get(key)) for key in ("files_capped", "candidate_files_capped", "scan_files_capped"))
        or int(summary.get("bytes_per_file_capped_count", 0) or 0) != 0
        or bool(repo_map.get("omitted_files"))
        or int(graph.get("edges_omitted_by_cap", 0) or 0) != 0
        or bool(ordinary_build.get("input", {}).get("capped"))
        or bool(selected_build.get("input", {}).get("capped"))
        or any(
            isinstance(item, dict) and item.get("reason") == "query_scan_truncated"
            for item in suggest_payload.get("omitted_sources", [])
        )
    ):
        raise PackError("selection plan requires a complete scan")
    secret_scan = repo_map.get("secret_scan", {}) if isinstance(repo_map.get("secret_scan"), dict) else {}
    if (
        int(ordinary_build.get("redaction", {}).get("redacted_lines", 0) or 0) != 0
        or int(selected_build.get("redaction", {}).get("redacted_lines", 0) or 0) != 0
        or bool(secret_scan.get("files_with_risks"))
        or int(secret_scan.get("files_omitted_by_cap", 0) or 0) != 0
    ):
        raise PackError("selection plan refuses secret-risk input")

    ordinary = [
        selection_plan_source(item, identities, source_cache, root_arg)
        for item in ordinary_build.get("included_sources", []) if isinstance(item, dict)
    ]
    decisions = [copy.deepcopy(item) for item in receipt.get("decisions", []) if isinstance(item, dict)]
    for decision in decisions:
        fallback = decision.get("exact_fallback", {})
        if fallback.get("kind") != "exact_source_slice":
            raise PackError("selection plan missing exact recovery")
        recovered_removed = []
        for removed in decision.get("removed_sources", []):
            if not isinstance(removed, dict):
                raise PackError("selection plan missing exact recovery")
            recovered = copy.deepcopy(removed)
            if recovered.get("exact_fallback", {}).get("kind") != "exact_source_slice":
                source = selection_plan_source(recovered, identities, source_cache, root_arg)
                recovered["frozen_identity"] = source["identity"]
                recovered["exact_fallback"] = exact_source_fallback(
                    root_arg, source["path"], source["lines"],
                    expected_content_sha256=source["content_sha256"],
                )
            recovered_removed.append(recovered)
        decision["removed_sources"] = recovered_removed
    selected = [item for item in decisions if item.get("status") == "selected"]
    omitted = [item for item in decisions if item.get("status") != "selected"]
    replacement = [
        {"candidate_identity": item["frozen_identity"], "removed": copy.deepcopy(item.get("removed_sources", []))}
        for item in selected if item.get("removed_sources")
    ]
    fallback = [
        {"identity": item["identity"], "exact_fallback": copy.deepcopy(item["exact_fallback"])}
        for item in ordinary
    ] + [
        {"identity": item["frozen_identity"], "exact_fallback": copy.deepcopy(item["exact_fallback"])}
        for item in decisions
    ]
    material: dict[str, Any] = {
        "schema_version": SELECTION_PLAN_SCHEMA_VERSION,
        "ordinary": ordinary,
        "candidate": decisions,
        "selected": selected,
        "omitted": omitted,
        "replacement": replacement,
        "ceiling": {
            "unit": "rendered_bytes",
            "ordinary": int(receipt.get("ordinary_pack_bytes", 0) or 0),
            "selected": int(receipt.get("selected_rendered_bytes", 0) or 0),
        },
        "fallback": fallback,
        "provenance": {
            "query_sha256": sha256_text(str(args.query)),
            "diff": cap_label(args.diff) if args.diff else None,
            "ordinary_pack_id": ordinary_build.get("pack_id"),
            "selected_pack_id": selected_build.get("pack_id"),
            "source_identities": sorted(item["identity"] for item in ordinary),
        },
        "safety": {
            "read_only": True, "provider_free": True, "complete_scan": True,
            "source_revalidation_required_on_apply": True,
        },
        "claim_boundary": {"provider_token_or_cost_savings_claim_allowed": False},
    }
    plan_id = "sha256:" + sha256_text(json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return {"schema_version": material.pop("schema_version"), "plan_id": plan_id, **material}


def read_selection_plan(root: Path, raw_path: str) -> dict[str, Any]:
    rel = output_rel_for_collision_check(raw_path, "--apply-selection-plan")
    try:
        value = json.loads(
            read_manifest_bytes_no_follow(root / rel).decode("utf-8"),
            object_pairs_hook=strict_json_object,
            parse_constant=reject_json_constant,
            parse_int=parse_receipt_int,
        )
        json_depth(value)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PackError("invalid selection plan JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SELECTION_PLAN_SCHEMA_VERSION:
        raise PackError("unsupported selection plan schema")
    return value


def apply_symbol_memory_graph(
    manifest: dict[str, Any],
    repo_map: dict[str, Any],
    *,
    complete_secret_paths: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Add bounded direct graph neighbors to an explicit auto-pack manifest."""

    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list):
        raise PackError("manifest sources must be a list")
    existing_sources = [
        copy.deepcopy(item) for item in raw_sources if isinstance(item, dict)
    ]
    existing_paths = {
        str(item.get("path", "")) for item in existing_sources if item.get("path")
    }
    graph = repo_map.get("graph") if isinstance(repo_map.get("graph"), dict) else {}
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    rank_items = (
        repo_map.get("graph_rank")
        if isinstance(repo_map.get("graph_rank"), list)
        else []
    )
    rank_by_path = {
        str(item.get("path", "")): item
        for item in rank_items
        if isinstance(item, dict) and item.get("path")
    }
    secret_scan = (
        repo_map.get("secret_scan")
        if isinstance(repo_map.get("secret_scan"), dict)
        else {}
    )
    risky_paths = (
        complete_secret_paths
        if complete_secret_paths is not None
        else {
            str(item.get("path", ""))
            for item in secret_scan.get("files_with_risks", [])
            if isinstance(item, dict) and item.get("path")
        }
    )
    direct_neighbors: set[str] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = edge.get("from")
        target = edge.get("to")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source in existing_paths and target not in existing_paths:
            direct_neighbors.add(target)
        if target in existing_paths and source not in existing_paths:
            direct_neighbors.add(source)

    eligible: list[tuple[int, str, int]] = []
    excluded_secret_risk_count = 0
    for path in direct_neighbors:
        if path in risky_paths:
            excluded_secret_risk_count += 1
            continue
        item = rank_by_path.get(path)
        if item is None or repo_map_path_has_sensitive_evidence(path):
            continue
        score = int(item.get("score", 0) or 0)
        line_count = int(item.get("line_count", 0) or 0)
        if score <= 0 or line_count <= 0:
            continue
        eligible.append((score, path, line_count))
    eligible.sort(key=lambda item: (-item[0], item[1]))

    seed_priorities = [
        int(item.get("priority", 0) or 0) for item in existing_sources
    ]
    maximum_graph_priority = max(1, min(seed_priorities, default=2) - 1)
    selected_sources: list[dict[str, Any]] = []
    for score, path, line_count in eligible[:MAX_GRAPH_APPLICATION_SOURCES]:
        source = {
            "path": path,
            "priority": max(1, min(score, maximum_graph_priority)),
            "label": f"graph:{path}"[:MAX_LABEL_CHARS],
            "lines": {"start": 1, "end": min(line_count, MAX_GRAPH_APPLICATION_LINES)},
        }
        existing_sources.append(source)
        selected_sources.append(
            {
                "path": source["path"],
                "priority": source["priority"],
                "lines": copy.deepcopy(source["lines"]),
                "reason": "direct_import_neighbor",
            }
        )
    result_manifest = build_suggest_manifest(existing_sources)
    return result_manifest, {
        "schema_version": GRAPH_APPLICATION_SCHEMA_VERSION,
        "mode": "explicit_opt_in",
        "selected_source_count": len(selected_sources),
        "selected_sources": selected_sources,
        "candidate_count": len(eligible),
        "candidate_cap": MAX_GRAPH_APPLICATION_SOURCES,
        "candidate_cap_reached": len(eligible) > MAX_GRAPH_APPLICATION_SOURCES,
        "excluded_secret_risk_count": excluded_secret_risk_count,
        "exact_source_fallback_retained": True,
        "deterministic_local_only": True,
        "provider_token_or_cost_savings_claim_allowed": False,
    }


def bind_graph_sources_to_repo_snapshot(
    root: Path,
    specs: list[SourceSpec],
    required_sources: set[tuple[str, str]],
    source_identities: dict[str, tuple[int, int, int, int, int, int, int, int]],
    *,
    source_cache: _SourceSnapshotCache,
    input_budget: _SourceInputBudget,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Warm immutable source snapshots only for repo-map-bound graph additions."""

    rejections: dict[tuple[str, str], dict[str, Any]] = {}
    for spec in specs:
        rel, _reason = lexical_rel(spec.path)
        if rel is None:
            continue
        lines_identity = spec.lines.identity() if spec.lines is not None else "all"
        source_identity = (rel.as_posix(), lines_identity)
        if source_identity not in required_sources:
            continue
        expected_identity = source_identities.get(rel.as_posix())
        if expected_identity is None:
            continue
        _source, omitted_item = resolve_source(
            root,
            spec,
            source_cache=source_cache,
            input_budget=input_budget,
            expected_identity=expected_identity,
        )
        if omitted_item is not None:
            rejections[source_identity] = copy.deepcopy(omitted_item)
    return rejections


def build_symbol_memory_payload(
    repo_map: dict[str, Any], *, applied: bool = False
) -> dict[str, Any]:
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
        "mode": "applied" if applied else "advisory",
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
            "advisory_does_not_change_manifest_pack_or_receipt": not applied,
            "explicit_graph_application_changes_manifest_and_pack": applied,
            "graph_rank_is_explain_only": not applied,
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
    if isinstance(payload.get("graph_application"), dict):
        explain["graph_application"] = copy.deepcopy(payload["graph_application"])
    if isinstance(payload.get("adaptive_k_application"), dict):
        explain["adaptive_k_application"] = copy.deepcopy(
            payload["adaptive_k_application"]
        )
    return explain


def auto_pack(root: Path, args: argparse.Namespace, *, root_arg: str) -> tuple[dict[str, Any], int]:
    plan_only = bool(getattr(args, "selection_plan", False))
    apply_plan_path = getattr(args, "apply_selection_plan", None)
    expected_plan = read_selection_plan(root, apply_plan_path) if apply_plan_path else None
    source_cache = _SourceSnapshotCache()
    input_budget = _SourceInputBudget()
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
    self_financing = bool(getattr(args, "self_financing_selection", False) or plan_only or apply_plan_path)
    apply_adaptive_k = bool(getattr(args, "apply_adaptive_k", False) or self_financing)
    if apply_adaptive_k:
        suggest_args.adaptive_k = True
    suggest_payload, rc = suggest_pack(
        root,
        suggest_args,
        root_arg=root_arg,
        _source_cache=source_cache,
        _input_budget=input_budget,
    )
    manifest = suggest_payload["manifest"]
    ordinary_build_payload: dict[str, Any] | None = None
    if self_financing:
        ordinary_build_payload = build_pack(
            root,
            manifest_to_source_specs(manifest),
            budget_bytes=bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES),
            root_arg=root_arg,
            store_artifact=False,
            sketch_duplicate_veto=getattr(args, "sketch_duplicate_veto", False),
            _source_cache=source_cache,
            _input_budget=input_budget,
        )
    adaptive_k_application: dict[str, Any] | None = None
    if apply_adaptive_k and isinstance(suggest_payload.get("adaptive_k"), dict):
        manifest, adaptive_k_application = apply_adaptive_k_manifest(
            manifest,
            suggest_payload["adaptive_k"],
        )
        suggest_payload["manifest"] = manifest
        retained_identities = {
            (str(item.get("path", "")), line_range_identity(item.get("lines")))
            for item in manifest.get("sources", [])
            if isinstance(item, dict)
        }
        suggest_payload["sources"] = [
            item
            for item in suggest_payload.get("sources", [])
            if isinstance(item, dict)
            and (
                str(item.get("path", "")),
                line_range_identity(item.get("lines")),
            )
            in retained_identities
        ]
    specs = manifest_to_source_specs(manifest)
    budget = bounded_int(args.budget_bytes, DEFAULT_BUDGET_BYTES, MIN_BUDGET_BYTES, MAX_BUDGET_BYTES)
    build_payload = build_pack(
        root,
        specs,
        budget_bytes=budget,
        root_arg=root_arg,
        store_artifact=False,
        delta_from_pack_id=args.delta_from_pack_id,
        sketch_duplicate_veto=getattr(args, "sketch_duplicate_veto", False),
        _source_cache=source_cache,
        _input_budget=input_budget,
    )
    if apply_adaptive_k:
        suggest_payload["estimated_pack_bytes"] = build_payload.get("pack_bytes", 0)
        suggest_payload["token_proxy"] = copy.deepcopy(
            build_payload.get("token_proxy", {})
        )
    repo_map_payload: dict[str, Any] | None = None
    graph_application: dict[str, Any] | None = None
    apply_symbol_memory = bool(getattr(args, "apply_symbol_memory", False) or self_financing)
    complete_secret_paths: set[str] | None = set() if apply_symbol_memory else None
    repo_map_source_identities: dict[
        str,
        tuple[int, int, int, int, int, int, int, int],
    ] = {}
    if getattr(args, "symbol_memory", False) or apply_symbol_memory or args.explain:
        repo_map_payload = build_repo_map_payload(
            root,
            args,
            suggest_payload,
            build_payload,
            root_arg=root_arg,
            complete_secret_paths_out=complete_secret_paths,
            source_identities_out=(
                repo_map_source_identities if apply_symbol_memory else None
            ),
        )
    self_financing_receipt: dict[str, Any] | None = None
    if self_financing and isinstance(repo_map_payload, dict) and ordinary_build_payload is not None:
        ordinary_ceiling = int(ordinary_build_payload.get("pack_bytes", 0) or 0)
        decisions: list[dict[str, Any]] = []
        recorded_secret_decisions: set[tuple[str, str]] = set()
        ordinary_sources = ordinary_build_payload.get("included_sources", [])
        retained_keys = {
            (str(item.get("path", "")), line_range_identity(item.get("lines")))
            for item in manifest.get("sources", []) if isinstance(item, dict)
        }
        for item in ordinary_sources if isinstance(ordinary_sources, list) else []:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("path", "")), line_range_identity(item.get("requested_lines")))
            if key not in retained_keys:
                source = {"path": key[0], "lines": copy.deepcopy(item.get("requested_lines"))}
                decisions.append(self_financing_candidate_receipt(
                    phase="adaptive", source=source, reason="adaptive_headroom_removal",
                    status="selected", secret_decision="allow", identities=repo_map_source_identities,
                    root_arg=root_arg, source_cache=source_cache,
                    byte_delta=-int(item.get("bytes", 0) or 0),
                    removed_sources=[source],
                ))

        existing_paths = {str(item.get("path", "")) for item in manifest.get("sources", []) if isinstance(item, dict)}
        query_terms = suggest_tokens(str(suggest_payload.get("query", "")))
        candidates: list[tuple[str, dict[str, Any], str]] = []
        for signature in repo_map_payload.get("signature_index", []):
            if not isinstance(signature, dict):
                continue
            path = str(signature.get("path", ""))
            searchable = suggest_tokens(f"{signature.get('name', '')} {signature.get('signature', '')}")
            if not query_terms.intersection(searchable):
                continue
            source = {
                "path": path, "priority": 2, "label": f"symbol:{path}"[:MAX_LABEL_CHARS],
                "lines": copy.deepcopy(signature.get("lines")),
            }
            if path in (complete_secret_paths or set()):
                decisions.append(self_financing_candidate_receipt(
                    phase="symbol", source=source, reason="secret_risk", status="no_op",
                    secret_decision="reject", identities=repo_map_source_identities,
                    root_arg=root_arg, source_cache=source_cache,
                ))
                recorded_secret_decisions.add(("symbol", path))
                continue
            if path in existing_paths:
                existing_source = next(
                    (
                        item for item in build_payload.get("included_sources", [])
                        if isinstance(item, dict)
                        and item.get("path") == path
                        and item.get("status") == "included"
                        and item.get("requested_lines") == item.get("included_lines")
                    ),
                    None,
                )
                if existing_source is not None:
                    source["lines"] = copy.deepcopy(existing_source["requested_lines"])
                decisions.append(self_financing_candidate_receipt(
                    phase="symbol", source=source, reason="duplicate_source", status="no_op",
                    secret_decision="allow", identities=repo_map_source_identities,
                    root_arg=root_arg, source_cache=source_cache,
                ))
                continue
            candidates.append(("symbol", source, "task_matching_symbol"))
            if len([item for item in candidates if item[0] == "symbol"]) >= MAX_GRAPH_APPLICATION_SOURCES:
                break
        graph_manifest, graph_preview = apply_symbol_memory_graph(
            manifest, repo_map_payload, complete_secret_paths=complete_secret_paths,
        )
        graph_sources = graph_manifest.get("sources", [])
        for source in graph_sources[len(manifest.get("sources", [])):]:
            if isinstance(source, dict):
                candidates.append(("graph", source, "direct_import_neighbor"))

        frozen_candidate_sources = {
            (str(source.get("path", "")), line_range_identity(source.get("lines")))
            for _phase, source, _reason in candidates
        }
        candidate_specs = manifest_to_source_specs(build_suggest_manifest(
            [source for _phase, source, _reason in candidates]
        ))
        candidate_snapshot_rejections = bind_graph_sources_to_repo_snapshot(
            root, candidate_specs, frozen_candidate_sources, repo_map_source_identities,
            source_cache=source_cache, input_budget=input_budget,
        )

        # Record secret-risk direct neighbors as explicit no-ops without exposing their contents.
        graph = repo_map_payload.get("graph", {})
        for edge in graph.get("edges", []) if isinstance(graph, dict) else []:
            if not isinstance(edge, dict):
                continue
            for path in (edge.get("from"), edge.get("to")):
                if isinstance(path, str) and path in (complete_secret_paths or set()) and path not in existing_paths:
                    if ("graph", path) in recorded_secret_decisions:
                        continue
                    source = {"path": path, "lines": None}
                    decisions.append(self_financing_candidate_receipt(
                        phase="graph", source=source, reason="secret_risk", status="no_op",
                        secret_decision="reject", identities=repo_map_source_identities,
                        root_arg=root_arg, source_cache=source_cache,
                    ))
                    recorded_secret_decisions.add(("graph", path))

        current_manifest = copy.deepcopy(manifest)
        current_build = build_payload
        protected_sources = [
            (
                str(item.get("path", "")),
                copy.deepcopy(item.get("lines")) if isinstance(item.get("lines"), dict) else None,
            )
            for item in current_manifest.get("sources", [])
            if isinstance(item, dict)
            and str(item.get("label", "")).startswith(
                ("file:", "output:", "test-output:", "diff:", "critical:")
            )
        ]

        def protected_sources_are_exact(build: dict[str, Any]) -> bool:
            included_sources = [
                item for item in build.get("included_sources", [])
                if isinstance(item, dict)
            ]
            for protected_path, protected_lines in protected_sources:
                matched = False
                for item in included_sources:
                    if (
                        item.get("path") != protected_path
                        or item.get("status") != "included"
                        or item.get("requested_lines") != item.get("included_lines")
                    ):
                        continue
                    if protected_lines is not None and item.get("requested_lines") != protected_lines:
                        continue
                    matched = True
                    break
                if not matched:
                    return False
            return True

        seen_candidates: set[tuple[str, str]] = set()
        for phase, candidate, reason in candidates:
            key = (str(candidate.get("path", "")), line_range_identity(candidate.get("lines")))
            if key in seen_candidates or key[0] in {str(item.get("path", "")) for item in current_manifest.get("sources", []) if isinstance(item, dict)}:
                decisions.append(self_financing_candidate_receipt(
                    phase=phase, source=candidate, reason="duplicate_source", status="no_op",
                    secret_decision="allow", identities=repo_map_source_identities,
                    root_arg=root_arg, source_cache=source_cache,
                ))
                continue
            seen_candidates.add(key)
            trial_sources = [copy.deepcopy(item) for item in current_manifest.get("sources", []) if isinstance(item, dict)] + [copy.deepcopy(candidate)]
            candidate_priority = int(candidate.get("priority", 0) or 0)
            removable = sorted(
                [
                    item for item in trial_sources[:-1]
                    if not str(item.get("label", "")).startswith(
                        ("file:", "output:", "test-output:", "diff:", "critical:")
                    )
                    and int(item.get("priority", 0) or 0) < candidate_priority
                ],
                key=lambda item: (int(item.get("priority", 0) or 0), str(item.get("path", ""))),
            )
            removed: list[dict[str, Any]] = []
            accepted_build: dict[str, Any] | None = None
            while True:
                trial_manifest = build_suggest_manifest(trial_sources)
                trial_build = build_pack(
                    root, manifest_to_source_specs(trial_manifest), budget_bytes=max(MIN_BUDGET_BYTES, ordinary_ceiling),
                    root_arg=root_arg, store_artifact=False,
                    sketch_duplicate_veto=getattr(args, "sketch_duplicate_veto", False),
                    _source_cache=source_cache, _input_budget=input_budget,
                    _required_snapshot_sources=frozen_candidate_sources,
                    _expected_source_identities=repo_map_source_identities,
                    _snapshot_rejections=candidate_snapshot_rejections,
                )
                candidate_included_exactly = any(
                    isinstance(item, dict)
                    and str(item.get("path", "")) == key[0]
                    and line_range_identity(item.get("requested_lines")) == key[1]
                    and line_range_identity(item.get("included_lines")) == key[1]
                    and item.get("status") == "included"
                    for item in trial_build.get("included_sources", [])
                )
                if (
                    int(trial_build.get("pack_bytes", 0) or 0) <= ordinary_ceiling
                    and candidate_included_exactly
                    and protected_sources_are_exact(trial_build)
                ):
                    accepted_build = trial_build
                    break
                if not removable:
                    break
                victim = removable.pop(0)
                trial_sources.remove(victim)
                victim_source = {
                    "path": victim.get("path"),
                    "lines": copy.deepcopy(victim.get("lines")),
                }
                if not isinstance(victim_source["lines"], dict):
                    prior = next(
                        (
                            item for item in current_build.get("included_sources", [])
                            if isinstance(item, dict)
                            and item.get("path") == victim_source["path"]
                            and item.get("status") == "included"
                            and item.get("requested_lines") == item.get("included_lines")
                        ),
                        None,
                    )
                    if prior is not None:
                        victim_source["lines"] = copy.deepcopy(prior["requested_lines"])
                removed.append({
                    "path": victim_source["path"], "lines": victim_source["lines"],
                    "reason": "lower_value_replacement",
                    "frozen_identity": frozen_source_identity(
                        str(victim_source["path"] or ""), victim_source["lines"],
                        repo_map_source_identities, source_cache,
                    ),
                    "exact_fallback": exact_source_fallback(
                        root_arg, str(victim_source["path"] or ""), victim_source["lines"],
                        expected_content_sha256=frozen_source_content_sha256(
                            str(victim_source["path"] or ""), victim_source["lines"], source_cache
                        ),
                    ),
                })
            if accepted_build is None:
                decisions.append(self_financing_candidate_receipt(
                    phase=phase, source=candidate, reason="ordinary_ceiling_no_safe_replacement", status="no_op",
                    secret_decision="allow", identities=repo_map_source_identities,
                    root_arg=root_arg, source_cache=source_cache,
                ))
                continue
            previous_bytes = int(current_build.get("pack_bytes", 0) or 0)
            current_manifest = build_suggest_manifest(trial_sources)
            current_build = accepted_build
            decisions.append(self_financing_candidate_receipt(
                phase=phase, source=candidate, reason=reason, status="selected",
                secret_decision="allow", identities=repo_map_source_identities,
                root_arg=root_arg, source_cache=source_cache,
                byte_delta=int(current_build.get("pack_bytes", 0) or 0) - previous_bytes,
                removed_sources=removed,
            ))
        manifest = current_manifest
        build_payload = current_build
        selected_rendered_bytes = int(build_payload.get("pack_bytes", 0) or 0)
        if (
            selected_rendered_bytes > ordinary_ceiling
            or not protected_sources_are_exact(build_payload)
        ):
            raise PackError("self-financing selection invariant failed")
        suggest_payload["manifest"] = manifest
        suggest_payload["estimated_pack_bytes"] = build_payload.get("pack_bytes", 0)
        suggest_payload["token_proxy"] = copy.deepcopy(build_payload.get("token_proxy", {}))
        selected_graph_decisions = [
            item for item in decisions
            if item.get("phase") == "graph" and item.get("status") == "selected"
        ]
        graph_application = {
            **graph_preview,
            "selected_source_count": len(selected_graph_decisions),
            "selected_sources": [
                {
                    "path": item.get("path"), "lines": copy.deepcopy(item.get("lines")),
                    "reason": item.get("reason"),
                }
                for item in selected_graph_decisions
            ],
        }
        phase_results = {}
        for phase in ("adaptive", "symbol", "graph"):
            phase_decisions = [item for item in decisions if item.get("phase") == phase]
            phase_results[phase] = {
                "status": "applied" if any(item.get("status") == "selected" for item in phase_decisions) else "no_op",
                "selected_count": sum(item.get("status") == "selected" for item in phase_decisions),
                "no_op_count": sum(item.get("status") == "no_op" for item in phase_decisions),
            }
        self_financing_receipt = {
            "schema_version": SELF_FINANCING_SELECTION_SCHEMA_VERSION,
            "mode": "explicit_opt_in", "phase_order": ["adaptive", "symbol", "graph"],
            "ordinary_pack_bytes": ordinary_ceiling,
            "selected_rendered_bytes": selected_rendered_bytes,
            "ceiling_respected": selected_rendered_bytes <= ordinary_ceiling,
            "phase_results": phase_results,
            "decisions": decisions,
            "claim_boundary": {"provider_token_or_cost_savings_claim_allowed": False},
        }
    elif apply_symbol_memory and isinstance(repo_map_payload, dict):
        repo_map_payload["safety"]["explain_only"] = False
        repo_map_payload["safety"]["caveats"] = [
            "Repo-map bytes are local sampled UTF-8 bytes and estimated chars_div_4 token proxies, not provider-token or savings claims.",
            "Graph ranking is applied only to the bounded direct-neighbor expansion recorded in graph_application; exact source retrieval remains available.",
        ]
        pre_graph_sources = {
            (str(item.get("path", "")), line_range_identity(item.get("lines")))
            for item in manifest.get("sources", [])
            if isinstance(item, dict) and item.get("path")
        }
        manifest, graph_application = apply_symbol_memory_graph(
            manifest,
            repo_map_payload,
            complete_secret_paths=complete_secret_paths,
        )
        suggest_payload["manifest"] = manifest
        specs = manifest_to_source_specs(manifest)
        graph_snapshot_sources = {
            (str(item.get("path", "")), line_range_identity(item.get("lines")))
            for item in manifest.get("sources", [])
            if isinstance(item, dict) and item.get("path")
        } - pre_graph_sources
        graph_snapshot_rejections = bind_graph_sources_to_repo_snapshot(
            root,
            specs,
            graph_snapshot_sources,
            repo_map_source_identities,
            source_cache=source_cache,
            input_budget=input_budget,
        )
        build_payload = build_pack(
            root,
            specs,
            budget_bytes=budget,
            root_arg=root_arg,
            store_artifact=False,
            delta_from_pack_id=args.delta_from_pack_id,
            sketch_duplicate_veto=getattr(args, "sketch_duplicate_veto", False),
            _source_cache=source_cache,
            _input_budget=input_budget,
            _required_snapshot_sources=graph_snapshot_sources,
            _expected_source_identities=repo_map_source_identities,
            _snapshot_rejections=graph_snapshot_rejections,
        )
        suggest_payload["estimated_pack_bytes"] = build_payload.get("pack_bytes", 0)
        suggest_payload["token_proxy"] = copy.deepcopy(
            build_payload.get("token_proxy", {})
        )
    selection_plan_payload: dict[str, Any] | None = None
    if plan_only or apply_plan_path:
        if not isinstance(self_financing_receipt, dict) or not isinstance(repo_map_payload, dict) or ordinary_build_payload is None:
            raise PackError("selection plan unavailable")
        selection_plan_payload = build_selection_plan(
            args, ordinary_build_payload, build_payload, self_financing_receipt,
            repo_map_payload, suggest_payload, repo_map_source_identities, source_cache, root_arg=root_arg,
        )
        if plan_only:
            return {
                "tool": TOOL_NAME, "schema_version": AUTO_SCHEMA_VERSION,
                "version": VERSION, "mode": "selection_plan",
                "selection_plan": selection_plan_payload,
            }, rc
        if expected_plan != selection_plan_payload:
            raise PackError("selection plan drift; regenerate the plan")
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
            "suggested": len(manifest.get("sources", [])),
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
    if (getattr(args, "adaptive_k", False) or apply_adaptive_k) and isinstance(
        suggest_payload.get("adaptive_k"), dict
    ):
        payload["adaptive_k"] = copy.deepcopy(suggest_payload["adaptive_k"])
    if adaptive_k_application is not None:
        payload["adaptive_k_application"] = adaptive_k_application
    if graph_application is not None:
        payload["graph_application"] = graph_application
    if self_financing_receipt is not None:
        payload["self_financing_selection"] = self_financing_receipt
    if selection_plan_payload is not None:
        payload["selection_plan"] = selection_plan_payload
        payload["selection_plan_application"] = {
            "status": "applied", "explicit": True,
            "revalidated_plan_id": selection_plan_payload["plan_id"],
        }
    if (getattr(args, "symbol_memory", False) or apply_symbol_memory) and isinstance(repo_map_payload, dict):
        payload["symbol_memory"] = build_symbol_memory_payload(
            repo_map_payload, applied=apply_symbol_memory
        )
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
    application = payload.get("adaptive_k_application")
    applied = isinstance(application, dict) and application.get("status") == "applied"
    print(
        "adaptive-k: "
        f"recommended={adaptive.get('recommended_k', 0)}/{adaptive.get('requested_top', 0)} "
        f"policy={policy.get('name', 'balanced')} "
        f"gates={regression_gates.get('status', 'pass')} "
        f"candidates={score_distribution.get('candidate_count', 0)} "
        f"budget_limited={budget_fit.get('budget_limited', False)} "
        f"apply={str(applied).lower()} reasons={reason_text or 'none'}"
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
    build_payload = payload.get("build", {}) if isinstance(payload.get("build"), dict) else {}
    sketch_duplicate = build_payload.get("sketch_duplicate_veto")
    sketch_suffix = ""
    if isinstance(sketch_duplicate, dict):
        cap_reached = str(bool(sketch_duplicate.get("comparison_cap_reached"))).lower()
        sketch_suffix = f" sketch_comparison_cap_reached={cap_reached}"
    print(
        f"context-guard-pack auto: {payload['sources']['suggested']} suggested source(s), "
        f"pack {payload['pack_bytes']}/{payload['budget_bytes']} bytes{sketch_suffix}"
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
    self_financing = payload.get("self_financing_selection")
    if isinstance(self_financing, dict):
        phases = self_financing.get("phase_results", {})
        phase_text = ",".join(
            f"{name}={phases.get(name, {}).get('status', 'no_op')}"
            for name in ("adaptive", "symbol", "graph")
        )
        print(
            "self-financing: "
            f"ceiling={self_financing.get('ordinary_pack_bytes', 0)} "
            f"selected={self_financing.get('selected_rendered_bytes', 0)} "
            f"{phase_text} provider_savings_claim=false"
        )
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
    build.add_argument(
        "--sketch-duplicate-veto",
        action="store_true",
        help=(
            "omit later rank-stable sanitized exact/sketch-set duplicates; use a fixed 100,000 verified-pair cap, "
            "then fail open; when enabled report sketch_comparison_cap_reached=true|false in text and "
            "sketch_duplicate_veto.comparison_cap_reached in JSON"
        ),
    )
    build.add_argument(
        "--delta-from-pack-id",
        type=pack_id_arg,
        metavar="PACK_ID",
        help=(
            "compare against one private local pack receipt using bounded rolling diagnostics; "
            "visible only in --json output or a stored receipt (--no-artifact requires --json)"
        ),
    )
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
    auto.add_argument(
        "--sketch-duplicate-veto",
        action="store_true",
        help=(
            "omit later rank-stable sanitized exact/sketch-set duplicates; use a fixed 100,000 verified-pair cap, "
            "then fail open; when enabled report sketch_comparison_cap_reached=true|false in text and "
            "sketch_duplicate_veto.comparison_cap_reached in JSON"
        ),
    )
    auto.add_argument(
        "--delta-from-pack-id",
        type=pack_id_arg,
        metavar="PACK_ID",
        help=(
            "compare against one private local pack receipt using bounded rolling diagnostics; "
            "visible only in --json output or a stored receipt (--no-artifact requires --json)"
        ),
    )
    auto.add_argument("--explain", action="store_true", help="include deterministic local selection/build explanation metadata")
    auto.add_argument("--adaptive-k", action="store_true", help="include local score/budget top-k advisory metadata without changing the manifest or pack")
    auto.add_argument(
        "--apply-adaptive-k",
        action="store_true",
        help=(
            "explicitly prune heuristic-selected sources to the locally recommended top-k "
            "after regression gates pass while always retaining explicit file/output/diff sources; "
            "implies --adaptive-k"
        ),
    )
    auto.add_argument("--adaptive-k-policy", choices=ADAPTIVE_K_POLICIES, default="balanced", help="local adaptive-k recommendation policy used when --adaptive-k is set")
    auto.add_argument("--adaptive-k-min-recall-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum recall proxy gate for --adaptive-k")
    auto.add_argument("--adaptive-k-min-precision-proxy", type=adaptive_k_threshold, default=0.0, help="metadata-only minimum precision proxy gate for --adaptive-k")
    auto.add_argument("--symbol-memory", action="store_true", help="include repo-map derived symbol/graph advisory metadata with exact source verification hints")
    auto.add_argument(
        "--apply-symbol-memory",
        action="store_true",
        help=(
            "explicitly add up to four direct import-neighbor slices from the local "
            "repo map to the manifest and pack; implies --symbol-memory"
        ),
    )
    auto.add_argument(
        "--self-financing-selection",
        action="store_true",
        help=(
            "explicitly apply Adaptive, then Symbol, then one-hop Graph selection while replacing "
            "only lower-value non-caller sources and never exceeding the ordinary pack bytes"
        ),
    )
    auto.add_argument(
        "--selection-plan", action="store_true",
        help="emit a read-only provider-free self-financing selection plan; requires --json",
    )
    auto.add_argument(
        "--apply-selection-plan", metavar="PLAN_JSON",
        help="explicitly apply a previously emitted selection plan after identity revalidation",
    )
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
            result = build_pack(
                root,
                specs,
                budget_bytes=budget,
                root_arg=str(args.root),
                store_artifact=not args.no_artifact,
                delta_from_pack_id=args.delta_from_pack_id,
                sketch_duplicate_veto=args.sketch_duplicate_veto,
            )
            if args.json:
                json.dump(result, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
                sys.stdout.write("\n")
            else:
                sys.stdout.write(str(result["pack"]))
                sketch_suffix = ""
                sketch_duplicate = result.get("sketch_duplicate_veto")
                if isinstance(sketch_duplicate, dict):
                    cap_reached = str(bool(sketch_duplicate.get("comparison_cap_reached"))).lower()
                    sketch_suffix = f" sketch_comparison_cap_reached={cap_reached}"
                print(
                    f"[context-guard-pack] pack_id={result['pack_id']} bytes={result['pack_bytes']}/{result['budget_bytes']} "
                    f"included={result['sources']['included']} partial={result['sources']['partial']} omitted={result['sources']['omitted']}"
                    f"{sketch_suffix}",
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
