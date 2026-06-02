#!/usr/bin/env python3
"""Classify stdin content and emit a sanitized, token-budget-friendly compression.

The CLI never promises lossless *semantic* compression. It performs conservative,
deterministic, content-type-aware shrinking (compact JSON, diff change-only views,
log/search de-duplication, whitespace normalization) so large local output costs
fewer tokens to keep in context. Secrets are redacted *before* the receipt is built,
so no secret ever reaches the compressed body or the metadata.

For exact byte-for-byte recovery the receipt points at `context-guard-artifact store`,
which keeps the full sanitized content as a queryable local artifact.
"""
from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from typing import Callable

DEFAULT_MAX_BYTES = 10_000_000
MAX_MAX_BYTES = 100_000_000
# 토큰 추정은 보수적 proxy 일 뿐이다(관측값 아님). 평균 ~4 chars/token 휴리스틱을 쓰되
# 메타데이터에 measurement="estimated" 로 명시해 관측 토큰 수와 혼동되지 않게 한다.
TOKEN_PROXY_CHARS_PER_TOKEN = 4
CONTENT_TYPES = ("json", "diff", "log", "search", "code", "prose")

# diff 구조 라인(파일 헤더/헝크/변경)을 식별한다. 나머지 context 라인은 접어서 줄인다.
DIFF_FILE_HEADER_RE = re.compile(r"^(diff --git |index [0-9a-f]|--- |\+\+\+ |rename |similarity |new file|deleted file)")
DIFF_HUNK_RE = re.compile(r"^@@ .* @@")
# search(grep/ripgrep) 라인: `path:line:content` 또는 `path:content`.
SEARCH_LINE_RE = re.compile(r"^[^\s:][^:\n]*:(?:\d+:)?.")
# log 시그널: 선두 타임스탬프나 로그 레벨 토큰.
LOG_LEVEL_RE = re.compile(r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL)\b")
LOG_TIMESTAMP_RE = re.compile(r"^\s*(?:\[)?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|^\s*\d{2}:\d{2}:\d{2}\b")
# code 시그널: 흔한 소스 키워드/구두점. diff 와 겹치지 않도록 diff 판정을 먼저 한다.
CODE_SIGNAL_RE = re.compile(
    r"(^\s*(def |class |function |func |import |from \S+ import |public |private |const |let |var |#include|package )"
    r"|[{};]\s*$|=>|::)"
)


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    """Clamp an int-like value into [minimum, maximum], falling back on default."""
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


class FallbackLineSanitizer:
    """Minimal secret scrubber used when the shared sanitizer cannot be loaded."""

    SECRET_VALUE_RE = re.compile(
        r"(?i)(Bearer\s+\S+|Basic\s+\S+|gh[pousr]_[A-Za-z0-9_]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|"
        r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9][A-Za-z0-9_-]{20,}|"
        r"AIza[0-9A-Za-z_\-]{20,}|"
        r"([A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|passwd|pwd)[A-Za-z0-9_.-]*\s*[:=]\s*)\S+)"
    )

    def __init__(self, *, show_paths: bool = False) -> None:
        self.show_paths = show_paths
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        def repl(match: re.Match[str]) -> str:
            groups = match.groups()
            if len(groups) >= 2 and groups[1]:
                return groups[1] + "[REDACTED]"
            return "[REDACTED]"

        line, count = self.SECRET_VALUE_RE.subn(repl, raw_line)
        if count:
            self.redactions += 1
        return line, bool(count)


def load_line_sanitizer(show_paths: bool) -> object:
    """Reuse the shipped strong sanitizer when present; else fall back locally.

    Mirrors context_escrow.py so the compress CLI redacts with the same rules
    as the rest of the kit when `sanitize_output.py` sits next to this script.
    """
    script_dir = Path(__file__).resolve().parent
    for name in ("sanitize_output.py", "context-guard-sanitize-output", "claude-sanitize-output"):
        candidate = script_dir / name
        if not candidate.exists():
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_context_guard_compress_sanitize_{os.getpid()}", str(candidate))
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
    """Redact secrets line-by-line, returning sanitized text and redacted-line count."""
    sanitizer = load_line_sanitizer(show_paths)
    redacted = 0
    out: list[str] = []
    for line in text.splitlines(True):
        sanitized, did_redact = sanitizer.sanitize(line)  # type: ignore[attr-defined]
        out.append(sanitized)
        if did_redact:
            redacted += 1
    return "".join(out), redacted


def read_bounded_stdin(max_bytes: int) -> tuple[str, bool, int]:
    """Read at most max_bytes from stdin, reporting truncation and bytes read."""
    data = sys.stdin.buffer.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated, len(data)


def line_count(text: str) -> int:
    """Count logical lines without an off-by-one on a trailing newline."""
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def byte_length(text: str) -> int:
    """UTF-8 byte length using the same lossy decode policy as the rest of the kit."""
    return len(text.encode("utf-8", errors="replace"))


def token_proxy(text: str) -> int:
    """Conservative token estimate (chars/4). Labeled 'estimated' in metadata."""
    if not text:
        return 0
    return max(1, round(len(text) / TOKEN_PROXY_CHARS_PER_TOKEN))


def classify_content(text: str) -> str:
    """Best-effort content classification into one of CONTENT_TYPES.

    Order matters: JSON and diff have the strongest unambiguous signals and are
    checked first; search/log/code are sampled over the first lines; prose is the
    conservative default so unknown text is never over-compressed.
    """
    stripped = text.strip()
    if not stripped:
        return "prose"
    if _looks_like_json(stripped):
        return "json"
    lines = stripped.splitlines()
    sample = lines[:200]
    if _looks_like_diff(sample):
        return "diff"
    if _looks_like_search(sample):
        return "search"
    if _looks_like_log(sample):
        return "log"
    if _looks_like_code(sample):
        return "code"
    return "prose"


def _looks_like_json(stripped: str) -> bool:
    if stripped[0] not in "{[":
        return False
    try:
        json.loads(stripped)
    except (ValueError, RecursionError):
        return False
    return True


def _ratio(matches: int, total: int, threshold: float) -> bool:
    return bool(total) and (matches / total) >= threshold


def _looks_like_diff(sample: list[str]) -> bool:
    headers = sum(1 for line in sample if DIFF_FILE_HEADER_RE.match(line) or DIFF_HUNK_RE.match(line))
    changes = sum(1 for line in sample if line[:1] in "+-" and not line.startswith(("+++", "---")))
    return headers >= 1 and (changes >= 1 or headers >= 2)


def _looks_like_search(sample: list[str]) -> bool:
    matches = sum(1 for line in sample if SEARCH_LINE_RE.match(line))
    return _ratio(matches, len(sample), 0.6) and len(sample) >= 2


def _looks_like_log(sample: list[str]) -> bool:
    matches = sum(1 for line in sample if LOG_TIMESTAMP_RE.match(line) or LOG_LEVEL_RE.search(line))
    return _ratio(matches, len(sample), 0.4)


def _looks_like_code(sample: list[str]) -> bool:
    matches = sum(1 for line in sample if CODE_SIGNAL_RE.search(line))
    return _ratio(matches, len(sample), 0.25)


def compress_json(text: str) -> tuple[str, dict[str, object]]:
    """Re-serialize JSON without insignificant whitespace (data-preserving)."""
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        # 파싱 불가 시 무손실을 깨지 않도록 prose 전략으로 안전하게 폴백한다.
        compressed, detail = compress_prose(text)
        detail["fallback_from"] = "json"
        return compressed, detail
    compact = json.dumps(parsed, ensure_ascii=False, separators=(",", ":"))
    if not text.endswith("\n"):
        trailing = ""
    else:
        trailing = "\n"
    return compact + trailing, {"strategy": "json-compact", "lossy": False, "json_parse_ok": True}


def compress_diff(text: str) -> tuple[str, dict[str, object]]:
    """Keep file headers, hunk headers, and +/- changes; collapse context runs."""
    out: list[str] = []
    context_run = 0
    collapsed = 0

    def flush() -> None:
        nonlocal context_run, collapsed
        if context_run:
            out.append(f"[context-guard-kit] {context_run} unchanged context line(s) omitted")
            collapsed += context_run
            context_run = 0

    for line in text.splitlines():
        is_structural = bool(DIFF_FILE_HEADER_RE.match(line) or DIFF_HUNK_RE.match(line))
        is_change = line[:1] in "+-" and not line.startswith(("+++", "---"))
        if is_structural or is_change:
            flush()
            out.append(line)
        elif line.startswith(" ") or line == "":
            context_run += 1
        else:
            flush()
            out.append(line)
    flush()
    return _join_lines(out, text), {"strategy": "diff-keep-changes", "lossy": True, "context_lines_omitted": collapsed}


def compress_log(text: str) -> tuple[str, dict[str, object]]:
    """Collapse consecutive identical lines into a single `line (xN)` marker."""
    out: list[str] = []
    collapsed = 0
    previous: str | None = None
    run = 0

    def flush() -> None:
        nonlocal previous, run, collapsed
        if previous is None:
            return
        if run > 1:
            out.append(f"{previous}  (x{run})")
            collapsed += run - 1
        else:
            out.append(previous)
        previous, run = None, 0

    for line in text.splitlines():
        if line == previous:
            run += 1
            continue
        flush()
        previous, run = line, 1
    flush()
    return _join_lines(out, text), {"strategy": "log-collapse-repeats", "lossy": True, "lines_collapsed": collapsed}


def compress_search(text: str) -> tuple[str, dict[str, object]]:
    """Drop exact-duplicate match lines while preserving first-seen order."""
    out: list[str] = []
    seen: set[str] = set()
    dropped = 0
    for line in text.splitlines():
        key = line.rstrip()
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        out.append(line)
    return _join_lines(out, text), {"strategy": "search-dedupe", "lossy": dropped > 0, "duplicate_lines_dropped": dropped}


def compress_code(text: str) -> tuple[str, dict[str, object]]:
    """Trim trailing whitespace and collapse 3+ blank lines to a single blank."""
    return _whitespace_normalize(text, strategy="code-whitespace", max_consecutive_blank=1)


def compress_prose(text: str) -> tuple[str, dict[str, object]]:
    """Trim trailing whitespace and collapse 2+ blank lines to a single blank."""
    return _whitespace_normalize(text, strategy="prose-whitespace", max_consecutive_blank=1)


def _whitespace_normalize(text: str, *, strategy: str, max_consecutive_blank: int) -> tuple[str, dict[str, object]]:
    out: list[str] = []
    blank_run = 0
    collapsed = 0
    for line in text.splitlines():
        trimmed = line.rstrip()
        if trimmed == "":
            blank_run += 1
            if blank_run > max_consecutive_blank:
                collapsed += 1
                continue
        else:
            blank_run = 0
        out.append(trimmed)
    lossy = collapsed > 0 or any(line != line.rstrip() for line in text.splitlines())
    return _join_lines(out, text), {"strategy": strategy, "lossy": lossy, "blank_lines_collapsed": collapsed}


def _join_lines(lines: list[str], original: str) -> str:
    """Join compressed lines, restoring a trailing newline only if the input had one."""
    body = "\n".join(lines)
    if original.endswith("\n") and body and not body.endswith("\n"):
        body += "\n"
    return body


STRATEGIES: dict[str, Callable[[str], tuple[str, dict[str, object]]]] = {
    "json": compress_json,
    "diff": compress_diff,
    "log": compress_log,
    "search": compress_search,
    "code": compress_code,
    "prose": compress_prose,
}


def build_metadata(
    *,
    content_type: str,
    type_source: str,
    strategy_detail: dict[str, object],
    original_text: str,
    compressed_text: str,
    redacted_lines: int,
    input_truncated: bool,
    input_bytes: int,
    max_bytes: int,
) -> dict[str, object]:
    """Assemble the compress receipt: observed byte/line counts plus an estimated token proxy.

    `redacted_lines` is computed before this point (redaction-before-receipt), so the
    metadata can be safely emitted. A deterministic retrieval hint points at escrow for
    exact-byte recovery because every strategy except json-compact is lossy.
    """
    original_bytes = byte_length(original_text)
    compressed_bytes = byte_length(compressed_text)
    ratio = round(compressed_bytes / original_bytes, 4) if original_bytes else 1.0
    lossy = bool(strategy_detail.get("lossy", True))
    retrieval_hint = (
        "Lossy: store the full sanitized text for exact recovery via "
        "`context-guard-artifact store` and query slices later."
        if lossy
        else "Data-preserving: compact form is semantically equivalent to the sanitized input."
    )
    return {
        "tool": "context-guard-kit.context_compress",
        "metadata_version": 1,
        "content_type": content_type,
        "type_source": type_source,
        "strategy": strategy_detail.get("strategy"),
        "strategy_detail": strategy_detail,
        "lossy": lossy,
        "input": {
            "bytes_read": input_bytes,
            "truncated": input_truncated,
            "max_bytes": max_bytes,
        },
        "redaction": {
            "redacted_lines": redacted_lines,
            "redacted_before_receipt": True,
        },
        "bytes": {
            "measurement": "observed",
            "original": original_bytes,
            "compressed": compressed_bytes,
            "saved": original_bytes - compressed_bytes,
            "compression_ratio": ratio,
        },
        "lines": {
            "measurement": "observed",
            "original": line_count(original_text),
            "compressed": line_count(compressed_text),
        },
        "token_proxy": {
            "measurement": "estimated",
            "method": f"chars_div_{TOKEN_PROXY_CHARS_PER_TOKEN}",
            "original": token_proxy(original_text),
            "compressed": token_proxy(compressed_text),
        },
        "retrieval_hint": (
            "Lossy: store the full sanitized text for exact recovery via "
            "`context-guard-artifact store` and query slices later."
        ),
    }


def compress_text(
    text: str,
    *,
    forced_type: str | None,
    show_paths: bool,
    input_truncated: bool,
    input_bytes: int,
    max_bytes: int,
) -> tuple[str, dict[str, object]]:
    """Sanitize first, then classify and compress, then build the receipt.

    Redaction runs on the raw input so no secret can leak into the classifier,
    the compressed body, or the metadata that follows.
    """
    sanitized, redacted_lines = sanitize_text(text, show_paths=show_paths)
    if forced_type is not None:
        content_type, type_source = forced_type, "override"
    else:
        content_type, type_source = classify_content(sanitized), "detected"
    compressed, strategy_detail = STRATEGIES[content_type](sanitized)
    # 보수성 보장: 어떤 전략도 입력보다 큰 결과를 내보내지 않는다. 작은 입력에서
    # 접기 마커가 원본보다 길어지는 경우 살균된 원본을 그대로 유지한다.
    if byte_length(compressed) >= byte_length(sanitized):
        compressed = sanitized
        strategy_detail["reduced"] = False
    else:
        strategy_detail["reduced"] = True
    metadata = build_metadata(
        content_type=content_type,
        type_source=type_source,
        strategy_detail=strategy_detail,
        original_text=sanitized,
        compressed_text=compressed,
        redacted_lines=redacted_lines,
        input_truncated=input_truncated,
        input_bytes=input_bytes,
        max_bytes=max_bytes,
    )
    return compressed, metadata


def render_text_receipt(metadata: dict[str, object]) -> str:
    """One-block human summary written to stderr in text mode."""
    byte_stats = metadata.get("bytes", {})
    token_stats = metadata.get("token_proxy", {})
    redaction = metadata.get("redaction", {})
    lines = [
        "[context-guard-kit] compress",
        f"- content_type: {metadata.get('content_type')} ({metadata.get('type_source')})",
        f"- strategy: {metadata.get('strategy')} (lossy={str(metadata.get('lossy')).lower()})",
    ]
    if isinstance(byte_stats, dict):
        lines.append(
            f"- bytes: {byte_stats.get('original')} -> {byte_stats.get('compressed')} "
            f"(ratio={byte_stats.get('compression_ratio')})"
        )
    if isinstance(token_stats, dict):
        lines.append(
            f"- token_proxy(estimated): {token_stats.get('original')} -> {token_stats.get('compressed')}"
        )
    if isinstance(redaction, dict) and redaction.get("redacted_lines"):
        lines.append(f"- redacted_lines: {redaction.get('redacted_lines')}")
    return "\n".join(lines) + "\n"


def run_compress(args: argparse.Namespace) -> int:
    """Read stdin, compress, then emit JSON or (compressed text + stderr receipt)."""
    max_bytes = bounded_int(args.max_bytes, DEFAULT_MAX_BYTES, 1, MAX_MAX_BYTES)
    raw_text, input_truncated, input_bytes = read_bounded_stdin(max_bytes)
    forced_type = args.type
    if forced_type is not None and forced_type not in STRATEGIES:
        print(f"context-guard-compress: unknown --type: {forced_type}", file=sys.stderr)
        return 2
    compressed, metadata = compress_text(
        raw_text,
        forced_type=forced_type,
        show_paths=args.show_paths,
        input_truncated=input_truncated,
        input_bytes=input_bytes,
        max_bytes=max_bytes,
    )
    if args.json:
        payload = {"metadata": metadata, "content": compressed}
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.metadata_only:
        print(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        sys.stdout.write(compressed)
        if not args.quiet:
            sys.stderr.write(render_text_receipt(metadata))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify and conservatively compress stdin (sanitized) for token-budget reuse.",
    )
    parser.add_argument(
        "--type",
        choices=CONTENT_TYPES,
        default=None,
        help="force a content type instead of auto-detecting (json/diff/log/search/code/prose)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON with metadata and compressed content")
    parser.add_argument(
        "--metadata-only",
        action="store_true",
        help="emit only the JSON metadata receipt (no compressed body)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the text receipt on stderr in text mode")
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths instead of path hashes; local debugging only because private paths may be exposed",
    )
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="maximum stdin bytes to read before truncating")
    parser.set_defaults(func=run_compress)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except RuntimeError as exc:
        print(f"context-guard-compress: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
