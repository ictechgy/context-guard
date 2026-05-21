#!/usr/bin/env python3
"""Sanitize grep/diff/log output before it enters Claude context.

The helper can wrap a command while preserving its exit code, or sanitize stdin.
It redacts common credential patterns, anonymizes absolute paths by default, and
keeps only bounded head/anchor/tail context when output is too large.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
from pathlib import PurePosixPath
import re
import subprocess
import sys
from typing import Iterable, TextIO

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# Match plausible absolute file paths without treating operators (`//`) or
# tiny string literals (`"/"`) as paths. Requiring at least one directory plus
# one leaf keeps the sanitizer from corrupting code while still anonymizing
# common grep/test output like /Users/me/project/app.py:12.
PATH_SEGMENT = r"[A-Za-z0-9._~+\-]+"
ABSOLUTE_PATH_RE = re.compile(
    rf"(?P<prefix>^|[\s('\"=])(?P<path>/(?:{PATH_SEGMENT}/)+{PATH_SEGMENT})"
)
WINDOWS_PATH_RE = re.compile(
    rf"(?P<prefix>^|[\s('\"=])(?P<path>[A-Za-z]:\\(?:{PATH_SEGMENT}\\)+{PATH_SEGMENT})"
)
PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
)
AUTH_HEADER_RE = re.compile(
    r"(?i)^(?P<prefix>\s*(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:Proxy-)?Authorization\s*:\s*).+$"
)
SECRET_KEY = (
    r"[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*"
    r"|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
    r"GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET"
)
INLINE_QUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<quote>[\"'])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)"
)
INLINE_UNQUOTED_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?P<lead>^|[\s{{\[,])"
    rf"(?P<prefix>(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*)"
    rf"(?P<value>[^\s,;}}\]]+)(?P<trailing>[;]?)"
)
SAFE_UNQUOTED_VALUES = {
    "[redacted]",
    "false",
    "none",
    "null",
    "os.getenv",
    "process.env",
    "true",
    "undefined",
}
IDENTIFIER_CHAIN_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
INLINE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;](?:{SECRET_KEY})=)[^\s&#;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--(?:api[_-]?key|token|secret|password|client[_-]?secret)\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--(?:api[_-]?key|token|secret|password|client[_-]?secret)=)\S+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:-p|-u|--user)\s+)\S+:\S+"), r"\1[REDACTED]"),
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
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE), r"\1[REDACTED]@"),
)
ANCHOR_RE = re.compile(
    r"^(?:diff --git |index [0-9a-f]|--- |\+\+\+ |@@ |Binary files |(?:[^:\n]+):\d+(?::\d+)?:)",
    re.IGNORECASE,
)
SECRET_WORD_RE = re.compile(r"(?i)\b(api[_-]?key|token|secret|password|private[_-]?key|client[_-]?secret)\b")
MAX_LINES_LIMIT = 5_000
MAX_CHARS_LIMIT = 1_000_000
MAX_LINE_CHARS_LIMIT = 100_000
MAX_SECTION_LINES_LIMIT = 2_000


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def normalize_budgets(args: argparse.Namespace) -> None:
    args.max_lines = bounded_int(args.max_lines, 240, 1, MAX_LINES_LIMIT)
    args.max_chars = bounded_int(args.max_chars, 24000, 1, MAX_CHARS_LIMIT)
    args.max_line_chars = bounded_int(args.max_line_chars, 3000, 1, MAX_LINE_CHARS_LIMIT)
    args.head_lines = bounded_int(args.head_lines, 50, 0, MAX_SECTION_LINES_LIMIT)
    args.tail_lines = bounded_int(args.tail_lines, 90, 0, MAX_SECTION_LINES_LIMIT)
    args.anchor_lines = bounded_int(args.anchor_lines, 80, 0, MAX_SECTION_LINES_LIMIT)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def stable_hash(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def anonymize_absolute_paths(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        path = match.group("path")
        normalized = path.replace("\\", "/")
        name = PurePosixPath(normalized).name or "path"
        return f"{prefix}{name}#path:{stable_hash(path)}"

    text = ABSOLUTE_PATH_RE.sub(repl, text)
    return WINDOWS_PATH_RE.sub(repl, text)


def cap_line(line: str, max_line_chars: int) -> tuple[str, bool]:
    if max_line_chars <= 0 or len(line) <= max_line_chars:
        return line, False
    newline = "\n" if line.endswith("\n") else ""
    body = line[:-1] if newline else line
    marker = f"...[line trimmed: {len(body)} chars]"
    keep = max(0, max_line_chars - len(marker) - len(newline))
    return body[:keep] + marker + newline, True


def should_redact_unquoted_secret_value(line: str, match: re.Match[str]) -> bool:
    value = match.group("value").strip()
    if not value:
        return False
    if value.lower() in SAFE_UNQUOTED_VALUES:
        return False
    if IDENTIFIER_CHAIN_RE.match(value):
        return False
    end = match.end("value")
    if end < len(line) and line[end] in "([{":
        # Likely a function call or expression (`api_key = os.getenv(...)`);
        # preserve it so Claude can still reason about code flow.
        return False
    if any(ch in value for ch in "()[]{}"):
        return False
    return True


def redact_secret_assignments(line: str) -> tuple[str, bool]:
    redacted = False

    def quoted_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        redacted = True
        return f"{match.group('lead')}{match.group('prefix')}{match.group('quote')}[REDACTED]{match.group('quote')}"

    def unquoted_repl(match: re.Match[str]) -> str:
        nonlocal redacted
        if not should_redact_unquoted_secret_value(line, match):
            return match.group(0)
        redacted = True
        return f"{match.group('lead')}{match.group('prefix')}[REDACTED]{match.group('trailing')}"

    line = INLINE_QUOTED_SECRET_ASSIGNMENT_RE.sub(quoted_repl, line)
    line = INLINE_UNQUOTED_SECRET_ASSIGNMENT_RE.sub(unquoted_repl, line)
    return line, redacted


MULTILINE_SECRET_ASSIGNMENT_RE = re.compile(
    rf"(?i)(?:^|[\s{{\[,])(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:export\s+)?"
    rf"[\"']?(?:{SECRET_KEY})[\"']?\s*[:=]\s*(?P<quote>[\"'])"
)


def has_unescaped_quote(text: str, quote: str, start: int = 0) -> bool:
    """Return True when text contains an unescaped quote delimiter."""
    escaped = False
    for char in text[start:]:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == quote:
            return True
    return False


def detect_multiline_secret_assignment(line: str) -> str | None:
    """Return the quote delimiter when any secret assignment starts a multiline value."""
    for marker in MULTILINE_SECRET_ASSIGNMENT_RE.finditer(line):
        quote = marker.group("quote")
        if not has_unescaped_quote(line, quote, marker.end("quote")):
            return quote
    return None


def private_key_state_after_line(line: str) -> bool | None:
    """Return updated private-key state for a line, or None when no marker appears."""
    if PRIVATE_KEY_BEGIN_RE.search(line):
        return not bool(PRIVATE_KEY_END_RE.search(line))
    if PRIVATE_KEY_END_RE.search(line):
        return False
    return None


def secret_or_private_key_redaction_label(line: str) -> str:
    if PRIVATE_KEY_BEGIN_RE.search(line) or PRIVATE_KEY_END_RE.search(line):
        return "[REDACTED PRIVATE KEY BLOCK]\n"
    return "[REDACTED MULTILINE SECRET]\n"


class LineSanitizer:
    def __init__(self, *, show_paths: bool = False) -> None:
        self.show_paths = show_paths
        self.in_private_key_block = False
        self.multiline_secret_quote: str | None = None
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        line = strip_ansi(raw_line)
        redacted = False
        diff_prefix = ""
        stripped_for_key = line.lstrip()
        if stripped_for_key.startswith(('+', '-')):
            diff_prefix = stripped_for_key[0]

        if self.multiline_secret_quote is not None:
            redacted = True
            label = "[REDACTED PRIVATE KEY BLOCK]\n" if (
                self.in_private_key_block or PRIVATE_KEY_BEGIN_RE.search(line) or PRIVATE_KEY_END_RE.search(line)
            ) else "[REDACTED MULTILINE SECRET]\n"
            key_state = private_key_state_after_line(line)
            if key_state is not None:
                self.in_private_key_block = key_state
            if has_unescaped_quote(line, self.multiline_secret_quote):
                self.multiline_secret_quote = None
            return self._finish(diff_prefix + label, redacted)

        if self.in_private_key_block:
            redacted = True
            if PRIVATE_KEY_END_RE.search(line):
                self.in_private_key_block = False
            return self._finish(diff_prefix + "[REDACTED PRIVATE KEY BLOCK]\n", redacted)

        multiline_quote = detect_multiline_secret_assignment(line)
        if multiline_quote is not None:
            self.multiline_secret_quote = multiline_quote
            key_state = private_key_state_after_line(line)
            if key_state is not None:
                self.in_private_key_block = key_state
            return self._finish(diff_prefix + secret_or_private_key_redaction_label(line), True)

        if PRIVATE_KEY_BEGIN_RE.search(line):
            redacted = True
            if not PRIVATE_KEY_END_RE.search(line):
                self.in_private_key_block = True
            return self._finish(diff_prefix + "[REDACTED PRIVATE KEY BLOCK]\n", redacted)

        new_line, count = AUTH_HEADER_RE.subn(r"\g<prefix>[REDACTED]", line)
        if count:
            redacted = True
            line = new_line

        line, assignment_redacted = redact_secret_assignments(line)
        if assignment_redacted:
            redacted = True

        for pattern, replacement in INLINE_PATTERNS:
            line, count = pattern.subn(replacement, line)
            if count:
                redacted = True

        return self._finish(line, redacted)

    def _finish(self, line: str, redacted: bool) -> tuple[str, bool]:
        if redacted:
            self.redactions += 1
        if not self.show_paths:
            line = anonymize_absolute_paths(line)
        return line, redacted


class BoundedOutput:
    def __init__(
        self,
        *,
        max_lines: int,
        max_chars: int,
        max_line_chars: int,
        head_lines: int,
        tail_lines: int,
        anchor_lines: int,
    ) -> None:
        self.max_lines = max_lines
        self.max_chars = max_chars
        self.max_line_chars = max_line_chars
        self.head_limit = max(0, head_lines)
        self.tail = collections.deque(maxlen=max(0, tail_lines))
        self.anchor_limit = max(0, anchor_lines)
        self.head: list[str] = []
        self.anchors: list[str] = []
        self.anchor_seen: set[str] = set()
        self.full: list[str] = []
        self.line_count = 0
        self.raw_chars = 0
        self.visible_chars = 0
        self.line_caps = 0
        self.trimmed = False

    def add(self, raw_line: str, sanitized_line: str, *, redacted: bool) -> None:
        self.line_count += 1
        self.raw_chars += len(raw_line)
        capped, was_capped = cap_line(sanitized_line, self.max_line_chars)
        if was_capped:
            self.line_caps += 1
        self.visible_chars += len(capped)

        if len(self.head) < self.head_limit:
            self.head.append(capped)
        self.tail.append(capped)
        if self._is_anchor(capped, redacted):
            key = capped.rstrip("\n")
            if key not in self.anchor_seen and len(self.anchors) < self.anchor_limit:
                self.anchor_seen.add(key)
                self.anchors.append(capped)

        if not self.trimmed:
            self.full.append(capped)
            if (self.max_lines > 0 and self.line_count > self.max_lines) or (
                self.max_chars > 0 and self.visible_chars > self.max_chars
            ):
                self.trimmed = True

    def _is_anchor(self, line: str, redacted: bool) -> bool:
        return redacted or bool(ANCHOR_RE.search(line)) or bool(SECRET_WORD_RE.search(line))

    def render(self, redactions: int) -> str:
        if not self.trimmed:
            return "".join(self.full)

        lines_budget = self.max_lines if self.max_lines > 0 else 240
        remaining = max(0, lines_budget - 8)
        head_n = min(len(self.head), max(1, remaining // 3) if remaining else 0)
        anchor_n = min(len(self.anchors), max(0, remaining // 3))
        tail_n = min(len(self.tail), max(0, remaining - head_n - anchor_n))

        rendered: list[str] = [
            (
                "[claude-token-kit] sanitized output trimmed: "
                f"lines={self.line_count} raw_chars={self.raw_chars} "
                f"sanitized_chars={self.visible_chars} redacted_lines={redactions} "
                f"line_caps={self.line_caps}\n"
            )
        ]
        if head_n:
            rendered.append(f"--- head ({head_n} lines) ---\n")
            rendered.extend(self.head[:head_n])
        if anchor_n:
            rendered.append(f"--- grep/diff/security anchors ({anchor_n} lines) ---\n")
            rendered.extend(self.anchors[:anchor_n])
        if tail_n:
            rendered.append(f"--- tail ({tail_n} lines) ---\n")
            rendered.extend(list(self.tail)[-tail_n:])
        text = "".join(rendered)
        if self.max_chars > 0 and len(text) > self.max_chars:
            marker = f"\n[claude-token-kit] rendered sanitized summary capped: {len(text)} chars\n"
            keep = max(0, self.max_chars - len(marker))
            text = text[:keep].rstrip() + marker
        return text


def sanitize_stream(stream: Iterable[str], args: argparse.Namespace) -> tuple[str, int, int]:
    sanitizer = LineSanitizer(show_paths=args.show_paths)
    bounded = BoundedOutput(
        max_lines=args.max_lines,
        max_chars=args.max_chars,
        max_line_chars=args.max_line_chars,
        head_lines=args.head_lines,
        tail_lines=args.tail_lines,
        anchor_lines=args.anchor_lines,
    )
    for raw_line in stream:
        sanitized, redacted = sanitizer.sanitize(raw_line)
        bounded.add(raw_line, sanitized, redacted=redacted)
    return bounded.render(sanitizer.redactions), sanitizer.redactions, bounded.line_count


def run_command(command: list[str]) -> tuple[Iterable[str], subprocess.Popen[str] | None, int | None]:
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors="replace",
        )
    except OSError as exc:
        print(f"claude-sanitize-output: command failed to start: {exc}", file=sys.stderr)
        return [], None, 127
    if proc.stdout is None:
        print("claude-sanitize-output: subprocess produced no stdout pipe", file=sys.stderr)
        return [], proc, 1
    return proc.stdout, proc, None


def stdin_has_data(stdin: TextIO) -> bool:
    return not stdin.isatty()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Redact secrets and budget grep/diff/log output before sending it to Claude."
    )
    parser.add_argument("--max-lines", type=int, default=240)
    parser.add_argument("--max-chars", type=int, default=24000)
    parser.add_argument("--max-line-chars", type=int, default=3000)
    parser.add_argument("--head-lines", type=int, default=50)
    parser.add_argument("--tail-lines", type=int, default=90)
    parser.add_argument("--anchor-lines", type=int, default=80)
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths instead of anonymizing them as basename#path:<hash>",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    normalize_budgets(args)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]

    proc: subprocess.Popen[str] | None = None
    early_rc: int | None = None
    if command:
        stream, proc, early_rc = run_command(command)
        if early_rc is not None and proc is None:
            return early_rc
    elif stdin_has_data(sys.stdin):
        stream = sys.stdin
    else:
        print("claude-sanitize-output: missing command or stdin", file=sys.stderr)
        return 2

    output, _redactions, _line_count = sanitize_stream(stream, args)
    if output:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")

    if proc is not None:
        rc = proc.wait()
        return early_rc if early_rc is not None else rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
