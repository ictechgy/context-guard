#!/usr/bin/env python3
"""Run a command, preserve exit code, and print a token-budgeted output summary.

Designed for Claude Code Bash tool output. It avoids dumping thousands of log
lines into the conversation while preserving the lines most likely to be useful.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import PurePosixPath
import re
import subprocess
import sys
from typing import Iterable

MAX_SUMMARY_ITEM_CHARS = 500
MAX_LINES_LIMIT = 5_000
MAX_CHARS_LIMIT = 1_000_000
MAX_LINE_CHARS_LIMIT = 100_000
MAX_SECTION_LINES_LIMIT = 2_000
MAX_RUNNER_SUMMARY_ITEMS_LIMIT = 100


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def normalize_budgets(args: argparse.Namespace) -> None:
    args.max_lines = bounded_int(args.max_lines, 220, 1, MAX_LINES_LIMIT)
    args.max_chars = bounded_int(args.max_chars, 20000, 1, MAX_CHARS_LIMIT)
    args.max_line_chars = bounded_int(args.max_line_chars, 4000, 1, MAX_LINE_CHARS_LIMIT)
    args.head_lines = bounded_int(args.head_lines, 40, 0, MAX_SECTION_LINES_LIMIT)
    args.tail_lines = bounded_int(args.tail_lines, 80, 0, MAX_SECTION_LINES_LIMIT)
    args.error_lines = bounded_int(args.error_lines, 120, 0, MAX_SECTION_LINES_LIMIT)
    args.runner_summary_items = bounded_int(args.runner_summary_items, 12, 0, MAX_RUNNER_SUMMARY_ITEMS_LIMIT)

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ABSOLUTE_PATH_RE = re.compile(r"(?P<prefix>^|[\s('\"=])(?P<path>/(?:[^\s:(),]+/)*[^\s:(),]+)")
SECRET_KEY = (
    r"[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*"
)
FALLBACK_INLINE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bAIza[0-9A-Za-z_\-]{20,}\b"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;](?:{SECRET_KEY})=)[^\s&#;]+"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)(\b(?:{SECRET_KEY})\s*[:=]\s*)[^\s]+"), r"\1[REDACTED]"),
)
FALLBACK_AUTH_HEADER_RE = re.compile(
    r"(?i)^(?P<prefix>\s*(?:(?:[^:\n]+):\d+(?::\d+)?:)?\s*(?:[+-]\s*)?(?:Proxy-)?Authorization\s*:\s*).+$"
)
ERROR_RE = re.compile(
    r"(FAIL|FAILED|ERROR|Error:|Exception|Traceback|AssertionError|panic:|fatal:|"
    r"segmentation fault|not ok|\bE\s+assert|\[ERROR\]|✗|✖)",
    re.IGNORECASE,
)
PYTEST_RESULT_RE = re.compile(r"^(?P<kind>FAILED|ERROR)\s+(?P<node>\S+)(?:\s+-\s+(?P<reason>.*))?$")
PYTEST_LOCATION_RE = re.compile(r"^(?P<file>[^:\s][^:\n]*\.py):(?P<line>\d+):(?P<message>.*)$")
JEST_FILE_RE = re.compile(
    r"^\s*FAIL\s+(?P<file>\S+(?:\.(?:test|spec)\.[cm]?[jt]sx?|__tests__/\S+\.[cm]?[jt]sx?))"
    r"(?:\s+>\s+(?P<name>.+))?\s*$"
)
JEST_TEST_RE = re.compile(r"^\s*[●✕×]\s+(?P<name>.+?)\s*$")
JEST_AT_RE = re.compile(
    r"^\s*at\s+(?:.+?\s+\()?(?P<file>[^()\s]+?\.[cm]?[jt]sx?):(?P<line>\d+):(?P<col>\d+)\)?\s*$"
)
VITEST_LOCATION_RE = re.compile(r"^\s*❯\s+(?P<file>[^()\s]+?\.[cm]?[jt]sx?):(?P<line>\d+):(?P<col>\d+)\s*$")
GO_FAIL_RE = re.compile(r"^--- FAIL: (?P<name>\S+)(?:\s+\([^)]+\))?")
GO_LOCATION_RE = re.compile(r"^\s*(?P<file>[^:\s]+_test\.go):(?P<line>\d+):\s*(?P<message>.*)$")
RUST_THREAD_RE = re.compile(
    r"^thread '(?P<name>[^']+)' panicked at (?:.*,\s+)?(?P<file>[^,\n]+?\.rs):(?P<line>\d+):(?P<col>\d+):?"
)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def anonymize_absolute_paths(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        path = match.group("path")
        name = PurePosixPath(path).name or "path"
        digest = hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:12]
        return f"{prefix}{name}#path:{digest}"

    return ABSOLUTE_PATH_RE.sub(repl, text)


class FallbackLineSanitizer:
    def __init__(self, *, show_paths: bool = False, diagnostic: str | None = None) -> None:
        self.show_paths = show_paths
        self.diagnostic = diagnostic
        self.diagnostic_emitted = False
        self.redactions = 0

    def sanitize(self, raw_line: str) -> tuple[str, bool]:
        if self.diagnostic and not self.diagnostic_emitted:
            print(f"claude-token-kit: sanitizer fallback active: {self.diagnostic}", file=sys.stderr)
            self.diagnostic_emitted = True
        line = strip_ansi(raw_line)
        if not self.show_paths:
            line = anonymize_absolute_paths(line)
        original = line
        auth_match = FALLBACK_AUTH_HEADER_RE.match(line)
        if auth_match:
            line = auth_match.group("prefix") + "[REDACTED]\n"
        else:
            for pattern, repl in FALLBACK_INLINE_PATTERNS:
                line = pattern.sub(repl, line)
        redacted = line != original
        if redacted:
            self.redactions += 1
        return line, redacted


def load_line_sanitizer(show_paths: bool) -> object:
    """Reuse the stronger sanitizer when it is shipped next to this wrapper."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    load_errors: list[str] = []
    for name in ("sanitize_output.py", "claude-sanitize-output"):
        candidate = os.path.join(script_dir, name)
        if not os.path.exists(candidate):
            continue
        try:
            loader = importlib.machinery.SourceFileLoader(f"_claude_token_sanitize_{os.getpid()}", candidate)
            spec = importlib.util.spec_from_loader(loader.name, loader)
            if spec is None:
                continue
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            return module.LineSanitizer(show_paths=show_paths)
        except Exception as exc:
            load_errors.append(f"{os.path.basename(candidate)} failed to load: {exc.__class__.__name__}: {exc}")
            continue
    diagnostic = "; ".join(load_errors) if load_errors else "strong sanitizer not found next to trim wrapper"
    return FallbackLineSanitizer(show_paths=show_paths, diagnostic=diagnostic)


def unique_keep_order(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        key = line.rstrip()
        if key not in seen:
            out.append(line)
            seen.add(key)
    return out


def cap_line(line: str, max_line_chars: int) -> tuple[str, bool]:
    if max_line_chars <= 0 or len(line) <= max_line_chars:
        return line, False
    newline = "\n" if line.endswith("\n") else ""
    body = line[:-1] if newline else line
    marker = f"...[line trimmed: {len(body)} chars]"
    keep = max(0, max_line_chars - len(marker) - len(newline))
    return body[:keep] + marker + newline, True


def cap_text(text: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    marker = f"\n[claude-token-kit] text capped: {len(text)} chars total\n"
    keep = max(0, max_chars - len(marker))
    return text[:keep].rstrip() + marker, True


def compact_item(
    text: str,
    limit: int = MAX_SUMMARY_ITEM_CHARS,
    *,
    show_paths: bool = False,
    sanitizer: object | None = None,
) -> str:
    """Normalize a failure-summary item without letting one log line dominate memory/output."""
    if sanitizer is None:
        sanitizer = load_line_sanitizer(show_paths)
    sanitized, _ = sanitizer.sanitize(text)  # type: ignore[attr-defined]
    item = re.sub(r"\s+", " ", strip_ansi(sanitized).strip())
    if len(item) <= limit:
        return item
    marker = f"...[item trimmed: {len(item)} chars]"
    keep = max(0, limit - len(marker))
    return item[:keep] + marker


class RunnerFailureSummary:
    """Bounded, runner-aware extraction of the most actionable failure lines.

    The extractor is intentionally online and stores only a small de-duplicated
    set of findings. That keeps the wrapper useful for huge logs without
    retaining the whole command output in memory.
    """

    def __init__(self, max_items_per_runner: int, *, show_paths: bool = False) -> None:
        self.max_items_per_runner = max(0, max_items_per_runner)
        self.show_paths = show_paths
        self.sanitizer = load_line_sanitizer(show_paths)
        self.items: dict[str, list[str]] = collections.defaultdict(list)
        self.seen: dict[str, set[str]] = collections.defaultdict(set)
        self.jest_active = False
        self.go_failed_seen = False

    def add(self, runner: str, item: str) -> None:
        if self.max_items_per_runner <= 0:
            return
        compact = compact_item(item, show_paths=self.show_paths, sanitizer=self.sanitizer)
        if not compact or compact in self.seen[runner]:
            return
        if len(self.items[runner]) >= self.max_items_per_runner:
            return
        self.items[runner].append(compact)
        self.seen[runner].add(compact)

    def feed(self, line: str) -> None:
        if self.max_items_per_runner <= 0:
            return

        stripped = strip_ansi(line.rstrip("\n"))

        match = PYTEST_RESULT_RE.match(stripped)
        if match and (".py" in match.group("node") or "::" in match.group("node")):
            reason = compact_item(match.group("reason") or "", show_paths=self.show_paths, sanitizer=self.sanitizer)
            if reason:
                self.add("pytest", f"{match.group('kind')} {match.group('node')} - {reason}")
            else:
                self.add("pytest", f"{match.group('kind')} {match.group('node')}")

        match = PYTEST_LOCATION_RE.match(stripped)
        if match and ERROR_RE.search(stripped):
            self.add("pytest", f"{match.group('file')}:{match.group('line')}: {match.group('message').strip()}")

        match = JEST_FILE_RE.match(stripped)
        if match:
            self.jest_active = True
            self.add("jest/vitest", f"FAIL {match.group('file')}")
            if match.group("name"):
                self.add("jest/vitest", f"test {match.group('name')}")

        if self.jest_active:
            match = JEST_TEST_RE.match(stripped)
            if match:
                self.add("jest/vitest", f"test {match.group('name')}")

            match = JEST_AT_RE.match(stripped)
            if match:
                self.add("jest/vitest", f"{match.group('file')}:{match.group('line')}:{match.group('col')}")

            match = VITEST_LOCATION_RE.match(stripped)
            if match:
                self.add("jest/vitest", f"{match.group('file')}:{match.group('line')}:{match.group('col')}")

        match = GO_FAIL_RE.match(stripped)
        if match:
            self.go_failed_seen = True
            self.add("go test", f"FAIL {match.group('name')}")

        match = GO_LOCATION_RE.match(stripped)
        if self.go_failed_seen and match:
            message = match.group("message").strip()
            suffix = f": {message}" if message else ""
            self.add("go test", f"{match.group('file')}:{match.group('line')}{suffix}")

        match = RUST_THREAD_RE.match(stripped)
        if match:
            self.add(
                "cargo test",
                f"{match.group('name')} at {match.group('file')}:{match.group('line')}:{match.group('col')}",
            )

    def as_lines(self, max_line_chars: int, max_lines: int) -> list[str]:
        if not self.items:
            return []
        if max_lines <= 0:
            return []
        out = ["\n--- runner failure summary ---\n"]
        used_lines = len(out[0].splitlines())
        for runner in sorted(self.items):
            runner_line = f"runner={runner}\n"
            if used_lines + 1 > max_lines:
                break
            out.append(runner_line)
            used_lines += 1
            for item in self.items[runner]:
                if used_lines + 1 > max_lines:
                    break
                line, _ = cap_line(f"- {item}\n", max_line_chars)
                out.append(line)
                used_lines += 1
        return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-lines", type=int, default=220)
    parser.add_argument("--max-chars", type=int, default=20000)
    parser.add_argument("--max-line-chars", type=int, default=4000)
    parser.add_argument("--head-lines", type=int, default=40)
    parser.add_argument("--tail-lines", type=int, default=80)
    parser.add_argument("--error-lines", type=int, default=120)
    parser.add_argument(
        "--runner-summary-items",
        type=int,
        default=12,
        help="maximum runner-specific failure facts to keep per detected runner (0 disables)",
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="show raw absolute paths in output instead of basename#path:<hash>; local debugging only because private paths may be exposed",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    normalize_budgets(args)

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("trim_command_output.py: missing command", file=sys.stderr)
        return 2

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
        print(f"claude-token-kit: command failed to start: {exc}", file=sys.stderr)
        return 127

    all_lines: list[str] = []
    head: list[str] = []
    tail: collections.deque[str] = collections.deque(maxlen=args.tail_lines)
    error_lines: list[str] = []
    total = 0
    raw_chars = 0
    visible_chars = 0
    any_line_capped = False
    runner_summary = RunnerFailureSummary(args.runner_summary_items, show_paths=args.show_paths)
    line_sanitizer = load_line_sanitizer(args.show_paths)
    redacted_lines = 0

    if proc.stdout is None:
        print("trim_command_output.py: subprocess produced no stdout pipe", file=sys.stderr)
        return 1
    for line in proc.stdout:
        total += 1
        raw_chars += len(line)
        visible_source, redacted = line_sanitizer.sanitize(line)  # type: ignore[attr-defined]
        if redacted:
            redacted_lines += 1
        visible_line, line_capped = cap_line(visible_source, args.max_line_chars)
        any_line_capped = any_line_capped or line_capped
        visible_chars += len(visible_line)
        if total <= args.head_lines:
            head.append(visible_line)
        tail.append(visible_line)
        if ERROR_RE.search(visible_line) and len(error_lines) < args.error_lines:
            error_lines.append(visible_line)
        runner_summary.feed(line)
        if total <= args.max_lines:
            all_lines.append(visible_line)

    rc = proc.wait()

    if total <= args.max_lines and visible_chars <= args.max_chars and not any_line_capped:
        sys.stdout.writelines(all_lines)
    else:
        head_budget = min(args.head_lines, max(1, args.max_lines // 4))
        tail_budget = min(args.tail_lines, max(1, args.max_lines // 3))
        head_out = head[:head_budget]
        tail_out = [line for line in list(tail)[-tail_budget:] if line not in set(head_out)]
        remaining = max(0, args.max_lines - len(head_out) - len(tail_out))
        error_out = unique_keep_order(error_lines)[:remaining]

        parts: list[str] = []
        parts.append(
            f"[claude-token-kit] output trimmed: {total} lines/{raw_chars} chars "
            f"-> budget about {args.max_lines} log lines/{args.max_chars} chars\n"
        )
        parts.append(f"[claude-token-kit] command exit_code={rc}\n")
        if any_line_capped:
            parts.append(f"[claude-token-kit] one or more lines were capped at {args.max_line_chars} chars\n")
        if redacted_lines:
            parts.append(f"[claude-token-kit] redacted_lines={redacted_lines}\n")
        summary_budget = max(0, min(args.max_lines, max(4, args.max_lines // 3))) if args.max_lines > 0 else 0
        runner_lines = runner_summary.as_lines(args.max_line_chars, summary_budget) if rc != 0 else []
        summary_line_count = len("".join(runner_lines).splitlines())
        remaining_log_budget = max(0, args.max_lines - summary_line_count)

        parts.extend(runner_lines)
        parts.append("\n--- head ---\n")
        if remaining_log_budget > 0:
            head_out = head_out[:remaining_log_budget]
            parts.extend(head_out)
            remaining_log_budget -= len(head_out)
        if error_out:
            parts.append("\n--- matched error/failure lines ---\n")
            error_out = error_out[:remaining_log_budget]
            parts.extend(error_out)
            remaining_log_budget -= len(error_out)
        parts.append("\n--- tail ---\n")
        if remaining_log_budget > 0:
            parts.extend(tail_out[-remaining_log_budget:])
        parts.append("\n[claude-token-kit] rerun the command without trim only if more context is essential.\n")
        output, capped = cap_text("".join(parts), args.max_chars)
        if capped:
            output += "[claude-token-kit] final summary was capped by --max-chars.\n"
        sys.stdout.write(output)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
