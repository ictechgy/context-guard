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
import json
import os
from pathlib import PurePosixPath
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from typing import Iterable, Iterator

MAX_SUMMARY_ITEM_CHARS = 500
MAX_LINES_LIMIT = 5_000
MAX_CHARS_LIMIT = 1_000_000
MAX_LINE_CHARS_LIMIT = 100_000
MAX_SECTION_LINES_LIMIT = 2_000
MAX_RUNNER_SUMMARY_ITEMS_LIMIT = 100
DEFAULT_TIMEOUT_SECONDS = 600
MAX_TIMEOUT_SECONDS = 86_400
TIMEOUT_EXIT_CODE = 124


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
    args.timeout_seconds = bounded_int(
        args.timeout_seconds,
        DEFAULT_TIMEOUT_SECONDS,
        1,
        MAX_TIMEOUT_SECONDS,
    )

TERMINAL_CONTROL_RE = re.compile(
    r"(?:"
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|"  # OSC title/clipboard controls
    r"\x1b[@-_][0-?]*[ -/]*[@-~]|"          # CSI and other ESC sequences
    r"[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\x7f-\x9f]"
    r")"
)
ABSOLUTE_PATH_RE = re.compile(r"(?P<prefix>^|[\s('\"=])(?P<path>/(?:[^\s:(),]+/)*[^\s:(),]+)")
SECRET_KEY = (
    r"[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*"
)
FALLBACK_INLINE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bglpat-[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-(?:ant|proj)-[A-Za-z0-9_-]{12,}\b"), "[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
    (re.compile(r"(?i)\bAIza[0-9A-Za-z_\-]{20,}\b"), "[REDACTED]"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "[REDACTED]"),
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.IGNORECASE), r"\1[REDACTED]@"),
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
    return TERMINAL_CONTROL_RE.sub("", text)


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
            print(f"context-guard-kit: sanitizer fallback active: {self.diagnostic}", file=sys.stderr)
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
    for name in ("sanitize_output.py", "context-guard-sanitize-output"):
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
    marker = f"\n[context-guard-kit] text capped: {len(text)} chars total\n"
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

    def as_dict(self) -> dict[str, list[str]]:
        return {runner: list(items) for runner, items in sorted(self.items.items()) if items}


def digest_line_items(lines: Iterable[str], *, limit: int, max_line_chars: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        item = strip_ansi(line).strip()
        if not item or item in seen:
            continue
        capped, _ = cap_line(item, max_line_chars)
        out.append(capped.strip())
        seen.add(item)
        if len(out) >= limit:
            break
    return out


class DuplicateLineTracker:
    """Track repeated sanitized lines without retaining unbounded unique output."""

    def __init__(self, *, max_groups: int = 12, max_unique: int = 2048) -> None:
        self.max_groups = max(0, max_groups)
        self.max_unique = max(1, max_unique)
        self.counts: dict[str, int] = {}
        self.first_line: dict[str, int] = {}
        self.overflow_unique_lines = 0

    def feed(self, line_number: int, line: str) -> None:
        text = strip_ansi(line).strip()
        if not text:
            return
        if text not in self.counts:
            if len(self.counts) >= self.max_unique:
                self.overflow_unique_lines += 1
                return
            self.counts[text] = 0
            self.first_line[text] = line_number
        self.counts[text] += 1

    def as_list(self) -> list[dict[str, object]]:
        groups: list[dict[str, object]] = []
        repeated = [
            (text, count)
            for text, count in self.counts.items()
            if count > 1
        ]
        for text, count in sorted(repeated, key=lambda item: (-item[1], self.first_line[item[0]], item[0]))[
            : self.max_groups
        ]:
            groups.append(
                {
                    "count": count,
                    "first_line": self.first_line[text],
                    "text": text,
                }
            )
        if groups and self.overflow_unique_lines:
            groups.append(
                {
                    "count": self.overflow_unique_lines,
                    "first_line": None,
                    "text": "[context-guard-kit] additional unique lines omitted from duplicate tracking",
                }
            )
        return groups


def command_preview(command: list[str], sanitizer: object, max_line_chars: int) -> str:
    try:
        raw = shlex.join(command)
    except Exception:
        raw = " ".join(command)
    sanitized, _ = sanitizer.sanitize(raw + "\n")  # type: ignore[attr-defined]
    capped, _ = cap_line(sanitized.strip(), max_line_chars)
    return capped.strip()


def digest_next_queries(
    *,
    rc: int,
    timed_out: bool,
    raw_output_truncated: bool,
    runner_items: dict[str, list[str]],
    top_error_lines: list[str],
) -> list[str]:
    if timed_out:
        return [
            "Inspect timeout cause first; rerun with a narrower command or higher --timeout-seconds only if needed.",
            "If the process spawned children, check whether the wrapped command handles termination cleanly.",
        ]
    if rc == 0:
        if raw_output_truncated:
            return [
                "Treat this as success unless a specific assertion needs raw logs.",
                "Query exact raw output only for the component named in the next task.",
            ]
        return ["No raw output follow-up needed; command completed successfully."]
    queries: list[str] = []
    if runner_items:
        queries.append("Run the failing test/node from runner_failure_summary directly with minimal verbosity.")
    if top_error_lines:
        queries.append("Inspect top_error_lines before rerunning the full command.")
    if raw_output_truncated:
        queries.append("Rerun without trim only if these failure facts are insufficient.")
    if not queries:
        queries.append("Rerun with a narrower command or grep for the first error before requesting raw output.")
    return queries


def build_failure_signature(
    *,
    status: str,
    rc: int,
    timed_out: bool,
    runner_items: dict[str, list[str]],
    top_error_lines: list[str],
) -> dict[str, object]:
    basis: list[str] = []
    source = "status"
    if runner_items:
        source = "runner_failure_summary"
        for runner in sorted(runner_items):
            for item in runner_items[runner]:
                basis.append(f"{runner}: {item}")
                if len(basis) >= 8:
                    break
            if len(basis) >= 8:
                break
    elif top_error_lines:
        source = "top_error_lines"
        basis = top_error_lines[:8]
    if not basis:
        basis = [f"status={status}", f"exit_code={rc}", f"timed_out={str(timed_out).lower()}"]
    digest = hashlib.sha256(
        json.dumps(
            {"status": status, "exit_code": rc, "timed_out": timed_out, "basis": basis},
            ensure_ascii=False,
            sort_keys=True,
        ).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    return {
        "hash": digest,
        "source": source,
        "basis": basis,
        "exit_code": rc,
        "timed_out": timed_out,
    }


def build_digest_payload(
    *,
    args: argparse.Namespace,
    command: list[str],
    rc: int,
    timed_out: bool,
    total: int,
    raw_chars: int,
    visible_chars: int,
    any_line_capped: bool,
    redacted_lines: int,
    head: list[str],
    tail: Iterable[str],
    error_lines: list[str],
    runner_summary: RunnerFailureSummary,
    line_sanitizer: object,
    duplicate_line_groups: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    raw_output_truncated = total > args.max_lines or visible_chars > args.max_chars or any_line_capped
    status = "timeout" if timed_out else ("success" if rc == 0 else "failure")
    runner_items = runner_summary.as_dict() if rc != 0 else {}
    top_error_lines = digest_line_items(error_lines, limit=12, max_line_chars=args.max_line_chars)
    sample_limit = 8 if status == "success" else 10
    tail_list = list(tail)
    payload: dict[str, object] = {
        "tool": "context-guard-kit.trim_command_output",
        "digest_version": 1,
        "status": status,
        "exit_code": rc,
        "timed_out": timed_out,
        "raw_output": {
            "lines": total,
            "chars": raw_chars,
            "visible_chars": visible_chars,
            "truncated": raw_output_truncated,
            "line_capped": any_line_capped,
            "redacted_lines": redacted_lines,
        },
        "budget": {
            "max_lines": args.max_lines,
            "max_chars": args.max_chars,
            "max_line_chars": args.max_line_chars,
        },
        "command_preview": command_preview(command, line_sanitizer, args.max_line_chars),
        "runner_failure_summary": runner_items,
        "top_error_lines": top_error_lines,
        "representative_head": digest_line_items(head, limit=sample_limit, max_line_chars=args.max_line_chars),
        "representative_tail": digest_line_items(
            tail_list[-sample_limit:],
            limit=sample_limit,
            max_line_chars=args.max_line_chars,
        ),
    }
    if duplicate_line_groups:
        payload["duplicate_line_groups"] = duplicate_line_groups
    if status != "success":
        payload["failure_signature"] = build_failure_signature(
            status=status,
            rc=rc,
            timed_out=timed_out,
            runner_items=runner_items,
            top_error_lines=top_error_lines,
        )
    payload["next_queries"] = digest_next_queries(
        rc=rc,
        timed_out=timed_out,
        raw_output_truncated=raw_output_truncated,
        runner_items=runner_items,
        top_error_lines=top_error_lines,
    )
    return payload


def render_digest_markdown(payload: dict[str, object], max_chars: int) -> str:
    raw_output = payload.get("raw_output", {})
    budget = payload.get("budget", {})
    lines: list[str] = []
    lines.append("[context-guard-kit] semantic digest\n")
    lines.append(f"- status: {payload.get('status')}\n")
    lines.append(f"- exit_code: {payload.get('exit_code')}\n")
    lines.append(f"- timed_out: {str(payload.get('timed_out')).lower()}\n")
    if isinstance(raw_output, dict):
        lines.append(
            "- raw_output: "
            f"{raw_output.get('lines')} lines/{raw_output.get('chars')} chars"
            f" (visible={raw_output.get('visible_chars')}, truncated={str(raw_output.get('truncated')).lower()})\n"
        )
        if raw_output.get("line_capped"):
            lines.append(f"- line_capped: true\n")
        if raw_output.get("redacted_lines"):
            lines.append(f"- redacted_lines: {raw_output.get('redacted_lines')}\n")
    if isinstance(budget, dict):
        lines.append(
            "- budget: "
            f"{budget.get('max_lines')} lines/{budget.get('max_chars')} chars/"
            f"line={budget.get('max_line_chars')} chars\n"
        )
    if payload.get("command_preview"):
        lines.append(f"- command: `{payload.get('command_preview')}`\n")
    failure_signature = payload.get("failure_signature")
    if isinstance(failure_signature, dict):
        lines.append(
            "- failure_signature: "
            f"{failure_signature.get('hash')} ({failure_signature.get('source')})\n"
        )

    runner_summary = payload.get("runner_failure_summary")
    if isinstance(runner_summary, dict) and runner_summary:
        lines.append("\n## runner_failure_summary\n")
        for runner, items in sorted(runner_summary.items()):
            lines.append(f"- runner={runner}\n")
            if isinstance(items, list):
                for item in items:
                    lines.append(f"  - {item}\n")

    duplicate_line_groups = payload.get("duplicate_line_groups")
    if isinstance(duplicate_line_groups, list) and duplicate_line_groups:
        lines.append("\n## duplicate_line_groups\n")
        for group in duplicate_line_groups:
            if not isinstance(group, dict):
                continue
            lines.append(
                "- "
                f"count={group.get('count')} "
                f"first_line={group.get('first_line')} "
                f"text={group.get('text')}\n"
            )

    for title, key in [
        ("top_error_lines", "top_error_lines"),
        ("representative_head", "representative_head"),
        ("representative_tail", "representative_tail"),
        ("next_queries", "next_queries"),
    ]:
        values = payload.get(key)
        if isinstance(values, list) and values:
            lines.append(f"\n## {title}\n")
            for value in values:
                lines.append(f"- {value}\n")

    text = "".join(lines)
    output, capped = cap_text(text, max_chars)
    if not capped:
        return output
    marker = "[context-guard-kit] digest capped by --max-chars.\n"
    if max_chars <= len(marker):
        return marker[:max_chars]
    output, _ = cap_text(text, max_chars - len(marker))
    return output + marker


def render_digest_json(payload: dict[str, object], max_chars: int) -> str:
    def dumps(data: dict[str, object]) -> str:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"

    def shrink_list_to_fit(data: dict[str, object], values: list[object]) -> None:
        if len(dumps(data)) <= max_chars:
            return
        lo, hi = 0, len(values)
        best = 0
        original = list(values)
        while lo <= hi:
            mid = (lo + hi) // 2
            values[:] = original[:mid]
            if len(dumps(data)) <= max_chars:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        values[:] = original[:best]

    def first_fitting(candidates: list[dict[str, object]]) -> str:
        for candidate in candidates:
            output = dumps(candidate)
            if len(output) <= max_chars:
                return output
        return dumps(candidates[-1])

    output = dumps(payload)
    if len(output) <= max_chars:
        return output

    capped = json.loads(json.dumps(payload))
    capped["digest_capped"] = True
    for key in ("duplicate_line_groups", "representative_tail", "representative_head", "top_error_lines", "next_queries"):
        values = capped.get(key)
        if isinstance(values, list):
            shrink_list_to_fit(capped, values)
    failure_signature = capped.get("failure_signature")
    if isinstance(failure_signature, dict):
        basis = failure_signature.get("basis")
        if isinstance(basis, list):
            shrink_list_to_fit(capped, basis)
    runner_summary = capped.get("runner_failure_summary")
    if isinstance(runner_summary, dict):
        for runner in sorted(runner_summary):
            values = runner_summary.get(runner)
            if isinstance(values, list):
                shrink_list_to_fit(capped, values)
    output = dumps(capped)
    if len(output) <= max_chars:
        return output

    compact_signature: object | None = None
    failure_signature = payload.get("failure_signature")
    if isinstance(failure_signature, dict):
        compact_signature = {
            "hash": failure_signature.get("hash"),
            "source": failure_signature.get("source"),
            "exit_code": failure_signature.get("exit_code"),
            "timed_out": failure_signature.get("timed_out"),
        }

    return first_fitting(
        [
            {
                "tool": payload.get("tool"),
                "digest_version": payload.get("digest_version"),
                "digest_capped": True,
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "timed_out": payload.get("timed_out"),
                "failure_signature": compact_signature,
                "raw_output": payload.get("raw_output"),
                "budget": payload.get("budget"),
                "next_queries": ["Raise --max-chars or inspect a narrower command for details."],
            },
            {
                "digest_capped": True,
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "timed_out": payload.get("timed_out"),
                "failure_signature": compact_signature,
                "raw_output": payload.get("raw_output"),
                "next_queries": ["Raise --max-chars or inspect a narrower command for details."],
            },
            {
                "digest_capped": True,
                "status": payload.get("status"),
                "exit_code": payload.get("exit_code"),
                "timed_out": payload.get("timed_out"),
                "failure_signature": compact_signature,
            },
            {"digest_capped": True},
        ]
    )


_STREAM_END = object()


def process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def terminate_process_tree(
    proc: subprocess.Popen[str],
    *,
    process_group_id: int | None = None,
    include_exited_group: bool = False,
) -> None:
    if os.name != "nt":
        pgid = process_group_id if process_group_id is not None else proc.pid
        if proc.poll() is not None and not include_exited_group:
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    pass
            if not process_group_exists(pgid):
                return
            time.sleep(0.05)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            return
        return

    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    except OSError:
        try:
            proc.kill()
        except OSError:
            return
    try:
        proc.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        return
    except OSError:
        return


class TimedCommandStream:
    def __init__(
        self,
        proc: subprocess.Popen[str],
        stdout: Iterable[str],
        *,
        timeout_seconds: int,
        process_group_id: int | None = None,
    ) -> None:
        self.proc = proc
        self.timeout_seconds = timeout_seconds
        self.process_group_id = process_group_id
        self.deadline = time.monotonic() + timeout_seconds
        self.timed_out = False
        self.timeout_reported = False
        self._stream_closed = False
        self._queue: queue.Queue[str | object] = queue.Queue(maxsize=1024)
        self._thread = threading.Thread(target=self._read_stdout, args=(stdout,), daemon=True)
        self._thread.start()

    def _read_stdout(self, stdout: Iterable[str]) -> None:
        try:
            for line in stdout:
                self._queue.put(line)
        finally:
            self._stream_closed = True
            self._queue.put(_STREAM_END)

    def timeout_message(self) -> str:
        return (
            f"[context-guard-kit] command timed out after {self.timeout_seconds}s; "
            "terminated wrapped process\n"
        )

    def _mark_timed_out(self) -> None:
        if not self.timed_out:
            self.timed_out = True
            terminate_process_tree(
                self.proc,
                process_group_id=self.process_group_id,
                include_exited_group=True,
            )

    def _timeout_line(self) -> str:
        self._mark_timed_out()
        self.timeout_reported = True
        return self.timeout_message()

    def __iter__(self) -> Iterator[str]:
        while True:
            remaining = self.deadline - time.monotonic()
            wait_time = 0.05 if self.proc.poll() is not None or self.timed_out else min(0.05, max(0.0, remaining))
            try:
                item = self._queue.get(timeout=wait_time)
            except queue.Empty:
                if remaining <= 0 and not self._stream_closed:
                    if not self.timeout_reported:
                        yield self._timeout_line()
                    break
                continue
            if item is _STREAM_END:
                break
            if not isinstance(item, str):
                continue
            yield item
            if not self._stream_closed and time.monotonic() >= self.deadline:
                if not self.timeout_reported:
                    yield self._timeout_line()
                break

    def returncode(self) -> int:
        if self.timed_out:
            return TIMEOUT_EXIT_CODE
        remaining = self.deadline - time.monotonic()
        try:
            return self.proc.wait(timeout=max(0.0, remaining))
        except subprocess.TimeoutExpired:
            self._mark_timed_out()
            return TIMEOUT_EXIT_CODE


def process_group_id_for(proc: subprocess.Popen[str]) -> int | None:
    if os.name == "nt":
        return None
    try:
        return os.getpgid(proc.pid)
    except ProcessLookupError:
        # start_new_session=True makes the child the group leader; if it exits
        # before getpgid(), the group id is still the leader pid while inherited
        # stdout descendants remain alive.
        return proc.pid


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
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "maximum runtime for wrapped commands before terminating the process group "
            f"(default: {DEFAULT_TIMEOUT_SECONDS}, max: {MAX_TIMEOUT_SECONDS})"
        ),
    )
    parser.add_argument(
        "--digest",
        choices=("off", "markdown", "json"),
        default="off",
        help=(
            "emit an opt-in semantic digest instead of raw/trimmed logs "
            "(default: off; formats: markdown, json)"
        ),
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

    popen_kwargs: dict[str, object] = {}
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            errors="replace",
            **popen_kwargs,
        )
    except OSError as exc:
        print(f"context-guard-kit: command failed to start: {exc}", file=sys.stderr)
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
    duplicate_tracker = DuplicateLineTracker()
    redacted_lines = 0

    if proc.stdout is None:
        print("trim_command_output.py: subprocess produced no stdout pipe", file=sys.stderr)
        return 1
    command_stream = TimedCommandStream(
        proc,
        proc.stdout,
        timeout_seconds=args.timeout_seconds,
        process_group_id=process_group_id_for(proc),
    )
    for line in command_stream:
        total += 1
        raw_chars += len(line)
        visible_source, redacted = line_sanitizer.sanitize(line)  # type: ignore[attr-defined]
        if redacted:
            redacted_lines += 1
        visible_line, line_capped = cap_line(visible_source, args.max_line_chars)
        any_line_capped = any_line_capped or line_capped
        visible_chars += len(visible_line)
        duplicate_tracker.feed(total, visible_line)
        if total <= args.head_lines:
            head.append(visible_line)
        tail.append(visible_line)
        if ERROR_RE.search(visible_line) and len(error_lines) < args.error_lines:
            error_lines.append(visible_line)
        runner_summary.feed(line)
        if total <= args.max_lines:
            all_lines.append(visible_line)

    rc = command_stream.returncode()
    if command_stream.timed_out and not command_stream.timeout_reported:
        line = command_stream.timeout_message()
        command_stream.timeout_reported = True
        total += 1
        raw_chars += len(line)
        visible_source, redacted = line_sanitizer.sanitize(line)  # type: ignore[attr-defined]
        if redacted:
            redacted_lines += 1
        visible_line, line_capped = cap_line(visible_source, args.max_line_chars)
        any_line_capped = any_line_capped or line_capped
        visible_chars += len(visible_line)
        duplicate_tracker.feed(total, visible_line)
        if total <= args.head_lines:
            head.append(visible_line)
        tail.append(visible_line)
        if ERROR_RE.search(visible_line) and len(error_lines) < args.error_lines:
            error_lines.append(visible_line)
        runner_summary.feed(line)
        if total <= args.max_lines:
            all_lines.append(visible_line)

    if args.digest != "off":
        payload = build_digest_payload(
            args=args,
            command=command,
            rc=rc,
            timed_out=command_stream.timed_out,
            total=total,
            raw_chars=raw_chars,
            visible_chars=visible_chars,
            any_line_capped=any_line_capped,
            redacted_lines=redacted_lines,
            head=head,
            tail=list(tail),
            error_lines=error_lines,
            runner_summary=runner_summary,
            line_sanitizer=line_sanitizer,
            duplicate_line_groups=duplicate_tracker.as_list(),
        )
        if args.digest == "json":
            sys.stdout.write(render_digest_json(payload, args.max_chars))
        else:
            sys.stdout.write(render_digest_markdown(payload, args.max_chars))
        return rc

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
            f"[context-guard-kit] output trimmed: {total} lines/{raw_chars} chars "
            f"-> budget about {args.max_lines} log lines/{args.max_chars} chars\n"
        )
        parts.append(f"[context-guard-kit] command exit_code={rc}\n")
        if any_line_capped:
            parts.append(f"[context-guard-kit] one or more lines were capped at {args.max_line_chars} chars\n")
        if redacted_lines:
            parts.append(f"[context-guard-kit] redacted_lines={redacted_lines}\n")
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
        parts.append("\n[context-guard-kit] rerun the command without trim only if more context is essential.\n")
        output, capped = cap_text("".join(parts), args.max_chars)
        if capped:
            output += "[context-guard-kit] final summary was capped by --max-chars.\n"
        sys.stdout.write(output)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
