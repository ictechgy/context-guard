#!/usr/bin/env python3
"""Run a command, preserve exit code, and print a token-budgeted output summary.

Designed for Claude Code Bash tool output. It avoids dumping thousands of log
lines into the conversation while preserving the lines most likely to be useful.
"""
from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from typing import Iterable

ERROR_RE = re.compile(
    r"(FAIL|FAILED|ERROR|Error:|Exception|Traceback|AssertionError|panic:|fatal:|"
    r"segmentation fault|not ok|\bE\s+assert|\[ERROR\]|✗|✖)",
    re.IGNORECASE,
)


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-lines", type=int, default=220)
    parser.add_argument("--max-chars", type=int, default=20000)
    parser.add_argument("--max-line-chars", type=int, default=4000)
    parser.add_argument("--head-lines", type=int, default=40)
    parser.add_argument("--tail-lines", type=int, default=80)
    parser.add_argument("--error-lines", type=int, default=120)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

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

    if proc.stdout is None:
        print("trim_command_output.py: subprocess produced no stdout pipe", file=sys.stderr)
        return 1
    for line in proc.stdout:
        total += 1
        raw_chars += len(line)
        visible_line, line_capped = cap_line(line, args.max_line_chars)
        any_line_capped = any_line_capped or line_capped
        visible_chars += len(visible_line)
        if total <= args.head_lines:
            head.append(visible_line)
        tail.append(visible_line)
        if ERROR_RE.search(line) and len(error_lines) < args.error_lines:
            error_lines.append(visible_line)
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
        parts.append("\n--- head ---\n")
        parts.extend(head_out)
        if error_out:
            parts.append("\n--- matched error/failure lines ---\n")
            parts.extend(error_out)
        parts.append("\n--- tail ---\n")
        parts.extend(tail_out)
        parts.append("\n[claude-token-kit] rerun the command without trim only if more context is essential.\n")
        output, capped = cap_text("".join(parts), args.max_chars)
        if capped:
            output += "[claude-token-kit] final summary was capped by --max-chars.\n"
        sys.stdout.write(output)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
