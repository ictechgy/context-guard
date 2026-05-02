#!/usr/bin/env python3
"""Claude Code PreToolUse hook: wrap noisy Bash commands.

Reads hook JSON from stdin and prints a JSON response understood by Claude Code.
Install via `.claude/settings.json` hooks. Keep this script project-local during
experiments so it can be versioned and reviewed.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys

# Reject shell control syntax before wrapping. The wrapper is intended only for a
# single safe argv-style command, not arbitrary shell programs.
SHELL_META_RE = re.compile(r"[;&|<>`$()\n\r\t]")
WRAPPER_MARKERS = (
    "trim_command_output.py",
    "claude-trim-output",
    "sanitize_output.py",
    "claude-sanitize-output",
)
FAIL_OPEN_ENV = "CLAUDE_TOKEN_SANITIZER_FAIL_OPEN"


def find_wrapper(kind: str) -> str | None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if kind == "sanitize":
        candidates = [
            os.path.join(script_dir, "claude-sanitize-output"),
            os.path.join(script_dir, "sanitize_output.py"),
        ]
    else:
        candidates = [
            os.path.join(script_dir, "claude-trim-output"),
            os.path.join(script_dir, "trim_command_output.py"),
        ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def split_single_safe_command(command: str) -> list[str] | None:
    if not command.strip() or SHELL_META_RE.search(command):
        return None
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    return argv or None


def npm_script_args(rest: list[str]) -> list[str]:
    value_options = {"--prefix", "--workspace", "-w", "--filter", "--cwd", "-C"}
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in value_options:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        break
    return rest[i:]


def is_noisy_command(argv: list[str]) -> bool:
    if not argv:
        return False
    first = argv[0]
    rest = argv[1:]

    if first in {"npm", "pnpm", "yarn", "bun"}:
        script_args = npm_script_args(rest)
        if not script_args:
            return False
        command = script_args[0]
        if command == "test":
            return True
        if command in {"run", "run-script"} and len(script_args) > 1:
            script = script_args[1]
            return script == "build" or script == "lint" or script.startswith("test")
        return command in {"build", "lint"}
    if first in {"pytest", "tox", "jest", "vitest"}:
        return True
    if first == "npx" and any(arg in {"jest", "vitest"} for arg in rest):
        return True
    if first == "python" and len(argv) > 2 and argv[1] == "-m" and argv[2] in {"pytest", "unittest"}:
        return True
    if first == "go" and "test" in rest:
        return True
    if first == "cargo" and "test" in rest:
        return True
    if first in {"mvn", "mvnw", "./mvnw"} and "test" in rest:
        return True
    if first in {"gradle", "gradlew", "./gradlew"} and "test" in rest:
        return True
    if first == "make" and any(arg in {"test", "build", "lint"} for arg in rest):
        return True
    return False


def is_sanitizable_output_command(argv: list[str]) -> bool:
    if not argv:
        return False
    first = argv[0]
    rest = argv[1:]

    if first in {"rg", "grep", "egrep", "fgrep"}:
        # `rg --files` is path listing rather than content search; the large
        # read/diet guards are better fits there.
        return not any(arg == "--files" for arg in rest)
    if first == "git" and rest:
        subcommand = rest[0]
        if subcommand == "grep":
            return True
        if subcommand in {"diff", "show"}:
            return True
        if subcommand == "log" and any(arg == "-p" or arg.startswith("--patch") for arg in rest[1:]):
            return True
    return False


def build_wrapped_command(wrapper: str, argv: list[str]) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + ["--max-lines", "220", "--"] + argv
    return shlex.join(wrapped_argv)


def build_sanitized_command(wrapper: str, argv: list[str]) -> str:
    if wrapper.endswith(".py"):
        prefix = ["python3", wrapper]
    else:
        prefix = [wrapper]
    wrapped_argv = prefix + ["--max-lines", "220", "--"] + argv
    return shlex.join(wrapped_argv)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"claude-token-rewrite-bash: invalid hook JSON: {exc}", file=sys.stderr)
        print("{}")
        return 0

    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    command = tool_input.get("command") or ""

    if not command or any(marker in command for marker in WRAPPER_MARKERS):
        print("{}")
        return 0

    argv = split_single_safe_command(command)
    if not argv:
        print("{}")
        return 0

    if is_noisy_command(argv):
        wrapper = find_wrapper("trim")
        if wrapper is None:
            print("claude-token-rewrite-bash: trim wrapper not found; leaving command unchanged", file=sys.stderr)
            print("{}")
            return 0
        wrapped = build_wrapped_command(wrapper, argv)
    elif is_sanitizable_output_command(argv):
        wrapper = find_wrapper("sanitize")
        if wrapper is None:
            reason = (
                "Search/diff command blocked because claude-sanitize-output is not installed next to "
                "claude-token-rewrite-bash. Install the sanitizer or set "
                f"{FAIL_OPEN_ENV}=1 to run unsanitized intentionally."
            )
            print(f"claude-token-rewrite-bash: {reason}", file=sys.stderr)
            if os.environ.get(FAIL_OPEN_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
                print("{}")
                return 0
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }, ensure_ascii=False))
            return 0
        wrapped = build_sanitized_command(wrapper, argv)
    else:
        print("{}")
        return 0

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": {"command": wrapped},
        }
    }
    print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
