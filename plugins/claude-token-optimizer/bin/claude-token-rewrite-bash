#!/usr/bin/env python3
"""Claude Code PreToolUse hook: wrap noisy Bash test/build/lint commands.

Reads hook JSON from stdin and prints a JSON response understood by Claude Code.
Install via `.claude/settings.json` hooks. Keep this script project-local during
experiments so it can be versioned and reviewed.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys

# Reject shell control syntax before wrapping. The wrapper is intended only for a
# single safe argv-style test/build/lint command, not arbitrary shell programs.
SHELL_META_RE = re.compile(r"[;&|<>`$()\n\r\t]")
WRAPPER_MARKERS = ("trim_command_output.py", "claude-trim-output")


def find_wrapper() -> str | None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "claude-trim-output"),
        os.path.join(script_dir, "trim_command_output.py"),
        "claude-token-kit/trim_command_output.py",
        ".claude/hooks/trim_command_output.py",
        "claude-trim-output",
    ]
    for path in candidates:
        if os.path.sep in path or (os.path.altsep and os.path.altsep in path):
            if os.path.exists(path):
                return path
        elif shutil.which(path):
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


def build_wrapped_command(wrapper: str, argv: list[str]) -> str:
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
    if not argv or not is_noisy_command(argv):
        print("{}")
        return 0

    wrapper = find_wrapper()
    if wrapper is None:
        print("claude-token-rewrite-bash: trim wrapper not found; leaving command unchanged", file=sys.stderr)
        print("{}")
        return 0
    wrapped = build_wrapped_command(wrapper, argv)

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
