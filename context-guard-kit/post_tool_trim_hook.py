#!/usr/bin/env python3
"""Trim Claude Code Bash PostToolUse output via the documented hook protocol."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types


MAX_HOOK_INPUT_BYTES = 16 * 1024 * 1024
MAX_TRIM_MODULE_BYTES = 3 * 1024 * 1024


class HookInputError(ValueError):
    """The hook payload is malformed or violates the bounded schema."""


class TrimModuleError(RuntimeError):
    """The adjacent trim implementation could not be loaded safely."""


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise HookInputError("duplicate JSON key")
        result[key] = value
    return result


def read_hook_payload() -> object:
    raw = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
    if len(raw) > MAX_HOOK_INPUT_BYTES:
        raise HookInputError("hook input exceeds byte cap")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except HookInputError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HookInputError("hook input is not valid JSON") from exc


def read_regular_file_without_symlinks(directory: Path, name: str) -> str | None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise TrimModuleError("O_NOFOLLOW is unavailable")
    directory_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC

    try:
        directory_fd = os.open(str(directory), directory_flags)
    except OSError as exc:
        raise TrimModuleError("trim module directory is unavailable") from exc
    try:
        try:
            file_fd = os.open(name, file_flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise TrimModuleError("trim module is unavailable") from exc
        try:
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise TrimModuleError("trim module is not a regular file")
            if metadata.st_size > MAX_TRIM_MODULE_BYTES:
                raise TrimModuleError("trim module exceeds byte cap")
            chunks: list[bytes] = []
            remaining = MAX_TRIM_MODULE_BYTES + 1
            while remaining > 0:
                chunk = os.read(file_fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)

    raw = b"".join(chunks)
    if len(raw) > MAX_TRIM_MODULE_BYTES:
        raise TrimModuleError("trim module exceeds byte cap")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise TrimModuleError("trim module is not UTF-8") from exc


def load_trim_function() -> object:
    script_dir = Path(__file__).resolve().parent
    for name in ("trim_command_output.py", "context-guard-trim-output"):
        source = read_regular_file_without_symlinks(script_dir, name)
        if source is None:
            continue
        module_name = (
            "_context_guard_post_tool_trim_"
            + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        )
        module = types.ModuleType(module_name)
        module.__file__ = str(script_dir / name)
        module.__package__ = ""
        sys.modules[module_name] = module
        try:
            exec(compile(source, str(script_dir / name), "exec"), module.__dict__)
        except Exception as exc:
            sys.modules.pop(module_name, None)
            raise TrimModuleError("trim module could not be loaded") from exc
        trim_function = getattr(module, "trim_captured_output", None)
        if not callable(trim_function):
            raise TrimModuleError("trim module lacks captured-output support")
        return trim_function
    raise TrimModuleError("trim module was not found")


def validate_bash_response(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        raise HookInputError("hook payload must be an object")
    if payload.get("hook_event_name") != "PostToolUse" or payload.get("tool_name") != "Bash":
        return None
    response = payload.get("tool_response")
    if not isinstance(response, dict):
        raise HookInputError("Bash tool_response must be an object")
    if not isinstance(response.get("stdout"), str) or not isinstance(response.get("stderr"), str):
        raise HookInputError("Bash stdout and stderr must be strings")
    if not isinstance(response.get("interrupted"), bool) or not isinstance(response.get("isImage"), bool):
        raise HookInputError("Bash flags must be booleans")
    return response


def main() -> int:
    try:
        response = validate_bash_response(read_hook_payload())
        if response is None:
            return 0
        trim_captured_output = load_trim_function()
        updated = {
            "stdout": trim_captured_output(response["stdout"], exit_code=0),
            "stderr": trim_captured_output(response["stderr"], exit_code=0),
            "interrupted": response["interrupted"],
            "isImage": response["isImage"],
        }
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": updated,
            }
        }
        sys.stdout.write(json.dumps(output, ensure_ascii=False, separators=(",", ":")) + "\n")
        return 0
    except HookInputError:
        print("context-guard-post-tool-trim: invalid hook input", file=sys.stderr)
        return 2
    except Exception:
        print("context-guard-post-tool-trim: trim implementation unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
