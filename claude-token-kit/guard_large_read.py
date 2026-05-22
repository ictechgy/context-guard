#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block large whole-file Read calls.

The hook nudges Claude toward symbol-scoped reads before a huge file is inserted
into the conversation. It is opt-in through project settings and can be disabled
with CLAUDE_TOKEN_READ_GUARD=0.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
for _helper_dir in (SCRIPT_DIR, SCRIPT_DIR.parent / "lib"):
    if (_helper_dir / "hook_secret_patterns.py").is_file():
        sys.path.insert(0, str(_helper_dir))
        break
from hook_secret_patterns import CONTROL_CHAR_RE, hook_label_has_sensitive_evidence

DEFAULT_MAX_BYTES = 48_000
DEFAULT_MAX_LINE_RANGE = 400
MAX_BYTES_LIMIT = 1_000_000
MAX_LINE_RANGE_LIMIT = 20_000
GUARD_ENV = "CLAUDE_TOKEN_READ_GUARD"
MAX_BYTES_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_BYTES"
MAX_LINE_RANGE_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_LINES"
PATH_LABEL_MAX_CHARS = 160


def truthy_disabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "off", "disabled"}


def bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        number = int(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(number, minimum), maximum)


def max_bytes() -> int:
    return bounded_env_int(MAX_BYTES_ENV, DEFAULT_MAX_BYTES, 1, MAX_BYTES_LIMIT)


def max_line_range() -> int:
    return bounded_env_int(MAX_LINE_RANGE_ENV, DEFAULT_MAX_LINE_RANGE, 1, MAX_LINE_RANGE_LIMIT)


def tool_input(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("tool_input") or payload.get("toolInput") or {}
    return value if isinstance(value, dict) else {}


def read_path_from_payload(payload: dict[str, Any]) -> str:
    data = tool_input(payload)
    for key in ("file_path", "path", "filePath"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def tool_name(payload: dict[str, Any]) -> str:
    value = payload.get("tool_name") or payload.get("toolName") or ""
    return value if isinstance(value, str) else ""


def compact_hook_text(value: str, limit: int = PATH_LABEL_MAX_CHARS) -> str:
    compact = " ".join(CONTROL_CHAR_RE.sub(" ", value.strip()).split())
    if len(compact) > limit:
        compact = compact[: limit - 15].rstrip() + "...[truncated]"
    return compact


def anonymized_path_label(path: Path) -> str:
    try:
        raw = str(path.resolve())
    except OSError:
        raw = str(path)
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]
    return f"redacted-path#path:{digest}"


def bounded_line_range_requested(payload: dict[str, Any]) -> bool:
    data = tool_input(payload)
    raw_limit = data.get("limit")
    if raw_limit is None:
        return False
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        return False
    if limit <= 0 or limit > max_line_range():
        return False
    raw_offset = data.get("offset")
    if raw_offset is not None:
        try:
            if int(raw_offset) < 0:
                return False
        except (TypeError, ValueError):
            return False
    return True


def safe_label(path: Path, root: Path) -> str:
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    try:
        label = resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        try:
            raw = str(resolved)
        except OSError:
            raw = str(path)
        digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]
        name = path.name or "path"
        if hook_label_has_sensitive_evidence(name):
            name = "redacted-path"
        else:
            name = compact_hook_text(name)
        return f"{name or 'path'}#path:{digest}"
    if hook_label_has_sensitive_evidence(label):
        return anonymized_path_label(resolved)
    return compact_hook_text(label) or "path"


def has_symlink_component(path: Path) -> bool:
    """Return True when a requested project path traverses a symlink."""
    if path.is_symlink():
        return True
    current = Path(path.anchor) if path.is_absolute() else Path()
    depth = 0
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        if current.is_symlink() and not (path.is_absolute() and depth == 0):
            return True
        depth += 1
    return False


def find_read_symbol_command() -> str:
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "claude-read-symbol").exists():
        return "claude-read-symbol"
    if (script_dir / "read_symbol.py").exists():
        return "python3 claude-token-kit/read_symbol.py"
    return "claude-read-symbol"


def suggested_commands(label: str, read_symbol: str) -> tuple[str, str]:
    rg_cmd = shlex.join(["rg", "-n", "<symbol-or-error>", "--", label])
    read_parts = shlex.split(read_symbol) + [label, "<SymbolName>"]
    return rg_cmd, shlex.join(read_parts)


def deny_response(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    if truthy_disabled(os.environ.get(GUARD_ENV)):
        print("{}")
        return 0
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"claude-token-guard-read: invalid hook JSON: {exc}", file=sys.stderr)
        print("{}")
        return 0
    if not isinstance(payload, dict):
        print("{}")
        return 0
    current_tool = tool_name(payload)
    if current_tool and current_tool != "Read":
        print("{}")
        return 0

    raw_path = read_path_from_payload(payload)
    if not raw_path:
        print("{}")
        return 0
    root = Path.cwd().resolve()
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = root / path
    if has_symlink_component(path):
        label = safe_label(path, root)
        reason = (
            f"[claude-token-kit] Read blocked for {label}: requested path traverses a symlink. "
            "Use a real project file path before reading or extracting symbols."
        )
        print(json.dumps(deny_response(reason), ensure_ascii=False))
        return 0
    try:
        resolved = path.resolve()
        if not resolved.is_file():
            print("{}")
            return 0
        size = resolved.stat().st_size
    except OSError as exc:
        print(f"claude-token-guard-read: could not stat requested file: {exc.strerror or exc.__class__.__name__}", file=sys.stderr)
        print("{}")
        return 0

    limit = max_bytes()
    if size <= limit:
        print("{}")
        return 0
    if bounded_line_range_requested(payload):
        print("{}")
        return 0

    label = safe_label(resolved, root)
    read_symbol = find_read_symbol_command()
    rg_cmd, symbol_cmd = suggested_commands(label, read_symbol)
    reason = (
        f"[claude-token-kit] Large Read blocked for {label} ({size} bytes > {limit} byte guard). "
        "Use targeted context first: "
        f"`{rg_cmd}` then `{symbol_cmd}`; "
        "plugin installs can use `claude-read-symbol` directly. "
        "or use the Read tool with offset/limit for a small line range if symbol extraction is not suitable. "
        f"Set {GUARD_ENV}=0 only for a deliberate local override."
    )
    print(json.dumps(deny_response(reason), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
