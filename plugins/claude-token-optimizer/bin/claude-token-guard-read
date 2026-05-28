#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block large whole-file Read calls.

The hook nudges Claude toward symbol-scoped reads before a huge file is inserted
into the conversation. It is opt-in through project settings and can be disabled
with CLAUDE_TOKEN_READ_GUARD=0.
"""
from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_hook_secret_patterns():
    searched = []
    for helper_dir in (SCRIPT_DIR, SCRIPT_DIR.parent / "lib"):
        helper_path = helper_dir / "hook_secret_patterns.py"
        searched.append(str(helper_path))
        if not helper_path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("_claude_token_hook_secret_patterns", helper_path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    raise ImportError("hook_secret_patterns.py not found in " + ", ".join(searched))


_hook_secret_patterns = _load_hook_secret_patterns()
CONTROL_CHAR_RE = _hook_secret_patterns.CONTROL_CHAR_RE
hook_label_has_sensitive_evidence = _hook_secret_patterns.hook_label_has_sensitive_evidence

DEFAULT_MAX_BYTES = 48_000
DEFAULT_MAX_LINE_RANGE = 400
MAX_BYTES_LIMIT = 1_000_000
MAX_LINE_RANGE_LIMIT = 20_000
OUTLINE_MAX_BYTES = 200_000
OUTLINE_MAX_ITEMS = 12
READ_GUARD_STATE_DIR = Path(".claude-token-optimizer")
READ_GUARD_STATE_FILE = "read-guard-cache.json"
READ_GUARD_STATE_MAX_ITEMS = 20
GUARD_ENV = "CLAUDE_TOKEN_READ_GUARD"
MAX_BYTES_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_BYTES"
MAX_LINE_RANGE_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_LINES"
PATH_LABEL_MAX_CHARS = 160
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


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


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
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
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        if current.is_symlink():
            return True
    return False


def base_open_flags() -> int:
    flags = os.O_RDONLY
    for optional_flag in ("O_CLOEXEC", "O_NONBLOCK"):
        flags |= getattr(os, optional_flag, 0)
    return flags


def no_follow_flag() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def directory_flag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    """Rewrite narrow platform-owned absolute aliases before no-follow traversal."""
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


def open_directory_at(parent_fd: int, component: str, full_path: Path) -> int:
    component_stat = lstat_at_no_follow(parent_fd, component)
    if component_stat is not None:
        if stat.S_ISLNK(component_stat.st_mode):
            raise OSError(errno.ELOOP, "path component must not be a symlink", str(full_path))
        if not stat.S_ISDIR(component_stat.st_mode):
            raise OSError(errno.ENOTDIR, "path component is not a directory", str(full_path))
    try:
        fd = os.open(component, base_open_flags() | directory_flag() | no_follow_flag(), dir_fd=parent_fd)
    except OSError as exc:
        if component_stat is not None and exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT, errno.EINVAL}:
            raise OSError(errno.ELOOP, "path component changed while opening", str(full_path)) from exc
        raise
    try:
        opened = os.fstat(fd)
        if component_stat is not None:
            if not stat.S_ISDIR(opened.st_mode) or not os.path.samestat(component_stat, opened):
                raise OSError(errno.ELOOP, "path component changed while opening", str(full_path))
        elif not stat.S_ISDIR(opened.st_mode):
            raise OSError(errno.ENOTDIR, "path component is not a directory", str(full_path))
        return fd
    except Exception:
        os.close(fd)
        raise


def lstat_no_symlink_components(path: Path) -> os.stat_result:
    """lstat each path component and reject any symlink traversal."""
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    if not components:
        raise OSError(errno.EINVAL, "requested path is not a regular file", str(path))

    current = Path(path.anchor) if path.is_absolute() else Path()
    last_stat = None
    for index, component in enumerate(components):
        current = current / component
        current_stat = current.lstat()
        if stat.S_ISLNK(current_stat.st_mode):
            raise OSError(errno.ELOOP, "requested path must not traverse symlinks", str(path))
        if index < len(components) - 1 and not stat.S_ISDIR(current_stat.st_mode):
            raise OSError(errno.ENOTDIR, "path component is not a directory", str(path))
        last_stat = current_stat
    assert last_stat is not None
    return last_stat


def lstat_at_no_follow(dir_fd: int, component: str) -> os.stat_result | None:
    if os.stat not in getattr(os, "supports_dir_fd", set()):
        return None
    if os.stat not in getattr(os, "supports_follow_symlinks", set()):
        return None
    return os.stat(component, dir_fd=dir_fd, follow_symlinks=False)


def open_regular_no_symlink(path: Path) -> int:
    """Open a regular file after no-follow traversal of every path component."""
    path = normalize_allowed_first_absolute_symlink(path)
    if os.open not in getattr(os, "supports_dir_fd", set()):
        before = lstat_no_symlink_components(path)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(errno.EINVAL, "requested path must be a regular file", str(path))
        flags = base_open_flags() | no_follow_flag()
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
                raise OSError(errno.ELOOP, "requested path changed while opening", str(path))
            return fd
        except Exception:
            os.close(fd)
            raise

    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    if not components:
        raise OSError(errno.EINVAL, "requested path is not a regular file", str(path))
    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", base_open_flags() | directory_flag())
    try:
        for component in components[:-1]:
            next_fd = open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd
        before = lstat_at_no_follow(dir_fd, components[-1])
        if before is not None:
            if stat.S_ISLNK(before.st_mode):
                raise OSError(errno.ELOOP, "requested path must not be a symlink", str(path))
            if not stat.S_ISREG(before.st_mode):
                raise OSError(errno.EINVAL, "requested path must be a regular file", str(path))
        fd = os.open(components[-1], base_open_flags() | no_follow_flag(), dir_fd=dir_fd)
        try:
            st = os.fstat(fd)
            if before is not None:
                if not stat.S_ISREG(st.st_mode) or not os.path.samestat(before, st):
                    raise OSError(errno.ELOOP, "requested path changed while opening", str(path))
            elif not stat.S_ISREG(st.st_mode):
                raise OSError(errno.EINVAL, "requested path must be a regular file", str(path))
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(dir_fd)


def regular_file_size_no_symlink(path: Path) -> int:
    """Return size for a regular file opened without following symlinks."""
    fd = open_regular_no_symlink(path)
    try:
        return os.fstat(fd).st_size
    finally:
        os.close(fd)


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


def read_prefix_for_outline(path: Path, max_bytes: int = OUTLINE_MAX_BYTES) -> tuple[str, bool]:
    try:
        fd = open_regular_no_symlink(path)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(max_bytes + 1)
    except OSError:
        return "", False
    finally:
        if "fd" in locals() and fd != -1:
            os.close(fd)
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated


def outline_kind_for_suffix(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix == ".go":
        return "go"
    if suffix == ".rs":
        return "rust"
    if suffix in {".md", ".mdx", ".markdown"}:
        return "markdown"
    return "text"


OUTLINE_PATTERNS: dict[str, tuple[tuple[str, str], ...]] = {
    "python": (
        ("class", r"^class\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
        ("function", r"^(?:async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    ),
    "javascript": (
        ("class", r"^(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\b"),
        (
            "function",
            r"^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\b",
        ),
        (
            "const",
            r"^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=",
        ),
    ),
    "go": (
        ("function", r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\b"),
        ("type", r"^type\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    ),
    "rust": (
        ("function", r"^(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
        ("type", r"^(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b"),
    ),
    "markdown": (
        ("heading", r"^(#{1,3})\s+(.+?)\s*$"),
    ),
}


def outline_items(path: Path, text: str, *, limit: int = OUTLINE_MAX_ITEMS) -> list[str]:
    kind = outline_kind_for_suffix(path)
    patterns = [(label, pattern) for label, pattern in OUTLINE_PATTERNS.get(kind, ())]
    if not patterns:
        return []
    compiled = [(label, re.compile(pattern)) for label, pattern in patterns]
    items: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if kind != "markdown" and line[:1].isspace():
            continue
        for label, pattern in compiled:
            match = pattern.match(stripped)
            if not match:
                continue
            name = "<heading>" if kind == "markdown" else match.group(1)
            items.append(f"line {line_number}: {label} {compact_hook_text(name, 80)}")
            break
        if len(items) >= limit:
            break
    return items


def line_estimate(prefix: str, size: int, truncated: bool) -> str:
    lines = prefix.count("\n") + (1 if prefix and not prefix.endswith("\n") else 0)
    if not truncated or not prefix:
        return str(lines)
    avg = max(1.0, len(prefix.encode("utf-8", errors="replace")) / max(1, lines))
    estimated = int(size / avg)
    return f"~{estimated} (estimated from first {lines})"


def progressive_read_ladder(path: Path, label: str, size: int, limit: int, read_symbol: str) -> str:
    prefix, prefix_truncated = read_prefix_for_outline(path)
    items = outline_items(path, prefix)
    rg_cmd, symbol_cmd = suggested_commands(label, read_symbol)
    range_limit = min(max_line_range(), 120)
    parts = [
        f"[claude-token-kit] Large Read blocked for {label} ({size} bytes > {limit} byte guard).",
        "Progressive read ladder:",
        f"1) Search names/errors: `{rg_cmd}`",
    ]
    if items:
        first_name = items[0].split(" ", 3)[-1].split(" ", 1)[-1]
        read_parts = shlex.split(read_symbol) + [label, first_name]
        parts.append(f"2) Read a symbol slice: `{shlex.join(read_parts)}` (or `{symbol_cmd}`)")
    else:
        parts.append(f"2) Read a symbol slice when you know the name: `{symbol_cmd}`")
    parts.append("Plugin installs can use `claude-read-symbol` directly.")
    parts.append(f"3) If no symbol fits, use Read with offset=0 limit={range_limit} and then narrow further.")
    parts.append(f"File outline: estimated_lines={line_estimate(prefix, size, prefix_truncated)}")
    if items:
        parts.append("Top-level outline: " + "; ".join(items))
    else:
        parts.append("Top-level outline: unavailable from the bounded prefix; search first.")
    parts.append("Use full-file Read only after these smaller queries fail.")
    parts.append(f"Set {GUARD_ENV}=0 only for a deliberate local override.")
    return " ".join(parts)


def read_guard_fingerprint(path: Path, label: str, size: int) -> str:
    try:
        stat_result = path.stat()
        mtime = getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1_000_000_000))
    except OSError:
        mtime = 0
    basis = f"{label}\0{size}\0{mtime}"
    return hashlib.sha256(basis.encode("utf-8", errors="replace")).hexdigest()[:16]


def load_read_guard_state(root: Path) -> dict[str, Any]:
    state_dir = root / READ_GUARD_STATE_DIR
    state_file = state_dir / READ_GUARD_STATE_FILE
    try:
        if state_dir.is_symlink() or state_file.is_symlink() or not state_file.is_file():
            return {}
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_read_guard_state(root: Path, state: dict[str, Any]) -> None:
    state_dir = root / READ_GUARD_STATE_DIR
    state_file = state_dir / READ_GUARD_STATE_FILE
    try:
        if state_dir.exists() and not state_dir.is_dir():
            return
        if state_dir.is_symlink() or state_file.is_symlink():
            return
        state_dir.mkdir(mode=0o700, exist_ok=True)
        try:
            os.chmod(state_dir, 0o700)
        except OSError:
            pass
        tmp = state_file.with_name(f".read-guard-{os.getpid()}-{secrets.token_hex(16)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = -1
        try:
            fd = os.open(str(tmp), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(state, handle, ensure_ascii=False)
            os.replace(tmp, state_file)
        except OSError:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                tmp.unlink()
            except OSError:
                pass
            return
        try:
            os.chmod(state_file, 0o600)
        except OSError:
            pass
    except OSError:
        return


def record_read_guard_attempt(root: Path, fp: str) -> int:
    state = load_read_guard_state(root)
    attempts = state.get("attempts")
    if not isinstance(attempts, dict):
        attempts = {}
    entry = attempts.get(fp)
    if not isinstance(entry, dict):
        entry = {"count": 0}
    count = bounded_int(entry.get("count", 0), 0, 0, 1_000_000) + 1
    attempts.pop(fp, None)
    attempts[fp] = {"count": count}
    if len(attempts) > READ_GUARD_STATE_MAX_ITEMS:
        for key in list(attempts)[: len(attempts) - READ_GUARD_STATE_MAX_ITEMS]:
            attempts.pop(key, None)
    state["attempts"] = attempts
    save_read_guard_state(root, state)
    return count


def repeated_read_hint(count: int) -> str:
    if count < 2:
        return ""
    return (
        f" Repeated-read dedup: this same oversized file fingerprint has been blocked {count} times; "
        "reuse the previous ladder and query a symbol or line range instead of retrying full-file Read."
    )


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
        reason = "[claude-token-kit] Read blocked because the hook payload was invalid JSON. Retry the tool call."
        print(json.dumps(deny_response(reason), ensure_ascii=False))
        return 0
    if not isinstance(payload, dict):
        reason = "[claude-token-kit] Read blocked because the hook payload was not a JSON object. Retry the tool call."
        print(json.dumps(deny_response(reason), ensure_ascii=False))
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
    path = normalize_allowed_first_absolute_symlink(path)
    if has_symlink_component(path):
        label = safe_label(path, root)
        reason = (
            f"[claude-token-kit] Read blocked for {label}: requested path traverses a symlink. "
            "Use a real project file path before reading or extracting symbols."
        )
        print(json.dumps(deny_response(reason), ensure_ascii=False))
        return 0
    try:
        size = regular_file_size_no_symlink(path)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            label = safe_label(path, root)
            reason = (
                f"[claude-token-kit] Read blocked for {label}: requested path traverses a symlink. "
                "Use a real project file path before reading or extracting symbols."
            )
            print(json.dumps(deny_response(reason), ensure_ascii=False))
            return 0
        if exc.errno in {errno.EINVAL, errno.ENOTDIR, errno.ENOENT}:
            print("{}")
            return 0
        label = safe_label(path, root)
        detail = compact_hook_text(exc.strerror or exc.__class__.__name__, 80)
        print(f"claude-token-guard-read: could not safely inspect requested file: {detail}", file=sys.stderr)
        reason = (
            f"[claude-token-kit] Read blocked for {label}: the guard could not safely inspect the file "
            f"({detail}). Use a bounded line range or verify the path locally first."
        )
        print(json.dumps(deny_response(reason), ensure_ascii=False))
        return 0

    limit = max_bytes()
    if size <= limit:
        print("{}")
        return 0
    if bounded_line_range_requested(payload):
        print("{}")
        return 0

    label = safe_label(path, root)
    read_symbol = find_read_symbol_command()
    try:
        attempt_count = record_read_guard_attempt(root, read_guard_fingerprint(path, label, size))
    except Exception:
        attempt_count = 1
    reason = progressive_read_ladder(path, label, size, limit, read_symbol) + repeated_read_hint(attempt_count)
    print(json.dumps(deny_response(reason), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
