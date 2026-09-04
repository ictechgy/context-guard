#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block large whole-file Read calls.

The hook nudges Claude toward symbol-scoped reads before a huge file is inserted
into the conversation. It is opt-in through project settings and can be disabled
with CONTEXT_GUARD_READ_GUARD=0. Legacy CLAUDE_TOKEN_* environment variables
remain supported for existing project settings.
"""
from __future__ import annotations

import copy
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
import time
from pathlib import Path
from typing import Any, NamedTuple

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


def _load_optional_helper(module_name: str):
    """선택적 helper 를 hook_secret_patterns 와 같은 방식으로 찾는다.

    없으면 None 을 돌려준다. 이 훅은 helper 없이도 예전과 완전히 동일하게 동작해야
    하므로, 로딩 실패는 결코 밖으로 새어 나가서는 안 된다.
    """
    for helper_dir in (SCRIPT_DIR, SCRIPT_DIR.parent / "lib"):
        helper_path = helper_dir / f"{module_name}.py"
        try:
            if not helper_path.is_file():
                continue
            spec = importlib.util.spec_from_file_location(f"_context_guard_{module_name}", helper_path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
        except Exception:  # noqa: BLE001 - helper 부재/파손이 훅 출력을 바꾸면 안 된다.
            continue
    return None


_hook_secret_patterns = _load_hook_secret_patterns()
_hook_journal = _load_optional_helper("hook_journal")
_hook_switch = _load_optional_helper("hook_switch")


def _journal_start():
    """저널 helper 가 있으면 단조 시계를 켠다. 없으면 None."""
    if _hook_journal is None:
        return None
    try:
        return _hook_journal.start_clock()
    except Exception:  # noqa: BLE001
        return None


def _journal_record(**fields) -> None:
    """저널 helper 가 있을 때만 한 줄 기록한다. 실패는 전부 삼킨다."""
    if _hook_journal is None:
        return
    try:
        _hook_journal.record("read", **fields)
    except Exception:  # noqa: BLE001
        pass


def _switch_says_off() -> bool:
    """세션 스위치로 read 훅이 꺼져 있는지 본다. helper 가 없으면 항상 False."""
    if _hook_switch is None:
        return False
    try:
        return bool(_hook_switch.is_disabled("read"))
    except Exception:  # noqa: BLE001
        return False


def read_disable_hint() -> str:
    """거부 사유 끝에 붙일 한 줄 해제 안내. helper 가 없으면 기존 환경변수 문구."""
    if _hook_switch is not None:
        try:
            return _hook_switch.disable_hint("read")
        except Exception:  # noqa: BLE001
            pass
    return f"Set {GUARD_ENV}=0 only for a deliberate local override."
CONTROL_CHAR_RE = _hook_secret_patterns.CONTROL_CHAR_RE
hook_label_has_sensitive_evidence = _hook_secret_patterns.hook_label_has_sensitive_evidence

DEFAULT_MAX_BYTES = 48_000
DEFAULT_MAX_LINE_RANGE = 400
MAX_BYTES_LIMIT = 1_000_000
MAX_LINE_RANGE_LIMIT = 20_000
OUTLINE_MAX_BYTES = 200_000
OUTLINE_MAX_ITEMS = 12
READ_GUARD_STATE_DIR = Path(".context-guard")
READ_GUARD_STATE_FILE = "read-guard-cache.json"
READ_GUARD_STATE_MAX_ITEMS = 128
GUARD_ENV = "CONTEXT_GUARD_READ_GUARD"
LEGACY_GUARD_ENV = "CLAUDE_TOKEN_READ_GUARD"
MAX_BYTES_ENV = "CONTEXT_GUARD_READ_GUARD_MAX_BYTES"
LEGACY_MAX_BYTES_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_BYTES"
MAX_LINE_RANGE_ENV = "CONTEXT_GUARD_READ_GUARD_MAX_LINES"
LEGACY_MAX_LINE_RANGE_ENV = "CLAUDE_TOKEN_READ_GUARD_MAX_LINES"
READ_PROOF_BYTES_ENV = "CONTEXT_GUARD_READ_GUARD_PROOF_BYTES"
LEGACY_READ_PROOF_BYTES_ENV = "CLAUDE_TOKEN_READ_GUARD_PROOF_BYTES"
DEFAULT_READ_PROOF_BYTES = 8 * 1024 * 1024
MIN_READ_PROOF_BYTES = 64 * 1024
MAX_READ_PROOF_BYTES = 64 * 1024 * 1024
READ_PROOF_CHUNK_BYTES = 64 * 1024
MAX_READ_RANGE_INTEGER = (1 << 63) - 1
ALLOWED_ENV_TEMPLATE_BASENAMES = frozenset({
    ".env.example",
    ".env.sample",
    ".env.template",
})
PATH_LABEL_MAX_CHARS = 160
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


def truthy_disabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "off", "disabled"}


def env_value(name: str, legacy_name: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is not None or legacy_name is None:
        return value
    return os.environ.get(legacy_name)


def bounded_env_int(name: str, legacy_name: str | None, default: int, minimum: int, maximum: int) -> int:
    raw = env_value(name, legacy_name)
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
    return bounded_env_int(MAX_BYTES_ENV, LEGACY_MAX_BYTES_ENV, DEFAULT_MAX_BYTES, 1, MAX_BYTES_LIMIT)


def max_line_range() -> int:
    return bounded_env_int(
        MAX_LINE_RANGE_ENV,
        LEGACY_MAX_LINE_RANGE_ENV,
        DEFAULT_MAX_LINE_RANGE,
        1,
        MAX_LINE_RANGE_LIMIT,
    )


def read_proof_bytes() -> int:
    return bounded_env_int(
        READ_PROOF_BYTES_ENV,
        LEGACY_READ_PROOF_BYTES_ENV,
        DEFAULT_READ_PROOF_BYTES,
        MIN_READ_PROOF_BYTES,
        MAX_READ_PROOF_BYTES,
    )


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


def strict_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not re.fullmatch(r"[+-]?[0-9]+", normalized):
        return None
    try:
        return int(normalized)
    except (TypeError, ValueError, OverflowError):
        return None


def large_read_range(payload: dict[str, Any]) -> tuple[int, int] | None:
    data = tool_input(payload)
    limit = strict_integer(data.get("limit"))
    if limit is None:
        return None
    if limit <= 0 or limit > max_line_range():
        return None
    raw_offset = data.get("offset", 0)
    offset = strict_integer(raw_offset)
    if offset is None or offset < 0 or offset > MAX_READ_RANGE_INTEGER:
        return None
    if limit > MAX_READ_RANGE_INTEGER - offset:
        return None
    return offset, limit


def bounded_line_range_requested(payload: dict[str, Any]) -> bool:
    return large_read_range(payload) is not None


def read_env_file_denied(path: Path) -> bool:
    basename = path.name
    return (
        basename.casefold().startswith(".env")
        and basename not in ALLOWED_ENV_TEMPLATE_BASENAMES
    )


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


class ReadRangeProof(NamedTuple):
    outcome: str
    charged_bytes: int
    scanned_bytes: int


def stat_identity(stat_result: os.stat_result) -> tuple[int, int, int, int]:
    mtime_ns = getattr(
        stat_result,
        "st_mtime_ns",
        int(stat_result.st_mtime * 1_000_000_000),
    )
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        mtime_ns,
    )


def prove_raw_read_range(
    fd: int,
    *,
    file_size: int,
    offset: int,
    limit: int,
    content_budget: int,
    proof_budget: int,
) -> ReadRangeProof:
    """Prove a zero-based logical-line range from raw bytes on one open fd."""
    if (
        file_size < 0
        or offset < 0
        or limit <= 0
        or content_budget < 0
        or proof_budget <= 0
        or offset > MAX_READ_RANGE_INTEGER
        or limit > MAX_READ_RANGE_INTEGER - offset
    ):
        raise ValueError("invalid raw Read proof parameters")

    selected_end = offset + limit
    line_index = 0
    charged_bytes = 0
    scanned_bytes = 0
    os.lseek(fd, 0, os.SEEK_SET)

    while scanned_bytes < file_size and scanned_bytes < proof_budget:
        remaining = min(
            READ_PROOF_CHUNK_BYTES,
            file_size - scanned_bytes,
            proof_budget - scanned_bytes,
        )
        chunk = os.read(fd, remaining)
        if not chunk:
            return ReadRangeProof("file_changed_during_proof", charged_bytes, scanned_bytes)
        for byte in chunk:
            scanned_bytes += 1
            if byte == 0x0A:
                line_index += 1
                if line_index >= selected_end:
                    return ReadRangeProof("allowed", charged_bytes, scanned_bytes)
                continue
            if offset <= line_index < selected_end:
                charged_bytes += 1
                if charged_bytes > content_budget:
                    return ReadRangeProof("content_budget_exceeded", charged_bytes, scanned_bytes)

    if scanned_bytes >= file_size:
        return ReadRangeProof("allowed", charged_bytes, scanned_bytes)
    return ReadRangeProof("proof_budget_exhausted", charged_bytes, scanned_bytes)


def raw_read_range_outcome(
    fd: int,
    initial_stat: os.stat_result,
    *,
    size: int,
    offset: int,
    limit: int,
    content_limit: int,
) -> str:
    """지정된 offset/limit로 raw-byte 증명을 수행하고 동일 fd의 정체성 변화까지 확인한다.

    peek/commit 분리 설계의 핵심: 밸브 판정과 증명이 fd 보유 구간 안에서만 일어나며
    별도로 재개방하지 않으므로 새 TOCTOU 창을 만들지 않는다.
    """
    try:
        proof = prove_raw_read_range(
            fd,
            file_size=size,
            offset=offset,
            limit=limit,
            content_budget=content_limit,
            proof_budget=read_proof_bytes(),
        )
        outcome = proof.outcome
    except (OSError, ValueError):
        outcome = "read_proof_failed"
    try:
        final_stat = os.fstat(fd)
    except OSError:
        return "file_changed_during_proof"
    if stat_identity(initial_stat) != stat_identity(final_stat):
        return "file_changed_during_proof"
    return outcome


def find_read_symbol_command() -> str:
    script_dir = Path(__file__).resolve().parent
    if (script_dir / "context-guard-read-symbol").exists():
        return shlex.join(
            [os.path.realpath(sys.executable), "-I", str((script_dir / "context-guard-read-symbol").resolve())]
        )
    if (script_dir / "read_symbol.py").exists():
        return shlex.join(
            [os.path.realpath(sys.executable), "-I", str((script_dir / "read_symbol.py").resolve())]
        )
    return "context-guard-read-symbol"


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


def progressive_read_ladder(
    path: Path,
    label: str,
    size: int,
    limit: int,
    read_symbol: str,
    *,
    command_path: str | None = None,
) -> str:
    """거부 사유를 한 줄로 만든다.

    예전에는 사다리 3단계 + 파일 아웃라인 + 추정 줄 수까지 실어 보냈다. 그 본문
    자체가 거부 한 번마다 수백~수천 바이트씩 모델 컨텍스트를 먹었고, 정작 다음
    행동에 필요한 것은 검색 명령 하나, 심볼 읽기 하나, 안전한 범위 하나뿐이다.
    아웃라인은 이 훅의 JSON 응답에 별도 필드가 없으므로 그냥 뺀다.
    """
    actionable_path = command_path if command_path is not None else label
    rg_cmd, _symbol_cmd = suggested_commands(actionable_path, read_symbol)
    range_limit = min(max_line_range(), 120)
    return (
        f"[context-guard] Read blocked: {label} is {size:,}B (> {limit:,}B). "
        f"Try: `{rg_cmd}` or context-guard-read-symbol {actionable_path} <Symbol>, "
        f"or Read with offset/limit <= {range_limit} lines. {read_disable_hint()}"
    )


def project_relative_path(path: Path, root: Path) -> str | None:
    try:
        normalized_path = Path(os.path.abspath(os.fspath(path)))
        normalized_root = Path(os.path.abspath(os.fspath(root)))
        return normalized_path.relative_to(normalized_root).as_posix()
    except (OSError, ValueError):
        return None


def project_relative_command_path(path: Path, root: Path) -> str | None:
    relative = project_relative_path(path, root)
    if relative is None:
        return None
    if (
        not relative
        or len(relative) > PATH_LABEL_MAX_CHARS
        or CONTROL_CHAR_RE.search(relative)
        or hook_label_has_sensitive_evidence(relative)
    ):
        return None
    return relative


def read_proof_denial_reason(
    outcome: str,
    *,
    path: Path,
    root: Path,
    size: int,
    content_limit: int,
    read_symbol: str,
) -> str:
    relative_project_path = project_relative_path(path, root)
    relative_path = project_relative_command_path(path, root)
    if outcome == "file_changed_during_proof":
        if relative_project_path is None:
            target = "an out-of-project file"
        elif relative_path is None:
            target = safe_label(path, root)
        else:
            target = f"project file `{shlex.quote(relative_path)}`"
        return (
            f"[context-guard-kit] Read blocked for {target}: file_changed_during_proof. "
            "The same open file changed identity, size, or modification time during the bounded proof. "
            "Stabilize the file and retry with a smaller positive limit. A later Read uses a separate open, "
            "so replacement after this hook returns remains a TOCTOU limitation."
        )

    outcome_detail = {
        "invalid_read_range": (
            "Large files require a positive integer limit within the configured maximum and a "
            "zero-based, nonnegative, nonoverflowing integer offset."
        ),
        "proof_budget_exhausted": (
            "The guard could not prove the requested start/end boundary or EOF within the raw-byte proof budget."
        ),
        "content_budget_exceeded": (
            "The selected logical-line content exceeds the byte guard; LF terminators are not charged, "
            "but CR and EOF-final content bytes are."
        ),
    }.get(outcome, "The bounded raw-byte Read proof could not safely allow this request.")

    if relative_project_path is None:
        return (
            f"[context-guard-kit] Large Read blocked for an out-of-project file "
            f"({size} bytes > {content_limit} byte guard): {outcome}. {outcome_detail} "
            "Use a smaller positive limit and lower zero-based offset, or first perform an explicitly "
            "user-authorized path-visible operation. No executable path suggestion is emitted for path privacy."
        )
    if relative_path is None:
        return (
            f"[context-guard-kit] Large Read blocked for {safe_label(path, root)} "
            f"({size} bytes > {content_limit} byte guard): {outcome}. {outcome_detail} "
            "Use a smaller positive limit and lower zero-based offset. No executable path suggestion is emitted "
            "because this project-relative path contains privacy-sensitive or non-command-safe bytes."
        )

    label = safe_label(path, root)
    ladder = progressive_read_ladder(
        path,
        label,
        size,
        content_limit,
        read_symbol,
        command_path=relative_path,
    )
    # 사다리는 이미 한 줄이다. 여기에 outcome/상세를 덧붙이면 다시 여러 문장이 되므로
    # 붙이지 않는다. outcome_detail 은 경로를 노출할 수 없는 위의 두 분기에서만 쓴다.
    return ladder


def read_guard_fingerprint(
    path: Path,
    label: str,
    size: int,
    *,
    stat_result: os.stat_result | None = None,
) -> str:
    if stat_result is None:
        try:
            stat_result = path.stat()
        except OSError:
            stat_result = None
    if stat_result is None:
        mtime = 0
    else:
        mtime = getattr(stat_result, "st_mtime_ns", int(stat_result.st_mtime * 1_000_000_000))
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


def default_read_guard_entry() -> dict[str, Any]:
    """캐시에 아직 없거나 손상된 지문에 사용할 기본 시도 엔트리."""
    return {"count": 0, "valve_used": False, "first_seen": 0, "last_seen": 0}


def normalize_read_guard_entry(entry: Any) -> dict[str, Any]:
    """레거시 `{"count": N}` 및 손상된 엔트리를 신규 스키마로 하위 호환 정규화한다."""
    normalized = default_read_guard_entry()
    if not isinstance(entry, dict):
        return normalized
    normalized["count"] = bounded_int(entry.get("count", 0), 0, 0, 1_000_000)
    normalized["valve_used"] = bool(entry.get("valve_used", False))
    normalized["first_seen"] = bounded_int(entry.get("first_seen", 0), 0, 0, MAX_READ_RANGE_INTEGER)
    normalized["last_seen"] = bounded_int(entry.get("last_seen", 0), 0, 0, MAX_READ_RANGE_INTEGER)
    return normalized


def peek_read_guard_attempt(root: Path, fp: str) -> dict[str, Any]:
    """카운터를 증가시키지 않고 현재 지문의 시도 엔트리를 읽는다(밸브 판정 전용).

    밸브 발화 여부는 대상 fd 보유 구간 안에서 결정해야 하므로, 영속화(commit)와
    분리된 읽기 전용 조회로 둔다. 대상 파일의 fd는 건드리지 않는다.
    """
    state = load_read_guard_state(root)
    attempts = state.get("attempts")
    if not isinstance(attempts, dict):
        return default_read_guard_entry()
    return normalize_read_guard_entry(attempts.get(fp))


def record_read_guard_attempt(root: Path, fp: str, *, valve_fired: bool = False) -> int:
    """시도 횟수를 1 증가시키고 병합 방식으로 영속화한다(commit 단계, fd 미보유 구간).

    기존 엔트리를 통째로 덮어쓰지 않고 필드를 병합해 valve_used/first_seen/last_seen을
    보존한다. pop 후 재삽입 순서를 유지해 초과분 축출을 LRU 유사하게 만든다.
    valve_used 등 전체 엔트리 조회가 필요하면 별도로 peek_read_guard_attempt를 쓴다
    (이 함수의 반환값은 호출부가 실제로 쓰는 count만 담는다).
    """
    state = load_read_guard_state(root)
    attempts = state.get("attempts")
    if not isinstance(attempts, dict):
        attempts = {}
    entry = normalize_read_guard_entry(attempts.get(fp))
    now = int(time.time())
    entry["count"] += 1
    entry["valve_used"] = entry["valve_used"] or valve_fired
    entry["first_seen"] = entry["first_seen"] or now
    entry["last_seen"] = now
    attempts.pop(fp, None)
    attempts[fp] = entry
    if len(attempts) > READ_GUARD_STATE_MAX_ITEMS:
        for key in list(attempts)[: len(attempts) - READ_GUARD_STATE_MAX_ITEMS]:
            attempts.pop(key, None)
    state["attempts"] = attempts
    save_read_guard_state(root, state)
    return entry["count"]


def repeated_read_hint(count: int) -> str:
    """1~2회차 사다리 거부에 덧붙이는 반복 신호 문구(3회차부터는 단축 메시지를 대신 쓴다)."""
    if count < 2:
        return ""
    return (
        f" Repeated-read dedup: this same oversized file fingerprint has been blocked {count} times; "
        "reuse the previous ladder and query a symbol or line range instead of retrying full-file Read."
    )


def valve_exhausted_reason(count: int) -> str:
    """지문이 과거에 실제로 밸브를 1회 발화(valve_used=True)한 뒤 다시 차단됐을 때 쓰는
    200바이트 미만 단축 메시지. "발화했다가 소진됨"을 뜻하므로 발화한 적이 없는
    지문에는 절대 쓰지 않는다 — 그 경우는 valve_budget_exceeded_reason을 쓴다.
    """
    return (
        f"[context-guard-kit] Read blocked ({count}x, escape valve exhausted). "
        f"Use a smaller offset/limit range for this file. {read_disable_hint()}"
    )


def valve_budget_exceeded_reason(count: int, content_limit: int) -> str:
    """좁힌 기본 범위(offset=0, limit=max_line_range())조차 예산을 넘어 밸브가 구조적으로
    발화할 수 없는 지문(minified/JSON/CSV/로그처럼 줄이 긴 파일)에 쓰는 200바이트 미만
    단축 메시지. "탈진"이라 말하지 않는다 — 애초에 켜진 적이 없기 때문이다. 실제 예산
    수치를 실어 에이전트가 스스로 유효한 offset/limit을 계산할 수 있게 한다.
    """
    return (
        f"[context-guard-kit] Large Read blocked ({count}x). Narrowed {max_line_range()}-line "
        f"range still exceeds the {content_limit:,}-byte guard; supply an explicit offset/limit "
        f"under it. {read_disable_hint()}"
    )


def deny_response(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def valve_updated_input_response(payload: dict[str, Any], offer: tuple[int, int]) -> dict[str, Any]:
    """3회차 밸브가 발화했을 때 offset/limit을 주입한 updatedInput 훅 응답을 만든다."""
    updated_input = copy.deepcopy(tool_input(payload))
    updated_input["offset"], updated_input["limit"] = offer
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated_input,
        }
    }


def main() -> int:
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print("ContextGuard helper: context-guard-guard-read")
        return 0
    started = _journal_start()
    # 저널에 실을 값은 페이로드를 읽은 뒤에야 확정되므로 가변 상자에 담아 둔다.
    journal_state: dict[str, Any] = {"session": None, "in_bytes": 0}

    def finish(
        response: dict[str, Any] | None = None,
        *,
        intervened: bool = False,
        withheld: int = 0,
        detail: str | None = None,
    ) -> int:
        """훅 응답 한 건을 내보내고 같은 사실을 저널에 한 줄 남긴다."""
        rendered = "{}" if response is None else json.dumps(response, ensure_ascii=False)
        print(rendered)
        _journal_record(
            started=started,
            intervened=intervened,
            session_id=journal_state["session"],
            input_bytes=journal_state["in_bytes"],
            output_bytes=len(rendered.encode("utf-8", errors="replace")),
            withheld_bytes=withheld,
            detail=detail,
        )
        return 0

    if truthy_disabled(env_value(GUARD_ENV, LEGACY_GUARD_ENV)):
        return finish(detail="env off")
    if _switch_says_off():
        return finish(detail="switched off")
    try:
        raw_stdin = sys.stdin.read()
        journal_state["in_bytes"] = len(raw_stdin.encode("utf-8", errors="replace"))
        payload = json.loads(raw_stdin)
    except json.JSONDecodeError as exc:
        print(f"context-guard-guard-read: invalid hook JSON: {exc}", file=sys.stderr)
        reason = "[context-guard-kit] Read blocked because the hook payload was invalid JSON. Retry the tool call."
        return finish(deny_response(reason), intervened=True, detail="invalid json")
    if not isinstance(payload, dict):
        reason = "[context-guard-kit] Read blocked because the hook payload was not a JSON object. Retry the tool call."
        return finish(deny_response(reason), intervened=True, detail="payload not object")
    journal_state["session"] = payload.get("session_id")
    current_tool = tool_name(payload)
    if current_tool and current_tool != "Read":
        return finish()

    raw_path = read_path_from_payload(payload)
    if not raw_path:
        return finish()
    root = Path.cwd().resolve()
    try:
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = root / path
        path = Path(os.path.abspath(os.fspath(path)))
        path = normalize_allowed_first_absolute_symlink(path)
        traverses_symlink = has_symlink_component(path)
    except (OSError, RuntimeError, ValueError):
        reason = (
            "[context-guard-kit] Read blocked because the requested file path could not be normalized safely. "
            "Retry with a valid, explicit file path."
        )
        return finish(deny_response(reason), intervened=True, detail="path not normalizable")
    if traverses_symlink:
        label = safe_label(path, root)
        reason = (
            f"[context-guard-kit] Read blocked for {label}: requested path traverses a symlink. "
            "Use a real project file path before reading or extracting symbols."
        )
        return finish(deny_response(reason), intervened=True, detail="symlink path")
    if read_env_file_denied(path):
        reason = (
            "[context-guard-kit] Read blocked by the Read-only environment-file policy: the normalized basename "
            "begins with .env and is not exactly .env.example, .env.sample, or .env.template. "
            "This hook protects Claude Read only; Glob name listings, Grep, and Bash/process access are out of scope."
        )
        return finish(deny_response(reason), intervened=True, detail="env file")
    content_limit = max_bytes()
    size = 0
    initial_stat: os.stat_result | None = None
    outcome = "invalid_read_range"
    fingerprint = ""
    valve_offer: tuple[int, int] | None = None
    fd = -1
    try:
        fd = open_regular_no_symlink(path)
        initial_stat = os.fstat(fd)
        size = initial_stat.st_size
        if size <= content_limit:
            return finish()

        # peek: fd 보유 구간 안에서 밸브 판정에 쓸 이전 시도 횟수를 읽는다(쓰기 없음).
        fingerprint = read_guard_fingerprint(path, safe_label(path, root), size, stat_result=initial_stat)
        attempt_peek = peek_read_guard_attempt(root, fingerprint)

        requested_range = large_read_range(payload)
        if requested_range is not None:
            outcome = raw_read_range_outcome(
                fd,
                initial_stat,
                size=size,
                offset=requested_range[0],
                limit=requested_range[1],
                content_limit=content_limit,
            )

        if (
            outcome not in ("allowed", "file_changed_during_proof")
            and attempt_peek["count"] + 1 == 3
            and not attempt_peek["valve_used"]
        ):
            candidate = (0, max_line_range())
            candidate_outcome = raw_read_range_outcome(
                fd,
                initial_stat,
                size=size,
                offset=candidate[0],
                limit=candidate[1],
                content_limit=content_limit,
            )
            if candidate_outcome == "allowed":
                outcome = "allowed"
                valve_offer = candidate
    except (OSError, ValueError) as exc:
        error_number = getattr(exc, "errno", None)
        if error_number == errno.ELOOP:
            label = safe_label(path, root)
            reason = (
                f"[context-guard-kit] Read blocked for {label}: requested path traverses a symlink. "
                "Use a real project file path before reading or extracting symbols."
            )
            return finish(deny_response(reason), intervened=True, detail="symlink path")
        if error_number == errno.ENOENT:
            return finish()
        label = safe_label(path, root)
        detail = compact_hook_text(getattr(exc, "strerror", "") or exc.__class__.__name__, 80)
        print(f"context-guard-guard-read: could not safely inspect requested file: {detail}", file=sys.stderr)
        if error_number in {errno.EINVAL, errno.ENOTDIR, errno.EISDIR}:
            reason = (
                f"[context-guard-kit] Read blocked for {label}: requested path is not a regular file. "
                "Use a real, non-symlink file path before reading."
            )
        else:
            reason = (
                f"[context-guard-kit] Read blocked for {label}: the guard could not safely inspect the file "
                f"({detail}). Use a bounded line range or verify the path locally first."
            )
        return finish(deny_response(reason), intervened=True, detail="inspect failed")
    finally:
        if fd != -1:
            os.close(fd)

    if outcome == "allowed" and valve_offer is not None:
        # commit: fd 종료 이후 밸브 발화를 지문에 1회로 기록한다(FIFO/LRU 유사 축출 유지).
        try:
            record_read_guard_attempt(root, fingerprint, valve_fired=True)
        except Exception:
            pass
        # 밸브가 주입한 범위는 raw_read_range_outcome 이 "allowed" 로 증명한 범위이므로
        # 그 내용 바이트는 content_limit 이하임이 보장된다. 따라서 컨텍스트에 들어가지
        # 않은 바이트의 보수적 추정치는 (파일 크기 - 바이트 가드)다. 실제 주입 범위는
        # 보통 이보다 작으므로 이 추정은 과대평가하지 않는다.
        return finish(
            valve_updated_input_response(payload, valve_offer),
            intervened=True,
            withheld=max(0, size - content_limit),
            detail="valve range injected",
        )

    if outcome == "allowed":
        return finish()

    try:
        attempt_count = record_read_guard_attempt(root, fingerprint, valve_fired=False)
    except Exception:
        attempt_count = 1

    # 3단 분기. 1) count<3: 아직 자기 교정 여지가 있으므로 전체 사다리를 준다.
    # 2) count>=3, valve_used=False: 밸브가 3회차에 시도됐고(구성상 이 카운트에
    #    도달하려면 반드시 시도됐다) 구조적으로 발화할 수 없었던 지문 — "탈진"이
    #    아니라 "애초에 켤 수 없다"이므로 실제 예산 수치가 담긴 실행 가능한 단축
    #    메시지를 쓴다. 3) valve_used=True: 과거에 실제로 발화했던 지문 — 기존
    #    "탈진" 단축 메시지.
    if attempt_peek["valve_used"]:
        reason = valve_exhausted_reason(attempt_count)
    elif attempt_count >= 3:
        reason = valve_budget_exceeded_reason(attempt_count, content_limit)
    else:
        read_symbol = find_read_symbol_command()
        reason = read_proof_denial_reason(
            outcome,
            path=path,
            root=root,
            size=size,
            content_limit=content_limit,
            read_symbol=read_symbol,
        ) + repeated_read_hint(attempt_count)
    # deny 는 파일 전체가 컨텍스트에 들어오지 않게 막은 것이므로 보류 바이트는 파일 크기다.
    return finish(deny_response(reason), intervened=True, withheld=size, detail=f"deny {outcome}")


if __name__ == "__main__":
    raise SystemExit(main())
