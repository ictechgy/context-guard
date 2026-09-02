#!/usr/bin/env python3
"""Claude Code Bash terminal-hook feedback with privacy-safe accounting.

The hook accepts both ``PostToolUse`` and ``PostToolUseFailure`` payloads. It
groups only exact ContextGuard wrapper envelopes, stores full SHA-256 identity
components instead of raw commands/session/tool IDs, and emits one bounded
strategy nudge on the second unique failure in an episode.

State is project-local at ``.context-guard/failures-v2.json``. A
symlink-safe advisory lock covers read/modify/durable-write so concurrent hook
processes cannot emit the same episode twice.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import shlex
import shutil
import stat
import sys
import time
import uuid
from pathlib import Path

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
redact_sensitive_hook_text = _hook_secret_patterns.redact_sensitive_hook_text

STATE_DIR = Path(".context-guard")
STATE_PATH = STATE_DIR / "failures-v2.json"
STATE_LOCK_PATH = STATE_DIR / "failures-v2.lock"
STATE_VERSION = 2
STATE_TTL_SECONDS = 30 * 60
MAX_EPISODES = 256
MAX_EVENT_IDS = 512
MAX_STATE_BYTES = 1_000_000
MAX_COUNTER = (1 << 63) - 1
STATE_LOCK_TIMEOUT_SECONDS = 2.0
STATE_LOCK_POLL_SECONDS = 0.01
CGW1_SENTINEL = "--context-guard-wrapper-v1"
CGW1_COMMAND_SEARCH_DIFF = "command_search_diff"
CGW1_SHELL_ARGV = ("bash", "-c")
LEGACY_V0_MAX_LINES = "220"
PROTOCOL_CGW1 = "cgw1"
PROTOCOL_LEGACY_V0 = "legacy-v0"
PROTOCOL_DIRECT = "direct"
PROTOCOL_FOREIGN = "legacy-or-foreign"
PROTOCOLS = frozenset({
    PROTOCOL_CGW1,
    PROTOCOL_LEGACY_V0,
    PROTOCOL_DIRECT,
    PROTOCOL_FOREIGN,
})
COUNTER_NAMES = frozenset({
    "dedupe",
    "conflict",
    "episode_expired",
    "event_expired",
    "episode_evicted",
    "event_evicted",
    "tracking_started",
    "nudge_emitted",
    "failure_after_emit",
    "success_reset",
    "interrupted",
    "missing_exit",
    "ambiguous_exit",
    "malformed_event",
    "missing_session",
    "missing_tool_id",
})

# Retained compatibility helpers are exercised by the legacy aggregate suite.
# The v2 runtime below does not use their truncated fingerprints or tail list.
MAX_TRACKED = 5
MIN_CONSECUTIVE = 2
STRATEGY_SWITCH_MIN_CONSECUTIVE = 3
FINGERPRINT_SELECTOR_FLAGS = {"-k", "-m", "--grep", "--testNamePattern", "--test-name-pattern"}
DIAGNOSTIC_MAX_CHARS = 240
MAX_HOOK_STDIN_BYTES = 1_000_000
ANSI_ESCAPE_RE = re.compile(r"(?:\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~])")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
UNSUPPORTED_STATE_IO_ERRNO = getattr(errno, "ENOTSUP", getattr(errno, "EOPNOTSUPP", errno.EINVAL))
UNSAFE_STATE_PATH_ERRNOS = {
    errno.ELOOP,
    errno.ENOTDIR,
    errno.EISDIR,
}
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    # macOS exposes these as first-component symlinks to /private/*.  Allow only
    # this OS-owned alias so tests and hooks in TMPDIR can still use no-follow
    # traversal without accepting arbitrary user-controlled symlink parents.
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


class UnsupportedSafeStateIOError(OSError):
    """현재 플랫폼에서 no-follow state IO 를 안전하게 보장할 수 없음."""


class UnsafeStatePathError(OSError):
    """state path 가 symlink/비정규 파일/부적절한 경로 형태라 거부됨."""


class InvalidStateError(OSError):
    """Persisted v2 state is malformed, unsupported, or oversized."""


class StateLockTimeoutError(OSError):
    """The bounded state lock deadline elapsed."""


@dataclass(frozen=True)
class CommandIdentity:
    protocol: str
    digest: str


@dataclass(frozen=True)
class TerminalEvent:
    hook_event_name: str
    outcome: str
    session_digest: str
    tool_id_digest: str
    command_identity: CommandIdentity

    @property
    def episode_key(self) -> str:
        components = (
            self.session_digest,
            self.command_identity.protocol,
            self.command_identity.digest,
        )
        return sha256_text(json.dumps(components, separators=(",", ":"), ensure_ascii=True))


# additionalContext 는 모델에게 주입되므로 사용자에게 직접 명령하는 톤보다 모델이 행동을
# 결정할 때 참고할 힌트 형태가 자연스럽다. 모델이 사용자에게 안내하도록 유도한다.
NUDGE_TEXT = (
    "AI 힌트: 같은 Bash 작업이 이 세션에서 두 번 실패했습니다. 동일 경로를 다시 실행하지 말고 "
    "실패의 공통 조건을 요약한 뒤 다른 가설, 더 작은 재현, 또는 수정 후의 좁은 검증으로 전환하세요. "
    "긴 출력이 artifact receipt로 저장되었다면 전체 로그를 재주입하지 말고 필요한 줄만 조회하세요. "
    "컨텍스트가 오염되었다면 사용자에게 `/compact` 또는 `/clear` 선택지를 짧게 안내하세요."
)
STRATEGY_SWITCH_TEXT = (
    " Strategy-switch signal: the same failure direction has now repeated at least three times. "
    "Stop retrying the identical command path; summarize the invariant failure, choose a different hypothesis "
    "or smaller reproducer, rehydrate exact artifact receipt slices when available, "
    "and only rerun after changing code, inputs, or diagnostic scope."
)


def normalize_command(command: str) -> str:
    """명령을 stable fingerprint 텍스트로 축약한다.

    "방향" 만 보존하기 위해 모든 `-`/`--` 옵션을 제거하고 positional 토큰 중 처음
    2 개(보통 `command primary_target`)와 대표 selector 옵션을 남긴다. 예:
    - `pytest tests/auth.py`, `pytest tests/auth.py -v` 는 같은 fingerprint.
    - `pytest tests/auth.py -k login` 과 `pytest tests/auth.py -k logout` 은 다른 fingerprint.
    - `pytest tests/billing.py` 는 다른 fingerprint.

    한계:
    - flag value 가 positional 으로 잘못 잡혀도 첫 2 개만 보므로 영향이 거의 없다.
    - 같은 작업을 여러 대상에 나눠 실행하면 (`pytest A` 후 `pytest B`) 다른 fp 로 본다.
    이 단순화는 도구별 옵션 목록 유지비용 없이 운영 의도("같은 방향으로 두 번 실패하면
    권유") 와 가장 잘 맞도록 의도적으로 거칠게 잡았다.
    """
    try:
        argv = shlex.split(command)
    except ValueError:
        argv = command.split()
    positional: list[str] = []
    selectors: list[tuple[str, str]] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        flag, sep, inline_value = token.partition("=")
        if flag in FINGERPRINT_SELECTOR_FLAGS:
            value = inline_value if sep else (argv[index + 1] if index + 1 < len(argv) else "")
            if value:
                selectors.append((flag, value))
                if not sep:
                    index += 1
        elif token != "--" and not token.startswith("-"):
            positional.append(token)
        index += 1
    normalized = positional[:2]
    selector_text = [f"{flag}={value}" for flag, value in sorted(selectors, key=lambda item: item[0])]
    return " ".join([*normalized, *selector_text])


def fingerprint(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _wrapper_prefixes() -> dict[str, tuple[str, ...]]:
    """Return only the wrapper identities emitted beside this nudge helper."""
    if Path(__file__).name == "failed_attempt_nudge.py":
        return {
            "sanitize": ("python3", str(SCRIPT_DIR / "sanitize_output.py")),
            "trim": ("python3", str(SCRIPT_DIR / "trim_command_output.py")),
        }
    return {
        "sanitize": (str(SCRIPT_DIR / "context-guard-sanitize-output"),),
        "trim": (str(SCRIPT_DIR / "context-guard-trim-output"),),
    }


def _approved_python_runtime() -> str:
    canonical = os.path.realpath(sys.executable)
    if not canonical or not os.path.isabs(canonical) or not os.path.isfile(canonical) or not os.access(canonical, os.X_OK):
        raise RuntimeError("approved Python runtime is unavailable")
    return canonical


def _approved_bash_runtime() -> str:
    found = shutil.which("bash", path=os.defpath)
    if not found:
        raise RuntimeError("approved Bash runtime is unavailable")
    canonical = os.path.realpath(found)
    if not os.path.isfile(canonical) or not os.access(canonical, os.X_OK):
        raise RuntimeError("approved Bash runtime is unavailable")
    return canonical


def _approved_env_runtime() -> str:
    found = shutil.which("env", path=os.defpath)
    if not found:
        raise RuntimeError("approved env runtime is unavailable")
    canonical = os.path.realpath(found)
    if not os.path.isfile(canonical) or not os.access(canonical, os.X_OK):
        raise RuntimeError("approved env runtime is unavailable")
    return canonical


def _runtime_shell_argv() -> tuple[str, ...]:
    return (
        _approved_env_runtime(),
        "-u", "BASH_ENV",
        "-u", "ENV",
        "-u", "PYTHONHOME",
        "-u", "PYTHONPATH",
        "-u", "PYTHONSTARTUP",
        "-u", "SHELLOPTS",
        "-u", "BASHOPTS",
        "-u", "PS4",
        _approved_bash_runtime(),
        "--noprofile",
        "--norc",
        "-p",
        "-c",
    )


def _runtime_wrapper_prefixes() -> dict[str, tuple[str, ...]]:
    adjacent = _wrapper_prefixes()
    return {
        kind: (_approved_python_runtime(), "-I", prefix[-1])
        for kind, prefix in adjacent.items()
    }


def _argv(command: str) -> tuple[str, ...] | None:
    try:
        values = shlex.split(command, posix=True)
    except (ValueError, TypeError):
        return None
    if not values or any("\x00" in value for value in values):
        return None
    return tuple(values)


def _is_wrapper_shaped(argv: tuple[str, ...]) -> bool:
    known = {
        "sanitize_output.py",
        "trim_command_output.py",
        "context-guard-sanitize-output",
        "context-guard-trim-output",
        "claude-sanitize-output",
        "claude-trim-output",
    }
    if not argv:
        return False
    first = os.path.basename(argv[0])
    if first in known:
        return True
    return (
        re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", first) is not None
        and len(argv) > 1
        and (
            os.path.basename(argv[1]) in known
            or (
                len(argv) > 2
                and argv[1] == "-I"
                and os.path.basename(argv[2]) in known
            )
        )
    )


def command_identity(command: str) -> CommandIdentity:
    """Structurally unwrap only the frozen current or allowlisted v0 shapes."""
    argv = _argv(command)
    if argv is None:
        return CommandIdentity(PROTOCOL_FOREIGN, sha256_text(command))

    prefixes = _wrapper_prefixes()
    runtime_prefixes = _runtime_wrapper_prefixes()
    current_shell_argv = _runtime_shell_argv()
    for prefix, shell_argv in (
        (runtime_prefixes["sanitize"], current_shell_argv),
        (prefixes["sanitize"], CGW1_SHELL_ARGV),
    ):
        sanitize_cgw1 = prefix + (
            CGW1_SENTINEL,
            CGW1_COMMAND_SEARCH_DIFF,
            "--",
            *shell_argv,
        )
        if len(argv) == len(sanitize_cgw1) + 1 and argv[:-1] == sanitize_cgw1:
            logical = argv[-1]
            if logical and not _is_wrapper_shaped(_argv(logical) or ()):
                return CommandIdentity(PROTOCOL_CGW1, sha256_text(logical))

    # The frozen A1 producer still emits this exact v0 envelope for trim.
    # The historical producer emitted it for sanitize as well, so both known
    # adjacent wrapper identities remain allowlisted for one compatibility
    # window. No other --/bash/-lc spelling is unwrapped.
    for prefix_set, shell_argv in (
        (prefixes, CGW1_SHELL_ARGV),
        (runtime_prefixes, current_shell_argv),
    ):
        for prefix in prefix_set.values():
            legacy_v0 = prefix + (
                "--max-lines",
                LEGACY_V0_MAX_LINES,
                "--",
                *shell_argv,
            )
            if len(argv) == len(legacy_v0) + 1 and argv[:-1] == legacy_v0:
                logical = argv[-1]
                if logical and not _is_wrapper_shaped(_argv(logical) or ()):
                    return CommandIdentity(PROTOCOL_LEGACY_V0, sha256_text(logical))

    protocol = PROTOCOL_FOREIGN if (
        _is_wrapper_shaped(argv) or CGW1_SENTINEL in argv
    ) else PROTOCOL_DIRECT
    return CommandIdentity(protocol, sha256_text(command))


def _base_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _no_follow_flag() -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return os.O_NOFOLLOW
    raise UnsupportedSafeStateIOError(
        UNSUPPORTED_STATE_IO_ERRNO,
        "failed-attempt nudge state requires POSIX no-follow file opens",
    )


def _directory_flag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def _normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def _normalize_allowed_first_absolute_symlink(path: Path) -> Path:
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
        if _normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def _open_directory_at(dir_fd: int, component: str, path: Path) -> int:
    fd = os.open(component, _base_open_flags() | _directory_flag() | _no_follow_flag(), dir_fd=dir_fd)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise UnsafeStatePathError(errno.ENOTDIR, "not a directory", str(path))
        return fd
    except Exception:
        os.close(fd)
        raise


def _mkdir_directory_at(dir_fd: int, component: str) -> None:
    os.mkdir(component, 0o777, dir_fd=dir_fd)


def _ensure_directory_no_symlink(path: Path, *, create: bool = False) -> int:
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise UnsupportedSafeStateIOError(
            UNSUPPORTED_STATE_IO_ERRNO,
            "failed-attempt nudge state requires directory-relative no-follow access",
        )
    path = _normalize_allowed_first_absolute_symlink(path)
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for component in components:
            if component in {"", "."}:
                continue
            if component == "..":
                raise UnsafeStatePathError(errno.EINVAL, "parent traversal is not allowed", str(path))
            try:
                next_fd = _open_directory_at(dir_fd, component, path)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    _mkdir_directory_at(dir_fd, component)
                except FileExistsError:
                    # 다른 hook process 가 방금 만든 경우. 아래 no-follow open 으로
                    # 실제 디렉터리인지 다시 검증하므로 symlink race 는 허용하지 않는다.
                    pass
                next_fd = _open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd
        return dir_fd
    except Exception:
        os.close(dir_fd)
        raise


def _open_regular_no_symlink(
    path: Path,
    flags: int | None = None,
    mode: int = 0o666,
    *,
    create_parent: bool = False,
) -> int:
    if os.open not in os.supports_dir_fd:
        raise UnsupportedSafeStateIOError(
            UNSUPPORTED_STATE_IO_ERRNO,
            "failed-attempt nudge state requires directory-relative no-follow opens",
        )
    path = _normalize_allowed_first_absolute_symlink(path)
    parent_fd = _ensure_directory_no_symlink(path.parent, create=create_parent)
    open_flags = (flags if flags is not None else _base_open_flags()) | _no_follow_flag()
    try:
        fd = os.open(path.name, open_flags, mode, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise UnsafeStatePathError(errno.EINVAL, "not a regular file", str(path))
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(parent_fd)


def _read_text_no_follow(path: Path) -> str:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def _is_unsafe_state_path_error(exc: OSError) -> bool:
    return isinstance(exc, UnsafeStatePathError) or exc.errno in UNSAFE_STATE_PATH_ERRNOS


def _rename_supports_dir_fd() -> bool:
    return os.rename in os.supports_dir_fd


def _rename_with_dir_fd(src: str, dst: str, parent_fd: int) -> None:
    os.rename(src, dst, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)


def _rename_state_entry(src: str, dst: str, parent_fd: int) -> None:
    if not _rename_supports_dir_fd():
        raise UnsupportedSafeStateIOError(
            UNSUPPORTED_STATE_IO_ERRNO,
            "failed-attempt nudge state requires directory-relative rename",
        )
    try:
        _rename_with_dir_fd(src, dst, parent_fd)
    except (NotImplementedError, TypeError) as exc:
        raise UnsupportedSafeStateIOError(
            UNSUPPORTED_STATE_IO_ERRNO,
            "failed-attempt nudge state requires directory-relative rename",
        ) from exc


def load_entries(path: Path) -> list[dict]:
    """state file 을 읽는다. 파일이 symlink/regular 가 아니거나 손상되면 빈 list 반환."""
    try:
        data = json.loads(_read_text_no_follow(path))
    except FileNotFoundError:
        return []
    except UnicodeDecodeError:
        return []
    except json.JSONDecodeError:
        return []
    except UnsupportedSafeStateIOError:
        raise
    except OSError as exc:
        if _is_unsafe_state_path_error(exc):
            return []
        raise
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def save_entries(path: Path, entries: list[dict]) -> None:
    """심볼릭 링크 / 동시 race 에 안전한 atomic write.

    - 부모/조상 디렉터리를 dir_fd + O_NOFOLLOW 로 열어 symlink/race 를 거부한다.
    - O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW 로 임시 파일을 쓰고 dir_fd 기반 rename 으로 교체.
    - 임시 파일 이름은 무작위라 동시 호출 충돌 가능성이 낮고 O_EXCL 로 재확인한다.
    - 모드는 0o600 으로 잠근다.
    """
    parent_fd = -1
    tmp_fd = -1
    tmp_name = f".nudge-{os.getpid()}-{uuid.uuid4().hex}.json.tmp"
    try:
        parent_fd = _ensure_directory_no_symlink(path.parent, create=True)
        tmp_fd = os.open(
            tmp_name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | _no_follow_flag(),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(tmp_fd, 0o600)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                tmp_fd = -1
                f.write(json.dumps(entries, ensure_ascii=False))
        finally:
            if tmp_fd != -1:
                os.close(tmp_fd)

        # 기존 state file 이 symlink/비정규 파일이면 거부. 이후 이름이 바뀌어도
        # dir_fd 기반 replace 는 symlink 타깃을 따라가지 않고 해당 dir entry 만 교체한다.
        try:
            existing_fd = os.open(path.name, _base_open_flags() | _no_follow_flag(), dir_fd=parent_fd)
        except FileNotFoundError:
            existing_fd = -1
        except OSError as exc:
            if _is_unsafe_state_path_error(exc):
                return
            raise
        else:
            try:
                if not stat.S_ISREG(os.fstat(existing_fd).st_mode):
                    return
            finally:
                os.close(existing_fd)

        _rename_state_entry(tmp_name, path.name, parent_fd)
        tmp_name = ""
    except UnsupportedSafeStateIOError:
        raise
    except OSError as exc:
        if _is_unsafe_state_path_error(exc):
            return
        raise
    finally:
        if tmp_fd != -1:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if parent_fd != -1:
            if tmp_name:
                try:
                    os.unlink(tmp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            try:
                os.close(parent_fd)
            except OSError:
                pass


def _read_bytes_no_follow(path: Path, limit: int = MAX_STATE_BYTES) -> bytes:
    fd = _open_regular_no_symlink(path)
    chunks: list[bytes] = []
    remaining = limit + 1
    try:
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise InvalidStateError(errno.EFBIG, "oversized v2 nudge state")
    return data


def _atomic_write_json(path: Path, value: object) -> None:
    """Write private JSON durably using only directory-relative no-follow IO."""
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise InvalidStateError(errno.EFBIG, "v2 nudge state exceeds size bound")

    parent_fd = -1
    tmp_fd = -1
    tmp_name = f".nudge-v2-{os.getpid()}-{uuid.uuid4().hex}.tmp"
    try:
        parent_fd = _ensure_directory_no_symlink(path.parent, create=True)
        tmp_fd = os.open(
            tmp_name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | _no_follow_flag(),
            0o600,
            dir_fd=parent_fd,
        )
        if not stat.S_ISREG(os.fstat(tmp_fd).st_mode):
            raise UnsafeStatePathError(errno.EINVAL, "temporary state is not regular")
        if hasattr(os, "fchmod"):
            os.fchmod(tmp_fd, 0o600)
        view = memoryview(encoded)
        written = 0
        while written < len(view):
            count = os.write(tmp_fd, view[written:])
            if count <= 0:
                raise OSError(errno.EIO, "short state write")
            written += count
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1

        try:
            existing_fd = os.open(
                path.name,
                _base_open_flags() | _no_follow_flag(),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            existing_fd = -1
        else:
            try:
                if not stat.S_ISREG(os.fstat(existing_fd).st_mode):
                    raise UnsafeStatePathError(errno.EINVAL, "state is not regular")
            finally:
                os.close(existing_fd)

        _rename_state_entry(tmp_name, path.name, parent_fd)
        tmp_name = ""
        os.fsync(parent_fd)
    finally:
        if tmp_fd != -1:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        if parent_fd != -1:
            if tmp_name:
                try:
                    os.unlink(tmp_name, dir_fd=parent_fd)
                except OSError:
                    pass
            try:
                os.close(parent_fd)
            except OSError:
                pass


@contextmanager
def state_lock(
    path: Path = STATE_LOCK_PATH,
    *,
    timeout: float = STATE_LOCK_TIMEOUT_SECONDS,
):
    """Acquire a bounded private sibling lock without following symlinks."""
    parent_fd = _ensure_directory_no_symlink(path.parent, create=True)
    lock_fd = -1
    try:
        lock_fd = os.open(
            path.name,
            os.O_CREAT | os.O_RDWR | _no_follow_flag(),
            0o600,
            dir_fd=parent_fd,
        )
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise UnsafeStatePathError(errno.EINVAL, "state lock is not regular")
        if hasattr(os, "fchmod"):
            os.fchmod(lock_fd, 0o600)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StateLockTimeoutError(
                        errno.ETIMEDOUT,
                        "v2 nudge state lock timed out",
                    )
                time.sleep(STATE_LOCK_POLL_SECONDS)
        yield
    finally:
        if lock_fd != -1:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(lock_fd)
            except OSError:
                pass
        os.close(parent_fd)


def empty_state() -> dict:
    return {
        "version": STATE_VERSION,
        "episodes": [],
        "events": [],
        "counters": {},
    }


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _valid_timestamp(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _validate_episode(value: object) -> dict:
    if not isinstance(value, dict):
        raise InvalidStateError(errno.EINVAL, "invalid episode record")
    required = {
        "key",
        "session",
        "protocol",
        "command",
        "state",
        "count",
        "updated_at",
    }
    if set(value) != required:
        raise InvalidStateError(errno.EINVAL, "invalid episode fields")
    if not all(
        isinstance(value[name], str) and _DIGEST_RE.fullmatch(value[name])
        for name in ("key", "session", "command")
    ):
        raise InvalidStateError(errno.EINVAL, "invalid episode digest")
    if not isinstance(value["protocol"], str) or value["protocol"] not in PROTOCOLS:
        raise InvalidStateError(errno.EINVAL, "invalid episode protocol")
    if not isinstance(value["state"], str) or value["state"] not in {"tracking", "emitted"}:
        raise InvalidStateError(errno.EINVAL, "invalid episode state")
    count = value["count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_COUNTER:
        raise InvalidStateError(errno.EINVAL, "invalid episode count")
    if value["state"] == "tracking" and count != 1:
        raise InvalidStateError(errno.EINVAL, "invalid tracking count")
    if value["state"] == "emitted" and count < 2:
        raise InvalidStateError(errno.EINVAL, "invalid emitted count")
    if not _valid_timestamp(value["updated_at"]):
        raise InvalidStateError(errno.EINVAL, "invalid episode timestamp")
    return dict(value)


def _validate_event(value: object) -> dict:
    if not isinstance(value, dict):
        raise InvalidStateError(errno.EINVAL, "invalid event record")
    required = {"id", "episode", "outcome", "updated_at"}
    if set(value) != required:
        raise InvalidStateError(errno.EINVAL, "invalid event fields")
    if not (
        isinstance(value["id"], str)
        and _DIGEST_RE.fullmatch(value["id"])
        and isinstance(value["episode"], str)
        and _DIGEST_RE.fullmatch(value["episode"])
    ):
        raise InvalidStateError(errno.EINVAL, "invalid event digest")
    if value["outcome"] not in {"failure", "success"}:
        raise InvalidStateError(errno.EINVAL, "invalid event outcome")
    if not _valid_timestamp(value["updated_at"]):
        raise InvalidStateError(errno.EINVAL, "invalid event timestamp")
    return dict(value)


def validate_state(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "episodes",
        "events",
        "counters",
    }:
        raise InvalidStateError(errno.EINVAL, "invalid v2 nudge state")
    if value["version"] != STATE_VERSION:
        raise InvalidStateError(errno.EINVAL, "unsupported v2 nudge state version")
    if not isinstance(value["episodes"], list) or not isinstance(value["events"], list):
        raise InvalidStateError(errno.EINVAL, "invalid v2 nudge collections")
    if not isinstance(value["counters"], dict):
        raise InvalidStateError(errno.EINVAL, "invalid v2 nudge counters")

    episodes = [_validate_episode(item) for item in value["episodes"]]
    events = [_validate_event(item) for item in value["events"]]
    if len({item["key"] for item in episodes}) != len(episodes):
        raise InvalidStateError(errno.EINVAL, "duplicate episode key")
    if len({item["id"] for item in events}) != len(events):
        raise InvalidStateError(errno.EINVAL, "duplicate event id")

    counters: dict[str, int] = {}
    for name, count in value["counters"].items():
        if (
            name not in COUNTER_NAMES
            or isinstance(count, bool)
            or not isinstance(count, int)
            or not 0 <= count <= MAX_COUNTER
        ):
            raise InvalidStateError(errno.EINVAL, "invalid v2 nudge counter")
        if count:
            counters[name] = count
    return {
        "version": STATE_VERSION,
        "episodes": episodes,
        "events": events,
        "counters": counters,
    }


def load_state(path: Path = STATE_PATH) -> dict:
    try:
        raw = _read_bytes_no_follow(path)
    except FileNotFoundError:
        return empty_state()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidStateError(errno.EINVAL, "invalid v2 nudge JSON") from exc
    return validate_state(value)


def save_state(state: dict, path: Path = STATE_PATH) -> None:
    _atomic_write_json(path, validate_state(state))


def safe_session_label(session_id: str | None) -> str | None:
    """session_id 를 파일명 안전 digest 로 변환. 없으면 None — 호출자가 hook 을 noop 한다."""
    if not session_id or not isinstance(session_id, str):
        return None
    digest = hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"sess-{digest}"


def diagnostic_text(exc: OSError) -> str:
    """Bound hook stderr diagnostics so hostile session/path text is not surfaced raw."""
    text = str(exc) or exc.__class__.__name__
    text = ANSI_ESCAPE_RE.sub(" ", text)
    text = CONTROL_CHAR_RE.sub(" ", text)
    text = redact_sensitive_hook_text(text)
    cwd = ""
    try:
        cwd = str(Path.cwd().resolve())
    except OSError:
        try:
            cwd = str(Path.cwd())
        except OSError:
            cwd = ""
    if cwd and cwd not in {"/", "\\"}:
        text = text.replace(cwd, "<cwd>")
    compact = " ".join(text.split())
    if len(compact) > DIAGNOSTIC_MAX_CHARS:
        compact = compact[: DIAGNOSTIC_MAX_CHARS - 15].rstrip() + "...[truncated]"
    return compact or exc.__class__.__name__


def extract_exit_code(tool_response: dict) -> int | None:
    for key in ("exitCode", "exit_code", "returncode"):
        value = tool_response.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
    return None


def read_bounded_stdin_text(limit: int = MAX_HOOK_STDIN_BYTES) -> tuple[str | None, bool]:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    data = stream.read(limit + 1)
    if isinstance(data, str):
        oversized = len(data.encode("utf-8", errors="replace")) > limit
        return (None, True) if oversized else (data, False)
    oversized = len(data) > limit
    if oversized:
        return None, True
    return data.decode("utf-8", errors="replace"), False


_MISSING = object()
_AMBIGUOUS = object()


def _alias(value: dict, snake: str, camel: str) -> object:
    snake_value = value.get(snake, _MISSING)
    camel_value = value.get(camel, _MISSING)
    if snake_value is not _MISSING and camel_value is not _MISSING:
        return snake_value if snake_value == camel_value else _AMBIGUOUS
    return snake_value if snake_value is not _MISSING else camel_value


def classify_terminal_event(payload: dict) -> tuple[TerminalEvent | None, str | None]:
    """Return one valid terminal event or a bounded no-transition reason."""
    tool_name = _alias(payload, "tool_name", "toolName")
    if tool_name is _AMBIGUOUS:
        return None, "malformed_event"
    if tool_name != "Bash":
        return None, None

    hook_event_name = _alias(payload, "hook_event_name", "hookEventName")
    if (
        not isinstance(hook_event_name, str)
        or hook_event_name not in {"PostToolUse", "PostToolUseFailure"}
    ):
        return None, "malformed_event"

    tool_input = _alias(payload, "tool_input", "toolInput")
    if not isinstance(tool_input, dict):
        return None, "malformed_event"
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None, "malformed_event"

    session_id = _alias(payload, "session_id", "sessionId")
    if session_id is _AMBIGUOUS:
        return None, "malformed_event"
    if not isinstance(session_id, str) or not session_id:
        return None, "missing_session"
    tool_use_id = _alias(payload, "tool_use_id", "toolUseId")
    if tool_use_id is _AMBIGUOUS:
        return None, "malformed_event"
    if not isinstance(tool_use_id, str) or not tool_use_id:
        return None, "missing_tool_id"

    outcome: str
    if hook_event_name == "PostToolUse":
        tool_response = _alias(payload, "tool_response", "toolResponse")
        if not isinstance(tool_response, dict):
            return None, "malformed_event"
        interrupted = tool_response.get("interrupted", False)
        if not isinstance(interrupted, bool):
            return None, "malformed_event"
        if interrupted:
            return None, "interrupted"
        alternate_exit_fields = {"exitCode", "returncode"}.intersection(tool_response)
        if alternate_exit_fields:
            return None, "ambiguous_exit"
        if "exit_code" not in tool_response:
            return None, "missing_exit"
        exit_code = tool_response["exit_code"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            return None, "ambiguous_exit"
        outcome = "success" if exit_code == 0 else "failure"
    else:
        error = payload.get("error")
        is_interrupt = _alias(payload, "is_interrupt", "isInterrupt")
        if is_interrupt is _AMBIGUOUS:
            return None, "malformed_event"
        if is_interrupt is _MISSING:
            is_interrupt = False
        if not isinstance(error, str) or not error:
            return None, "malformed_event"
        if not isinstance(is_interrupt, bool):
            return None, "malformed_event"
        lowered_error = error.casefold()
        if is_interrupt or any(
            marker in lowered_error
            for marker in ("interrupt", "cancelled", "canceled")
        ):
            return None, "interrupted"
        outcome = "failure"

    return TerminalEvent(
        hook_event_name=hook_event_name,
        outcome=outcome,
        session_digest=sha256_text(session_id),
        tool_id_digest=sha256_text(tool_use_id),
        command_identity=command_identity(command),
    ), None


def _increment_counter(state: dict, name: str, amount: int = 1) -> None:
    if name not in COUNTER_NAMES or amount <= 0:
        return
    counters = state["counters"]
    counters[name] = min(MAX_COUNTER, int(counters.get(name, 0)) + amount)


def _prune_expired(state: dict, now: float) -> None:
    episodes = [
        item
        for item in state["episodes"]
        if now - float(item["updated_at"]) <= STATE_TTL_SECONDS
    ]
    events = [
        item
        for item in state["events"]
        if now - float(item["updated_at"]) <= STATE_TTL_SECONDS
    ]
    _increment_counter(state, "episode_expired", len(state["episodes"]) - len(episodes))
    _increment_counter(state, "event_expired", len(state["events"]) - len(events))
    state["episodes"] = episodes
    state["events"] = events


def _enforce_lru(state: dict) -> None:
    if len(state["episodes"]) > MAX_EPISODES:
        ordered = sorted(
            state["episodes"],
            key=lambda item: (float(item["updated_at"]), item["key"]),
        )
        evict = len(ordered) - MAX_EPISODES
        evicted_keys = {item["key"] for item in ordered[:evict]}
        state["episodes"] = [
            item for item in state["episodes"] if item["key"] not in evicted_keys
        ]
        _increment_counter(state, "episode_evicted", evict)
    if len(state["events"]) > MAX_EVENT_IDS:
        ordered = sorted(
            state["events"],
            key=lambda item: (float(item["updated_at"]), item["id"]),
        )
        evict = len(ordered) - MAX_EVENT_IDS
        evicted_ids = {item["id"] for item in ordered[:evict]}
        state["events"] = [
            item for item in state["events"] if item["id"] not in evicted_ids
        ]
        _increment_counter(state, "event_evicted", evict)


def _nudge_response(hook_event_name: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": hook_event_name,
            "additionalContext": NUDGE_TEXT,
        }
    }


def apply_payload(
    state: dict,
    payload: dict,
    *,
    now: float | None = None,
) -> tuple[dict, dict]:
    """Pure v2 FSM transition used by the locked runtime and protocol tests."""
    state = validate_state(state)
    timestamp = time.time() if now is None else float(now)
    if not _valid_timestamp(timestamp):
        raise ValueError("now must be a finite non-negative timestamp")
    _prune_expired(state, timestamp)
    _enforce_lru(state)

    event, reason = classify_terminal_event(payload)
    if event is None:
        if reason is not None:
            _increment_counter(state, reason)
        return state, {}

    existing_event = next(
        (item for item in state["events"] if item["id"] == event.tool_id_digest),
        None,
    )
    if existing_event is not None:
        if (
            existing_event["episode"] == event.episode_key
            and existing_event["outcome"] == event.outcome
        ):
            _increment_counter(state, "dedupe")
        else:
            _increment_counter(state, "conflict")
        return state, {}

    state["events"].append({
        "id": event.tool_id_digest,
        "episode": event.episode_key,
        "outcome": event.outcome,
        "updated_at": timestamp,
    })
    episode = next(
        (item for item in state["episodes"] if item["key"] == event.episode_key),
        None,
    )

    response: dict = {}
    if event.outcome == "success":
        if episode is not None:
            state["episodes"].remove(episode)
            _increment_counter(state, "success_reset")
    elif episode is None:
        state["episodes"].append({
            "key": event.episode_key,
            "session": event.session_digest,
            "protocol": event.command_identity.protocol,
            "command": event.command_identity.digest,
            "state": "tracking",
            "count": 1,
            "updated_at": timestamp,
        })
        _increment_counter(state, "tracking_started")
    elif episode["state"] == "tracking":
        episode["state"] = "emitted"
        episode["count"] = 2
        episode["updated_at"] = timestamp
        _increment_counter(state, "nudge_emitted")
        response = _nudge_response(event.hook_event_name)
    else:
        episode["count"] = min(MAX_COUNTER, int(episode["count"]) + 1)
        episode["updated_at"] = timestamp
        _increment_counter(state, "failure_after_emit")

    _enforce_lru(state)
    return validate_state(state), response


def update_state_transaction(
    payload: dict,
    *,
    now: float | None = None,
    state_path: Path = STATE_PATH,
    lock_path: Path = STATE_LOCK_PATH,
) -> dict:
    """Serialize one event and return output only after durable persistence."""
    event, _reason = classify_terminal_event(payload)
    if event is None and _reason is None:
        return {}
    with state_lock(lock_path):
        state = load_state(state_path)
        state, response = apply_payload(state, payload, now=now)
        save_state(state, state_path)
    return response


def update_entries(entries: list[dict], fp: str, success: bool) -> list[dict]:
    """성공한 fingerprint 는 카운트 리셋. 실패는 append.

    리셋 의미: 같은 fp 의 마지막 연속 실패 streak 을 끊는다. 다음 동일 fp 실패는 1 회로
    재시작되어 fail→success→fail 패턴이 잘못 nudge 되지 않는다.
    """
    if success:
        # 마지막 entry 가 같은 fp 이면 streak 을 끊기 위해 dummy 'ok' marker 를 push.
        entries.append({"fp": fp, "ok": True})
    else:
        entries.append({"fp": fp})
    if len(entries) > MAX_TRACKED:
        entries = entries[-MAX_TRACKED:]
    return entries


def count_consecutive_failures(entries: list[dict], fp: str) -> int:
    """tail 에서 같은 fp 의 연속 실패 카운트. ok marker 또는 다른 fp 를 만나면 멈춘다."""
    consecutive = 0
    for entry in reversed(entries):
        if entry.get("fp") != fp:
            break
        if entry.get("ok"):
            break
        consecutive += 1
    return consecutive


def main() -> int:
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print("ContextGuard helper: context-guard-failed-nudge")
        return 0
    raw_payload, oversized = read_bounded_stdin_text()
    if oversized:
        sys.stderr.write("context-guard-failed-nudge: oversized hook JSON skipped\n")
        print("{}")
        return 0
    try:
        payload = json.loads(raw_payload or "")
    except json.JSONDecodeError:
        print("{}")
        return 0
    if not isinstance(payload, dict):
        print("{}")
        return 0
    try:
        response = update_state_transaction(payload)
    except OSError as exc:
        # Never emit from an uncommitted transition: a later retry must not
        # produce repeated text after read/lock/durability failure.
        sys.stderr.write(
            "context-guard-failed-nudge: state update skipped: "
            f"{diagnostic_text(exc)}\n"
        )
        response = {}
    print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
