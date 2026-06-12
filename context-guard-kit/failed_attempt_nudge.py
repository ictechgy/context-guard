#!/usr/bin/env python3
"""Claude Code PostToolUse hook: 동일 Bash 명령이 연속 실패하면 /clear 권유.

같은 명령으로 두 번 연속 실패하면 그 흐름은 컨텍스트 오염을 일으키고 prompt cache 도
매 retry 마다 재워밍된다. 이 hook 은 그 패턴을 감지해 다음 turn 의 추가 컨텍스트로
짧은 모델 힌트를 주입한다 (블록하지 않음).

PostToolUse 의 `hookSpecificOutput.additionalContext` 는 Claude Code 공식 hook 명세상
모델 컨텍스트로 surfacing 되는 키이다 (https://code.claude.com/docs/en/hooks 참조).

상태 저장: 프로젝트 로컬 `.context-guard/failures-<session>.json`.
session_id 가 없으면 cross-session 오염을 피하기 위해 hook 자체를 noop 한다.
같은 fingerprint 가 한 번이라도 성공하면 카운트를 리셋한다 (false-positive 방지).
트래킹 깊이는 5 회로 제한해 디스크 사용을 무시할 수 있게 한다.

Install via `.claude/settings.json` PostToolUse hook with matcher "Bash".
"""
from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import sys
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
STATE_FILE_TEMPLATE = "failures-{session}.json"
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


# additionalContext 는 모델에게 주입되므로 사용자에게 직접 명령하는 톤보다 모델이 행동을
# 결정할 때 참고할 힌트 형태가 자연스럽다. 모델이 사용자에게 안내하도록 유도한다.
NUDGE_TEXT = (
    "AI 힌트: 동일 Bash 명령이 이 세션에서 연속 두 번 실패했습니다. "
    "이는 현재 접근 방식이 같은 방향으로 막혀 있고, 실패 시도가 누적될수록 컨텍스트가 오염되며 "
    "prompt cache 도 매 retry 마다 재워밍됨을 의미합니다. "
    "재시도 전에 사용자에게 `/clear` 또는 `/compact focus on …` 으로 세션을 정리한 뒤 "
    "재현 명령·기대 결과·금지 사항을 더 좁혀 다시 prompt 하도록 안내하거나, "
    "근본적으로 다른 방향(다른 모듈 / 검증 명령 / 더 작은 재현)을 제안하세요."
)
STRATEGY_SWITCH_TEXT = (
    " Strategy-switch signal: the same failure direction has now repeated at least three times. "
    "Stop retrying the identical command path; summarize the invariant failure, choose a different hypothesis "
    "or smaller reproducer, and only rerun after changing code, inputs, or diagnostic scope."
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

    tool_name = payload.get("tool_name") or payload.get("toolName")
    if tool_name != "Bash":
        print("{}")
        return 0

    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    tool_response = payload.get("tool_response") or payload.get("toolResponse") or {}
    if not isinstance(tool_input, dict) or not isinstance(tool_response, dict):
        print("{}")
        return 0

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        print("{}")
        return 0

    exit_code = extract_exit_code(tool_response)
    if exit_code is None:
        # exit_code 미확정 — 실패 여부를 모르므로 회귀 위험 방지 차원에서 noop.
        print("{}")
        return 0

    session = safe_session_label(payload.get("session_id") or payload.get("sessionId"))
    if session is None:
        # session_id 가 없으면 cross-session 오염 위험으로 그냥 noop. 상태 파일도 만들지 않는다.
        print("{}")
        return 0

    fp = fingerprint(normalize_command(command))
    state_path = STATE_DIR / STATE_FILE_TEMPLATE.format(session=session)

    try:
        entries = load_entries(state_path)
    except OSError as exc:
        # state 읽기 실패해도 실행을 막지 않는다. 진단 신호만 stderr 에 남긴 뒤 새 streak 으로 시작한다.
        sys.stderr.write(f"context-guard-failed-nudge: state read skipped: {diagnostic_text(exc)}\n")
        entries = []
    success = exit_code == 0
    entries = update_entries(entries, fp, success)
    try:
        save_entries(state_path, entries)
    except OSError as exc:
        # state 저장 실패해도 실행을 막지 않는다. 진단 신호만 stderr 에 남긴다.
        sys.stderr.write(f"context-guard-failed-nudge: state write skipped: {diagnostic_text(exc)}\n")

    if success:
        # 성공이면 nudge 는 절대 발화하지 않는다.
        print("{}")
        return 0

    consecutive = count_consecutive_failures(entries, fp)
    if consecutive < MIN_CONSECUTIVE:
        print("{}")
        return 0

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": NUDGE_TEXT + (STRATEGY_SWITCH_TEXT if consecutive >= STRATEGY_SWITCH_MIN_CONSECUTIVE else ""),
        }
    }
    print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
