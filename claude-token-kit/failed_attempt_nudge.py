#!/usr/bin/env python3
"""Claude Code PostToolUse hook: 동일 Bash 명령이 연속 실패하면 /clear 권유.

같은 명령으로 두 번 연속 실패하면 그 흐름은 컨텍스트 오염을 일으키고 prompt cache 도
매 retry 마다 재워밍된다. 이 hook 은 그 패턴을 감지해 다음 turn 의 추가 컨텍스트로
짧은 모델 힌트를 주입한다 (블록하지 않음).

PostToolUse 의 `hookSpecificOutput.additionalContext` 는 Claude Code 공식 hook 명세상
모델 컨텍스트로 surfacing 되는 키이다 (https://code.claude.com/docs/en/hooks 참조).

상태 저장: 프로젝트 로컬 `.claude-token-optimizer/failures-<session>.json`.
session_id 가 없으면 cross-session 오염을 피하기 위해 hook 자체를 noop 한다.
같은 fingerprint 가 한 번이라도 성공하면 카운트를 리셋한다 (false-positive 방지).
트래킹 깊이는 5 회로 제한해 디스크 사용을 무시할 수 있게 한다.

Install via `.claude/settings.json` PostToolUse hook with matcher "Bash".
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
from pathlib import Path

STATE_DIR = Path(".claude-token-optimizer")
STATE_FILE_TEMPLATE = "failures-{session}.json"
MAX_TRACKED = 5
MIN_CONSECUTIVE = 2

# additionalContext 는 모델에게 주입되므로 사용자에게 직접 명령하는 톤보다 모델이 행동을
# 결정할 때 참고할 힌트 형태가 자연스럽다. 모델이 사용자에게 안내하도록 유도한다.
NUDGE_TEXT = (
    "AI 힌트: 동일 Bash 명령이 이 세션에서 연속 두 번 실패했습니다. "
    "이는 현재 접근 방식이 같은 방향으로 막혀 있고, 실패 시도가 누적될수록 컨텍스트가 오염되며 "
    "prompt cache 도 매 retry 마다 재워밍됨을 의미합니다. "
    "재시도 전에 사용자에게 `/clear` 또는 `/compact focus on …` 으로 세션을 정리한 뒤 "
    "재현 명령·기대 결과·금지 사항을 더 좁혀 다시 prompt 하도록 안내하거나, "
    "근본적으로 다른 방향(다른 모듈 / 검증 명령 / 보조 AI 위임)을 제안하세요."
)


def normalize_command(command: str) -> str:
    """명령을 stable fingerprint 텍스트로 축약한다.

    "방향" 만 보존하기 위해 모든 `-`/`--` 옵션을 제거하고 positional 토큰 중 처음
    2 개(보통 `command primary_target`)만 남긴다. 예:
    - `pytest tests/auth.py`, `pytest tests/auth.py -v`,
      `pytest tests/auth.py -k login` 모두 같은 fingerprint = "pytest tests/auth.py".
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
    positional = [tok for tok in argv if not tok.startswith("-")]
    return " ".join(positional[:2])


def fingerprint(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _is_real_dir(path: Path) -> bool:
    """심볼릭 링크가 아닌 실제 디렉터리인지 검사."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return False
    import stat as _stat

    return _stat.S_ISDIR(st.st_mode)


def load_entries(path: Path) -> list[dict]:
    """state file 을 읽는다. 파일이 symlink/regular 가 아니거나 손상되면 빈 list 반환."""
    if not path.exists():
        return []
    try:
        # symlink 를 따라가지 않고 직접 검사 — 공격자가 미리 심어둔 symlink 회피.
        st = os.lstat(path)
    except OSError:
        return []
    import stat as _stat

    if not _stat.S_ISREG(st.st_mode):
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def save_entries(path: Path, entries: list[dict]) -> None:
    """심볼릭 링크 / 동시 race 에 안전한 atomic write.

    - 부모 디렉터리가 symlink 면 거부 (외부 경로로 쓰기 회피).
    - O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW 로 임시 파일에 쓰고 os.replace 로 atomic 교체.
    - 임시 파일 이름은 무작위라 동시 호출 충돌 없음.
    - 모드는 0o600 으로 잠근다.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if not _is_real_dir(parent):
        # symlink 디렉터리는 거부 — silent noop.
        return

    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd, tmp_name = tempfile.mkstemp(prefix=".nudge-", suffix=".json.tmp", dir=str(parent))
    try:
        os.close(fd)
        # mkstemp 가 만든 파일을 다시 NOFOLLOW 로 열어 안전하게 쓴다.
        write_fd = os.open(tmp_name, flags, 0o600)
        try:
            with os.fdopen(write_fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(entries, ensure_ascii=False))
        except Exception:
            try:
                os.close(write_fd)
            except OSError:
                pass
            raise
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        # 기존 state file 이 symlink 면 거부 (regular file 만 교체).
        if path.exists():
            try:
                st = os.lstat(path)
            except OSError:
                st = None
            import stat as _stat

            if st is not None and not _stat.S_ISREG(st.st_mode):
                return
        os.replace(tmp_name, path)
        tmp_name = ""  # replaced
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def safe_session_label(session_id: str | None) -> str | None:
    """session_id 를 파일명 안전 형태로 변환. 없으면 None — 호출자가 hook 을 noop 한다."""
    if not session_id or not isinstance(session_id, str):
        return None
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:64]
    return cleaned or None


def extract_exit_code(tool_response: dict) -> int | None:
    for key in ("exitCode", "exit_code", "returncode"):
        value = tool_response.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
    return None


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
    try:
        payload = json.load(sys.stdin)
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

    entries = load_entries(state_path)
    success = exit_code == 0
    entries = update_entries(entries, fp, success)
    try:
        save_entries(state_path, entries)
    except OSError as exc:
        # state 저장 실패해도 실행을 막지 않는다. 진단 신호만 stderr 에 남긴다.
        if exc.errno not in {errno.EACCES, errno.ENOENT, errno.EROFS}:
            sys.stderr.write(f"claude-token-failed-nudge: state write skipped: {exc}\n")

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
            "additionalContext": NUDGE_TEXT,
        }
    }
    print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
