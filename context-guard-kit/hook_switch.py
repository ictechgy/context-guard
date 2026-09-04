#!/usr/bin/env python3
"""세션 단위 훅 해제 스위치 (`context-guard hooks off|on|status`).

왜 있는가: 지금까지 훅을 끄는 길은 프로세스 환경 변수(`CONTEXT_GUARD_DISABLE`,
`CONTEXT_GUARD_READ_GUARD=0`)나 setup 재실행뿐이었다. 오탐이 났을 때 에이전트나
사용자가 "이 훅만, 잠깐만" 끌 수 있는 명령이 없었다. 이 모듈은 프로젝트 로컬
`.context-guard/hooks-off.json` 에 훅별 만료 시각을 적고, 각 훅은 시작할 때 이
파일 한 번만 읽어 자신이 꺼져 있으면 no-op 한다.

계약:
- 기본 만료 2시간, 최대 24시간. 만료된 항목은 없는 것으로 본다.
- 파일이 없거나 깨져 있으면 "모두 켜짐"이다. 읽기 실패는 훅을 깨뜨리지 않는다.
- 훅 이름은 read(Read 가드), bash(Bash 재작성/축약), nudge(반복 실패 힌트), all.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

STATE_DIR_NAME = ".context-guard"
STATE_FILE_NAME = "hooks-off.json"
STATE_VERSION = 1
HOOK_NAMES = ("read", "bash", "nudge")
DEFAULT_DURATION_SECONDS = 2 * 60 * 60
MAX_DURATION_SECONDS = 24 * 60 * 60
MAX_STATE_BYTES = 4096
DURATION_RE = re.compile(r"^(\d+)([mhd])$")
DISABLE_HINT = "Disable for this session: context-guard hooks off {name}"


def state_path(root: Path | None = None) -> Path:
    """스위치 파일 경로. 훅은 프로젝트 cwd 에서 실행되므로 기본은 cwd 다."""
    return (root or Path.cwd()) / STATE_DIR_NAME / STATE_FILE_NAME


def parse_duration(text: str) -> int:
    """`30m`, `2h`, `1d` 를 초로 바꾼다. 범위 밖이면 ValueError."""
    match = DURATION_RE.match(text.strip().lower())
    if not match:
        raise ValueError(f"duration must look like 30m, 2h, or 1d (got {text!r})")
    amount, unit = int(match.group(1)), match.group(2)
    seconds = amount * {"m": 60, "h": 3600, "d": 86400}[unit]
    if seconds <= 0 or seconds > MAX_DURATION_SECONDS:
        raise ValueError("duration must be between 1m and 24h")
    return seconds


def _load_state(path: Path) -> dict[str, float]:
    """파일을 읽어 {훅: 만료 epoch} 를 돌려준다. 문제가 있으면 빈 dict."""
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES:
            return {}
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(parsed, dict) or parsed.get("version") != STATE_VERSION:
        return {}
    raw = parsed.get("off")
    if not isinstance(raw, dict):
        return {}
    state: dict[str, float] = {}
    for name, expires in raw.items():
        if name in HOOK_NAMES and isinstance(expires, (int, float)) and not isinstance(expires, bool):
            state[name] = float(expires)
    return state


def _active(state: dict[str, float], now: float) -> dict[str, float]:
    """만료되지 않은 항목만 남긴다."""
    return {name: expires for name, expires in state.items() if expires > now}


def _write_state(path: Path, state: dict[str, float]) -> None:
    """0700 디렉터리에 0600 파일로 원자적으로 쓴다. 비어 있으면 파일을 지운다."""
    directory = path.parent
    if directory.is_symlink():
        raise OSError(f"{directory} must not be a symlink")
    directory.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink():
        raise OSError(f"{path} must not be a symlink")
    if not state:
        if path.exists():
            path.unlink()
        return
    payload = json.dumps({"version": STATE_VERSION, "off": state}, sort_keys=True)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    temp.replace(path)


def is_disabled(hook: str, *, root: Path | None = None, now: float | None = None) -> bool:
    """훅이 이 세션에서 꺼져 있는지 본다. 어떤 오류도 False 로 삼킨다."""
    if hook not in HOOK_NAMES:
        return False
    try:
        state = _active(_load_state(state_path(root)), time.time() if now is None else now)
    except Exception:  # noqa: BLE001 - 스위치는 절대 훅을 깨뜨리지 않는다.
        return False
    return hook in state


def disable_hint(hook: str) -> str:
    """훅 메시지 끝에 붙이는 한 줄 해제 안내."""
    return DISABLE_HINT.format(name=hook)


def _target_names(name: str) -> tuple[str, ...]:
    if name == "all":
        return HOOK_NAMES
    if name not in HOOK_NAMES:
        raise ValueError(f"hook must be one of {', '.join(HOOK_NAMES)}, or all (got {name!r})")
    return (name,)


def set_off(name: str, *, duration_seconds: int, root: Path | None = None, now: float | None = None) -> dict[str, float]:
    """훅을 끈다. 이미 꺼져 있으면 만료를 새 값으로 갱신한다."""
    current = time.time() if now is None else now
    path = state_path(root)
    state = _active(_load_state(path), current)
    for target in _target_names(name):
        state[target] = current + duration_seconds
    _write_state(path, state)
    return state


def set_on(name: str, *, root: Path | None = None, now: float | None = None) -> dict[str, float]:
    """훅을 다시 켠다."""
    current = time.time() if now is None else now
    path = state_path(root)
    state = _active(_load_state(path), current)
    for target in _target_names(name):
        state.pop(target, None)
    _write_state(path, state)
    return state


def status(root: Path | None = None, *, now: float | None = None) -> dict[str, Any]:
    """훅별 상태를 돌려준다."""
    current = time.time() if now is None else now
    state = _active(_load_state(state_path(root)), current)
    hooks = {}
    for hook in HOOK_NAMES:
        if hook in state:
            hooks[hook] = {"enabled": False, "expires_in_seconds": int(state[hook] - current)}
        else:
            hooks[hook] = {"enabled": True}
    return {"schema_version": "contextguard.hooks-switch.v1", "hooks": hooks}


def _render_status(report: dict[str, Any]) -> str:
    parts = []
    for hook, info in report["hooks"].items():
        if info["enabled"]:
            parts.append(f"{hook}=on")
        else:
            minutes = max(1, info["expires_in_seconds"] // 60)
            parts.append(f"{hook}=off({minutes}m left)")
    return "hooks: " + " ".join(parts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="context-guard hooks",
        description="Turn ContextGuard hooks off or on for this project session without editing settings.",
    )
    parser.add_argument("--root", type=Path, default=None, help="project root (default: cwd)")
    parser.add_argument("--json", action="store_true", help="print JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    off = commands.add_parser("off", help="disable a hook for a while")
    off.add_argument("name", help="read | bash | nudge | all")
    off.add_argument("--for", dest="duration", default="2h", help="duration such as 30m, 2h, 1d (max 24h; default 2h)")
    on = commands.add_parser("on", help="re-enable a hook")
    on.add_argument("name", help="read | bash | nudge | all")
    commands.add_parser("status", help="show which hooks are off")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "off":
            set_off(args.name, duration_seconds=parse_duration(args.duration), root=args.root)
        elif args.command == "on":
            set_on(args.name, root=args.root)
    except ValueError as exc:
        print(f"context-guard hooks: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"context-guard hooks: could not update {state_path(args.root)}: {exc}", file=sys.stderr)
        return 1
    report = status(args.root)
    print(json.dumps(report, indent=2) if args.json else _render_status(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
