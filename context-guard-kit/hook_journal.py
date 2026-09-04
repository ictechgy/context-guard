#!/usr/bin/env python3
"""훅 호출마다 한 줄 JSONL을 남기는 로컬 저널.

왜 있는가: HANDOFF 가 지적했듯 훅의 Python spawn 비용은 한 번도 장부에 오른 적이
없다. 어떤 훅이 실제로 개입하고 얼마를 보류했는지, 그 대가로 몇 ms 를 썼는지를
로컬에만 기록해 `context-guard doctor` 가 순효과를 한 줄로 보여줄 수 있게 한다.

계약:
- 네트워크 없음. 프로젝트 로컬 `.context-guard/hook-journal.jsonl` 에만 쓴다.
- 절대 훅을 깨뜨리지 않는다. 모든 실패는 False 를 돌려주고 삼킨다.
- 명령 문자열, 파일 경로, 출력 본문은 기록하지 않는다. 바이트 수와 짧은 사유만 남긴다.
- 1 MiB 를 넘으면 한 세대만 회전한다(`hook-journal.1.jsonl`).
- `CONTEXT_GUARD_HOOK_JOURNAL=0` 으로 끌 수 있다.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

JOURNAL_DIR_NAME = ".context-guard"
JOURNAL_FILE_NAME = "hook-journal.jsonl"
JOURNAL_ROTATED_FILE_NAME = "hook-journal.1.jsonl"
JOURNAL_MAX_BYTES = 1_048_576
JOURNAL_ENV = "CONTEXT_GUARD_HOOK_JOURNAL"
MAX_DETAIL_CHARS = 80
MAX_READ_ROWS = 20_000
HOOK_NAMES = ("read", "bash", "nudge", "trim")
SCHEMA_VERSION = "contextguard.hook-journal.v1"


def start_clock() -> float:
    """경과 시간 측정용 단조 시계 값을 돌려준다. 훅 진입 직후 한 번 부른다."""
    return time.perf_counter()


def journal_is_disabled() -> bool:
    """환경 변수로 저널이 꺼졌는지 본다. 값이 0/false/no/off 면 꺼진 것이다."""
    value = os.environ.get(JOURNAL_ENV, "").strip().lower()
    return value in {"0", "false", "no", "off", "disabled"}


def _session_label(session_id: object) -> str | None:
    """세션 id 를 짧은 해시로 바꾼다. 원문 id 는 저널에 남기지 않는다."""
    if not isinstance(session_id, str) or not session_id:
        return None
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]


def _clean_detail(detail: object) -> str | None:
    """사유 문자열을 한 줄, 80자로 제한한다. 제어 문자는 공백으로 바꾼다."""
    if not isinstance(detail, str) or not detail:
        return None
    cleaned = "".join(ch if ch.isprintable() else " " for ch in detail)
    return cleaned[:MAX_DETAIL_CHARS]


def _journal_paths(root: Path | None) -> tuple[Path, Path, Path]:
    """(디렉터리, 현재 파일, 회전 파일) 경로를 돌려준다."""
    base = (root or Path.cwd()) / JOURNAL_DIR_NAME
    return base, base / JOURNAL_FILE_NAME, base / JOURNAL_ROTATED_FILE_NAME


def _ensure_private_dir(path: Path) -> bool:
    """저널 디렉터리를 0700 으로 준비한다. 심볼릭 링크면 거부한다."""
    if path.is_symlink():
        return False
    if not path.exists():
        path.mkdir(mode=0o700, exist_ok=True)
    return path.is_dir()


def _rotate_if_needed(current: Path, rotated: Path) -> None:
    """현재 파일이 상한을 넘으면 한 세대만 보관하고 새로 시작한다."""
    try:
        info = current.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise OSError("hook journal must not be a symlink")
    if info.st_size < JOURNAL_MAX_BYTES:
        return
    if rotated.exists() or rotated.is_symlink():
        rotated.unlink()
    current.replace(rotated)


def _append_line(path: Path, line: str) -> None:
    """O_NOFOLLOW 로 열어 한 줄을 덧붙인다. 파일은 0600 으로 만든다."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def record(
    hook: str,
    *,
    started: float | None,
    intervened: bool,
    session_id: object = None,
    input_bytes: int = 0,
    output_bytes: int = 0,
    withheld_bytes: int = 0,
    detail: object = None,
    root: Path | None = None,
) -> bool:
    """훅 호출 한 건을 저널에 남긴다.

    hook: HOOK_NAMES 중 하나. started: start_clock() 값(없으면 ms 는 null).
    intervened: 훅이 실제로 개입(거부/재작성/힌트 주입)했는지.
    withheld_bytes: 개입으로 모델 컨텍스트에 들어가지 않은 것으로 *추정*되는 바이트.
    돌려주는 값은 기록 성공 여부이며, 실패해도 예외를 밖으로 내지 않는다.
    """
    if journal_is_disabled():
        return False
    try:
        elapsed_ms = None if started is None else round((time.perf_counter() - started) * 1000, 1)
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "hook": hook if hook in HOOK_NAMES else "other",
            "session": _session_label(session_id),
            "ms": elapsed_ms,
            "in": max(0, int(input_bytes)),
            "out": max(0, int(output_bytes)),
            "intervened": bool(intervened),
            "withheld": max(0, int(withheld_bytes)),
        }
        cleaned = _clean_detail(detail)
        if cleaned:
            entry["detail"] = cleaned
        directory, current, rotated = _journal_paths(root)
        if not _ensure_private_dir(directory):
            return False
        _rotate_if_needed(current, rotated)
        _append_line(current, json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True
    except Exception:  # noqa: BLE001 - 저널은 절대 훅을 깨뜨리지 않는다.
        return False


def read_rows(root: Path | None = None, *, max_rows: int = MAX_READ_ROWS) -> list[dict[str, Any]]:
    """회전 파일과 현재 파일을 순서대로 읽어 최근 max_rows 줄을 돌려준다.

    깨진 줄은 건너뛴다. 파일이 없으면 빈 목록이다.
    """
    _directory, current, rotated = _journal_paths(root)
    rows: list[dict[str, Any]] = []
    for path in (rotated, current):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        rows.append(parsed)
        except OSError:
            continue
    return rows[-max_rows:]


def _int_field(row: dict[str, Any], key: str) -> int:
    value = row.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """저널 행을 훅별로 집계한다.

    돌려주는 값은 관측 집계이며 토큰이나 비용 절감 주장이 아니다. withheld 는
    개입으로 컨텍스트에 들어가지 않은 것으로 추정한 바이트, overhead_ms 는 훅 자체가
    쓴 시간이다. 둘을 한 줄에 나란히 두는 것이 이 저널의 존재 이유다.
    """
    by_hook: dict[str, dict[str, Any]] = {}
    total = {"invocations": 0, "interventions": 0, "withheld_bytes": 0, "overhead_ms": 0.0}
    for row in rows:
        hook = row.get("hook") if isinstance(row.get("hook"), str) else "other"
        bucket = by_hook.setdefault(
            hook, {"invocations": 0, "interventions": 0, "withheld_bytes": 0, "overhead_ms": 0.0}
        )
        elapsed = row.get("ms")
        elapsed_ms = float(elapsed) if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) else 0.0
        intervened = row.get("intervened") is True
        for target in (bucket, total):
            target["invocations"] += 1
            target["interventions"] += 1 if intervened else 0
            target["withheld_bytes"] += _int_field(row, "withheld")
            target["overhead_ms"] += elapsed_ms
    for bucket in list(by_hook.values()) + [total]:
        bucket["overhead_ms"] = round(bucket["overhead_ms"], 1)
    return {
        "schema_version": SCHEMA_VERSION,
        "rows": len(rows),
        "total": total,
        "by_hook": dict(sorted(by_hook.items())),
        "claim_boundary": {
            "token_or_cost_savings_claim_allowed": False,
            "note": (
                "withheld_bytes is an estimate of bytes a hook kept out of the model context; "
                "overhead_ms is time the hook itself spent. Neither is a measured token or cost saving."
            ),
        },
    }


def render_one_line(summary: dict[str, Any]) -> str:
    """doctor 가 쓰는 한 줄 요약(statusline 은 아직 쓰지 않는다)."""
    total = summary["total"]
    if not summary["rows"]:
        return "hook journal: no rows yet (hooks write .context-guard/hook-journal.jsonl as they run)"
    return (
        f"hook journal: {total['invocations']} calls, {total['interventions']} interventions, "
        f"~{total['withheld_bytes']:,}B withheld, {total['overhead_ms']:.0f} ms hook overhead "
        "(observed, not a savings claim)"
    )


def main(argv: list[str] | None = None) -> int:
    """`python3 hook_journal.py [--root DIR] [--json]` 로 요약을 출력한다."""
    args = list(sys.argv[1:] if argv is None else argv)
    root: Path | None = None
    as_json = False
    while args:
        item = args.pop(0)
        if item == "--json":
            as_json = True
        elif item == "--root" and args:
            root = Path(args.pop(0))
        elif item in {"-h", "--help"}:
            print("usage: hook_journal.py [--root DIR] [--json]")
            return 0
        else:
            print(f"hook_journal: unknown argument {item!r}", file=sys.stderr)
            return 2
    summary = summarize(read_rows(root))
    if as_json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(render_one_line(summary))
        for name, bucket in summary["by_hook"].items():
            print(
                f"  {name:6s} {bucket['invocations']:>6} calls {bucket['interventions']:>6} interventions "
                f"{bucket['withheld_bytes']:>12,}B withheld {bucket['overhead_ms']:>8.0f} ms"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
