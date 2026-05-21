#!/usr/bin/env python3
"""Claude Code 토큰 절감 벤치마크 자동 실행 runner.

`research/benchmark-plan.md` 의 task set × variant 조합을 비대화형 `claude -p`
호출로 실행하고, `tokens_per_successful_task` 측정에 필요한 컬럼을 CSV 에 적재한다.

사용 예:

```bash
claude-token-kit/benchmark_runner.py \
    --tasks bench/tasks.json --variants bench/variants.json \
    --csv bench/results.csv

claude-token-kit/benchmark_runner.py --tasks bench/tasks.json \
    --variants bench/variants.json --task-id t01 --variant baseline --dry-run
```

Task fixture (`tasks.json`): 각 task 는 다음 필드를 가진다.

```json
[
  {
    "id": "t01",
    "prompt": "Add validation to src/auth/session.ts ...",
    "model": "sonnet",
    "effort": "medium",
    "max_turns": 3,
    "max_budget_usd": 1.0,
    "allowed_tools": ["Read", "Edit", "Bash(npm test*)"],
    "success_command": "npm test -- auth/session",
    "success_cwd": "."
  }
]
```

Variant fixture (`variants.json`): 각 variant 는 `claude -p` 에 추가할 옵션 묶음을 정의한다.

```json
[
  {"name": "baseline", "extra_args": []},
  {"name": "context_hygiene", "extra_args": ["--strict-mcp-config", "--mcp-config", "bench/minimal-mcp.json"]}
]
```

dry-run 모드는 실제 호출은 하지 않고 어떤 명령이 실행될지만 출력한다.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import datetime as _dt
import json
import math
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - benchmark runner already requires POSIX no-follow IO.
    fcntl = None  # type: ignore[assignment]

CSV_COLUMNS = [
    "date",
    "claude_version",
    "task_id",
    "variant",
    "model",
    "effort",
    "total_tokens",
    "input_tokens",
    "output_tokens",
    "cache_read",
    "cache_creation",
    "cost_usd",
    "success",
    "corrections",
    "notes",
]
MAX_CSV_NOTE_CHARS = 500
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")
SECRET_NOTE_KEY_RE = r"[A-Za-z0-9_.-]*(?:api[-_]?key|token|secret|password|client[-_]?secret)[A-Za-z0-9_.-]*"
SECRET_NOTE_VALUE_RE = r"(?:'[^']*'|\"[^\"]*\"|[^\s,}&#;]+)"
SECRET_NOTE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;]({SECRET_NOTE_KEY_RE})=)[^\s?&#;]+"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)(^|[\s{{,?&#;])([\"']?(?:{SECRET_NOTE_KEY_RE})[\"']?\s*[:=]\s*){SECRET_NOTE_VALUE_RE}"), r"\1\2[REDACTED]"),
    (re.compile(rf"(?i)(--(?:{SECRET_NOTE_KEY_RE})(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:-u|--user)(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "[REDACTED]"),
    (re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"), "[REDACTED]"),
    (re.compile(r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"npm_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "[REDACTED]"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED]"),
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s@]+@", re.IGNORECASE), r"\1[REDACTED]@"),
)

# claude -p --output-format json 의 usage 키 후보. Anthropic SDK 와 Claude Code 의 출력
# 형식이 시간이 지나며 바뀔 수 있어 다중 후보로 best-effort 매칭한다.
USAGE_KEY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("input_tokens", ("input_tokens",)),
    ("output_tokens", ("output_tokens",)),
    ("cache_read", ("cache_read_input_tokens", "cacheRead")),
    ("cache_creation", ("cache_creation_input_tokens", "cacheCreation")),
)
COST_KEYS = ("total_cost_usd", "cost_usd", "costUSD")
MAX_USAGE_TOKEN_COUNT = 10**12
MAX_USAGE_COST_USD = 10**9
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


def _base_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _no_follow_flag() -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return os.O_NOFOLLOW
    raise OSError("platform does not support no-follow file opens")


def no_follow_file_ops_supported() -> bool:
    return hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd


def require_no_follow_file_ops_supported() -> None:
    if not no_follow_file_ops_supported():
        raise SystemExit(
            "benchmark runner requires POSIX no-follow file operations for safe fixture and CSV paths; "
            "this platform is not supported yet."
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
            raise OSError(f"not a directory: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _ensure_directory_no_symlink(path: Path, *, create: bool = False) -> int:
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative no-follow directory access")
    path = _normalize_allowed_first_absolute_symlink(path)
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for component in components:
            try:
                next_fd = _open_directory_at(dir_fd, component, path)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o777, dir_fd=dir_fd)
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
        raise OSError("platform does not support directory-relative no-follow opens")
    path = _normalize_allowed_first_absolute_symlink(path)
    parent_fd = _ensure_directory_no_symlink(path.parent, create=create_parent)
    open_flags = (flags if flags is not None else _base_open_flags()) | _no_follow_flag()
    try:
        fd = os.open(path.name, open_flags, mode, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"not a regular file: {path}")
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


@contextmanager
def csv_file_lock(csv_path: Path, *, create_parent: bool) -> Any:
    """Serialize CSV read/write access with a no-follow sidecar lock file."""
    if fcntl is None:
        raise OSError("platform does not support advisory CSV locks")
    lock_path = csv_path.with_name(f"{csv_path.name}.lock")
    fd = _open_regular_no_symlink(lock_path, os.O_CREAT | os.O_RDWR, 0o666, create_parent=create_parent)
    locked = False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        try:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


# 재현성 우선: fixture 에 명시되지 않은 필드는 argv 로 전달하지 않는다.
# 사용자가 baseline 으로 의도한 변형이 implicit default(예: effort="medium")로 인해
# 왜곡되지 않도록, 파싱 단계에서 명시 여부를 그대로 보존한다.
@dataclass
class TaskFixture:
    id: str
    prompt: str
    model: str = "sonnet"
    effort: str | None = None
    max_turns: int = 3
    max_budget_usd: float | None = None
    allowed_tools: list[str] = field(default_factory=list)
    success_command: str | None = None
    success_cwd: str = "."


@dataclass
class Variant:
    name: str
    extra_args: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    task_id: str
    variant: str
    model: str
    effort: str
    tokens: dict[str, int]
    cost_usd: float
    success: bool
    notes: str
    corrections: int = 0


def parse_positive_int(value: Any, *, field: str, owner: str) -> int:
    """Parse a JSON fixture field that must be a positive integer."""
    if isinstance(value, bool):
        raise SystemExit(f"{owner} {field} must be a positive integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        parsed = int(value.strip())
    else:
        raise SystemExit(f"{owner} {field} must be a positive integer")
    if parsed <= 0:
        raise SystemExit(f"{owner} {field} must be > 0")
    return parsed


def parse_string_list(value: Any, *, field: str, owner: str) -> list[str]:
    """Parse a JSON fixture field that must be a list of non-empty strings."""
    if value is None:
        raise SystemExit(f"{owner} {field} must be a JSON list of strings")
    if not isinstance(value, list):
        raise SystemExit(f"{owner} {field} must be a JSON list of strings")
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise SystemExit(f"{owner} {field}[{index}] must be a string")
        if not item.strip():
            raise SystemExit(f"{owner} {field}[{index}] must be non-empty")
        items.append(item)
    return items


def normalize_usage_token(value: Any) -> int | None:
    """Return a safe non-negative token count, or None for invalid metrics."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(numeric) or numeric < 0 or numeric > MAX_USAGE_TOKEN_COUNT:
        return None
    return int(numeric)


def normalize_usage_cost(value: Any) -> float | None:
    """Return a safe non-negative cost value, or None for invalid metrics."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        numeric = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(numeric) or numeric < 0 or numeric > MAX_USAGE_COST_USD:
        return None
    return numeric


def parse_tasks(path: Path) -> list[TaskFixture]:
    raw = json.loads(_read_text_no_follow(path))
    if not isinstance(raw, list):
        raise SystemExit(f"tasks file must be a JSON list: {path}")
    fixtures: list[TaskFixture] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SystemExit(f"task entry must be a JSON object: {item}")
        effort_raw = item.get("effort")
        budget_raw = item.get("max_budget_usd")
        if budget_raw is not None:
            try:
                budget = float(budget_raw)
            except (TypeError, ValueError):
                raise SystemExit(f"task {item.get('id')} max_budget_usd must be number or null")
            if not math.isfinite(budget) or budget <= 0:
                raise SystemExit(f"task {item.get('id')} max_budget_usd must be finite and > 0 (use null for unlimited)")
        else:
            budget = None
        fixtures.append(TaskFixture(
            id=str(item["id"]),
            prompt=str(item["prompt"]),
            model=str(item.get("model", "sonnet")),
            effort=str(effort_raw) if effort_raw is not None else None,
            max_turns=parse_positive_int(item.get("max_turns", 3), field="max_turns", owner=f"task {item.get('id')}"),
            max_budget_usd=budget,
            allowed_tools=parse_string_list(
                item.get("allowed_tools", []),
                field="allowed_tools",
                owner=f"task {item.get('id')}",
            ),
            success_command=item.get("success_command"),
            success_cwd=str(item.get("success_cwd", ".")),
        ))
    return fixtures


def parse_variants(path: Path) -> list[Variant]:
    raw = json.loads(_read_text_no_follow(path))
    if not isinstance(raw, list):
        raise SystemExit(f"variants file must be a JSON list: {path}")
    variants: list[Variant] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SystemExit(f"variant entry must be a JSON object: {item}")
        variants.append(Variant(
            name=str(item["name"]),
            extra_args=parse_string_list(
                item.get("extra_args", []),
                field="extra_args",
                owner=f"variant {item.get('name')}",
            ),
        ))
    return variants


def collect_usage(payload: Any) -> tuple[dict[str, int], float]:
    """`claude -p --output-format json` 응답에서 token / cost 추출.

    의도된 정책: 한 응답에 top-level usage 와 nested per-message usage 가 동시에 있으면
    이중 합산이 되어 비용이 과대 보고된다. 따라서 각 bucket / cost 모두 **첫 매칭** 만
    채택한다 (top-level → BFS 순서). 응답 구조가 바뀌어 첫 매칭이 의도와 다른 경우에는
    fixture/variant 단위로 측정 결과를 점검하라.
    """
    tokens: dict[str, int] = {key: 0 for key, _ in USAGE_KEY_GROUPS}
    seen_token: dict[str, bool] = {key: False for key, _ in USAGE_KEY_GROUPS}
    cost = 0.0
    seen_cost = False
    # BFS 로 walk 해 top-level dict 가 nested dict 보다 먼저 평가되도록 한다.
    queue: list[Any] = [payload]
    while queue:
        cur = queue.pop(0)
        if isinstance(cur, dict):
            for bucket, keys in USAGE_KEY_GROUPS:
                if seen_token[bucket]:
                    continue
                for key in keys:
                    token_count = normalize_usage_token(cur.get(key))
                    if token_count is not None:
                        tokens[bucket] = token_count
                        seen_token[bucket] = True
                        break
            if not seen_cost:
                for key in COST_KEYS:
                    cost_value = normalize_usage_cost(cur.get(key))
                    if cost_value is not None:
                        cost = cost_value
                        seen_cost = True
                        break
            queue.extend(cur.values())
        elif isinstance(cur, list):
            queue.extend(cur)
    return tokens, cost


def claude_version(claude_bin: str) -> str:
    try:
        proc = subprocess.run([claude_bin, "--version"], text=True, capture_output=True, timeout=5)
        return proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def build_claude_argv(claude_bin: str, task: TaskFixture, variant: Variant) -> list[str]:
    """`claude -p` argv 를 빌드한다.

    fixture 에 명시되지 않은 옵션(effort, max_budget_usd) 은 argv 에서 빠진다.
    이렇게 해야 baseline variant 의 실제 의미(=defaults 그대로)가 implicit
    runner default 로 왜곡되지 않는다.
    """
    argv = [claude_bin, "-p", "--model", task.model,
            "--max-turns", str(task.max_turns), "--output-format", "json"]
    if task.effort:
        argv.extend(["--effort", task.effort])
    if task.max_budget_usd is not None:
        argv.extend(["--max-budget-usd", str(task.max_budget_usd)])
    if task.allowed_tools:
        argv.extend(["--allowedTools", ",".join(task.allowed_tools)])
    argv.extend(variant.extra_args)
    argv.append(task.prompt)
    return argv


def executable_argv0(command: str) -> str:
    resolved = shutil.which(command)
    if resolved:
        return str(Path(resolved).expanduser().resolve())
    path = Path(command).expanduser()
    if path.is_absolute():
        return str(path)
    return str(path.resolve())


# shlex.split 은 shell injection 은 막지만 `true ; echo pwned` 같은 입력을 그대로
# `["true", ";", "echo", "pwned"]` 로 분해해 /usr/bin/true 가 ";"·"echo"·"pwned" 를
# 그냥 인자로 무시하고 success=true 로 끝나는 false-positive 를 만들 수 있다.
# 따라서 shlex 분해 결과 토큰에 셸 합성 의도를 가진 것으로 보이는 문자가 포함되면 거부한다.
_SHELL_META_TOKENS = frozenset({";", "&&", "||", "|", "&", "<", ">", ">>", "<<", "<<<"})


def _has_shell_meta(argv: list[str]) -> bool:
    for tok in argv:
        if tok in _SHELL_META_TOKENS:
            return True
        # 토큰 안에 `$( ... )` / 백틱 같은 명령 치환 흔적이 있어도 거부.
        if "$(" in tok or "`" in tok:
            return True
    return False


def run_success_command(task: TaskFixture, project_root: Path) -> tuple[bool, str]:
    """fixture 의 success_command 를 실행한다.

    - `shlex.split + shell=False` 로 단일 argv 만 실행한다.
    - 분해된 토큰에 셸 합성 의도(`;`, `&&`, `|`, `$()`, 백틱 등)가 있으면 거부한다.
      `success_command` 는 단일 검증 명령 또는 헬퍼 스크립트 한 개의 경로여야 한다.
    - `success_cwd` 가 project_root 밖으로 escape 하면 거부한다 (..//../etc 같은 케이스).
    """
    if not task.success_command:
        return True, "no success_command configured"
    try:
        argv = shlex.split(task.success_command)
    except ValueError as exc:
        return False, f"success_command parse error: {exc}"
    if not argv:
        return False, "success_command parsed to empty argv"
    if _has_shell_meta(argv):
        return False, "success_command contains shell-composition tokens (use a helper script)"
    project_root_resolved = project_root.resolve()
    cwd = (project_root / task.success_cwd).resolve()
    try:
        cwd.relative_to(project_root_resolved)
    except ValueError:
        return False, f"success_cwd escapes project_root: {cwd}"
    try:
        proc = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"success_command failed to launch: {exc}"
    return proc.returncode == 0, f"exit={proc.returncode}"


def run_fixture(task: TaskFixture, variant: Variant, claude_bin: str,
                project_root: Path, dry_run: bool) -> RunResult:
    argv = build_claude_argv(claude_bin, task, variant)
    if dry_run:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=True, notes=f"dry-run: {shlex.join(argv)}",
        )
    argv[0] = executable_argv0(argv[0])
    try:
        proc = subprocess.run(argv, cwd=project_root, text=True, capture_output=True, timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude launch failed: {exc}",
        )
    if proc.returncode != 0:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude exit={proc.returncode}: {proc.stderr[-200:].strip()}",
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude returned non-JSON: {exc.msg}",
        )
    tokens, cost = collect_usage(payload)
    success, success_note = run_success_command(task, project_root)
    return RunResult(
        task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
        tokens=tokens, cost_usd=cost, success=success, notes=success_note,
    )


def append_csv(csv_path: Path, claude_ver: str, result: RunResult, *, skip_existing: bool = False) -> bool:
    with csv_file_lock(csv_path, create_parent=True):
        if skip_existing and (result.task_id, result.variant) in _read_existing_keys_unlocked(csv_path):
            return False
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        fd = _open_regular_no_symlink(csv_path, flags, 0o666, create_parent=True)
        try:
            new_file = os.fstat(fd).st_size == 0
            with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
                fd = -1
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                if new_file:
                    writer.writeheader()
                tokens = result.tokens
                total = sum(tokens.values())
                writer.writerow({
                    "date": _dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                    "claude_version": claude_ver,
                    "task_id": result.task_id,
                    "variant": result.variant,
                    "model": result.model,
                    "effort": result.effort,
                    "total_tokens": total,
                    "input_tokens": tokens.get("input_tokens", 0),
                    "output_tokens": tokens.get("output_tokens", 0),
                    "cache_read": tokens.get("cache_read", 0),
                    "cache_creation": tokens.get("cache_creation", 0),
                    "cost_usd": f"{result.cost_usd:.6f}",
                    "success": "true" if result.success else "false",
                    "corrections": result.corrections,
                    "notes": sanitize_csv_note(result.notes),
                })
        finally:
            if fd != -1:
                os.close(fd)
    return True


def _read_existing_keys_unlocked(csv_path: Path) -> set[tuple[str, str]]:
    try:
        fd = _open_regular_no_symlink(csv_path)
    except FileNotFoundError:
        return set()
    keys: set[tuple[str, str]] = set()
    try:
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as f:
            fd = -1
            reader = csv.DictReader(f)
            for row in reader:
                tid = row.get("task_id") or ""
                var = row.get("variant") or ""
                if tid and var:
                    keys.add((tid, var))
    finally:
        if fd != -1:
            os.close(fd)
    return keys


def _csv_exists_no_follow(csv_path: Path) -> bool:
    """Probe the CSV itself without following symlinks or creating a sidecar lock."""
    try:
        fd = _open_regular_no_symlink(csv_path)
    except FileNotFoundError:
        return False
    else:
        os.close(fd)
        return True


def existing_keys(csv_path: Path) -> set[tuple[str, str]]:
    """이미 적재된 (task_id, variant) 조합. resume 시 skip 판정에 사용."""
    if not _csv_exists_no_follow(csv_path):
        return set()
    with csv_file_lock(csv_path, create_parent=False):
        return _read_existing_keys_unlocked(csv_path)


def sanitize_note_text(value: Any) -> str:
    """Normalize untrusted benchmark note text without output-length policy."""
    text = "" if value is None else str(value)
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in text)
    text = " ".join(text.split())
    for pattern, replacement in SECRET_NOTE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def sanitize_csv_note(value: Any) -> str:
    """Normalize untrusted notes before writing them to benchmark CSV output."""
    text = sanitize_note_text(value)
    if text.startswith(CSV_FORMULA_PREFIXES):
        text = "'" + text
    if len(text) > MAX_CSV_NOTE_CHARS:
        text = text[:MAX_CSV_NOTE_CHARS - 12].rstrip() + "…[truncated]"
    return text


def filter_targets(tasks: list[TaskFixture], variants: list[Variant],
                   only_task: str | None, only_variant: str | None) -> list[tuple[TaskFixture, Variant]]:
    targets: list[tuple[TaskFixture, Variant]] = []
    for task in tasks:
        if only_task and task.id != only_task:
            continue
        for variant in variants:
            if only_variant and variant.name != only_variant:
                continue
            targets.append((task, variant))
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tasks", required=True, type=Path, help="task fixture JSON")
    parser.add_argument("--variants", required=True, type=Path, help="variant fixture JSON")
    parser.add_argument("--csv", default=Path("bench/results.csv"), type=Path,
                        help="results CSV path (header is added on first write)")
    parser.add_argument("--task-id", default=None, help="run only the named task id")
    parser.add_argument("--variant", default=None, help="run only the named variant")
    parser.add_argument("--claude-bin", default=os.environ.get("CLAUDE_BIN", "claude"),
                        help="claude CLI executable (default: $CLAUDE_BIN or 'claude')")
    parser.add_argument("--project-root", default=Path("."), type=Path,
                        help="working directory used for success_command (default: cwd)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the claude command without invoking it")
    parser.add_argument("--resume", action="store_true",
                        help="skip (task_id, variant) rows already present in --csv")
    args = parser.parse_args()

    require_no_follow_file_ops_supported()

    if not args.dry_run and shutil.which(args.claude_bin) is None:
        # claude_bin 이 절대경로면 shutil.which 가 None 일 수 있으므로 추가 검사.
        if not Path(args.claude_bin).exists():
            print(f"claude binary not found: {args.claude_bin}", file=sys.stderr)
            return 2

    tasks = parse_tasks(args.tasks)
    variants = parse_variants(args.variants)
    targets = filter_targets(tasks, variants, args.task_id, args.variant)
    if not targets:
        print("no (task, variant) targets matched the filters", file=sys.stderr)
        return 1

    skip_keys = existing_keys(args.csv) if args.resume else set()
    project_root = args.project_root.resolve()
    claude_ver = "dry-run" if args.dry_run else claude_version(args.claude_bin)

    completed = 0
    for task, variant in targets:
        if (task.id, variant.name) in skip_keys:
            print(f"skip {task.id}/{variant.name} (already in {args.csv})")
            continue
        print(f"run {task.id}/{variant.name} ...", flush=True)
        result = run_fixture(task, variant, args.claude_bin, project_root, args.dry_run)
        # dry-run row 는 CSV 에 적재하지 않는다. 적재하면 (a) tokens=0/cost=0 이 평균을
        # 깎고, (b) --resume 이 그 (task, variant) 를 skip 해 실제 측정값이 영구 누락된다.
        wrote = True
        if not args.dry_run:
            wrote = append_csv(args.csv, claude_ver, result, skip_existing=args.resume)
        completed += 1
        status = "ok" if result.success else "FAIL"
        if args.dry_run:
            suffix = " (dry-run; CSV not updated)"
        elif not wrote:
            suffix = " (CSV not updated; row already present)"
        else:
            suffix = ""
        print(f"  {status} tokens={sum(result.tokens.values())} cost=${result.cost_usd:.4f} {sanitize_note_text(result.notes)}{suffix}")
    target = args.csv if not args.dry_run else "(dry-run; no CSV writes)"
    print(f"completed {completed} run(s); results in {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
