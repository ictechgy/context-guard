#!/usr/bin/env python3
"""Claude Code 토큰 절감 벤치마크 자동 실행 runner.

`research/benchmark-plan.md` 의 task set × variant 조합을 비대화형 `claude -p`
호출로 실행하고, `tokens_per_successful_task` 측정에 필요한 컬럼을 CSV 에 적재한다.

사용 예:

```bash
context-guard-kit/benchmark_runner.py \
    --tasks bench/tasks.json --variants bench/variants.json \
    --csv bench/results.csv

context-guard-kit/benchmark_runner.py --tasks bench/tasks.json \
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
    "variant_prompt_files": {"context_hygiene": "t01.context_hygiene.prompt.md"},
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
import collections
from contextlib import contextmanager
import csv
import datetime as _dt
import json
import math
import os
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
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
    "provider_cached_tokens",
    "provider_cached_tokens_measured",
    "cost_usd",
    "cost_measured",
    "wall_time_seconds",
    "turns",
    "hook_triggers",
    "bytes_before",
    "bytes_after",
    "artifacts_used",
    "external_tokens",
    "external_tokens_measured",
    "external_cost_usd",
    "external_cost_measured",
    "total_cost_with_shift_usd",
    "success",
    "corrections",
    "notes",
    "primary_tokens_measured",
]
MAX_CSV_NOTE_CHARS = 500
MAX_CSV_ROWS = 100_000
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")
PLACEHOLDER_SUCCESS_COMMAND_MARKER = "fixture-only placeholder: replace success_command before real benchmark runs"
PROTECTED_VARIANT_FLAGS = frozenset({
    "--",
    "-p",
    "--print",
    "--model",
    "--max-turns",
    "--output-format",
    "--allowedTools",
    "--allowed-tools",
    "--max-budget-usd",
    "--effort",
})
SECRET_NOTE_KEY_RE = r"[A-Za-z0-9_.-]*(?:api[-_]?key|token|secret|password|client[-_]?secret)[A-Za-z0-9_.-]*"
SECRET_NOTE_VALUE_RE = r"(?:'[^']*'|\"[^\"]*\"|[^\s,}&#;]+)"
SECRET_NOTE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;]({SECRET_NOTE_KEY_RE})=)[^\s?&#;]+"), r"\1[REDACTED]"),
    (re.compile(rf"(?i)(^|[\s{{,?&#;])([\"']?(?:{SECRET_NOTE_KEY_RE})[\"']?\s*[:=]\s*){SECRET_NOTE_VALUE_RE}"), r"\1\2[REDACTED]"),
    (re.compile(rf"(?i)(^|[\s\"'])(--(?:{SECRET_NOTE_KEY_RE})(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(^|[\s\"'])((?:-u|--user)(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"), r"\1\2[REDACTED]"),
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

# claude -p --output-format json 및 호환 벤치마크 provider usage 키 후보.
# Anthropic SDK, Claude Code, OpenAI-style JSON 출력 형식이 시간이 지나며 바뀔 수
# 있어 다중 후보로 best-effort 매칭한다.
USAGE_KEY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("input_tokens", ("input_tokens", "inputTokens", "prompt_tokens", "promptTokens")),
    ("output_tokens", ("output_tokens", "outputTokens", "completion_tokens", "completionTokens")),
    ("cache_read", ("cache_read_input_tokens", "cacheRead")),
    ("cache_creation", ("cache_creation_input_tokens", "cacheCreation")),
)
PROVIDER_CACHE_DETAIL_KEYS = (
    "prompt_tokens_details",
    "promptTokensDetails",
    "input_tokens_details",
    "inputTokensDetails",
)
PROVIDER_CACHED_TOKEN_KEYS = ("cached_tokens", "cachedTokens")
COST_KEYS = ("total_cost_usd", "cost_usd", "costUSD")
SHIFT_METRIC_KEY_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("turns", ("turns", "num_turns", "total_turns")),
    ("hook_triggers", ("hook_triggers", "hookTriggerCount", "hook_trigger_count")),
    ("bytes_before", ("bytes_before", "bytesBefore", "raw_bytes_before")),
    ("bytes_after", ("bytes_after", "bytesAfter", "visible_bytes_after")),
    ("artifacts_used", ("artifacts_used", "artifact_count", "artifactsUsed")),
)
EXTERNAL_TOKEN_AGGREGATE_KEYS = ("external_tokens",)
EXTERNAL_COST_AGGREGATE_KEYS = ("external_cost_usd",)
EXTERNAL_SOURCE_KEY_GROUPS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("auxiliary", ("auxiliary_tokens",), ("auxiliary_cost_usd",)),
    ("subagent", ("subagent_tokens",), ("subagent_cost_usd",)),
    ("provider", ("provider_tokens",), ("provider_cost_usd",)),
)
MAX_USAGE_TOKEN_COUNT = 10**12
MAX_USAGE_COST_USD = 10**9
# Byte -> token proxy 환산 계수. 측정된 모델 토큰이 아니라 byte delta 기반 보수적
# 추정치이며, report에서 evidence="inferred"로 분명히 라벨링한다. 영어 텍스트 기준
# ~4 bytes/token의 통용 근사값을 사용한다.
TOKEN_PROXY_BYTES_PER_TOKEN = 4
BENCH_RUN_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.run-evidence.v1"
MATCHED_PAIR_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.matched-pair.v1"
SELF_HOSTED_METRICS_SCHEMA_VERSION = "contextguard.bench.self-hosted-metrics.v1"
SELF_HOSTED_METRICS_KEY = "self_hosted_metrics"
SELF_HOSTED_METRICS_CLAIM_BOUNDARY = "self_hosted_metrics_only_not_hosted_api_token_or_cost_savings"
MAX_SELF_HOSTED_LABEL_CHARS = 120
MAX_SELF_HOSTED_LATENCY_MS = 7 * 24 * 60 * 60 * 1000
MAX_SELF_HOSTED_MEMORY_MB = 10_000_000
CLAUDE_OUTPUT_MAX_BYTES = 1_000_000
SUCCESS_COMMAND_OUTPUT_MAX_BYTES = 64_000
VERSION_OUTPUT_MAX_BYTES = 16_000
PROCESS_TERMINATE_GRACE_SECONDS = 2.0
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
    fd = _open_regular_no_symlink(lock_path, os.O_CREAT | os.O_RDWR, 0o600, create_parent=create_parent)
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
    variant_prompt_files: dict[str, str] = field(default_factory=dict)
    variant_prompt_texts: dict[str, str] = field(default_factory=dict)


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
    cost_measured: bool = False
    wall_time_seconds: float = 0.0
    turns: int = 0
    hook_triggers: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    artifacts_used: int = 0
    external_tokens: int = 0
    external_tokens_measured: bool = False
    external_cost_usd: float = 0.0
    external_cost_measured: bool = False
    provider_cached_tokens: int = 0
    provider_cached_tokens_measured: bool = False
    primary_tokens_measured: bool = False
    self_hosted_metrics: dict[str, Any] | None = None


@dataclass
class BoundedProcessResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False


def is_placeholder_success_command(command: str | None) -> bool:
    return bool(command and PLACEHOLDER_SUCCESS_COMMAND_MARKER in command)


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


def parse_string_map(value: Any, *, field: str, owner: str) -> dict[str, str]:
    """Parse a JSON fixture field that must be an object of non-empty string values."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SystemExit(f"{owner} {field} must be a JSON object of strings")
    items: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise SystemExit(f"{owner} {field} keys must be non-empty strings")
        if not isinstance(raw_value, str) or not raw_value.strip():
            raise SystemExit(f"{owner} {field}.{raw_key} must be a non-empty string")
        items[raw_key] = raw_value
    return items


def validate_variant_extra_args(extra_args: list[str], *, owner: str) -> list[str]:
    for index, arg in enumerate(extra_args):
        flag = arg.split("=", 1)[0]
        if flag in PROTECTED_VARIANT_FLAGS:
            raise SystemExit(
                f"{owner} extra_args[{index}] must not override runner-controlled Claude flags: {flag}"
            )
    return extra_args


def validate_variant_prompt_file_path(raw_path: str, *, owner: str) -> Path:
    """Return a safe relative prompt-file path, or fail before any file read."""
    rel_path = Path(raw_path)
    if rel_path.is_absolute():
        raise SystemExit(f"{owner} variant_prompt_files path must be relative: {raw_path}")
    if not rel_path.parts or rel_path == Path("."):
        raise SystemExit(f"{owner} variant_prompt_files path must name a file")
    if any(part in ("", ".", "..") for part in rel_path.parts):
        raise SystemExit(f"{owner} variant_prompt_files path must not contain '.', '..', or empty components: {raw_path}")
    return rel_path


def load_variant_prompt_files(
    tasks: list[TaskFixture],
    variants: list["Variant"],
    *,
    task_file_dir: Path,
) -> None:
    """Validate variant prompt-file keys first, then read file-backed prompts no-follow.

    Unknown variant keys are rejected before dereferencing their mapped prompt files.
    This preserves the benchmark runner's no-follow fixture safety while making prompt
    evidence swaps explicit and reviewable.
    """
    known_variants = {variant.name for variant in variants}
    for task in tasks:
        unknown = sorted(set(task.variant_prompt_files) - known_variants)
        if unknown:
            raise SystemExit(
                f"task {task.id} variant_prompt_files references unknown variant(s): {', '.join(unknown)}"
            )

    for task in tasks:
        loaded: dict[str, str] = {}
        for variant_name, raw_path in task.variant_prompt_files.items():
            rel_path = validate_variant_prompt_file_path(
                raw_path,
                owner=f"task {task.id} variant {variant_name}",
            )
            loaded[variant_name] = _read_text_no_follow(task_file_dir / rel_path)
        task.variant_prompt_texts = loaded


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


def parse_tasks(path: Path, variants: list["Variant"] | None = None) -> list[TaskFixture]:
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
        task_id = str(item["id"])
        if "variant_prompts" in item:
            raise SystemExit(
                f"task {task_id} variant_prompts is not supported; use file-backed variant_prompt_files"
            )
        fixtures.append(TaskFixture(
            id=task_id,
            prompt=str(item["prompt"]),
            model=str(item.get("model", "sonnet")),
            effort=str(effort_raw) if effort_raw is not None else None,
            max_turns=parse_positive_int(item.get("max_turns", 3), field="max_turns", owner=f"task {task_id}"),
            max_budget_usd=budget,
            allowed_tools=parse_string_list(
                item.get("allowed_tools", []),
                field="allowed_tools",
                owner=f"task {task_id}",
            ),
            success_command=item.get("success_command"),
            success_cwd=str(item.get("success_cwd", ".")),
            variant_prompt_files=parse_string_map(
                item.get("variant_prompt_files"),
                field="variant_prompt_files",
                owner=f"task {task_id}",
            ),
        ))
    if variants is not None:
        load_variant_prompt_files(fixtures, variants, task_file_dir=path.parent)
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
            extra_args=validate_variant_extra_args(
                parse_string_list(
                    item.get("extra_args", []),
                    field="extra_args",
                    owner=f"variant {item.get('name')}",
                ),
                owner=f"variant {item.get('name')}",
            ),
        ))
    return variants


def collect_usage(payload: Any) -> tuple[dict[str, int], float, bool, bool]:
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
    queue: collections.deque[Any] = collections.deque([payload])
    while queue:
        cur = queue.popleft()
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
    # Token-savings claims require a comparable primary-token total.  Cache
    # buckets are optional zeroes in normal provider payloads, but the core
    # input/output buckets must both be observed; otherwise an output-only or
    # input-only partial payload would be treated as measured zero for the
    # missing side and could overstate savings.
    primary_tokens_measured = seen_token["input_tokens"] and seen_token["output_tokens"]
    return tokens, cost, seen_cost, primary_tokens_measured


def collect_provider_cache_telemetry(payload: Any) -> tuple[int, bool]:
    """Extract provider-specific prompt-cache telemetry without changing token totals.

    OpenAI-style responses expose cached prompt tokens under
    `usage.prompt_tokens_details.cached_tokens`.  That number is useful cache
    telemetry, but `prompt_tokens` may already include cached tokens, so keep it
    separate from the primary token buckets and from ContextGuard savings claims.
    Anthropic-style `cache_read_input_tokens` remains in the normal `cache_read`
    bucket handled by `collect_usage`.
    """
    queue: collections.deque[Any] = collections.deque([payload])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            for details_key in PROVIDER_CACHE_DETAIL_KEYS:
                details = cur.get(details_key)
                if not isinstance(details, dict):
                    continue
                for cached_key in PROVIDER_CACHED_TOKEN_KEYS:
                    cached = normalize_usage_token(details.get(cached_key))
                    if cached is not None:
                        return cached, True
            queue.extend(cur.values())
        elif isinstance(cur, list):
            queue.extend(cur)
    return 0, False


def collect_provider_cached_tokens(payload: Any) -> int:
    """Return cached-token telemetry value for callers that only need the count."""
    cached_tokens, _measured = collect_provider_cache_telemetry(payload)
    return cached_tokens


def elapsed_seconds_since(start: float) -> float:
    return max(0.0, time.monotonic() - start)


def first_normalized_token(cur: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = normalize_usage_token(cur.get(key))
        if value is not None:
            return value
    return None


def first_normalized_cost(cur: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        value = normalize_usage_cost(cur.get(key))
        if value is not None:
            return value
    return None


def contains_external_source_tokens(value: Any) -> bool:
    queue: collections.deque[Any] = collections.deque([value])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            for _source, token_keys, _cost_keys in EXTERNAL_SOURCE_KEY_GROUPS:
                if first_normalized_token(cur, token_keys) is not None:
                    return True
            queue.extend(cur.values())
        elif isinstance(cur, list):
            queue.extend(cur)
    return False


def collect_shift_metrics(payload: Any) -> dict[str, int | float | bool]:
    """Collect optional cost-shift / byte-saving metrics without requiring them.

    External work is reported by evolving Claude/runner payloads either as one
    aggregate (`external_tokens` + `external_cost_usd`) or as explicit source
    records (`auxiliary_*`, `subagent_*`, `provider_*`).  Do not mix those two
    shapes: if an aggregate token count exists, it is authoritative; otherwise
    sum only source-token records and mark cost measured only when every
    positive source-token record carries its matching source cost.
    """
    metrics: dict[str, int | float | bool] = {key: 0 for key, _ in SHIFT_METRIC_KEY_GROUPS}
    seen: dict[str, bool] = {key: False for key, _ in SHIFT_METRIC_KEY_GROUPS}
    aggregate_tokens: int | None = None
    aggregate_cost = 0.0
    aggregate_cost_measured = False
    source_tokens = 0
    source_tokens_measured = False
    source_cost = 0.0
    source_cost_covered = True
    metrics["external_cost_usd"] = 0.0
    metrics["external_cost_measured"] = False
    metrics["external_tokens"] = 0
    metrics["external_tokens_measured"] = False
    queue: collections.deque[Any] = collections.deque([payload])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            for bucket, keys in SHIFT_METRIC_KEY_GROUPS:
                if seen[bucket]:
                    continue
                value = first_normalized_token(cur, keys)
                if value is not None:
                    metrics[bucket] = value
                    seen[bucket] = True

            if aggregate_tokens is None:
                value = first_normalized_token(cur, EXTERNAL_TOKEN_AGGREGATE_KEYS)
                if value is not None:
                    aggregate_tokens = value
                    cost = first_normalized_cost(cur, EXTERNAL_COST_AGGREGATE_KEYS)
                    if cost is not None:
                        aggregate_cost = cost
                        aggregate_cost_measured = True

            source_values = [
                (value, cost_keys)
                for _source, token_keys, cost_keys in EXTERNAL_SOURCE_KEY_GROUPS
                for value in [first_normalized_token(cur, token_keys)]
                if value is not None
            ]
            if source_values and not any(contains_external_source_tokens(value) for value in cur.values()):
                for value, cost_keys in source_values:
                    source_tokens += value
                    source_tokens_measured = True
                    cost = first_normalized_cost(cur, cost_keys)
                    if cost is not None:
                        source_cost += cost
                    elif value > 0:
                        source_cost_covered = False
            queue.extend(cur.values())
        elif isinstance(cur, list):
            queue.extend(cur)

    if aggregate_tokens is not None:
        metrics["external_tokens"] = aggregate_tokens
        metrics["external_tokens_measured"] = True
        metrics["external_cost_usd"] = aggregate_cost if aggregate_cost_measured else 0.0
        metrics["external_cost_measured"] = aggregate_cost_measured
    elif source_tokens_measured:
        metrics["external_tokens"] = source_tokens
        metrics["external_tokens_measured"] = True
        metrics["external_cost_usd"] = source_cost
        metrics["external_cost_measured"] = source_cost_covered
    return metrics


def normalize_self_hosted_metric(value: Any, *, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        return None
    return number


def sanitize_self_hosted_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = sanitize_note_text(value)
    if not text:
        return None
    if len(text) > MAX_SELF_HOSTED_LABEL_CHARS:
        text = text[:MAX_SELF_HOSTED_LABEL_CHARS - 12].rstrip() + "…[truncated]"
    return text


def normalize_self_hosted_metrics(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    metrics: dict[str, float] = {}
    labels: dict[str, str] = {}
    availability = {
        "latency_ms": False,
        "peak_memory_mb": False,
        "quality_score": False,
    }
    latency = normalize_self_hosted_metric(raw.get("latency_ms"), maximum=MAX_SELF_HOSTED_LATENCY_MS)
    if latency is not None:
        metrics["latency_ms"] = latency
        availability["latency_ms"] = True
    peak_memory = normalize_self_hosted_metric(raw.get("peak_memory_mb"), maximum=MAX_SELF_HOSTED_MEMORY_MB)
    if peak_memory is not None:
        metrics["peak_memory_mb"] = peak_memory
        availability["peak_memory_mb"] = True
    quality = normalize_self_hosted_metric(raw.get("quality_score"), maximum=1.0)
    if quality is not None:
        metrics["quality_score"] = quality
        availability["quality_score"] = True
    for key in ("model_server", "optimization", "quality_metric"):
        label = sanitize_self_hosted_label(raw.get(key))
        if label is not None:
            labels[key] = label
    if not metrics:
        return None
    return {
        "schema_version": SELF_HOSTED_METRICS_SCHEMA_VERSION,
        "source": f"explicit_provider_payload.{SELF_HOSTED_METRICS_KEY}",
        "metrics": metrics,
        "labels": labels,
        "measurement_availability": availability,
        "claim_boundary": {
            "id": SELF_HOSTED_METRICS_CLAIM_BOUNDARY,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
            "requires_provider_measured_matched_tasks_for_hosted_claims": True,
            "reason": (
                "Self-hosted local/model-server latency, memory, and quality metrics "
                "are not hosted API token or cost telemetry."
            ),
        },
    }


def collect_self_hosted_metrics(payload: Any) -> dict[str, Any] | None:
    """Collect explicit self-hosted metric sidecars without broad key inference.

    Only a nested object named exactly `self_hosted_metrics` is considered.  Do
    not infer from incidental keys like `self_hosted_latency_ms`: that would make
    local/model-server telemetry too easy to mix into hosted API claim surfaces.
    """
    queue: collections.deque[Any] = collections.deque([payload])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            if SELF_HOSTED_METRICS_KEY in cur:
                normalized = normalize_self_hosted_metrics(cur.get(SELF_HOSTED_METRICS_KEY))
                if normalized is not None:
                    return normalized
            queue.extend(cur.values())
        elif isinstance(cur, list):
            queue.extend(cur)
    return None


def claude_version(claude_bin: str) -> str:
    try:
        proc = run_bounded_command(
            [claude_bin, "--version"],
            cwd=Path.cwd(),
            timeout_seconds=5,
            max_output_bytes=VERSION_OUTPUT_MAX_BYTES,
        )
        return proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"
    except (OSError, subprocess.TimeoutExpired, ValueError):
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
    argv.append("--")
    argv.append(task.variant_prompt_texts.get(variant.name, task.prompt))
    return argv


def executable_argv0(command: str) -> str:
    resolved = shutil.which(command)
    if resolved:
        return str(Path(resolved).expanduser().resolve())
    path = Path(command).expanduser()
    if path.is_absolute():
        return str(path)
    return str(path.resolve())


def _signal_process_group(proc: subprocess.Popen[bytes], sig: int, pgid: int | None) -> None:
    if pgid is not None:
        try:
            os.killpg(pgid, sig)
            return
        except (AttributeError, ProcessLookupError):
            pass
        except OSError:
            pass
    try:
        if sig == signal.SIGKILL:
            proc.kill()
        else:
            proc.terminate()
    except OSError:
        pass


def run_bounded_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> BoundedProcessResult:
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = proc.pid
    selector = selectors.DefaultSelector()
    buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {"stdout": proc.stdout, "stderr": proc.stderr}
    for name, stream in streams.items():
        if stream is None:
            continue
        try:
            os.set_blocking(stream.fileno(), False)
        except (AttributeError, OSError):
            pass
        selector.register(stream, selectors.EVENT_READ, name)

    timed_out = False
    output_truncated = False
    terminated_at: float | None = None
    sent_kill = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            now = time.monotonic()
            if now >= deadline:
                timed_out = True
                if terminated_at is None:
                    _signal_process_group(proc, signal.SIGTERM, pgid)
                    terminated_at = now
            if terminated_at is not None and not sent_kill:
                if now - terminated_at >= PROCESS_TERMINATE_GRACE_SECONDS:
                    _signal_process_group(proc, signal.SIGKILL, pgid)
                    sent_kill = True
            if sent_kill and terminated_at is not None:
                if now - terminated_at >= PROCESS_TERMINATE_GRACE_SECONDS * 2:
                    timed_out = True
                    break
            events = selector.select(timeout=0.05)
            for key, _ in events:
                name = key.data
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    try:
                        stream.close()
                    except OSError:
                        pass
                    continue
                buffer = buffers[name]
                remaining = max_output_bytes - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_truncated = True
                    if terminated_at is None:
                        _signal_process_group(proc, signal.SIGTERM, pgid)
                        terminated_at = time.monotonic()
    finally:
        selector.close()

    try:
        returncode = proc.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _signal_process_group(proc, signal.SIGKILL, pgid)
        try:
            returncode = proc.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            returncode = 124
            timed_out = True
    if timed_out:
        returncode = 124
    elif output_truncated:
        returncode = 125
    return BoundedProcessResult(
        returncode=returncode,
        stdout=bytes(buffers["stdout"]).decode("utf-8", "replace"),
        stderr=bytes(buffers["stderr"]).decode("utf-8", "replace"),
        timed_out=timed_out,
        output_truncated=output_truncated,
    )


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
        proc = run_bounded_command(
            argv,
            cwd=cwd,
            timeout_seconds=600,
            max_output_bytes=SUCCESS_COMMAND_OUTPUT_MAX_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return False, f"success_command failed to launch: {exc}"
    if proc.timed_out:
        return False, "success_command timed out after 600s"
    if proc.output_truncated:
        return False, f"success_command output limit exceeded ({SUCCESS_COMMAND_OUTPUT_MAX_BYTES} bytes)"
    return proc.returncode == 0, f"exit={proc.returncode}"


def run_fixture(task: TaskFixture, variant: Variant, claude_bin: str,
                project_root: Path, dry_run: bool) -> RunResult:
    argv = build_claude_argv(claude_bin, task, variant)
    started_at = time.monotonic()
    if dry_run:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=True, notes=f"dry-run: {shlex.join(argv)}",
            wall_time_seconds=0.0,
        )
    if is_placeholder_success_command(task.success_command):
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False,
            notes=f"{PLACEHOLDER_SUCCESS_COMMAND_MARKER}; refusing to invoke provider",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    argv[0] = executable_argv0(argv[0])
    try:
        proc = run_bounded_command(
            argv,
            cwd=project_root,
            timeout_seconds=1800,
            max_output_bytes=CLAUDE_OUTPUT_MAX_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude launch failed: {exc}",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    if proc.timed_out:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes="claude timed out after 1800s",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    if proc.output_truncated:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude output limit exceeded ({CLAUDE_OUTPUT_MAX_BYTES} bytes)",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    if proc.returncode != 0:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude exit={proc.returncode}: {proc.stderr[-200:].strip()}",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return RunResult(
            task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
            tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
            success=False, notes=f"claude returned non-JSON: {exc.msg}",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )
    tokens, cost, cost_measured, primary_tokens_measured = collect_usage(payload)
    provider_cached_tokens, provider_cached_tokens_measured = collect_provider_cache_telemetry(payload)
    shift_metrics = collect_shift_metrics(payload)
    self_hosted_metrics = collect_self_hosted_metrics(payload)
    success, success_note = run_success_command(task, project_root)
    return RunResult(
        task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
        tokens=tokens, cost_usd=cost, success=success, notes=success_note,
        cost_measured=cost_measured,
        primary_tokens_measured=primary_tokens_measured,
        wall_time_seconds=elapsed_seconds_since(started_at),
        turns=int(shift_metrics["turns"]),
        hook_triggers=int(shift_metrics["hook_triggers"]),
        bytes_before=int(shift_metrics["bytes_before"]),
        bytes_after=int(shift_metrics["bytes_after"]),
        artifacts_used=int(shift_metrics["artifacts_used"]),
        external_tokens=int(shift_metrics["external_tokens"]),
        external_tokens_measured=bool(shift_metrics["external_tokens_measured"]),
        external_cost_usd=float(shift_metrics["external_cost_usd"]),
        external_cost_measured=bool(shift_metrics["external_cost_measured"]),
        provider_cached_tokens=provider_cached_tokens,
        provider_cached_tokens_measured=provider_cached_tokens_measured,
        self_hosted_metrics=self_hosted_metrics,
    )


def append_csv(csv_path: Path, claude_ver: str, result: RunResult, *, skip_existing: bool = False) -> bool:
    with csv_file_lock(csv_path, create_parent=True):
        if skip_existing and (result.task_id, result.variant) in _read_existing_keys_unlocked(csv_path):
            return False
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        fd = _open_regular_no_symlink(csv_path, flags, 0o600, create_parent=True)
        try:
            new_file = os.fstat(fd).st_size == 0
            if not new_file:
                validate_csv_schema(csv_path, read_csv_header_unlocked(csv_path))
            with os.fdopen(fd, "a", encoding="utf-8", newline="") as f:
                fd = -1
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                if new_file:
                    writer.writeheader()
                tokens = result.tokens
                total = sum(tokens.values())
                shifted_cost_known = cost_shift_measured(result)
                writer.writerow({
                    "date": sanitize_csv_cell(_dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")),
                    "claude_version": sanitize_csv_cell(claude_ver),
                    "task_id": sanitize_csv_cell(result.task_id),
                    "variant": sanitize_csv_cell(result.variant),
                    "model": sanitize_csv_cell(result.model),
                    "effort": sanitize_csv_cell(result.effort),
                    "total_tokens": total,
                    "input_tokens": tokens.get("input_tokens", 0),
                    "output_tokens": tokens.get("output_tokens", 0),
                    "cache_read": tokens.get("cache_read", 0),
                    "cache_creation": tokens.get("cache_creation", 0),
                    "provider_cached_tokens": result.provider_cached_tokens,
                    "provider_cached_tokens_measured": (
                        "true" if result.provider_cached_tokens_measured else "false"
                    ),
                    "cost_usd": f"{result.cost_usd:.6f}",
                    "cost_measured": "true" if result.cost_measured else "false",
                    "wall_time_seconds": f"{result.wall_time_seconds:.6f}",
                    "turns": result.turns,
                    "hook_triggers": result.hook_triggers,
                    "bytes_before": result.bytes_before,
                    "bytes_after": result.bytes_after,
                    "artifacts_used": result.artifacts_used,
                    "external_tokens": result.external_tokens,
                    "external_tokens_measured": "true" if result.external_tokens_measured else "false",
                    "external_cost_usd": f"{result.external_cost_usd:.6f}",
                    "external_cost_measured": "true" if result.external_cost_measured else "false",
                    "total_cost_with_shift_usd": (
                        f"{(result.cost_usd + result.external_cost_usd):.6f}" if shifted_cost_known else ""
                    ),
                    "success": "true" if result.success else "false",
                    "corrections": result.corrections,
                    "notes": sanitize_csv_note(result.notes),
                    "primary_tokens_measured": "true" if result.primary_tokens_measured else "false",
                })
        finally:
            if fd != -1:
                os.close(fd)
    return True


def cost_shift_measured(result: RunResult) -> bool:
    return (
        result.cost_measured
        and result.external_tokens_measured
        and (result.external_tokens == 0 or result.external_cost_measured)
    )


def read_csv_header_unlocked(csv_path: Path) -> list[str] | None:
    fd = _open_regular_no_symlink(csv_path)
    try:
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as handle:
            fd = -1
            reader = csv.reader(handle)
            try:
                return next(reader)
            except StopIteration:
                return None
    finally:
        if fd != -1:
            os.close(fd)


def validate_csv_schema(csv_path: Path, fieldnames: list[str] | None) -> None:
    """Fail loudly instead of appending/reporting across incompatible CSV schemas."""
    if fieldnames is None:
        return
    if fieldnames != CSV_COLUMNS:
        raise SystemExit(
            f"CSV schema mismatch for {csv_path}; start a new --csv file or migrate the header "
            f"to: {','.join(CSV_COLUMNS)}"
        )


def write_text_no_follow(path: Path, text: str) -> None:
    fd = _open_regular_no_symlink(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600, create_parent=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
    finally:
        if fd != -1:
            os.close(fd)


def append_cost_shift_ledger(path: Path, claude_ver: str, result: RunResult) -> None:
    shifted_cost_known = cost_shift_measured(result)
    byte_metrics_observed = bool(result.bytes_before or result.bytes_after)
    payload = {
        "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
        "date": _dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "claude_version": claude_ver,
        "task_id": result.task_id,
        "variant": result.variant,
        "transform_id": result.variant,
        "success": result.success,
        "primary_cost_measured": result.cost_measured,
        "primary_cost_usd": round(result.cost_usd, 6),
        "primary_tokens_measured": result.primary_tokens_measured,
        "provider_cached_tokens": result.provider_cached_tokens,
        "provider_cached_tokens_measured": result.provider_cached_tokens_measured,
        "wall_time_seconds": round(result.wall_time_seconds, 6),
        "external_tokens_measured": result.external_tokens_measured,
        "external_cost_measured": result.external_cost_measured,
        "external_cost_usd": round(result.external_cost_usd, 6),
        "total_cost_with_shift_usd": (
            round(result.cost_usd + result.external_cost_usd, 6) if shifted_cost_known else None
        ),
        "primary_tokens": sum(result.tokens.values()),
        "external_tokens": result.external_tokens,
        "artifacts_used": result.artifacts_used,
        "bytes_before": result.bytes_before,
        "bytes_after": result.bytes_after,
        "hook_triggers": result.hook_triggers,
        "turns": result.turns,
        "notes": sanitize_csv_note(result.notes),
        "measurement_availability": {
            "primary_tokens": result.primary_tokens_measured,
            "primary_cost": result.cost_measured,
            "external_tokens": result.external_tokens_measured,
            "external_cost": result.external_cost_measured,
            "shifted_cost": shifted_cost_known,
            "provider_cache": result.provider_cached_tokens_measured,
            "byte_metrics": byte_metrics_observed,
            "wall_time": result.wall_time_seconds >= 0,
            "self_hosted_metrics": result.self_hosted_metrics is not None,
        },
        "proxy_metrics": {
            "byte_metrics_observed": byte_metrics_observed,
            "token_proxy": "chars_div_4",
            "bytes_per_token": TOKEN_PROXY_BYTES_PER_TOKEN,
            "claim_boundary": "proxy_only_not_hosted_token_savings",
        },
    }
    if result.self_hosted_metrics is not None:
        payload["self_hosted_metrics"] = result.self_hosted_metrics
    with csv_file_lock(path, create_parent=True):
        fd = _open_regular_no_symlink(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600, create_parent=True)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                fd = -1
                handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
        finally:
            if fd != -1:
                os.close(fd)


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
            fieldnames = list(reader.fieldnames) if reader.fieldnames is not None else None
            validate_csv_schema(csv_path, fieldnames)
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


def read_csv_rows(csv_path: Path) -> list[dict[str, str]]:
    try:
        fd = _open_regular_no_symlink(csv_path)
    except FileNotFoundError:
        return []
    try:
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as handle:
            fd = -1
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames) if reader.fieldnames is not None else None
            validate_csv_schema(csv_path, fieldnames)
            rows: list[dict[str, str]] = []
            for index, row in enumerate(reader, start=1):
                if index > MAX_CSV_ROWS:
                    raise SystemExit(f"CSV row limit exceeded for {csv_path}: > {MAX_CSV_ROWS}")
                rows.append(row)
            return rows
    finally:
        if fd != -1:
            os.close(fd)


def row_int(row: dict[str, str], key: str) -> int:
    try:
        return int(float(row.get(key) or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def row_optional_nonnegative_int(row: dict[str, str], key: str) -> int | None:
    raw = row.get(key)
    if raw is None:
        return None
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]+", text):
        return None
    try:
        return int(text)
    except (TypeError, ValueError, OverflowError):
        return None


def row_float(row: dict[str, str], key: str) -> float:
    try:
        value = float(row.get(key) or 0)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return value if math.isfinite(value) else 0.0


def row_optional_float(row: dict[str, str], key: str) -> float | None:
    raw = row.get(key)
    if raw is None or str(raw).strip() == "":
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    return value if math.isfinite(value) else None


def row_has_finite_float(row: dict[str, str], key: str) -> bool:
    return row_optional_float(row, key) is not None


def row_bool(row: dict[str, str], key: str) -> bool:
    return str(row.get(key) or "").strip().lower() == "true"


def row_success(row: dict[str, str]) -> bool:
    return str(row.get("success") or "").strip().lower() == "true"


def row_cost_shift_measured(row: dict[str, str]) -> bool:
    return (
        row_bool(row, "cost_measured")
        and row_bool(row, "external_tokens_measured")
        and (row_int(row, "external_tokens") == 0 or row_bool(row, "external_cost_measured"))
    )


def summarize_benchmark_rows(rows: list[dict[str, str]], baseline_variant: str) -> dict[str, Any]:
    by_variant: dict[str, dict[str, Any]] = {}
    successful_rows_by_variant_task: dict[str, dict[str, list[dict[str, str]]]] = {}
    seen_tasks_by_variant: dict[str, set[str]] = {}
    successful_tasks_by_variant: dict[str, set[str]] = {}

    for row_index, raw_row in enumerate(rows, start=1):
        row = dict(raw_row)
        row["_row_index"] = str(row_index)
        variant = row.get("variant") or "unknown"
        task_id = row.get("task_id") or "unknown"
        seen_tasks_by_variant.setdefault(variant, set()).add(task_id)
        bucket = by_variant.setdefault(
            variant,
            {
                "runs": 0,
                "successful_runs": 0,
                "failed_runs": 0,
                "total_tokens_all_runs": 0,
                "primary_tokens_measured_runs": 0,
                "primary_cost_all_runs_usd": 0.0,
                "primary_cost_measured_runs": 0,
                "wall_time_seconds_all_runs": 0.0,
                "wall_time_seconds_measured_runs": 0,
                "provider_cached_tokens_all_runs": 0,
                "provider_cached_tokens_measured_runs": 0,
                "total_cost_with_shift_all_runs_usd": 0.0,
                "total_cost_with_shift_measured_runs": 0,
                "total_tokens_successful": 0,
                "primary_tokens_measured_successful": 0,
                "primary_cost_successful_usd": 0.0,
                "primary_cost_measured_successful": 0,
                "wall_time_seconds_successful": 0.0,
                "wall_time_seconds_measured_successful": 0,
                "provider_cached_tokens_successful": 0,
                "provider_cached_tokens_measured_successful": 0,
                "external_cost_successful_usd": 0.0,
                "external_cost_unknown_successful": 0,
                "total_cost_with_shift_successful_usd": 0.0,
                "total_cost_with_shift_measured_successful": 0,
                "external_tokens_successful": 0,
                "external_tokens_measured_successful": 0,
                "artifacts_used_successful": 0,
                "corrections_successful": 0,
                "bytes_before_successful": 0,
                "bytes_after_successful": 0,
                "turns_successful": 0,
                "hook_triggers_successful": 0,
            },
        )
        bucket["runs"] += 1
        bucket["total_tokens_all_runs"] += row_int(row, "total_tokens")
        if row_bool(row, "primary_tokens_measured"):
            bucket["primary_tokens_measured_runs"] += 1
        bucket["wall_time_seconds_all_runs"] += row_float(row, "wall_time_seconds")
        if row_has_finite_float(row, "wall_time_seconds"):
            bucket["wall_time_seconds_measured_runs"] += 1
        bucket["provider_cached_tokens_all_runs"] += row_int(row, "provider_cached_tokens")
        if row_bool(row, "provider_cached_tokens_measured"):
            bucket["provider_cached_tokens_measured_runs"] += 1
        if row_bool(row, "cost_measured"):
            bucket["primary_cost_all_runs_usd"] += row_float(row, "cost_usd")
            bucket["primary_cost_measured_runs"] += 1
        shifted_cost = row_optional_float(row, "total_cost_with_shift_usd")
        if row_cost_shift_measured(row) and shifted_cost is not None:
            bucket["total_cost_with_shift_all_runs_usd"] += shifted_cost
            bucket["total_cost_with_shift_measured_runs"] += 1
        if not row_success(row):
            bucket["failed_runs"] += 1
            continue
        bucket["successful_runs"] += 1
        successful_tasks_by_variant.setdefault(variant, set()).add(task_id)
        successful_rows_by_variant_task.setdefault(variant, {}).setdefault(task_id, []).append(row)
        bucket["total_tokens_successful"] += row_int(row, "total_tokens")
        if row_bool(row, "primary_tokens_measured"):
            bucket["primary_tokens_measured_successful"] += 1
        bucket["wall_time_seconds_successful"] += row_float(row, "wall_time_seconds")
        if row_has_finite_float(row, "wall_time_seconds"):
            bucket["wall_time_seconds_measured_successful"] += 1
        bucket["provider_cached_tokens_successful"] += row_int(row, "provider_cached_tokens")
        if row_bool(row, "provider_cached_tokens_measured"):
            bucket["provider_cached_tokens_measured_successful"] += 1
        if row_bool(row, "cost_measured"):
            bucket["primary_cost_successful_usd"] += row_float(row, "cost_usd")
            bucket["primary_cost_measured_successful"] += 1
        if row_bool(row, "external_tokens_measured") and (
            row_int(row, "external_tokens") == 0 or row_bool(row, "external_cost_measured")
        ):
            bucket["external_cost_successful_usd"] += row_float(row, "external_cost_usd")
        else:
            bucket["external_cost_unknown_successful"] += 1
        if row_cost_shift_measured(row) and shifted_cost is not None:
            bucket["total_cost_with_shift_successful_usd"] += shifted_cost
            bucket["total_cost_with_shift_measured_successful"] += 1
        if row_bool(row, "external_tokens_measured"):
            bucket["external_tokens_successful"] += row_int(row, "external_tokens")
            bucket["external_tokens_measured_successful"] += 1
        bucket["artifacts_used_successful"] += row_int(row, "artifacts_used")
        bucket["corrections_successful"] += row_int(row, "corrections")
        bucket["bytes_before_successful"] += row_int(row, "bytes_before")
        bucket["bytes_after_successful"] += row_int(row, "bytes_after")
        bucket["turns_successful"] += row_int(row, "turns")
        bucket["hook_triggers_successful"] += row_int(row, "hook_triggers")

    for variant, bucket in by_variant.items():
        successes = bucket["successful_runs"]
        runs = bucket["runs"]
        bucket["failure_rate"] = (bucket["failed_runs"] / runs) if runs else None
        bucket["task_count"] = len(seen_tasks_by_variant.get(variant, set()))
        bucket["successful_task_count"] = len(successful_tasks_by_variant.get(variant, set()))
        if bucket["task_count"]:
            bucket["tokens_per_task_including_failures"] = (
                bucket["total_tokens_all_runs"] / bucket["task_count"]
                if bucket["primary_tokens_measured_runs"] == runs
                else None
            )
            bucket["wall_time_seconds_per_task_including_failures"] = (
                bucket["wall_time_seconds_all_runs"] / bucket["task_count"]
            )
            bucket["provider_cached_tokens_per_task_including_failures"] = (
                bucket["provider_cached_tokens_all_runs"] / bucket["task_count"]
            )
            if bucket["primary_cost_measured_runs"] == runs:
                bucket["primary_cost_per_task_including_failures_usd"] = (
                    bucket["primary_cost_all_runs_usd"] / bucket["task_count"]
                )
            else:
                bucket["primary_cost_per_task_including_failures_usd"] = None
            if bucket["total_cost_with_shift_measured_runs"] == runs:
                bucket["total_cost_with_shift_per_task_including_failures_usd"] = (
                    bucket["total_cost_with_shift_all_runs_usd"] / bucket["task_count"]
                )
            else:
                bucket["total_cost_with_shift_per_task_including_failures_usd"] = None
        else:
            bucket["tokens_per_task_including_failures"] = None
            bucket["wall_time_seconds_per_task_including_failures"] = None
            bucket["provider_cached_tokens_per_task_including_failures"] = None
            bucket["primary_cost_per_task_including_failures_usd"] = None
            bucket["total_cost_with_shift_per_task_including_failures_usd"] = None
        if successes:
            bucket["tokens_per_successful_task"] = (
                bucket["total_tokens_successful"] / successes
                if bucket["primary_tokens_measured_successful"] == successes
                else None
            )
            bucket["wall_time_seconds_per_successful_task"] = bucket["wall_time_seconds_successful"] / successes
            bucket["provider_cached_tokens_per_successful_task"] = (
                bucket["provider_cached_tokens_successful"] / successes
            )
            if bucket["primary_cost_measured_successful"] == successes:
                bucket["primary_cost_per_successful_task_usd"] = (
                    bucket["primary_cost_successful_usd"] / successes
                )
            else:
                bucket["primary_cost_per_successful_task_usd"] = None
            if bucket["total_cost_with_shift_measured_successful"] == successes:
                bucket["total_cost_with_shift_per_successful_task_usd"] = (
                    bucket["total_cost_with_shift_successful_usd"] / successes
                )
            else:
                bucket["total_cost_with_shift_per_successful_task_usd"] = None
            bucket["external_tokens_per_successful_task"] = (
                bucket["external_tokens_successful"] / successes
                if bucket["external_tokens_measured_successful"] == successes
                else None
            )
            bucket["artifacts_used_per_successful_task"] = bucket["artifacts_used_successful"] / successes
            bucket["corrections_per_successful_task"] = bucket["corrections_successful"] / successes
            before = bucket["bytes_before_successful"]
            after = bucket["bytes_after_successful"]
            bucket["byte_reduction_ratio"] = (after / before) if before else None
        else:
            bucket["tokens_per_successful_task"] = None
            bucket["wall_time_seconds_per_successful_task"] = None
            bucket["provider_cached_tokens_per_successful_task"] = None
            bucket["primary_cost_per_successful_task_usd"] = None
            bucket["total_cost_with_shift_per_successful_task_usd"] = None
            bucket["external_tokens_per_successful_task"] = None
            bucket["artifacts_used_per_successful_task"] = None
            bucket["corrections_per_successful_task"] = None
            bucket["byte_reduction_ratio"] = None

        # 각 variant는 하나의 compression strategy를 대표한다. byte 절감/토큰 proxy/
        # 텔레메트리 증거 등급을 보수적으로(additive) 노출한다. 토큰 proxy는 측정된
        # 모델 토큰이 아니라 byte delta 기반 추정치이므로 evidence="inferred"로 둔다.
        bucket["compression_strategy"] = variant
        bucket["is_baseline_strategy"] = variant == baseline_variant
        bytes_before = bucket["bytes_before_successful"]
        bytes_after = bucket["bytes_after_successful"]
        byte_metrics_present = bool(bytes_before or bytes_after)
        if successes and byte_metrics_present:
            bytes_saved = max(0, bytes_before - bytes_after)
            token_proxy_saved = bytes_saved // TOKEN_PROXY_BYTES_PER_TOKEN
            bucket["bytes_saved_successful"] = bytes_saved
            bucket["bytes_saved_per_successful_task"] = bytes_saved / successes
            bucket["byte_savings_pct"] = ((bytes_before - bytes_after) / bytes_before * 100.0) if bytes_before else None
            bucket["token_proxy_saved_successful"] = token_proxy_saved
            bucket["token_proxy_saved_per_successful_task"] = token_proxy_saved / successes
        else:
            bucket["bytes_saved_successful"] = None
            bucket["bytes_saved_per_successful_task"] = None
            bucket["byte_savings_pct"] = None
            bucket["token_proxy_saved_successful"] = None
            bucket["token_proxy_saved_per_successful_task"] = None
        bucket["observed_telemetry"] = {
            "tokens": (
                "observed" if runs and bucket["primary_tokens_measured_runs"] == runs
                else ("partial" if bucket["primary_tokens_measured_runs"] else "unavailable")
            ),
            "primary_cost": (
                "observed" if runs and bucket["primary_cost_measured_runs"] == runs
                else ("partial" if bucket["primary_cost_measured_runs"] else "unavailable")
            ),
            "external_tokens": (
                "observed" if successes and bucket["external_tokens_measured_successful"] == successes
                else ("partial" if bucket["external_tokens_measured_successful"] else "unavailable")
            ),
            "byte_savings": "observed" if byte_metrics_present else "unavailable",
            "token_proxy": "inferred" if (successes and byte_metrics_present) else "unavailable",
            "wall_time": (
                "observed" if runs and bucket["wall_time_seconds_measured_runs"] == runs
                else ("partial" if bucket["wall_time_seconds_measured_runs"] else "unavailable")
            ),
            "provider_cache": (
                "observed" if runs and bucket["provider_cached_tokens_measured_runs"] == runs
                else ("partial" if bucket["provider_cached_tokens_measured_runs"] else "unavailable")
            ),
        }

    def average_task_metric(variant: str, task_id: str, key: str) -> float | None:
        values = [
            row_optional_float(row, key)
            for row in successful_rows_by_variant_task.get(variant, {}).get(task_id, [])
        ]
        known = [value for value in values if value is not None]
        return (sum(known) / len(known)) if known else None

    def average_task_int_metric(variant: str, task_id: str, key: str) -> float | None:
        rows_for_task = successful_rows_by_variant_task.get(variant, {}).get(task_id, [])
        if not rows_for_task:
            return None
        values = [row_optional_nonnegative_int(row, key) for row in rows_for_task]
        if any(value is None for value in values):
            return None
        return sum(value for value in values if value is not None) / len(values)

    def average_paired_metric(
        variant: str,
        task_ids: set[str],
        key: str,
    ) -> tuple[float | None, float | None, int]:
        baseline_values: list[float] = []
        variant_values: list[float] = []
        for task_id in sorted(task_ids):
            baseline_value = average_task_metric(baseline_variant, task_id, key)
            variant_value = average_task_metric(variant, task_id, key)
            if baseline_value is None or variant_value is None:
                continue
            baseline_values.append(baseline_value)
            variant_values.append(variant_value)
        if not baseline_values:
            return None, None, 0
        return (
            sum(baseline_values) / len(baseline_values),
            sum(variant_values) / len(variant_values),
            len(baseline_values),
        )

    def average_paired_int_metric(
        variant: str,
        task_ids: set[str],
        key: str,
    ) -> tuple[float | None, float | None, int]:
        baseline_values: list[float] = []
        variant_values: list[float] = []
        for task_id in sorted(task_ids):
            baseline_value = average_task_int_metric(baseline_variant, task_id, key)
            variant_value = average_task_int_metric(variant, task_id, key)
            if baseline_value is None or variant_value is None:
                continue
            baseline_values.append(baseline_value)
            variant_values.append(variant_value)
        if not baseline_values:
            return None, None, 0
        return (
            sum(baseline_values) / len(baseline_values),
            sum(variant_values) / len(variant_values),
            len(baseline_values),
        )

    def row_indices_for(rows_for_task: list[dict[str, str]]) -> list[int]:
        out: list[int] = []
        for row in rows_for_task:
            index = row_optional_nonnegative_int(row, "_row_index")
            if index is not None:
                out.append(index)
        return out

    def all_rows_bool(rows_for_task: list[dict[str, str]], key: str) -> bool:
        return bool(rows_for_task) and all(row_bool(row, key) for row in rows_for_task)

    def all_rows_optional_int(rows_for_task: list[dict[str, str]], key: str) -> list[int] | None:
        values = [row_optional_nonnegative_int(row, key) for row in rows_for_task]
        if not values or any(value is None for value in values):
            return None
        return [value for value in values if value is not None]

    def all_rows_optional_float(rows_for_task: list[dict[str, str]], key: str) -> list[float] | None:
        values = [row_optional_float(row, key) for row in rows_for_task]
        if not values or any(value is None for value in values):
            return None
        return [value for value in values if value is not None]

    def average_optional_int(rows_for_task: list[dict[str, str]], key: str) -> float | None:
        values = all_rows_optional_int(rows_for_task, key)
        return (sum(values) / len(values)) if values else None

    def average_optional_float(rows_for_task: list[dict[str, str]], key: str) -> float | None:
        values = all_rows_optional_float(rows_for_task, key)
        return (sum(values) / len(values)) if values else None

    def total_optional_int(rows_for_task: list[dict[str, str]], key: str) -> int | None:
        values = all_rows_optional_int(rows_for_task, key)
        return sum(values) if values is not None else None

    def all_rows_shifted_cost_measured(rows_for_task: list[dict[str, str]]) -> bool:
        return bool(rows_for_task) and all(
            row_cost_shift_measured(row) and row_optional_float(row, "total_cost_with_shift_usd") is not None
            for row in rows_for_task
        )

    def matched_side_evidence(variant: str, task_id: str, rows_for_task: list[dict[str, str]]) -> dict[str, Any]:
        primary_tokens_measured = all_rows_bool(rows_for_task, "primary_tokens_measured")
        primary_cost_measured = all_rows_bool(rows_for_task, "cost_measured")
        shifted_cost_measured = all_rows_shifted_cost_measured(rows_for_task)
        provider_cache_measured = all_rows_bool(rows_for_task, "provider_cached_tokens_measured")
        external_tokens_measured = all_rows_bool(rows_for_task, "external_tokens_measured")
        external_cost_measured = all_rows_bool(rows_for_task, "external_cost_measured")
        corrections_values = all_rows_optional_int(rows_for_task, "corrections")
        bytes_before_values = [row_optional_nonnegative_int(row, "bytes_before") for row in rows_for_task]
        bytes_after_values = [row_optional_nonnegative_int(row, "bytes_after") for row in rows_for_task]
        byte_metrics_observed = bool(rows_for_task) and not any(
            value is None for value in [*bytes_before_values, *bytes_after_values]
        )
        bytes_before_total = sum(value for value in bytes_before_values if value is not None)
        bytes_after_total = sum(value for value in bytes_after_values if value is not None)
        byte_delta = bytes_after_total - bytes_before_total if byte_metrics_observed else None
        token_proxy_delta = (
            int(byte_delta / TOKEN_PROXY_BYTES_PER_TOKEN) if byte_delta is not None else None
        )
        return {
            "variant": variant,
            "task_id": task_id,
            "run_count": len(rows_for_task),
            "row_indices": row_indices_for(rows_for_task),
            "primary_tokens": {
                "measured": primary_tokens_measured,
                "average": average_optional_int(rows_for_task, "total_tokens") if primary_tokens_measured else None,
                "total": total_optional_int(rows_for_task, "total_tokens") if primary_tokens_measured else None,
            },
            "primary_cost_usd": {
                "measured": primary_cost_measured,
                "average": average_optional_float(rows_for_task, "cost_usd") if primary_cost_measured else None,
            },
            "total_cost_with_shift_usd": {
                "measured": shifted_cost_measured,
                "average": (
                    average_optional_float(rows_for_task, "total_cost_with_shift_usd")
                    if shifted_cost_measured else None
                ),
            },
            "external_tokens": {
                "measured": external_tokens_measured,
                "total": total_optional_int(rows_for_task, "external_tokens") if external_tokens_measured else None,
            },
            "external_cost_usd": {
                "measured": external_cost_measured,
                "total": (
                    sum(row_float(row, "external_cost_usd") for row in rows_for_task)
                    if external_cost_measured else None
                ),
            },
            "bytes": {
                "measurement": "observed" if byte_metrics_observed else "unavailable",
                "before_total": bytes_before_total if byte_metrics_observed else None,
                "after_total": bytes_after_total if byte_metrics_observed else None,
                "delta_total": byte_delta,
                "token_proxy_delta": token_proxy_delta,
                "token_proxy": "chars_div_4_proxy_only" if byte_metrics_observed else "unavailable",
            },
            "wall_time_seconds": {
                "measured": all_rows_optional_float(rows_for_task, "wall_time_seconds") is not None,
                "average": average_optional_float(rows_for_task, "wall_time_seconds"),
            },
            "provider_cached_tokens": {
                "measured": provider_cache_measured,
                "average": (
                    average_optional_int(rows_for_task, "provider_cached_tokens")
                    if provider_cache_measured else None
                ),
            },
            "corrections": {
                "measured": corrections_values is not None,
                "average": (sum(corrections_values) / len(corrections_values)) if corrections_values else None,
            },
        }

    def matched_pair_evidence_entry(
        variant: str,
        task_id: str,
        quality_gate: str,
    ) -> dict[str, Any]:
        baseline_rows = successful_rows_by_variant_task[baseline_variant][task_id]
        variant_rows = successful_rows_by_variant_task[variant][task_id]
        baseline_evidence = matched_side_evidence(baseline_variant, task_id, baseline_rows)
        variant_evidence = matched_side_evidence(variant, task_id, variant_rows)
        baseline_token_avg = baseline_evidence["primary_tokens"]["average"]
        variant_token_avg = variant_evidence["primary_tokens"]["average"]
        token_claim_allowed = (
            quality_gate == "pass"
            and bool(baseline_evidence["primary_tokens"]["measured"])
            and bool(variant_evidence["primary_tokens"]["measured"])
            and isinstance(baseline_token_avg, (int, float))
            and baseline_token_avg > 0
            and isinstance(variant_token_avg, (int, float))
        )
        baseline_cost_avg = baseline_evidence["total_cost_with_shift_usd"]["average"]
        variant_cost_avg = variant_evidence["total_cost_with_shift_usd"]["average"]
        shifted_cost_claim_allowed = (
            quality_gate == "pass"
            and bool(baseline_evidence["total_cost_with_shift_usd"]["measured"])
            and bool(variant_evidence["total_cost_with_shift_usd"]["measured"])
            and isinstance(baseline_cost_avg, (int, float))
            and baseline_cost_avg > 0
            and isinstance(variant_cost_avg, (int, float))
        )
        token_delta = (
            variant_token_avg - baseline_token_avg
            if token_claim_allowed
            else None
        )
        token_savings_pct = (
            (baseline_token_avg - variant_token_avg) / baseline_token_avg * 100.0
            if token_delta is not None
            else None
        )
        cost_delta = (
            variant_cost_avg - baseline_cost_avg
            if shifted_cost_claim_allowed
            else None
        )
        cost_savings_pct = (
            (baseline_cost_avg - variant_cost_avg) / baseline_cost_avg * 100.0
            if cost_delta is not None
            else None
        )
        base_after = baseline_evidence["bytes"]["after_total"]
        variant_after = variant_evidence["bytes"]["after_total"]
        byte_after_delta = (
            variant_after - base_after
            if isinstance(base_after, int) and isinstance(variant_after, int)
            else None
        )
        return {
            "schema_version": MATCHED_PAIR_EVIDENCE_SCHEMA_VERSION,
            "task_id": task_id,
            "baseline_variant": baseline_variant,
            "variant": variant,
            "transform_id": variant,
            "quality_gate": quality_gate,
            "evidence_kind": "matched_successful_task_bucket",
            "measurements": {
                "baseline": baseline_evidence,
                "variant": variant_evidence,
            },
            "delta": {
                "primary_tokens_average": token_delta,
                "token_savings_pct": token_savings_pct,
                "total_cost_with_shift_usd_average": cost_delta,
                "cost_savings_pct_with_shift": cost_savings_pct,
                "bytes_after_total": byte_after_delta,
                "token_proxy_after_total": (
                    int(byte_after_delta / TOKEN_PROXY_BYTES_PER_TOKEN)
                    if byte_after_delta is not None else None
                ),
                "proxy_measurement": "chars_div_4_proxy_only",
            },
            "claim_boundary": {
                "quality_gate": quality_gate,
                "token_savings_claim_allowed": token_claim_allowed,
                "shifted_cost_claim_allowed": shifted_cost_claim_allowed,
                "byte_proxy_only": True,
                "requires_matched_successful_tasks": True,
                "raw_estimate_only_claim_allowed": False,
            },
        }

    comparisons: list[dict[str, Any]] = []
    matched_pair_evidence: list[dict[str, Any]] = []
    baseline = by_variant.get(baseline_variant)
    baseline_successful_tasks = successful_tasks_by_variant.get(baseline_variant, set())
    baseline_failure_rate = baseline.get("failure_rate") if baseline else None
    for variant, bucket in sorted(by_variant.items()):
        if variant == baseline_variant:
            continue
        variant_successful_tasks = successful_tasks_by_variant.get(variant, set())
        matched_tasks = baseline_successful_tasks & variant_successful_tasks
        token_matched_tasks = {
            task_id for task_id in matched_tasks
            if all(
                row_bool(row, "primary_tokens_measured")
                for row in successful_rows_by_variant_task[baseline_variant][task_id]
            )
            and all(
                row_bool(row, "primary_tokens_measured")
                for row in successful_rows_by_variant_task[variant][task_id]
            )
        }
        base_tokens, variant_tokens, token_task_count = average_paired_metric(
            variant,
            token_matched_tasks,
            "total_tokens",
        )
        base_wall_time, variant_wall_time, wall_time_task_count = average_paired_metric(
            variant,
            matched_tasks,
            "wall_time_seconds",
        )
        base_corrections, variant_corrections, corrections_task_count = average_paired_int_metric(
            variant,
            matched_tasks,
            "corrections",
        )
        base_cost, variant_cost, cost_task_count = average_paired_metric(
            variant,
            {
                task_id for task_id in matched_tasks
                if all(
                    row_cost_shift_measured(row)
                    for row in successful_rows_by_variant_task[baseline_variant][task_id]
                )
                and all(
                    row_cost_shift_measured(row)
                    for row in successful_rows_by_variant_task[variant][task_id]
                )
            },
            "total_cost_with_shift_usd",
        )
        failure_rate = bucket.get("failure_rate")
        failure_delta = None
        if isinstance(baseline_failure_rate, (int, float)) and isinstance(failure_rate, (int, float)):
            failure_delta = (failure_rate - baseline_failure_rate) * 100.0
        missing_baseline_success_tasks = sorted(baseline_successful_tasks - variant_successful_tasks)
        quality_gate = "pass"
        if not baseline or not baseline.get("successful_runs"):
            quality_gate = "insufficient_baseline"
        elif not bucket.get("successful_runs"):
            quality_gate = "insufficient_success"
        elif missing_baseline_success_tasks:
            quality_gate = "matched_task_regression"
        elif failure_delta is not None and failure_delta >= 10.0:
            quality_gate = "failure_rate_regression"
        elif matched_tasks and corrections_task_count < len(matched_tasks):
            quality_gate = "insufficient_corrections_data"
        elif (
            isinstance(base_corrections, (int, float))
            and isinstance(variant_corrections, (int, float))
            and variant_corrections > base_corrections
        ):
            quality_gate = "corrections_regression"
        comparison: dict[str, Any] = {
            "variant": variant,
            "baseline_variant": baseline_variant,
            "quality_gate": quality_gate,
            "baseline_failure_rate": baseline_failure_rate,
            "variant_failure_rate": failure_rate,
            "failure_rate_delta_pp": failure_delta,
            "matched_successful_task_count": len(matched_tasks),
            "baseline_successful_task_count": len(baseline_successful_tasks),
            "missing_baseline_success_tasks": missing_baseline_success_tasks,
            "baseline_corrections_per_successful_task": base_corrections,
            "variant_corrections_per_successful_task": variant_corrections,
            "paired_corrections_task_count": corrections_task_count,
        }
        if isinstance(base_corrections, (int, float)) and isinstance(variant_corrections, (int, float)):
            comparison["corrections_delta_per_successful_task"] = variant_corrections - base_corrections
        if isinstance(base_tokens, (int, float)) and isinstance(variant_tokens, (int, float)) and base_tokens:
            comparison["token_delta_per_successful_task"] = variant_tokens - base_tokens
            comparison["token_savings_pct"] = (base_tokens - variant_tokens) / base_tokens * 100.0
            comparison["paired_token_task_count"] = token_task_count
        else:
            comparison["token_savings_pct"] = None
            comparison["paired_token_task_count"] = 0
        if (
            isinstance(base_wall_time, (int, float))
            and isinstance(variant_wall_time, (int, float))
            and base_wall_time
        ):
            comparison["wall_time_delta_seconds_per_successful_task"] = variant_wall_time - base_wall_time
            comparison["wall_time_change_pct"] = (variant_wall_time - base_wall_time) / base_wall_time * 100.0
            comparison["paired_wall_time_task_count"] = wall_time_task_count
        else:
            comparison["wall_time_delta_seconds_per_successful_task"] = None
            comparison["wall_time_change_pct"] = None
            comparison["paired_wall_time_task_count"] = wall_time_task_count
        if isinstance(base_cost, (int, float)) and isinstance(variant_cost, (int, float)) and base_cost:
            comparison["total_cost_with_shift_delta_usd"] = variant_cost - base_cost
            comparison["cost_savings_pct_with_shift"] = (base_cost - variant_cost) / base_cost * 100.0
            comparison["paired_cost_task_count"] = cost_task_count
        else:
            comparison["cost_savings_pct_with_shift"] = None
            comparison["paired_cost_task_count"] = cost_task_count
        for task_id in sorted(matched_tasks):
            matched_pair_evidence.append(matched_pair_evidence_entry(variant, task_id, quality_gate))
        comparisons.append(comparison)

    claim_status = "insufficient_baseline"
    if baseline and baseline.get("successful_runs"):
        claim_status = "compare_variants" if comparisons else "baseline_only"
        if comparisons:
            quality_ok = all(item.get("quality_gate") == "pass" for item in comparisons)
            paired_token_data = all((item.get("paired_token_task_count") or 0) > 0 for item in comparisons)
            token_savings_observed = all((item.get("token_savings_pct") or 0) > 0 for item in comparisons)
            shifted_cost_savings = [
                item.get("cost_savings_pct_with_shift")
                for item in comparisons
                if isinstance(item.get("cost_savings_pct_with_shift"), (int, float))
            ]
            all_shifted_cost_measured = len(shifted_cost_savings) == len(comparisons)
            shifted_cost_ok = all_shifted_cost_measured and all(value > 0 for value in shifted_cost_savings)
            if not quality_ok:
                claim_status = "quality_gate_watch"
            elif not paired_token_data:
                claim_status = "insufficient_paired_data"
            elif token_savings_observed and shifted_cost_ok:
                claim_status = "token_and_shifted_cost_savings_observed"
            elif token_savings_observed and not all_shifted_cost_measured:
                claim_status = "token_savings_observed_cost_unmeasured"
            elif token_savings_observed:
                claim_status = "token_savings_observed_cost_shift_watch"
    return {
        "schema": "context-guard-bench-report-v1",
        "baseline_variant": baseline_variant,
        "row_count": len(rows),
        "summary_by_variant": by_variant,
        "comparisons": comparisons,
        "matched_pair_evidence": matched_pair_evidence,
        "claim_status": claim_status,
        "caveat": (
            "Proxy byte reductions are reported separately from matched-task token/cost metrics; "
            "shifted cost savings require measured primary cost and measured external cost when "
            "external tokens are present. Wall time and provider cached-token fields are diagnostic "
            "telemetry, not proof of ContextGuard-caused token or cost savings; provider-cache "
            "discounts must stay separate from token-reduction claims."
        ),
    }

def write_report_json(csv_path: Path, report_path: Path, baseline_variant: str) -> dict[str, Any]:
    # Keep lock order stable across all report writes: source CSV first, derived
    # report second. Do not introduce a report -> CSV path; that can deadlock
    # concurrent report generation.
    with csv_file_lock(csv_path, create_parent=True):
        report = summarize_benchmark_rows(read_csv_rows(csv_path), baseline_variant)
        with csv_file_lock(report_path, create_parent=True):
            write_text_no_follow(
                report_path,
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            )
    return report


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


def sanitize_csv_cell(value: Any) -> str:
    """Normalize short untrusted CSV labels and block spreadsheet formulas."""
    text = sanitize_note_text(value)
    if text.startswith(CSV_FORMULA_PREFIXES):
        text = "'" + text
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


def normalized_output_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return Path(os.path.normpath(str(_normalize_allowed_first_absolute_symlink(expanded))))


def existing_file_identity(path: Path) -> tuple[int, int] | None:
    try:
        fd = _open_regular_no_symlink(normalized_output_path(path))
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        return (int(st.st_dev), int(st.st_ino))
    finally:
        os.close(fd)


def validate_distinct_output_paths(csv_path: Path, ledger_path: Path | None, report_path: Path | None) -> None:
    outputs = [("csv", csv_path), ("ledger-jsonl", ledger_path), ("report-json", report_path)]
    seen: dict[Path, str] = {}
    seen_identity: dict[tuple[int, int], str] = {}
    for label, path in outputs:
        if path is None:
            continue
        normalized = normalized_output_path(path)
        previous = seen.get(normalized)
        if previous is not None:
            raise SystemExit(f"--{label} must not point to the same path as --{previous}: {normalized}")
        seen[normalized] = label
        identity = existing_file_identity(normalized)
        if identity is not None:
            previous_identity = seen_identity.get(identity)
            if previous_identity is not None:
                raise SystemExit(f"--{label} must not point to the same file as --{previous_identity}: {normalized}")
            seen_identity[identity] = label


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
    parser.add_argument("--ledger-jsonl", default=None, type=Path,
                        help="optional JSONL ledger path for cost-shift accounting per run")
    parser.add_argument("--report-json", default=None, type=Path,
                        help="optional A/B summary report JSON path generated from --csv after real runs")
    parser.add_argument("--baseline-variant", default="baseline",
                        help="variant name used as the report baseline (default: baseline)")
    args = parser.parse_args()

    require_no_follow_file_ops_supported()
    validate_distinct_output_paths(args.csv, args.ledger_jsonl, args.report_json)

    variants = parse_variants(args.variants)
    tasks = parse_tasks(args.tasks, variants=variants)
    targets = filter_targets(tasks, variants, args.task_id, args.variant)
    if not targets:
        print("no (task, variant) targets matched the filters", file=sys.stderr)
        return 1

    skip_keys = existing_keys(args.csv) if args.resume else set()
    runnable_targets = [
        (task, variant)
        for task, variant in targets
        if (task.id, variant.name) not in skip_keys
    ]
    placeholder_targets = [
        f"{task.id}/{variant.name}"
        for task, variant in runnable_targets
        if is_placeholder_success_command(task.success_command)
    ]
    if placeholder_targets and not args.dry_run:
        print(
            f"{PLACEHOLDER_SUCCESS_COMMAND_MARKER}; refusing non-dry-run provider invocation for: "
            f"{', '.join(placeholder_targets)}",
            file=sys.stderr,
        )
        return 2

    if runnable_targets and not args.dry_run and shutil.which(args.claude_bin) is None:
        # claude_bin 이 절대경로면 shutil.which 가 None 일 수 있으므로 추가 검사.
        if not Path(args.claude_bin).exists():
            print(f"claude binary not found: {args.claude_bin}", file=sys.stderr)
            return 2

    project_root = args.project_root.resolve()
    claude_ver = "dry-run" if args.dry_run else (claude_version(args.claude_bin) if runnable_targets else "skipped")

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
            if wrote and args.ledger_jsonl is not None:
                append_cost_shift_ledger(args.ledger_jsonl, claude_ver, result)
        completed += 1
        status = "ok" if result.success else "FAIL"
        if args.dry_run:
            suffix = " (dry-run; CSV not updated)"
        elif not wrote:
            suffix = " (CSV not updated; row already present)"
        else:
            suffix = ""
        print(
            f"  {status} tokens={sum(result.tokens.values())} cost=${result.cost_usd:.4f} "
            f"wall_time={result.wall_time_seconds:.3f}s {sanitize_note_text(result.notes)}{suffix}"
        )
    target = args.csv if not args.dry_run else "(dry-run; no CSV writes)"
    if args.report_json is not None and not args.dry_run:
        report = write_report_json(args.csv, args.report_json, args.baseline_variant)
        print(f"report {args.report_json}: {report['claim_status']}")
    print(f"completed {completed} run(s); results in {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
