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
import hashlib
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
MAX_EVIDENCE_JSONL_BYTES = 5_000_000
MAX_EVIDENCE_JSONL_LINES = 100_000
# Byte -> token proxy 환산 계수. 측정된 모델 토큰이 아니라 byte delta 기반 보수적
# 추정치이며, report에서 evidence="inferred"로 분명히 라벨링한다. 영어 텍스트 기준
# ~4 bytes/token의 통용 근사값을 사용한다.
TOKEN_PROXY_BYTES_PER_TOKEN = 4
BENCH_RUN_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.run-evidence.v1"
MATCHED_PAIR_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.matched-pair.v1"
MEASUREMENT_BASELINE_SCHEMA_VERSION = "contextguard.bench.measurement-baseline.v1"
DEFAULT_MATRIX_SCHEMA_VERSION = "contextguard.bench.default-matrix.v1"
PUBLIC_CLAIM_READINESS_SCHEMA_VERSION = "contextguard.bench.public-claim-readiness.v1"
SELF_HOSTED_METRICS_SCHEMA_VERSION = "contextguard.bench.self-hosted-metrics.v1"
SELF_HOSTED_METRICS_KEY = "self_hosted_metrics"
SELF_HOSTED_METRICS_CLAIM_BOUNDARY = "self_hosted_metrics_only_not_hosted_api_token_or_cost_savings"
EVIDENCE_REPLAY_SOURCE_TYPES = frozenset({"synthetic_fixture", "provider_export", "manual_audit"})
PROVIDER_EXPORT_PUBLIC_CLAIM_SCOPES = frozenset({
    "provider_measured_matched_task",
    "provider_measured_matched_task_public_claim",
    "hosted_api_provider_measured_matched_task",
})
REPLAY_PUBLIC_CLAIM_CANDIDATE_STATUS = "provider_export_public_claim_candidate"
REPLAY_PROVIDER_CLAIM_GATES_NOT_MET_STATUS = "provider_export_claim_gates_not_met"
REPLAY_NOT_PUBLIC_CLAIM_STATUS = "replay_only_not_public_claim"
REPLAY_UNKNOWN_MIXED_CSV_STATUS = "unknown_mixed_csv"
REPLAY_PUBLIC_CLAIM_ELIGIBLE_RAW_STATUSES = frozenset({
    "token_and_shifted_cost_savings_observed",
})
REPLAY_CLAIM_BOUNDARY = (
    "Evidence replay is an import/replay mode. Synthetic fixtures and manual audits are never "
    "hosted API token/cost savings evidence; public claims require complete provider_export "
    "provenance for every report row plus the normal matched-task quality, token, cost, and "
    "shifted-cost gates."
)
DEFAULT_MATRIX_CLASSIFICATIONS = ("default-on", "advisory", "experimental", "reject/rework")
DEFAULT_MATRIX_CLASSIFICATION_STRENGTH = {
    "experimental": 0,
    "advisory": 1,
    "default-on": 2,
}
DEFAULT_MATRIX_LANES: tuple[dict[str, Any], ...] = (
    {
        "id": "trimming",
        "label": "Trimming / digest output",
        "policy_ceiling": "default-on",
        "task_keywords": ("long_log_analysis", "output_transform", "trim", "trimming", "sanitize_output", "digest"),
        "variant_keywords": ("trim", "trimming", "sanitize", "digest", "brief"),
    },
    {
        "id": "artifact_escrow",
        "label": "Artifact escrow / receipt handles",
        "policy_ceiling": "default-on",
        "task_keywords": ("artifact_receipt", "artifact", "receipt", "escrow", "output_sandbox", "response_sandbox"),
        "variant_keywords": ("artifact", "receipt", "escrow", "output_sandbox", "response_sandbox"),
    },
    {
        "id": "tool_pruning",
        "label": "Tool/MCP schema pruning",
        "policy_ceiling": "default-on",
        "task_keywords": ("tool_schema", "tool_prune", "tool_pruning", "mcp_schema", "defer_report"),
        "variant_keywords": ("tool_prune", "tool_pruning", "tool_schema", "mcp", "defer"),
    },
    {
        "id": "cache_advice",
        "label": "Cache layout advice",
        "policy_ceiling": "advisory",
        "task_keywords": ("cache_layout", "cache_advice", "cache_score", "provider_cache"),
        "variant_keywords": ("cache_layout", "cache_advice", "cache_score", "provider_cache", "cache"),
    },
    {
        "id": "adaptive_k",
        "label": "Adaptive-k context packing",
        "policy_ceiling": "advisory",
        "task_keywords": ("adaptive_k", "adaptive", "top_k", "context_pack"),
        "variant_keywords": ("adaptive_k", "adaptive", "top_k", "pack_adaptive"),
    },
    {
        "id": "optional_compression",
        "label": "Optional compression",
        "policy_ceiling": "advisory",
        "task_keywords": ("learned_compression", "compression", "compress", "context_diff"),
        "variant_keywords": ("learned_compression", "compression", "compress", "context_diff"),
    },
)
DEFAULT_MATRIX_LANE_IDS = tuple(str(item["id"]) for item in DEFAULT_MATRIX_LANES)
DEFAULT_MATRIX_LANE_BY_ID = {str(item["id"]): item for item in DEFAULT_MATRIX_LANES}
MAX_DEFAULT_MATRIX_EVIDENCE_ITEMS = 20
DEFAULT_MATRIX_CLAIM_BOUNDARY = {
    "id": "default_matrix_reporting_only_not_runtime_default_or_savings_claim",
    "reporting_only": True,
    "changes_runtime_defaults": False,
    "hosted_api_token_savings_claim_allowed": False,
    "hosted_api_cost_savings_claim_allowed": False,
    "public_claims_must_use_report_claim_status_and_matched_pair_evidence": True,
    "reason": (
        "The default matrix classifies local benchmark lanes for review only; it does not "
        "turn features on by default and does not authorize hosted API savings claims."
    ),
}
PUBLIC_CLAIM_READINESS_GATE_IDS = (
    "matched_successful_tasks",
    "provider_measured_token_cost",
    "quality_non_inferiority",
    "shifted_cost_accounting",
    "confidence_failure_notes",
    "provider_export_provenance",
)
PUBLIC_CLAIM_READINESS_CLAIM_BOUNDARY = {
    "id": "public_claim_readiness_authoritative_release_gate",
    "reporting_only": True,
    "claim_allowed_field": "public_claim_readiness.claim_allowed",
    "unsupported_claims_forbidden": True,
    "hosted_api_token_savings_claim_without_claim_allowed_forbidden": True,
    "hosted_api_cost_savings_claim_without_claim_allowed_forbidden": True,
    "fixed_percent_savings_claim_without_matched_provider_report_forbidden": True,
    "requires_matched_successful_tasks": True,
    "requires_provider_measured_tokens_and_cost": True,
    "requires_quality_non_inferiority": True,
    "requires_shifted_cost_accounting": True,
    "requires_confidence_and_failure_notes": True,
    "requires_provider_export_provenance": True,
    "reason": (
        "Public hosted token/cost savings claims are forbidden unless every readiness gate passes "
        "and public_claim_readiness.claim_allowed is true."
    ),
}
MAX_SELF_HOSTED_LABEL_CHARS = 120
MAX_SELF_HOSTED_LATENCY_MS = 7 * 24 * 60 * 60 * 1000
MAX_SELF_HOSTED_MEMORY_MB = 10_000_000
MAX_VARIANT_PROMPT_FILE_BYTES = 128_000
MAX_FIXTURE_FILE_BYTES = 1_000_000
MAX_CLAUDE_PROMPT_ARG_BYTES = MAX_VARIANT_PROMPT_FILE_BYTES
CLAUDE_OUTPUT_MAX_BYTES = 1_000_000
SUCCESS_COMMAND_OUTPUT_MAX_BYTES = 64_000
VERSION_OUTPUT_MAX_BYTES = 16_000
PROCESS_TERMINATE_GRACE_SECONDS = 2.0
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}

# --- Phase 4/5 optional image-context evaluation profile (evaluation-only) ---
# 이 profile 은 task fixture 가 명시적으로 opt-in 할 때만 동작한다. profile 이 없는
# 기존 replay 는 스키마/동작이 그대로 유지된다. profile 이 붙은 report 는 어떤
# 경우에도 public claim / promotion 권한을 얻지 못하도록 clamp 된다.
IMAGE_CONTEXT_EVALUATION_PROFILE_ID = "contextguard.bench.image-context-pack-evaluation.v1"
SUPPORTED_EVALUATION_PROFILE_IDS = frozenset({IMAGE_CONTEXT_EVALUATION_PROFILE_ID})
IMAGE_CONTEXT_READINESS_SCHEMA_VERSION = "contextguard.bench.image-context-pack-readiness.v1"
IMAGE_CONTEXT_PROFILE_REPORT_KEY = "image_context_pack"
EVALUATION_PROFILES_REPORT_KEY = "evaluation_profiles"
IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS = "image_context_pack_evaluation_only_not_public_claim"
PROFILE_STATUS_BLOCKED = "blocked"
PROFILE_STATUS_READY_FOR_BOUNDED_PILOT_REVIEW = "ready_for_bounded_pilot_review"
# 가져온 local proof-verifier 레코드는 "누가 만들었는지" 를 인증하지 않고 artifact 를
# 다시 읽지도 않는다. 라벨로 그 경계를 명시한다.
IMPORTED_LOCAL_VERIFIER_ATTESTATION_LABEL = "imported_local_verifier_attestation"
PROOF_VERIFICATION_SCHEMA_VERSION = "contextguard.experiments.proof-carrying-context-verification.v1"
PROOF_VERIFICATION_VERIFIED_STATUS = "verified"

# reject_prewrite 오류 ID. 출력이 하나라도 기록되기 전에 실패해야 하는 구조적 오류다.
PROFILE_REJECT_CONTROLS_MISSING = "profile_controls_missing"
PROFILE_REJECT_SCHEMA_INVALID = "profile_schema_invalid"
PROFILE_REJECT_BINDING_MISMATCH = "profile_binding_mismatch"
PROFILE_REJECT_BATCH_INCOMPLETE = "profile_batch_incomplete"
PROFILE_REJECT_FRESH_OUTPUT_REQUIRED = "profile_fresh_output_required"
PROFILE_REJECT_PROMPT_BINDING_INVALID = "profile_prompt_binding_invalid"
PROFILE_REJECT_CORRECTION_INCONSISTENT = "profile_correction_inconsistent"
PROFILE_REJECT_MEASUREMENT_INCONSISTENT = "profile_measurement_inconsistent"
PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT = "profile_fallback_claim_inconsistent"
PROFILE_REJECT_ERROR_IDS = (
    PROFILE_REJECT_CONTROLS_MISSING,
    PROFILE_REJECT_SCHEMA_INVALID,
    PROFILE_REJECT_BINDING_MISMATCH,
    PROFILE_REJECT_BATCH_INCOMPLETE,
    PROFILE_REJECT_FRESH_OUTPUT_REQUIRED,
    PROFILE_REJECT_PROMPT_BINDING_INVALID,
    PROFILE_REJECT_CORRECTION_INCONSISTENT,
    PROFILE_REJECT_MEASUREMENT_INCONSISTENT,
    PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT,
)

# lane gate ID. 순서는 report/dashboard 출력 순서와 동일하게 고정한다.
IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING = "profile_and_prompt_binding"
IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW = "protected_zone_deny_review"
IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING = "exact_text_fallback_binding"
IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW = "missed_context_review"
IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY = "human_correction_consistency"
IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT = "generic_matched_success_and_measurement"
IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY = "evaluation_only_promotion_boundary"
IMAGE_CONTEXT_GATE_IDS = (
    IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING,
    IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW,
    IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING,
    IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW,
    IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY,
    IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT,
    IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY,
)
IMAGE_CONTEXT_GATE_LABELS = {
    IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING: "Profile and prompt binding",
    IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW: "Protected-zone deny review attestation",
    IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING: "Exact-text fallback binding",
    IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW: "Missed-context review",
    IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY: "Human correction consistency",
    IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT: "Generic matched success and provider measurement",
    IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY: "Evaluation-only promotion boundary",
}
# 품질 게이트가 회귀를 보고할 때 lane blocker 로 승격시키는 기존 generic quality_gate 값.
IMAGE_CONTEXT_QUALITY_BLOCKER_GATES = (
    "insufficient_baseline",
    "insufficient_success",
    "insufficient_corrections_data",
    "matched_task_regression",
    "failure_rate_regression",
    "corrections_regression",
)
IMAGE_CONTEXT_PROFILE_BLOCKER_GATE_ID = "image_context_pack_evaluation_only"
IMAGE_CONTEXT_CLAIM_BOUNDARY = {
    "id": "image_context_pack_evaluation_only_never_promotion_or_public_claim",
    "evaluation_only": True,
    "promotion_authority": False,
    "public_claim_allowed": False,
    "runtime_authority": False,
    "hosted_savings_claim_allowed": False,
    "fallback_attestation_label": IMPORTED_LOCAL_VERIFIER_ATTESTATION_LABEL,
    "fallback_attestation_is_independently_verified": False,
    "protected_zone_evidence_is_review_attestation_not_semantic_proof": True,
    "reason": (
        "The image-context evaluation profile reviews imported evidence only. It does not render, "
        "parse, or reread any image or artifact, does not authenticate who produced an imported "
        "verifier or review record, and can never authorize a public savings claim, a quality "
        "non-inferiority claim, or a runtime promotion."
    ),
}
PROFILE_SAMPLE_ADEQUACY_POLICY_STATUS = "not_defined_for_promotion"
PROFILE_EVIDENCE_LEVEL_NOT_APPLICABLE = "not_applicable"

# profile 중첩 블록의 명시적 byte/count 한계. 타입/한계 검사는 항상 semantic 분류보다
# 먼저 실행되어 oversize 값이 blocked 분기로 새지 않도록 한다.
MAX_PROFILE_LABEL_CHARS = 120
MAX_PROFILE_POLICY_CHARS = 120
MAX_PROFILE_NOTE_CHARS = 500
MAX_PROFILE_SUMMARY_CHARS = 500
MAX_PROFILE_COMMAND_CHARS = 500
MAX_PROFILE_RECEIPT_ID_CHARS = 200
MAX_PROFILE_BLOCKER_ITEMS = 20
MAX_PROFILE_BLOCKER_CHARS = 120
MAX_PROFILE_PROTECTED_REGION_COUNT = 10_000
MAX_PROFILE_CORRECTION_COUNT = 10_000
MAX_PROFILE_PROOF_UNIT_COUNT = 1_000
SHA256_HEX_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
PROTECTED_ZONE_DENY_POLICY = "deny"
PROFILE_REVIEW_RESULTS = ("pass", "fail", "unknown")


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


def _read_text_no_follow(path: Path, *, max_bytes: int = MAX_FIXTURE_FILE_BYTES) -> str:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise SystemExit(f"fixture file exceeds {max_bytes} bytes: {path}")
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SystemExit(f"fixture file must be UTF-8 text: {path}: {exc.reason}") from None
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
    # 선택적 evaluation profile opt-in. None 이면 기존 generic 동작을 그대로 유지한다.
    evaluation_profile: str | None = None


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
class EvidenceReplayRow:
    result: RunResult
    source_type: str
    provider_name: str | None
    capture_command_or_export_id: str | None
    claim_scope: str
    provider_export_provenance_complete: bool
    public_claim_eligible: bool
    explicit_notes: bool
    line_number: int
    # profile 을 선언하지 않은 row 는 두 필드가 모두 None 이며 generic 경로와 동일하다.
    evaluation_profile: str | None = None
    evaluation_controls: dict[str, Any] | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.result.task_id, self.result.variant)

    def provenance_payload(self) -> dict[str, Any]:
        return {
            "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
            "mode": "evidence_jsonl_replay",
            "evidence_source_type": self.source_type,
            "provider_name": self.provider_name,
            "capture_command_or_export_id": self.capture_command_or_export_id,
            "claim_scope": self.claim_scope,
            "provider_export_provenance_complete": self.provider_export_provenance_complete,
            "public_claim_eligible": self.public_claim_eligible,
            "explicit_notes": self.explicit_notes,
            "line_number": self.line_number,
            "claim_boundary": REPLAY_CLAIM_BOUNDARY,
        }


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


def require_argv_safe_prompt(text: str, *, owner: str) -> str:
    """Keep prompt-bearing argv below a bounded size to avoid E2BIG failures."""
    size = len(text.encode("utf-8", errors="replace"))
    if size > MAX_CLAUDE_PROMPT_ARG_BYTES:
        raise SystemExit(
            f"{owner} prompt exceeds argv-safe limit "
            f"({size} bytes > {MAX_CLAUDE_PROMPT_ARG_BYTES}); use a smaller fixture prompt"
        )
    return text


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


def validate_variant_prompt_file_references(
    tasks: list[TaskFixture],
    variants: list["Variant"],
) -> None:
    """Validate variant prompt-file keys and paths without dereferencing files.

    Unknown variant keys and unsafe relative paths are rejected before any file
    read. Missing prompt files are intentionally not checked here so a run
    narrowed by --task-id/--variant is not blocked by unselected prompt files.
    """
    known_variants = {variant.name for variant in variants}
    for task in tasks:
        unknown = sorted(set(task.variant_prompt_files) - known_variants)
        if unknown:
            raise SystemExit(
                f"task {task.id} variant_prompt_files references unknown variant(s): {', '.join(unknown)}"
            )
        for variant_name, raw_path in task.variant_prompt_files.items():
            validate_variant_prompt_file_path(
                raw_path,
                owner=f"task {task.id} variant {variant_name}",
            )


def read_variant_prompt_file(path: Path, *, owner: str, display_path: str | None = None) -> str:
    """Read one selected prompt file with no-follow IO and an argv-safe size cap."""
    label = display_path or path.name
    try:
        fd = _open_regular_no_symlink(path)
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        raise SystemExit(f"{owner} variant_prompt_files could not read prompt file: {label}: {detail}") from None
    try:
        size = os.fstat(fd).st_size
        if size > MAX_VARIANT_PROMPT_FILE_BYTES:
            raise SystemExit(
                f"{owner} variant_prompt_files prompt file exceeds "
                f"{MAX_VARIANT_PROMPT_FILE_BYTES} bytes: {label}"
            )
        try:
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                raw = handle.read(MAX_VARIANT_PROMPT_FILE_BYTES + 1)
        except OSError as exc:
            detail = exc.strerror or exc.__class__.__name__
            raise SystemExit(f"{owner} variant_prompt_files could not read prompt file: {label}: {detail}") from None
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > MAX_VARIANT_PROMPT_FILE_BYTES:
        raise SystemExit(
            f"{owner} variant_prompt_files prompt text exceeds "
            f"{MAX_VARIANT_PROMPT_FILE_BYTES} bytes after decoding: {label}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(
            f"{owner} variant_prompt_files prompt file must be UTF-8 text: "
            f"{label}: {exc.reason}"
        ) from None
    return require_argv_safe_prompt(text, owner=f"{owner} variant_prompt_files")


def load_variant_prompt_files_for_targets(
    targets: list[tuple[TaskFixture, "Variant"]],
    *,
    task_file_dir: Path,
) -> None:
    """Load file-backed prompts only for selected (task, variant) targets."""
    for task, variant in targets:
        raw_path = task.variant_prompt_files.get(variant.name)
        if raw_path is None:
            continue
        rel_path = validate_variant_prompt_file_path(
            raw_path,
            owner=f"task {task.id} variant {variant.name}",
        )
        task.variant_prompt_texts[variant.name] = read_variant_prompt_file(
            task_file_dir / rel_path,
            owner=f"task {task.id} variant {variant.name}",
            display_path=str(rel_path),
        )


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
        validate_variant_prompt_file_references(fixtures, variants)
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


def normalize_self_hosted_metrics(raw: Any, *, source: str) -> dict[str, Any] | None:
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
        "source": source,
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

    Only explicit top-level telemetry envelopes are considered.  Do not infer
    from incidental keys like `self_hosted_latency_ms` or arbitrary nested model
    message content: that would make local/model-server telemetry too easy to
    mix into hosted API claim surfaces.
    """
    if not isinstance(payload, dict):
        return None
    candidates = [
        (
            payload.get(SELF_HOSTED_METRICS_KEY),
            f"explicit_provider_payload.{SELF_HOSTED_METRICS_KEY}",
        )
    ]
    metrics_envelope = payload.get("metrics")
    if isinstance(metrics_envelope, dict):
        candidates.append((
            metrics_envelope.get(SELF_HOSTED_METRICS_KEY),
            f"explicit_provider_payload.metrics.{SELF_HOSTED_METRICS_KEY}",
        ))
    for raw, source in candidates:
        normalized = normalize_self_hosted_metrics(raw, source=source)
        if normalized is not None:
            return normalized
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
    prompt = require_argv_safe_prompt(
        task.variant_prompt_texts.get(variant.name, task.prompt),
        owner=f"task {task.id} variant {variant.name}",
    )
    argv.append(prompt)
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


def csv_file_stamp_unlocked(csv_path: Path) -> tuple[int, int, int, int] | None:
    try:
        fd = _open_regular_no_symlink(csv_path)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))
    finally:
        os.close(fd)


def refresh_existing_key_cache_unlocked(
    csv_path: Path,
    existing_key_cache: set[tuple[str, str]],
    existing_key_cache_stamp: dict[str, tuple[int, int, int, int] | None] | None,
) -> None:
    current_stamp = csv_file_stamp_unlocked(csv_path)
    if existing_key_cache_stamp is not None and existing_key_cache_stamp.get("stamp") == current_stamp:
        return
    refreshed = _read_existing_keys_unlocked(csv_path)
    existing_key_cache.clear()
    existing_key_cache.update(refreshed)
    if existing_key_cache_stamp is not None:
        existing_key_cache_stamp["stamp"] = current_stamp


def resume_key_present(
    csv_path: Path,
    key: tuple[str, str],
    existing_key_cache: set[tuple[str, str]],
    existing_key_cache_stamp: dict[str, tuple[int, int, int, int] | None] | None,
) -> bool:
    if not _csv_exists_no_follow(csv_path):
        existing_key_cache.clear()
        if existing_key_cache_stamp is not None:
            existing_key_cache_stamp["stamp"] = None
        return False
    with csv_file_lock(csv_path, create_parent=False):
        refresh_existing_key_cache_unlocked(csv_path, existing_key_cache, existing_key_cache_stamp)
        return key in existing_key_cache


def resume_runnable_targets(
    csv_path: Path,
    targets: list[tuple[TaskFixture, Variant]],
    *,
    resume: bool,
    existing_key_cache: set[tuple[str, str]],
    existing_key_cache_stamp: dict[str, tuple[int, int, int, int] | None] | None,
) -> list[tuple[TaskFixture, Variant]]:
    if not resume:
        return list(targets)
    return [
        (task, variant)
        for task, variant in targets
        if not resume_key_present(csv_path, (task.id, variant.name), existing_key_cache, existing_key_cache_stamp)
    ]


def append_csv(
    csv_path: Path,
    claude_ver: str,
    result: RunResult,
    *,
    skip_existing: bool = False,
    existing_key_cache: set[tuple[str, str]] | None = None,
    existing_key_cache_stamp: dict[str, tuple[int, int, int, int] | None] | None = None,
) -> bool:
    with csv_file_lock(csv_path, create_parent=True):
        key = (result.task_id, result.variant)
        if skip_existing:
            if existing_key_cache is not None:
                refresh_existing_key_cache_unlocked(csv_path, existing_key_cache, existing_key_cache_stamp)
                if key in existing_key_cache:
                    return False
            elif key in _read_existing_keys_unlocked(csv_path):
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
        if existing_key_cache is not None:
            existing_key_cache.add(key)
        if existing_key_cache_stamp is not None:
            existing_key_cache_stamp["stamp"] = csv_file_stamp_unlocked(csv_path)
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


def append_cost_shift_ledger(
    path: Path,
    claude_ver: str,
    result: RunResult,
    *,
    replay_provenance: dict[str, Any] | None = None,
) -> None:
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
    if replay_provenance is not None:
        payload["replay_provenance"] = replay_provenance
        payload["evidence_source_type"] = replay_provenance.get("evidence_source_type")
        payload["public_claim_eligible"] = bool(replay_provenance.get("public_claim_eligible"))
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
            for index, row in enumerate(reader, start=1):
                if index > MAX_CSV_ROWS:
                    raise SystemExit(f"CSV row limit exceeded for {csv_path}: > {MAX_CSV_ROWS}")
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
    keys, _stamp = existing_keys_snapshot(csv_path)
    return keys


def existing_keys_snapshot(csv_path: Path) -> tuple[set[tuple[str, str]], tuple[int, int, int, int] | None]:
    """Loaded resume keys plus the CSV stamp observed under the same lock."""
    if not _csv_exists_no_follow(csv_path):
        return set(), None
    with csv_file_lock(csv_path, create_parent=False):
        return _read_existing_keys_unlocked(csv_path), csv_file_stamp_unlocked(csv_path)


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


def file_has_content_no_follow(path: Path) -> bool:
    try:
        fd = _open_regular_no_symlink(path)
    except FileNotFoundError:
        return False
    try:
        return os.fstat(fd).st_size > 0
    finally:
        os.close(fd)


def require_evidence_object(raw: Any, *, owner: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SystemExit(f"{owner} evidence row must be a JSON object")
    return raw


def evidence_non_empty_string(raw: Any, *, field: str, owner: str, required: bool = True) -> str | None:
    if raw is None:
        if required:
            raise SystemExit(f"{owner} {field} must be a non-empty string")
        return None
    if not isinstance(raw, str):
        raise SystemExit(f"{owner} {field} must be a string")
    text = sanitize_note_text(raw)
    if not text:
        if required:
            raise SystemExit(f"{owner} {field} must be a non-empty string")
        return None
    return text


def evidence_bool(raw: Any, *, field: str, owner: str, default: bool = False) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise SystemExit(f"{owner} {field} must be a boolean")
    return raw


def evidence_nonnegative_int(
    raw: Any,
    *,
    field: str,
    owner: str,
    default: int = 0,
    maximum: int = MAX_USAGE_TOKEN_COUNT,
) -> int:
    if raw is None:
        return default
    value = normalize_usage_token(raw)
    if value is None or value > maximum:
        raise SystemExit(f"{owner} {field} must be a finite non-negative integer")
    return value


def evidence_nonnegative_float(
    raw: Any,
    *,
    field: str,
    owner: str,
    default: float = 0.0,
    maximum: float = MAX_USAGE_COST_USD,
) -> float:
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise SystemExit(f"{owner} {field} must be a finite non-negative number")
    value = float(raw)
    if not math.isfinite(value) or value < 0 or value > maximum:
        raise SystemExit(f"{owner} {field} must be a finite non-negative number")
    return value


def evidence_first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw:
            return raw[key]
    return None


def parse_evidence_provenance(raw: dict[str, Any], *, owner: str) -> dict[str, Any]:
    provenance = raw.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise SystemExit(f"{owner} provenance must be a JSON object")
    source_raw = (
        provenance.get("evidence_source_type")
        if isinstance(provenance, dict) and "evidence_source_type" in provenance
        else raw.get("evidence_source_type")
    )
    source_type = evidence_non_empty_string(source_raw, field="evidence_source_type", owner=owner)
    assert source_type is not None
    if source_type not in EVIDENCE_REPLAY_SOURCE_TYPES:
        raise SystemExit(
            f"{owner} evidence_source_type must be one of: {', '.join(sorted(EVIDENCE_REPLAY_SOURCE_TYPES))}"
        )
    provider_name = evidence_non_empty_string(
        provenance.get("provider_name") if isinstance(provenance, dict) else raw.get("provider_name"),
        field="provider_name",
        owner=owner,
        required=False,
    )
    capture_id = evidence_non_empty_string(
        (
            provenance.get("capture_command_or_export_id")
            if isinstance(provenance, dict) and "capture_command_or_export_id" in provenance
            else raw.get("capture_command_or_export_id")
        ),
        field="capture_command_or_export_id",
        owner=owner,
        required=False,
    )
    claim_scope = evidence_non_empty_string(
        provenance.get("claim_scope") if isinstance(provenance, dict) else raw.get("claim_scope"),
        field="claim_scope",
        owner=owner,
    )
    assert claim_scope is not None
    provider_authority = (
        source_type == "provider_export"
        and provider_name is not None
        and capture_id is not None
        and claim_scope in PROVIDER_EXPORT_PUBLIC_CLAIM_SCOPES
    )
    return {
        "source_type": source_type,
        "provider_name": provider_name,
        "capture_command_or_export_id": capture_id,
        "claim_scope": claim_scope,
        "provider_public_claim_authority": provider_authority,
    }


def parse_evidence_tokens(raw: dict[str, Any], *, owner: str) -> tuple[dict[str, int], set[str]]:
    token_block = raw.get("tokens")
    if token_block is not None and not isinstance(token_block, dict):
        raise SystemExit(f"{owner} tokens must be a JSON object")
    tokens: dict[str, int] = {}
    observed: set[str] = set()
    source = token_block if isinstance(token_block, dict) else {}
    for bucket, _keys in USAGE_KEY_GROUPS:
        value = source.get(bucket) if bucket in source else raw.get(bucket)
        if value is not None:
            observed.add(bucket)
        tokens[bucket] = evidence_nonnegative_int(value, field=bucket, owner=owner)
    return tokens, observed


def parse_evidence_row(raw_value: Any, *, owner: str, line_number: int) -> EvidenceReplayRow:
    raw = require_evidence_object(raw_value, owner=owner)
    schema = evidence_non_empty_string(raw.get("schema_version"), field="schema_version", owner=owner)
    if schema != BENCH_RUN_EVIDENCE_SCHEMA_VERSION:
        raise SystemExit(
            f"{owner} schema_version must be {BENCH_RUN_EVIDENCE_SCHEMA_VERSION}"
        )
    task_id = evidence_non_empty_string(raw.get("task_id"), field="task_id", owner=owner)
    variant = evidence_non_empty_string(raw.get("variant"), field="variant", owner=owner)
    assert task_id is not None and variant is not None
    provenance = parse_evidence_provenance(raw, owner=owner)
    provider_authority = bool(provenance["provider_public_claim_authority"])
    raw_primary_tokens_measured = evidence_bool(
        raw.get("primary_tokens_measured"),
        field="primary_tokens_measured",
        owner=owner,
    )
    raw_cost_measured = evidence_bool(
        evidence_first(raw, "cost_measured", "primary_cost_measured"),
        field="cost_measured",
        owner=owner,
    )
    if provenance["source_type"] in {"synthetic_fixture", "manual_audit"}:
        primary_tokens_measured = False
        cost_measured = False
    elif provider_authority:
        primary_tokens_measured = raw_primary_tokens_measured
        cost_measured = raw_cost_measured
    else:
        if raw_primary_tokens_measured or raw_cost_measured:
            raise SystemExit(
                f"{owner} provider_export measured flags require provider_name, "
                "capture_command_or_export_id, and a provider-measured matched-task claim_scope"
            )
        primary_tokens_measured = False
        cost_measured = False

    tokens, observed_token_buckets = parse_evidence_tokens(raw, owner=owner)
    if primary_tokens_measured and not {"input_tokens", "output_tokens"}.issubset(observed_token_buckets):
        raise SystemExit(
            f"{owner} primary_tokens_measured=true requires input_tokens and output_tokens evidence"
        )
    cost_usd = evidence_nonnegative_float(
        evidence_first(raw, "cost_usd", "primary_cost_usd"),
        field="cost_usd",
        owner=owner,
    )
    if cost_measured and "cost_usd" not in raw and "primary_cost_usd" not in raw:
        raise SystemExit(f"{owner} cost_measured=true requires cost_usd evidence")

    if "success" not in raw:
        raise SystemExit(f"{owner} success must be a boolean")
    success = evidence_bool(raw.get("success"), field="success", owner=owner)
    notes = evidence_non_empty_string(raw.get("notes"), field="notes", owner=owner, required=False)
    explicit_notes = notes is not None
    model = evidence_non_empty_string(raw.get("model"), field="model", owner=owner, required=False) or "evidence-replay"
    effort = evidence_non_empty_string(raw.get("effort"), field="effort", owner=owner, required=False) or ""
    self_hosted_metrics = None
    if SELF_HOSTED_METRICS_KEY in raw:
        self_hosted_metrics = normalize_self_hosted_metrics(
            raw.get(SELF_HOSTED_METRICS_KEY),
            source="evidence_jsonl.self_hosted_metrics",
        )
        if self_hosted_metrics is None:
            raise SystemExit(f"{owner} self_hosted_metrics must be normalized explicit metrics")

    result = RunResult(
        task_id=task_id,
        variant=variant,
        model=model,
        effort=effort,
        tokens=tokens,
        cost_usd=cost_usd,
        success=success,
        notes=notes or f"evidence replay ({provenance['source_type']})",
        corrections=evidence_nonnegative_int(raw.get("corrections"), field="corrections", owner=owner),
        cost_measured=cost_measured,
        wall_time_seconds=evidence_nonnegative_float(
            raw.get("wall_time_seconds"),
            field="wall_time_seconds",
            owner=owner,
            maximum=MAX_SELF_HOSTED_LATENCY_MS / 1000,
        ),
        turns=evidence_nonnegative_int(raw.get("turns"), field="turns", owner=owner),
        hook_triggers=evidence_nonnegative_int(raw.get("hook_triggers"), field="hook_triggers", owner=owner),
        bytes_before=evidence_nonnegative_int(raw.get("bytes_before"), field="bytes_before", owner=owner),
        bytes_after=evidence_nonnegative_int(raw.get("bytes_after"), field="bytes_after", owner=owner),
        artifacts_used=evidence_nonnegative_int(raw.get("artifacts_used"), field="artifacts_used", owner=owner),
        external_tokens=evidence_nonnegative_int(raw.get("external_tokens"), field="external_tokens", owner=owner),
        external_tokens_measured=evidence_bool(
            raw.get("external_tokens_measured"),
            field="external_tokens_measured",
            owner=owner,
        ),
        external_cost_usd=evidence_nonnegative_float(
            raw.get("external_cost_usd"),
            field="external_cost_usd",
            owner=owner,
        ),
        external_cost_measured=evidence_bool(
            raw.get("external_cost_measured"),
            field="external_cost_measured",
            owner=owner,
        ),
        provider_cached_tokens=evidence_nonnegative_int(
            raw.get("provider_cached_tokens"),
            field="provider_cached_tokens",
            owner=owner,
        ),
        provider_cached_tokens_measured=evidence_bool(
            raw.get("provider_cached_tokens_measured"),
            field="provider_cached_tokens_measured",
            owner=owner,
        ),
        primary_tokens_measured=primary_tokens_measured,
        self_hosted_metrics=self_hosted_metrics,
    )
    return EvidenceReplayRow(
        result=result,
        source_type=str(provenance["source_type"]),
        provider_name=provenance["provider_name"],
        capture_command_or_export_id=provenance["capture_command_or_export_id"],
        claim_scope=str(provenance["claim_scope"]),
        provider_export_provenance_complete=provider_authority,
        public_claim_eligible=False,
        explicit_notes=explicit_notes,
        line_number=line_number,
    )


def read_evidence_jsonl(path: Path) -> list[EvidenceReplayRow]:
    fd = _open_regular_no_symlink(path)
    try:
        size = os.fstat(fd).st_size
        if size > MAX_EVIDENCE_JSONL_BYTES:
            raise SystemExit(
                f"evidence JSONL exceeds {MAX_EVIDENCE_JSONL_BYTES} bytes: {path}"
            )
        rows: list[EvidenceReplayRow] = []
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            for line_number, line in enumerate(handle, start=1):
                if line_number > MAX_EVIDENCE_JSONL_LINES:
                    raise SystemExit(
                        f"evidence JSONL line limit exceeded for {path}: > {MAX_EVIDENCE_JSONL_LINES}"
                    )
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise SystemExit(
                        f"{path}:{line_number} evidence row must be JSON: {exc.msg}"
                    ) from None
                rows.append(parse_evidence_row(payload, owner=f"{path}:{line_number}", line_number=line_number))
    finally:
        if fd != -1:
            os.close(fd)
    if not rows:
        raise SystemExit(f"evidence JSONL contains no rows: {path}")
    return rows


def validate_evidence_coverage(
    evidence_rows: list[EvidenceReplayRow],
    runnable_targets: list[tuple[TaskFixture, Variant]],
) -> dict[tuple[str, str], EvidenceReplayRow]:
    by_key: dict[tuple[str, str], EvidenceReplayRow] = {}
    for row in evidence_rows:
        if row.key in by_key:
            raise SystemExit(
                f"duplicate evidence row for {row.key[0]}/{row.key[1]} "
                f"(lines {by_key[row.key].line_number} and {row.line_number})"
            )
        by_key[row.key] = row
    missing = [
        f"{task.id}/{variant.name}"
        for task, variant in runnable_targets
        if (task.id, variant.name) not in by_key
    ]
    if missing:
        raise SystemExit(f"missing evidence row(s) for selected targets: {', '.join(missing)}")
    return {
        (task.id, variant.name): by_key[(task.id, variant.name)]
        for task, variant in runnable_targets
    }


def run_evidence_fixture(task: TaskFixture, variant: Variant, evidence: EvidenceReplayRow) -> RunResult:
    result = evidence.result
    if result.task_id != task.id or result.variant != variant.name:
        raise SystemExit(
            f"evidence target mismatch: expected {task.id}/{variant.name}, "
            f"got {result.task_id}/{result.variant}"
        )
    if result.model == "evidence-replay":
        result.model = task.model
    if not result.effort:
        result.effort = task.effort or ""
    return result


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


def measurement_baseline_contract() -> dict[str, Any]:
    """Describe the benchmark report's current measurement baseline contract.

    This block is descriptive. It does not change the CSV schema and does not
    grant token/cost savings claims by itself; those remain gated by matched
    successful tasks, measured primary tokens/costs, shifted-cost accounting,
    and quality gates.
    """
    return {
        "schema_version": MEASUREMENT_BASELINE_SCHEMA_VERSION,
        "csv_schema_unchanged": True,
        "csv_columns": list(CSV_COLUMNS),
        "captured_fields": {
            "task_identity": ["task_id", "variant"],
            "run_configuration": ["model", "effort", "claude_version"],
            "primary_token_buckets": [
                "input_tokens",
                "output_tokens",
                "cache_read",
                "cache_creation",
                "total_tokens",
                "primary_tokens_measured",
            ],
            "primary_cost": ["cost_usd", "cost_measured"],
            "provider_cache_telemetry": ["provider_cached_tokens", "provider_cached_tokens_measured"],
            "latency": ["wall_time_seconds"],
            "quality_and_result": ["success", "corrections", "notes"],
            "tooling_and_proxy_metrics": ["turns", "hook_triggers", "bytes_before", "bytes_after", "artifacts_used"],
            "shifted_cost_accounting": [
                "external_tokens",
                "external_tokens_measured",
                "external_cost_usd",
                "external_cost_measured",
                "total_cost_with_shift_usd",
            ],
        },
        "claim_eligible_fields": {
            "token_savings": [
                "matched successful baseline and variant tasks",
                "primary_tokens_measured=true on both sides",
                "quality_gate=pass",
            ],
            "shifted_cost_savings": [
                "matched successful baseline and variant tasks",
                "cost_measured=true on both sides",
                "external_cost_measured=true when external_tokens are present",
                "quality_gate=pass",
            ],
        },
        "proxy_only_fields": {
            "byte_metrics": ["bytes_before", "bytes_after"],
            "token_proxy": "chars_div_4_proxy_only",
            "provider_cache": "diagnostic_telemetry_not_contextguard_token_reduction",
        },
        "missing_future_run_identity_fields": [
            "repo_revision",
            "agent_harness",
            "feature_flags",
            "provider_name",
            "success_command_identity",
        ],
        "claim_boundary": {
            "descriptive_contract_only": True,
            "enables_savings_claims_by_itself": False,
            "requires_matched_successful_tasks": True,
            "requires_shifted_cost_accounting_for_cost_claims": True,
            "raw_proxy_estimates_are_not_hosted_api_token_savings": True,
        },
    }


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
    report = {
        "schema": "context-guard-bench-report-v1",
        "baseline_variant": baseline_variant,
        "row_count": len(rows),
        "measurement_baseline": measurement_baseline_contract(),
        "summary_by_variant": by_variant,
        "comparisons": comparisons,
        "matched_pair_evidence": matched_pair_evidence,
        "claim_status": claim_status,
        "caveat": (
            "Proxy byte reductions are reported separately from matched-task token/cost metrics; "
            "shifted cost savings require measured primary cost and measured external cost when "
            "external tokens are present. Wall time and provider cached-token fields are diagnostic "
            "telemetry, not proof of ContextGuard-caused token or cost savings; provider-cache "
            "discounts must stay separate from token-reduction claims. Public hosted savings "
            "claims must use public_claim_readiness.claim_allowed; unsupported claims are forbidden."
        ),
    }
    report["public_claim_readiness"] = build_public_claim_readiness(report)
    report["default_matrix"] = build_default_matrix(report)
    return report

def annotate_replay_report(
    report: dict[str, Any],
    replay_rows: list[EvidenceReplayRow],
    *,
    mixed_csv: bool,
) -> dict[str, Any]:
    source_types = sorted({row.source_type for row in replay_rows})
    provider_names = sorted({row.provider_name for row in replay_rows if row.provider_name})
    claim_scopes = sorted({row.claim_scope for row in replay_rows})
    same_run_complete = (not mixed_csv) and len(replay_rows) == int(report.get("row_count") or 0)
    all_provider_claim_authority = bool(replay_rows) and all(
        row.provider_export_provenance_complete for row in replay_rows
    )
    raw_claim_status = str(report.get("claim_status") or "")
    matched_pair_evidence = report.get("matched_pair_evidence")
    matched_claim_gates_allow_public_claim = (
        isinstance(matched_pair_evidence, list)
        and bool(matched_pair_evidence)
        and all(
            isinstance(item, dict)
            and isinstance(item.get("claim_boundary"), dict)
            and bool(item["claim_boundary"].get("token_savings_claim_allowed"))
            and bool(item["claim_boundary"].get("shifted_cost_claim_allowed"))
            for item in matched_pair_evidence
        )
    )
    report_claim_gates_allow_public_claim = (
        raw_claim_status in REPLAY_PUBLIC_CLAIM_ELIGIBLE_RAW_STATUSES
        and matched_claim_gates_allow_public_claim
    )
    if not same_run_complete:
        public_claim_status = REPLAY_UNKNOWN_MIXED_CSV_STATUS
        public_claim_eligible = False
    elif all_provider_claim_authority and report_claim_gates_allow_public_claim:
        public_claim_status = REPLAY_PUBLIC_CLAIM_CANDIDATE_STATUS
        public_claim_eligible = True
    elif all_provider_claim_authority:
        public_claim_status = REPLAY_PROVIDER_CLAIM_GATES_NOT_MET_STATUS
        public_claim_eligible = False
    else:
        public_claim_status = REPLAY_NOT_PUBLIC_CLAIM_STATUS
        public_claim_eligible = False
    report["raw_metric_claim_status"] = raw_claim_status
    report["public_claim_status"] = public_claim_status
    report["public_claim_eligible"] = public_claim_eligible
    if not public_claim_eligible:
        report["claim_status"] = public_claim_status
    report["replay_evidence"] = {
        "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
        "mode": "evidence_jsonl_replay",
        "row_count": len(replay_rows),
        "source_types": source_types,
        "provider_names": provider_names,
        "claim_scopes": claim_scopes,
        "same_run_complete": same_run_complete,
        "mixed_csv": mixed_csv,
        "provider_export_provenance_complete": all_provider_claim_authority,
        "report_claim_gates_allow_public_claim": report_claim_gates_allow_public_claim,
        "public_claim_status": public_claim_status,
        "public_claim_eligible": public_claim_eligible,
        "target_keys": [f"{row.result.task_id}/{row.result.variant}" for row in replay_rows],
        "claim_boundary": REPLAY_CLAIM_BOUNDARY,
    }
    report["public_claim_readiness"] = build_public_claim_readiness(
        report,
        replay_rows=replay_rows,
        mixed_csv=mixed_csv,
    )
    report["default_matrix"] = build_default_matrix(report)
    return report


def report_public_claim_status(report: dict[str, Any]) -> tuple[str, bool | None]:
    if "public_claim_status" in report:
        return str(report.get("public_claim_status")), bool(report.get("public_claim_eligible"))
    return (
        "csv_provenance_unknown_requires_original_evidence_or_trusted_ledger",
        None,
    )



def public_claim_readiness_gate(
    gate_id: str,
    label: str,
    passed: bool,
    reason: str,
    evidence: dict[str, Any] | None = None,
    *,
    unknown: bool = False,
) -> dict[str, Any]:
    status = "unknown" if unknown else ("pass" if passed else "fail")
    return {
        "id": gate_id,
        "label": label,
        "required": True,
        "status": status,
        "passed": passed and not unknown,
        "reason": reason,
        "evidence": evidence or {},
    }


def public_claim_pair_side_measured(pair: dict[str, Any], side: str, metric: str) -> bool:
    measurements = pair.get("measurements") if isinstance(pair.get("measurements"), dict) else {}
    side_block = measurements.get(side) if isinstance(measurements.get(side), dict) else {}
    metric_block = side_block.get(metric) if isinstance(side_block.get(metric), dict) else {}
    return bool(metric_block.get("measured"))


def public_claim_numeric_values(items: list[Any]) -> list[float]:
    values: list[float] = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            continue
        numeric = float(item)
        if math.isfinite(numeric):
            values.append(numeric)
    return values


def public_claim_readiness_evidence_text(evidence: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in evidence.items():
        if isinstance(value, list):
            display = ",".join(str(item) for item in value[:5])
            if len(value) > 5:
                display += ",…"
        elif isinstance(value, dict):
            display = ",".join(f"{k}={v}" for k, v in list(value.items())[:5])
            if len(value) > 5:
                display += ",…"
        else:
            display = str(value)
        parts.append(f"{key}={display}")
    return "; ".join(parts)


def build_public_claim_readiness(
    report: dict[str, Any],
    *,
    replay_rows: list[EvidenceReplayRow] | None = None,
    mixed_csv: bool = False,
) -> dict[str, Any]:
    comparisons = report.get("comparisons") if isinstance(report.get("comparisons"), list) else []
    comparisons = [item for item in comparisons if isinstance(item, dict)]
    pairs = report.get("matched_pair_evidence") if isinstance(report.get("matched_pair_evidence"), list) else []
    pairs = [item for item in pairs if isinstance(item, dict)]
    row_count = int(report.get("row_count") or 0)
    replay_evidence = report.get("replay_evidence") if isinstance(report.get("replay_evidence"), dict) else {}
    replay_count = len(replay_rows or [])
    public_claim_status, public_claim_eligible = report_public_claim_status(report)
    raw_metric_claim_status = report.get("raw_metric_claim_status", report.get("claim_status"))

    comparison_variants = [str(item.get("variant")) for item in comparisons if item.get("variant")]
    matched_counts = public_claim_numeric_values([
        item.get("matched_successful_task_count") for item in comparisons
    ])
    missing_baseline_successes = [
        task
        for item in comparisons
        for task in (item.get("missing_baseline_success_tasks") or [])
    ]
    baseline_success_counts = public_claim_numeric_values([
        item.get("baseline_successful_task_count") for item in comparisons
    ])
    matched_tasks_pass = (
        bool(comparisons)
        and bool(pairs)
        and len(matched_counts) == len(comparisons)
        and all(value > 0 for value in matched_counts)
        and len(baseline_success_counts) == len(comparisons)
        and all(value > 0 for value in baseline_success_counts)
        and not missing_baseline_successes
    )
    gates = [
        public_claim_readiness_gate(
            "matched_successful_tasks",
            "Matched successful tasks",
            matched_tasks_pass,
            "matched_successful_tasks_present" if matched_tasks_pass else "missing_or_regressed_matched_successful_tasks",
            {
                "comparison_count": len(comparisons),
                "matched_pair_count": len(pairs),
                "variants": comparison_variants[:MAX_DEFAULT_MATRIX_EVIDENCE_ITEMS],
                "min_matched_successful_task_count": min(matched_counts) if matched_counts else None,
                "missing_baseline_success_task_count": len(missing_baseline_successes),
            },
        )
    ]

    provider_measured_token_cost_pass = bool(pairs) and all(
        public_claim_pair_side_measured(pair, "baseline", "primary_tokens")
        and public_claim_pair_side_measured(pair, "variant", "primary_tokens")
        and public_claim_pair_side_measured(pair, "baseline", "primary_cost_usd")
        and public_claim_pair_side_measured(pair, "variant", "primary_cost_usd")
        for pair in pairs
    )
    gates.append(public_claim_readiness_gate(
        "provider_measured_token_cost",
        "Provider-measured token and primary cost",
        provider_measured_token_cost_pass,
        "provider_measured_primary_tokens_and_cost" if provider_measured_token_cost_pass else "missing_provider_measured_primary_tokens_or_cost",
        {
            "matched_pair_count": len(pairs),
            "required_fields": [
                "matched_pair_evidence[*].measurements.baseline.primary_tokens.measured",
                "matched_pair_evidence[*].measurements.variant.primary_tokens.measured",
                "matched_pair_evidence[*].measurements.baseline.primary_cost_usd.measured",
                "matched_pair_evidence[*].measurements.variant.primary_cost_usd.measured",
            ],
        },
    ))

    quality_gates = sorted({str(item.get("quality_gate") or "unknown") for item in comparisons})
    failure_deltas = public_claim_numeric_values([
        item.get("failure_rate_delta_pp") for item in comparisons
    ])
    correction_deltas = public_claim_numeric_values([
        item.get("corrections_delta_per_successful_task") for item in comparisons
    ])
    quality_pass = bool(comparisons) and all(item.get("quality_gate") == "pass" for item in comparisons)
    gates.append(public_claim_readiness_gate(
        "quality_non_inferiority",
        "Quality non-inferiority",
        quality_pass,
        "all_quality_gates_pass" if quality_pass else "quality_gate_not_pass",
        {
            "quality_gates": quality_gates,
            "max_failure_rate_delta_pp": max(failure_deltas) if failure_deltas else None,
            "max_corrections_delta_per_successful_task": max(correction_deltas) if correction_deltas else None,
        },
    ))

    shifted_cost_pass = bool(pairs) and all(
        isinstance(pair.get("claim_boundary"), dict)
        and bool((pair.get("claim_boundary") or {}).get("shifted_cost_claim_allowed"))
        and public_claim_pair_side_measured(pair, "baseline", "total_cost_with_shift_usd")
        and public_claim_pair_side_measured(pair, "variant", "total_cost_with_shift_usd")
        for pair in pairs
    )
    gates.append(public_claim_readiness_gate(
        "shifted_cost_accounting",
        "Shifted-cost accounting",
        shifted_cost_pass,
        "shifted_cost_claim_gates_pass" if shifted_cost_pass else "missing_shifted_cost_claim_accounting",
        {
            "matched_pair_count": len(pairs),
            "required_fields": [
                "matched_pair_evidence[*].claim_boundary.shifted_cost_claim_allowed",
                "matched_pair_evidence[*].measurements.baseline.total_cost_with_shift_usd.measured",
                "matched_pair_evidence[*].measurements.variant.total_cost_with_shift_usd.measured",
            ],
        },
    ))

    has_replay = replay_rows is not None and bool(replay_rows)
    explicit_note_count = sum(1 for row in (replay_rows or []) if row.explicit_notes)
    failed_rows = [row for row in (replay_rows or []) if not row.result.success]
    failed_rows_with_notes = sum(1 for row in failed_rows if row.explicit_notes)
    comparison_failure_fields_present = bool(comparisons) and all(
        "baseline_failure_rate" in item
        and "variant_failure_rate" in item
        and "failure_rate_delta_pp" in item
        and "paired_corrections_task_count" in item
        for item in comparisons
    )
    confidence_notes_pass = (
        has_replay
        and explicit_note_count == replay_count
        and failed_rows_with_notes == len(failed_rows)
        and comparison_failure_fields_present
    )
    gates.append(public_claim_readiness_gate(
        "confidence_failure_notes",
        "Confidence and failure notes",
        confidence_notes_pass,
        "explicit_replay_notes_and_failure_rate_evidence_present" if confidence_notes_pass else "missing_explicit_replay_notes_or_failure_evidence",
        {
            "replay_row_count": replay_count,
            "explicit_note_count": explicit_note_count,
            "failed_row_count": len(failed_rows),
            "failed_rows_with_notes": failed_rows_with_notes,
            "comparison_failure_fields_present": comparison_failure_fields_present,
        },
        unknown=not has_replay,
    ))

    same_run_complete = bool(replay_evidence.get("same_run_complete")) if replay_evidence else (
        has_replay and not mixed_csv and replay_count == row_count
    )
    source_types = sorted({row.source_type for row in (replay_rows or [])})
    provider_names = sorted({row.provider_name for row in (replay_rows or []) if row.provider_name})
    provider_export_pass = (
        has_replay
        and not mixed_csv
        and same_run_complete
        and replay_count == row_count
        and all(row.provider_export_provenance_complete for row in (replay_rows or []))
    )
    gates.append(public_claim_readiness_gate(
        "provider_export_provenance",
        "Provider-export provenance",
        provider_export_pass,
        "complete_provider_export_same_run_provenance" if provider_export_pass else "missing_or_mixed_provider_export_provenance",
        {
            "replay_row_count": replay_count,
            "report_row_count": row_count,
            "mixed_csv": mixed_csv,
            "same_run_complete": same_run_complete,
            "source_types": source_types,
            "provider_names": provider_names[:MAX_DEFAULT_MATRIX_EVIDENCE_ITEMS],
        },
        unknown=not has_replay,
    ))

    passed_required_gate_count = sum(1 for gate in gates if gate["passed"])
    blocking_gate_ids = [str(gate["id"]) for gate in gates if not gate["passed"]]
    required_gates_pass = passed_required_gate_count == len(gates)
    claim_allowed = (
        required_gates_pass
        and public_claim_status == REPLAY_PUBLIC_CLAIM_CANDIDATE_STATUS
        and bool(public_claim_eligible)
    )
    if claim_allowed:
        readiness_status = REPLAY_PUBLIC_CLAIM_CANDIDATE_STATUS
        reason = "all_required_public_claim_gates_pass"
    elif not has_replay:
        readiness_status = "csv_provenance_unknown_requires_original_evidence_or_trusted_ledger"
        reason = "replay_evidence_required_for_public_claim"
    elif provider_export_pass:
        readiness_status = REPLAY_PROVIDER_CLAIM_GATES_NOT_MET_STATUS
        reason = "provider_export_present_but_readiness_gates_failed"
    else:
        readiness_status = "public_claim_blocked"
        reason = "unsupported_public_savings_claim_forbidden"

    return {
        "schema_version": PUBLIC_CLAIM_READINESS_SCHEMA_VERSION,
        "generated_from": "matched_pair_evidence_and_replay_provenance",
        "status": readiness_status,
        "reason": reason,
        "claim_allowed": claim_allowed,
        "public_claim_status_observed": public_claim_status,
        "public_claim_eligible_observed": public_claim_eligible,
        "raw_metric_claim_status_observed": raw_metric_claim_status,
        "required_gate_ids": list(PUBLIC_CLAIM_READINESS_GATE_IDS),
        "required_gate_count": len(gates),
        "passed_required_gate_count": passed_required_gate_count,
        "blocking_gate_ids": blocking_gate_ids,
        "gates": gates,
        "claim_boundary": PUBLIC_CLAIM_READINESS_CLAIM_BOUNDARY,
    }


def default_matrix_normalized_key(value: Any) -> str:
    text = str(value or "").lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def default_matrix_contains_key(haystack: str, needle: str) -> bool:
    needle = default_matrix_normalized_key(needle)
    if not needle:
        return False
    return needle in haystack


def infer_default_matrix_lanes(pair: dict[str, Any]) -> list[tuple[str, str]]:
    task_id = default_matrix_normalized_key(pair.get("task_id"))
    variant = default_matrix_normalized_key(pair.get("variant"))
    matches: list[tuple[str, str]] = []
    for lane in DEFAULT_MATRIX_LANES:
        lane_id = str(lane["id"])
        task_keywords = tuple(str(item) for item in lane.get("task_keywords", ()))
        variant_keywords = tuple(str(item) for item in lane.get("variant_keywords", ()))
        if any(default_matrix_contains_key(task_id, item) for item in task_keywords):
            matches.append((lane_id, "exact_key"))
        elif any(default_matrix_contains_key(variant, item) for item in variant_keywords):
            matches.append((lane_id, "name_heuristic"))
    return matches


def default_matrix_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if not math.isfinite(numeric):
        return None
    return numeric


def default_matrix_unique(values: list[Any]) -> list[Any]:
    out: list[Any] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def default_matrix_cap(values: list[Any]) -> list[Any]:
    return default_matrix_unique(values)[:MAX_DEFAULT_MATRIX_EVIDENCE_ITEMS]


def default_matrix_lane_match_method(methods: set[str]) -> str:
    if "exact_key" in methods:
        return "exact_key"
    if "name_heuristic" in methods:
        return "name_heuristic"
    return "absent"


def default_matrix_clamp_classification(classification: str, ceiling: str) -> tuple[str, bool]:
    if classification == "reject/rework":
        return classification, False
    if ceiling not in DEFAULT_MATRIX_CLASSIFICATION_STRENGTH:
        return classification, False
    current_strength = DEFAULT_MATRIX_CLASSIFICATION_STRENGTH.get(classification, 0)
    ceiling_strength = DEFAULT_MATRIX_CLASSIFICATION_STRENGTH[ceiling]
    if current_strength > ceiling_strength:
        return ceiling, True
    return classification, False


def default_matrix_token_evidence(token_values: list[float], pair_count: int, byte_proxy_positive: bool) -> str:
    if pair_count and len(token_values) == pair_count and all(value > 0 for value in token_values):
        return "measured_positive"
    if token_values:
        if any(value < 0 for value in token_values):
            return "measured_regression"
        return "measured_incomplete_or_mixed"
    if byte_proxy_positive:
        return "byte_proxy_only"
    return "unavailable"


def classify_default_matrix_lane(
    lane_id: str,
    pairs: list[dict[str, Any]],
    methods: set[str],
) -> dict[str, Any]:
    lane = DEFAULT_MATRIX_LANE_BY_ID[lane_id]
    policy_ceiling = str(lane["policy_ceiling"])
    if not pairs:
        classification = "experimental"
        reason_codes = ["no_matched_lane_evidence"]
        return {
            "lane": lane_id,
            "label": lane["label"],
            "classification": classification,
            "policy_ceiling": policy_ceiling,
            "policy_clamped": False,
            "lane_match_method": "absent",
            "matched_task_count": 0,
            "matched_tasks": [],
            "matched_variants": [],
            "quality_gate": "insufficient_evidence",
            "quality_gates": [],
            "token_evidence": "unavailable",
            "shifted_cost_evidence": "unavailable",
            "byte_proxy_evidence": "unavailable",
            "matched_pair_claim_gates": {
                "token_savings_claim_allowed": False,
                "shifted_cost_claim_allowed": False,
            },
            "public_claim_allowed": False,
            "reason_codes": reason_codes,
            "claim_boundary": {
                "classification_is_reporting_only": True,
                "hosted_api_savings_claim_allowed": False,
                "requires_report_claim_status_and_matched_pair_evidence": True,
            },
        }

    quality_gates = sorted({str(pair.get("quality_gate") or "unknown") for pair in pairs})
    quality_gate = quality_gates[0] if len(quality_gates) == 1 else "mixed"
    token_values = [
        value for value in (
            default_matrix_number((pair.get("delta") or {}).get("token_savings_pct"))
            for pair in pairs
            if isinstance(pair.get("delta"), dict)
        )
        if value is not None
    ]
    cost_values = [
        value for value in (
            default_matrix_number((pair.get("delta") or {}).get("cost_savings_pct_with_shift"))
            for pair in pairs
            if isinstance(pair.get("delta"), dict)
        )
        if value is not None
    ]
    byte_after_deltas = [
        value for value in (
            default_matrix_number((pair.get("delta") or {}).get("bytes_after_total"))
            for pair in pairs
            if isinstance(pair.get("delta"), dict)
        )
        if value is not None
    ]
    byte_proxy_positive = bool(byte_after_deltas) and any(value < 0 for value in byte_after_deltas)
    token_claim_gate = bool(pairs) and all(
        isinstance(pair.get("claim_boundary"), dict)
        and bool((pair.get("claim_boundary") or {}).get("token_savings_claim_allowed"))
        for pair in pairs
    )
    shifted_cost_claim_gate = bool(pairs) and all(
        isinstance(pair.get("claim_boundary"), dict)
        and bool((pair.get("claim_boundary") or {}).get("shifted_cost_claim_allowed"))
        for pair in pairs
    )
    reason_codes: list[str] = []
    if any(gate != "pass" for gate in quality_gates):
        classification = "reject/rework"
        reason_codes.extend(f"quality_gate_{gate}" for gate in quality_gates if gate != "pass")
    elif any(value < 0 for value in token_values):
        classification = "reject/rework"
        reason_codes.append("measured_token_regression")
    elif any(value < 0 for value in cost_values):
        classification = "reject/rework"
        reason_codes.append("measured_shifted_cost_regression")
    elif (
        len(token_values) == len(pairs)
        and all(value > 0 for value in token_values)
        and len(cost_values) == len(pairs)
        and all(value >= 0 for value in cost_values)
        and token_claim_gate
        and shifted_cost_claim_gate
    ):
        classification = "default-on"
        reason_codes.append("quality_pass_measured_token_and_shifted_cost_non_regression")
    elif len(token_values) == len(pairs) and all(value > 0 for value in token_values) and token_claim_gate:
        classification = "advisory"
        reason_codes.append("quality_pass_measured_token_savings_shifted_cost_unproven")
    elif byte_proxy_positive:
        classification = "advisory"
        reason_codes.append("quality_pass_byte_proxy_only")
    else:
        classification = "experimental"
        reason_codes.append("quality_pass_but_no_positive_measured_or_proxy_savings")

    if lane_id == "optional_compression" and classification == "advisory" and not token_values:
        classification = "experimental"
        reason_codes.append("optional_compression_requires_provider_token_evidence_for_advisory")

    classification, policy_clamped = default_matrix_clamp_classification(classification, policy_ceiling)
    if policy_clamped:
        reason_codes.append(f"policy_ceiling_{policy_ceiling}")

    return {
        "lane": lane_id,
        "label": lane["label"],
        "classification": classification,
        "policy_ceiling": policy_ceiling,
        "policy_clamped": policy_clamped,
        "lane_match_method": default_matrix_lane_match_method(methods),
        "matched_task_count": len({str(pair.get("task_id")) for pair in pairs}),
        "matched_tasks": default_matrix_cap([pair.get("task_id") for pair in pairs if pair.get("task_id")]),
        "matched_variants": default_matrix_cap([pair.get("variant") for pair in pairs if pair.get("variant")]),
        "quality_gate": quality_gate,
        "quality_gates": quality_gates,
        "token_evidence": default_matrix_token_evidence(token_values, len(pairs), byte_proxy_positive),
        "shifted_cost_evidence": (
            "measured_non_regression"
            if cost_values and len(cost_values) == len(pairs) and all(value >= 0 for value in cost_values)
            else ("measured_regression" if any(value < 0 for value in cost_values) else "unavailable")
        ),
        "byte_proxy_evidence": (
            "observed_positive" if byte_proxy_positive
            else ("observed_non_positive" if byte_after_deltas else "unavailable")
        ),
        "matched_pair_claim_gates": {
            "token_savings_claim_allowed": token_claim_gate,
            "shifted_cost_claim_allowed": shifted_cost_claim_gate,
        },
        "public_claim_allowed": False,
        "reason_codes": default_matrix_unique(reason_codes),
        "claim_boundary": {
            "classification_is_reporting_only": True,
            "hosted_api_savings_claim_allowed": False,
            "requires_report_claim_status_and_matched_pair_evidence": True,
        },
    }


def build_default_matrix(report: dict[str, Any]) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {lane_id: [] for lane_id in DEFAULT_MATRIX_LANE_IDS}
    methods: dict[str, set[str]] = {lane_id: set() for lane_id in DEFAULT_MATRIX_LANE_IDS}
    unmatched_variants: set[str] = set()
    pairs = report.get("matched_pair_evidence") if isinstance(report.get("matched_pair_evidence"), list) else []
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        lane_matches = infer_default_matrix_lanes(pair)
        if not lane_matches:
            if pair.get("variant"):
                unmatched_variants.add(str(pair.get("variant")))
            continue
        for lane_id, method in lane_matches:
            buckets[lane_id].append(pair)
            methods[lane_id].add(method)
    lanes = [
        classify_default_matrix_lane(lane_id, buckets[lane_id], methods[lane_id])
        for lane_id in DEFAULT_MATRIX_LANE_IDS
    ]
    classification_counts = {
        classification: sum(1 for lane in lanes if lane.get("classification") == classification)
        for classification in DEFAULT_MATRIX_CLASSIFICATIONS
    }
    return {
        "schema_version": DEFAULT_MATRIX_SCHEMA_VERSION,
        "classification_set": list(DEFAULT_MATRIX_CLASSIFICATIONS),
        "generated_from": "matched_pair_evidence",
        "reporting_only": True,
        "claim_status_observed": report.get("claim_status"),
        "public_claim_allowed": False,
        "claim_boundary": DEFAULT_MATRIX_CLAIM_BOUNDARY,
        "lanes": lanes,
        "summary": {
            "lane_count": len(lanes),
            "classification_counts": classification_counts,
            "unmatched_variants": sorted(unmatched_variants)[:MAX_DEFAULT_MATRIX_EVIDENCE_ITEMS],
        },
    }


def markdown_value(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    text = sanitize_note_text(value)
    return text.replace("|", "\\|") or "n/a"


def render_dashboard_markdown(report: dict[str, Any]) -> str:
    public_claim_status, public_claim_eligible = report_public_claim_status(report)
    metric_claim_status = report.get("raw_metric_claim_status", report.get("claim_status"))
    lines = [
        "# ContextGuard Benchmark Dashboard",
        "",
        f"- Schema: `{markdown_value(report.get('schema'))}`",
        f"- Baseline variant: `{markdown_value(report.get('baseline_variant'))}`",
        f"- Rows: {markdown_value(report.get('row_count'))}",
        f"- Metric claim status: `{markdown_value(metric_claim_status)}`",
        f"- Public claim status: `{markdown_value(public_claim_status)}`",
        f"- Public claim eligible: `{markdown_value(public_claim_eligible)}`",
        "",
        "> Claim boundary: this dashboard is not a hosted savings claim unless report claim gates "
        "allow it and public-claim provenance is complete. Proxy byte reductions are diagnostic "
        "and are not hosted API token savings.",
        "",
        "## Variant summary",
        "",
        "| Variant | Runs | Successes | Failure rate | Tokens/success | Bytes saved | Token proxy saved | Quality notes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    summaries = report.get("summary_by_variant") if isinstance(report.get("summary_by_variant"), dict) else {}
    comparison_by_variant = {
        item.get("variant"): item
        for item in report.get("comparisons", [])
        if isinstance(item, dict)
    }
    for variant, summary in sorted(summaries.items()):
        if not isinstance(summary, dict):
            continue
        comparison = comparison_by_variant.get(variant, {})
        quality = comparison.get("quality_gate") if isinstance(comparison, dict) else None
        if quality is None and summary.get("is_baseline_strategy"):
            quality = "baseline"
        lines.append(
            "| "
            + " | ".join([
                markdown_value(variant),
                markdown_value(summary.get("runs")),
                markdown_value(summary.get("successful_runs")),
                markdown_value(summary.get("failure_rate")),
                markdown_value(summary.get("tokens_per_successful_task")),
                markdown_value(summary.get("bytes_saved_successful")),
                markdown_value(summary.get("token_proxy_saved_successful")),
                markdown_value(quality),
            ])
            + " |"
        )
    lines.extend([
        "",
        "## Comparisons",
        "",
        "| Variant | Quality gate | Matched tasks | Token paired tasks | Token savings % | Shifted cost savings % |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ])
    comparisons = report.get("comparisons") if isinstance(report.get("comparisons"), list) else []
    if comparisons:
        for item in comparisons:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                + " | ".join([
                    markdown_value(item.get("variant")),
                    markdown_value(item.get("quality_gate")),
                    markdown_value(item.get("matched_successful_task_count")),
                    markdown_value(item.get("paired_token_task_count")),
                    markdown_value(item.get("token_savings_pct")),
                    markdown_value(item.get("cost_savings_pct_with_shift")),
                ])
                + " |"
            )
    else:
        lines.append("| n/a | n/a | 0 | 0 | n/a | n/a |")
    readiness = report.get("public_claim_readiness") if isinstance(report.get("public_claim_readiness"), dict) else None
    if readiness is not None:
        lines.extend([
            "",
            "## Public claim readiness",
            "",
            f"- Status: `{markdown_value(readiness.get('status'))}`",
            f"- Claim allowed: `{markdown_value(readiness.get('claim_allowed'))}`",
            "",
            "| Gate | Status | Reason | Evidence |",
            "| --- | --- | --- | --- |",
        ])
        gates = readiness.get("gates") if isinstance(readiness.get("gates"), list) else []
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            evidence = gate.get("evidence") if isinstance(gate.get("evidence"), dict) else {}
            lines.append(
                "| "
                + " | ".join([
                    markdown_value(gate.get("id")),
                    markdown_value(gate.get("status")),
                    markdown_value(gate.get("reason")),
                    markdown_value(public_claim_readiness_evidence_text(evidence)),
                ])
                + " |"
            )
        boundary = readiness.get("claim_boundary")
        if isinstance(boundary, dict):
            lines.extend([
                "",
                f"- Public claim boundary: {markdown_value(boundary.get('reason'))}",
            ])
    default_matrix = report.get("default_matrix") if isinstance(report.get("default_matrix"), dict) else None
    if default_matrix is not None:
        lines.extend([
            "",
            "## Default matrix",
            "",
            "| Lane | Classification | Matched Tasks | Quality Gate | Token Evidence | Public Claim | Reason |",
            "| --- | --- | ---: | --- | --- | --- | --- |",
        ])
        lanes = default_matrix.get("lanes") if isinstance(default_matrix.get("lanes"), list) else []
        for lane in lanes:
            if not isinstance(lane, dict):
                continue
            reasons = lane.get("reason_codes") if isinstance(lane.get("reason_codes"), list) else []
            lines.append(
                "| "
                + " | ".join([
                    markdown_value(lane.get("lane")),
                    markdown_value(lane.get("classification")),
                    markdown_value(lane.get("matched_task_count")),
                    markdown_value(lane.get("quality_gate")),
                    markdown_value(lane.get("token_evidence")),
                    markdown_value(lane.get("public_claim_allowed")),
                    markdown_value(", ".join(str(item) for item in reasons[:3])),
                ])
                + " |"
            )
        boundary = default_matrix.get("claim_boundary")
        if isinstance(boundary, dict):
            lines.extend([
                "",
                f"- Matrix boundary: {markdown_value(boundary.get('reason'))}",
            ])
    replay = report.get("replay_evidence") if isinstance(report.get("replay_evidence"), dict) else None
    if replay is not None:
        lines.extend([
            "",
            "## Replay evidence provenance",
            "",
            f"- Source types: `{markdown_value(', '.join(replay.get('source_types') or []))}`",
            f"- Claim scopes: `{markdown_value(', '.join(replay.get('claim_scopes') or []))}`",
            f"- Same-run complete: `{markdown_value(replay.get('same_run_complete'))}`",
            f"- Mixed/pre-existing CSV: `{markdown_value(replay.get('mixed_csv'))}`",
            f"- Boundary: {markdown_value(replay.get('claim_boundary'))}",
        ])
    else:
        lines.extend([
            "",
            "## Provenance note",
            "",
            "- CSV-only dashboards have unknown public-claim provenance unless regenerated from "
            "the original evidence JSONL or a future trusted provenance ledger.",
        ])
    lines.extend([
        "",
        "## Re-run context",
        "",
        "- Evidence replay: `context-guard-bench --tasks <tasks.json> --variants <variants.json> "
        "--evidence-jsonl <evidence.jsonl> --csv <results.csv> --report-json <report.json> "
        "--dashboard-md <dashboard.md>`",
    ])
    return "\n".join(lines) + "\n"


def write_report_outputs(
    csv_path: Path,
    report_path: Path | None,
    dashboard_path: Path | None,
    baseline_variant: str,
    *,
    replay_rows: list[EvidenceReplayRow] | None = None,
    mixed_csv: bool = False,
) -> dict[str, Any]:
    # Keep lock order stable across all derived writes: source CSV first, then
    # report, then dashboard. Do not introduce a derived-output -> CSV path.
    with csv_file_lock(csv_path, create_parent=True):
        report = summarize_benchmark_rows(read_csv_rows(csv_path), baseline_variant)
        if replay_rows is not None:
            report = annotate_replay_report(report, replay_rows, mixed_csv=mixed_csv)
        if report_path is not None:
            with csv_file_lock(report_path, create_parent=True):
                write_text_no_follow(
                    report_path,
                    json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                )
        if dashboard_path is not None:
            with csv_file_lock(dashboard_path, create_parent=True):
                write_text_no_follow(dashboard_path, render_dashboard_markdown(report))
    return report


def write_report_json(csv_path: Path, report_path: Path, baseline_variant: str) -> dict[str, Any]:
    # Keep lock order stable across all report writes: source CSV first, derived
    # report second. Do not introduce a report -> CSV path; that can deadlock
    # concurrent report generation.
    return write_report_outputs(csv_path, report_path, None, baseline_variant)


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


def validate_distinct_output_paths(
    csv_path: Path,
    ledger_path: Path | None,
    report_path: Path | None,
    dashboard_path: Path | None = None,
) -> None:
    outputs = [
        ("csv", csv_path),
        ("ledger-jsonl", ledger_path),
        ("report-json", report_path),
        ("dashboard-md", dashboard_path),
    ]
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
    parser.add_argument("--dashboard-md", default=None, type=Path,
                        help="optional Markdown dashboard path generated from the benchmark report")
    parser.add_argument("--evidence-jsonl", default=None, type=Path,
                        help="optional validated run-evidence JSONL replay input; skips provider invocation")
    parser.add_argument("--baseline-variant", default="baseline",
                        help="variant name used as the report baseline (default: baseline)")
    args = parser.parse_args()

    require_no_follow_file_ops_supported()
    validate_distinct_output_paths(args.csv, args.ledger_jsonl, args.report_json, args.dashboard_md)

    variants = parse_variants(args.variants)
    tasks = parse_tasks(args.tasks, variants=variants)
    targets = filter_targets(tasks, variants, args.task_id, args.variant)
    if not targets:
        print("no (task, variant) targets matched the filters", file=sys.stderr)
        return 1

    if args.resume:
        skip_keys, skip_keys_loaded_stamp = existing_keys_snapshot(args.csv)
        skip_keys_stamp = {"stamp": skip_keys_loaded_stamp}
    else:
        skip_keys = set()
        skip_keys_stamp = None
    runnable_targets = resume_runnable_targets(
        args.csv,
        targets,
        resume=args.resume,
        existing_key_cache=skip_keys,
        existing_key_cache_stamp=skip_keys_stamp,
    )
    if args.evidence_jsonl is not None:
        if args.dry_run:
            for task, variant in targets:
                if args.resume and resume_key_present(args.csv, (task.id, variant.name), skip_keys, skip_keys_stamp):
                    print(f"skip {task.id}/{variant.name} (already in {args.csv})")
                    continue
                print(f"evidence replay dry-run: {task.id}/{variant.name} <- {args.evidence_jsonl}")
            print("completed 0 run(s); results in (dry-run; no CSV writes)")
            return 0
        csv_had_preexisting_content = file_has_content_no_follow(args.csv)
        evidence_rows = read_evidence_jsonl(args.evidence_jsonl)
        runnable_targets = resume_runnable_targets(
            args.csv,
            targets,
            resume=args.resume,
            existing_key_cache=skip_keys,
            existing_key_cache_stamp=skip_keys_stamp,
        )
        evidence_by_key = validate_evidence_coverage(evidence_rows, runnable_targets)
        runnable_keys = {(task.id, variant.name) for task, variant in runnable_targets}
        claude_ver = "evidence-replay"
        completed = 0
        replay_rows_written: list[EvidenceReplayRow] = []
        for task, variant in targets:
            if args.resume and (task.id, variant.name) not in runnable_keys:
                print(f"skip {task.id}/{variant.name} (already in {args.csv})")
                continue
            evidence = evidence_by_key[(task.id, variant.name)]
            print(f"replay {task.id}/{variant.name} ...", flush=True)
            result = run_evidence_fixture(task, variant, evidence)
            wrote = append_csv(
                args.csv,
                claude_ver,
                result,
                skip_existing=args.resume,
                existing_key_cache=skip_keys if args.resume else None,
                existing_key_cache_stamp=skip_keys_stamp,
            )
            if wrote:
                replay_rows_written.append(evidence)
                if args.ledger_jsonl is not None:
                    append_cost_shift_ledger(
                        args.ledger_jsonl,
                        claude_ver,
                        result,
                        replay_provenance=evidence.provenance_payload(),
                    )
            completed += 1
            status = "ok" if result.success else "FAIL"
            suffix = "" if wrote else " (CSV not updated; row already present)"
            print(
                f"  {status} tokens={sum(result.tokens.values())} cost=${result.cost_usd:.4f} "
                f"wall_time={result.wall_time_seconds:.3f}s {sanitize_note_text(result.notes)}{suffix}"
            )
        if args.report_json is not None or args.dashboard_md is not None:
            report = write_report_outputs(
                args.csv,
                args.report_json,
                args.dashboard_md,
                args.baseline_variant,
                replay_rows=replay_rows_written,
                mixed_csv=csv_had_preexisting_content or bool(skip_keys) or len(replay_rows_written) != int(completed),
            )
            if args.report_json is not None:
                print(f"report {args.report_json}: {report['claim_status']}")
            if args.dashboard_md is not None:
                print(f"dashboard {args.dashboard_md}: {report_public_claim_status(report)[0]}")
        print(f"completed {completed} run(s); results in {args.csv}")
        return 0

    runnable_targets = resume_runnable_targets(
        args.csv,
        targets,
        resume=args.resume,
        existing_key_cache=skip_keys,
        existing_key_cache_stamp=skip_keys_stamp,
    )
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

    if runnable_targets:
        load_variant_prompt_files_for_targets(runnable_targets, task_file_dir=args.tasks.parent)

    project_root = args.project_root.resolve()
    claude_ver = "dry-run" if args.dry_run else (claude_version(args.claude_bin) if runnable_targets else "skipped")

    completed = 0
    for task, variant in targets:
        if args.resume and resume_key_present(args.csv, (task.id, variant.name), skip_keys, skip_keys_stamp):
            print(f"skip {task.id}/{variant.name} (already in {args.csv})")
            continue
        print(f"run {task.id}/{variant.name} ...", flush=True)
        result = run_fixture(task, variant, args.claude_bin, project_root, args.dry_run)
        # dry-run row 는 CSV 에 적재하지 않는다. 적재하면 (a) tokens=0/cost=0 이 평균을
        # 깎고, (b) --resume 이 그 (task, variant) 를 skip 해 실제 측정값이 영구 누락된다.
        wrote = True
        if not args.dry_run:
            wrote = append_csv(
                args.csv,
                claude_ver,
                result,
                skip_existing=args.resume,
                existing_key_cache=skip_keys if args.resume else None,
                existing_key_cache_stamp=skip_keys_stamp,
            )
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
    if (args.report_json is not None or args.dashboard_md is not None) and not args.dry_run:
        report = write_report_outputs(args.csv, args.report_json, args.dashboard_md, args.baseline_variant)
        if args.report_json is not None:
            print(f"report {args.report_json}: {report['claim_status']}")
        if args.dashboard_md is not None:
            print(f"dashboard {args.dashboard_md}: {report_public_claim_status(report)[0]}")
    print(f"completed {completed} run(s); results in {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
