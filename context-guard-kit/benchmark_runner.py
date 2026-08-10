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
    "output_format": "json",
    "allowed_tools": ["Read", "Edit", "Bash(npm test*)"],
    "variant_prompt_files": {"context_hygiene": "t01.context_hygiene.prompt.md"},
    "success_command": "npm test -- auth/session",
    "success_cwd": "."
  }
]
```

`output_format`은 선택 필드이며 기본값은 `json`이다. 허용값은 `json`과
`stream-json`뿐이다. `stream-json`은 runner가 `--verbose`를 함께 추가하고,
마지막 terminal result를 bounded NDJSON으로 검증한다. 이 형식의 cost 값도
provider 청구액을 authoritative하게 증명하지 않는다.

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
import base64
import collections
from contextlib import contextmanager, nullcontext
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
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

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
    "primary_cost_provenance",
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
    "--verbose",
    "--allowedTools",
    "--allowed-tools",
    "--max-budget-usd",
    "--effort",
})
MEASUREMENT_PROTECTED_VARIANT_FLAGS = frozenset({
    "--settings",
    "--setting-sources",
    "--include-hook-events",
    "--no-session-persistence",
    "--safe-mode",
    "--bare",
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
PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE = "client_estimate"
PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT = "provider_export"
PRIMARY_COST_PROVENANCE_UNAVAILABLE = "unavailable"
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
MEASUREMENT_BASELINE_SCHEMA_VERSION = "contextguard.bench.measurement-baseline.v2"
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
CLAUDE_STREAM_MAX_LINES = 10_000
CLAUDE_STREAM_MAX_LINE_BYTES = 1_000_000
CLAUDE_OUTPUT_FORMATS = frozenset({"json", "stream-json"})
MEASUREMENT_SUBSTRATE_SCHEMA_VERSION = "contextguard.bench.measurement-substrate.v2"
MEASUREMENT_RAW_RECEIPT_SCHEMA_VERSION = "contextguard.bench.raw-receipt.v2"
MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION = "contextguard.bench.artifact-index.v2"
MEASUREMENT_ID_NAMESPACE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MEASUREMENT_ENV_NAME_RE = re.compile(r"\A[A-Z][A-Z0-9_]{0,127}\Z")
MEASUREMENT_SECRET_ENV_NAME_RE = re.compile(
    r"(?:^|_)(?:API_?KEY|AUTH|AUTHORIZATION|BEARER|CREDENTIALS?|OAUTH|PASSWORD|PRIVATE_?KEY|SECRET|TOKEN)(?:_|$)",
    re.IGNORECASE,
)
MEASUREMENT_CREDENTIAL_ENV_NAMES = frozenset({
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_PAT",
    "NETRC",
    "KUBECONFIG",
    "NPM_CONFIG_USERCONFIG",
})
MEASUREMENT_RUNNER_ENV_NAMES = frozenset({
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "TMPDIR",
    "CLAUDE_CONFIG_DIR",
})
MEASUREMENT_VARIANT_KEYS = frozenset({
    "schema_version",
    "settings_file",
    "setting_sources",
    "environment",
    "workspace",
    "session",
    "hook_events",
    "cli_capabilities",
    "identity",
    "artifact_root",
})
MEASUREMENT_RAW_MAX_BYTES = CLAUDE_OUTPUT_MAX_BYTES
MEASUREMENT_RAW_MAX_LINES = CLAUDE_STREAM_MAX_LINES
MEASUREMENT_RAW_MAX_LINE_BYTES = 256_000
MEASUREMENT_HOOK_MAX_EVENTS = 1_000
MEASUREMENT_HOOK_TEXT_MAX_CHARS = 256
MEASUREMENT_HOOK_FIELD_MAX_BYTES = 4_096
MEASUREMENT_HOOK_OUTPUT_MAX_BYTES = 64_000
MEASUREMENT_DOCUMENTED_HOOK_EVENTS = (
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "UserPromptSubmit",
    "SessionStart",
    "SessionEnd",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "PreCompact",
)
SUCCESS_COMMAND_OUTPUT_MAX_BYTES = 64_000
VERSION_OUTPUT_MAX_BYTES = 16_000
MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES = 65_536
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
# experimental_registry.PROOF_VERIFICATION_CLAIM_BOUNDARY 와 반드시 같은 문자열이다.
# 가져온 attestation 은 이 local-only 경계를 그대로 선언할 때만 verified 로 인정한다.
PROOF_VERIFICATION_CLAIM_BOUNDARY = (
    "Local receipt/hash/range/command binding only; no semantic-safety, protected-zone, freshness, replacement, "
    "omission, or hosted-savings authority."
)
# local verifier 는 rehydration 을 절대 실행하지 않는다. 실행했다고 주장하는 레코드는
# 이 evaluation-only 경계를 벗어나므로 verified 로 받아들이지 않는다.
PROOF_VERIFICATION_REHYDRATION_EXECUTED = False
# verified attestation 에서 placeholder 로 취급해 거부할 receipt/command 값이다.
PROFILE_FALLBACK_PLACEHOLDER_VALUES = frozenset({"", "none", "null", "n/a", "-"})

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
# profile 은 evaluation-only replay 전용이다. --evidence-jsonl 없이 profiled task 가
# 선택되면 provider runtime 을 부르기 전에, 어떤 출력/lock 도 만들기 전에 거부한다.
PROFILE_REJECT_REPLAY_REQUIRED = "profile_replay_required"
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
    PROFILE_REJECT_REPLAY_REQUIRED,
)

# lane gate ID. 순서는 report/dashboard 출력 순서와 동일하게 고정한다.
IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING = "profile_and_prompt_binding"
IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW = "protected_zone_deny_review"
IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING = "exact_text_fallback_binding"
IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW = "missed_context_review"
IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY = "human_correction_consistency"
# generic quality gate 결과를 lane 이 직접 소비한다. profile 이 generic regression 을
# 무시하고 ready 로 올라가는 경로를 막는다.
IMAGE_CONTEXT_GATE_CORRECTIONS_REGRESSION = "corrections_regression"
IMAGE_CONTEXT_GATE_FAILURE_RATE_REGRESSION = "failure_rate_regression"
IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT = "generic_matched_success_and_measurement"
IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY = "evaluation_only_promotion_boundary"
IMAGE_CONTEXT_GATE_IDS = (
    IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING,
    IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW,
    IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING,
    IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW,
    IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY,
    IMAGE_CONTEXT_GATE_CORRECTIONS_REGRESSION,
    IMAGE_CONTEXT_GATE_FAILURE_RATE_REGRESSION,
    IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT,
    IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY,
)
# lane gate 를 막는 generic quality_gate 값. summarize_benchmark_rows 가 계산한다.
GENERIC_QUALITY_GATE_PASS = "pass"
GENERIC_QUALITY_GATE_CORRECTIONS_REGRESSION = "corrections_regression"
GENERIC_QUALITY_GATE_FAILURE_RATE_REGRESSION = "failure_rate_regression"
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

# profile 중첩 블록의 명시적 byte/count 한계. 타입/한계 검사는 항상 semantic 분류보다
# 먼저 실행되어 oversize 값이 blocked 분기로 새지 않도록 한다.
MAX_PROFILE_LABEL_CHARS = 120
MAX_PROFILE_POLICY_CHARS = 120
MAX_PROFILE_NOTE_CHARS = 500
MAX_PROFILE_SUMMARY_CHARS = 500
MAX_PROFILE_COMMAND_CHARS = 500
MAX_PROFILE_RECEIPT_ID_CHARS = 200
MAX_PROFILE_BLOCKER_ITEMS = 20
MAX_PROFILE_PROTECTED_REGION_COUNT = 10_000
MAX_PROFILE_CORRECTION_COUNT = 10_000
SHA256_HEX_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
PROTECTED_ZONE_DENY_POLICY = "deny"
# 프로파일 진단에 실리는 작성자 통제 라벨은 문자셋이 안전해 보여도 원문을 절대 남기지
# 않는다. G006 은 regex-safe 값까지 포함한 완전 불투명 표현을 요구한다.
PROFILE_REDACTED_PLACEHOLDER = "[REDACTED]"
MAX_PROFILE_ERROR_LABELS = 5


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


def _read_bytes_no_follow(path: Path, *, max_bytes: int = MAX_FIXTURE_FILE_BYTES) -> bytes:
    fd = _open_regular_no_symlink(path)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, max_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise SystemExit(f"fixture file exceeds {max_bytes} bytes: {path}")
    finally:
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


@contextmanager
def csv_parent_directory_lock(csv_path: Path, *, create_parent: bool) -> Any:
    """Serialize a CSV transaction without creating a lock sidecar.

    Normal writers take this stable directory-inode lock before the historical
    sidecar lock. Profiled replay can therefore hold it across freshness validation
    and its complete batch without leaving a sidecar on rejection. The stable inode
    also avoids an unlink-while-waiters race.
    """
    if fcntl is None:
        raise OSError("platform does not support advisory CSV locks")
    parent = csv_path.parent
    if create_parent:
        parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


# S003 real task suite: one sanitized regular file inside a hermetic fixture tree.
# 경로는 POSIX 상대 경로로 정규화하고, mode 는 실행 비트만 구분하는 두 값으로 좁힌다.
@dataclass(frozen=True)
class FixtureTreeEntry:
    path: str
    data: bytes
    executable: bool


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
    # 끝에 추가해 기존 positional TaskFixture 생성자의 필드 순서를 보존한다.
    output_format: str = "json"
    # S003 real task suite: sanitized hermetic fixture tree + bounded success checker.
    # None 이면 S001/S002 의 기존 동작(빈 workspace, project_root 체커)을 그대로 유지한다.
    fixture_tree: str | None = None
    success_checker: str | None = None
    fixture_tree_entries: tuple["FixtureTreeEntry", ...] | None = None
    success_checker_bytes: bytes | None = None


@dataclass
class Variant:
    name: str
    extra_args: list[str] = field(default_factory=list)
    # S001 is opt-in. Legacy variants keep the historical execution path.
    measurement: "MeasurementVariant | None" = None


@dataclass(frozen=True)
class MeasurementIdentity:
    candidate_hash: str
    repetition: int
    arm: str
    attempt: int
    namespace: str

    def components(self, task_id: str) -> tuple[str, str, int, str, int, str]:
        return (
            self.candidate_hash,
            task_id,
            self.repetition,
            self.arm,
            self.attempt,
            self.namespace,
        )

    def run_id(self, task_id: str) -> str:
        values = (MEASUREMENT_SUBSTRATE_SCHEMA_VERSION,) + self.components(task_id)
        canonical = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        payload = b"contextguard.bench.run-id.v2\0" + struct.pack(">Q", len(canonical)) + canonical
        return hashlib.sha256(payload).hexdigest()

    def legacy_v1_run_id(self, task_id: str) -> str:
        canonical = json.dumps(
            self.components(task_id), ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class MeasurementVariant:
    settings_file: Path
    setting_sources: tuple[str, ...]
    environment_allow: tuple[str, ...]
    environment_overrides: tuple[tuple[str, str], ...]
    workspace_mode: str
    session_mode: str
    session_persistence: str
    hook_events_enabled: bool
    registered_bindings: tuple[tuple[str, str], ...]
    required_event_classes: tuple[str, ...]
    pair_registered_bindings: tuple[tuple[str, str], ...]
    cli_capabilities: tuple[str, ...]
    identity: MeasurementIdentity
    artifact_root: Path
    settings_payload: dict[str, Any] = field(compare=False, repr=False)
    settings_source_bytes: bytes = field(compare=False, repr=False)


@dataclass(frozen=True)
class MeasurementRunContext:
    run_id: str
    run_root: Path
    home: Path
    xdg_config: Path
    xdg_cache: Path
    xdg_data: Path
    xdg_state: Path
    tmp: Path
    workspace: Path
    session: Path
    raw_path: Path
    receipt_path: Path
    index_path: Path


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
    primary_cost_provenance: str = PRIMARY_COST_PROVENANCE_UNAVAILABLE
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

    def __post_init__(self) -> None:
        self.validate_primary_cost_contract()

    def validate_primary_cost_contract(self) -> None:
        allowed = {
            PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE,
            PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT,
            PRIMARY_COST_PROVENANCE_UNAVAILABLE,
        }
        if self.primary_cost_provenance not in allowed:
            raise ValueError(f"invalid primary_cost_provenance: {self.primary_cost_provenance!r}")
        provenance_is_measured = self.primary_cost_provenance == PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT
        if self.cost_measured is not provenance_is_measured:
            raise ValueError(
                "primary_cost_provenance must be provider_export exactly when cost_measured=true"
            )


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
    # profile 을 선언하지 않은 row 는 세 필드가 모두 None 이며 generic 경로와 동일하다.
    evaluation_profile: str | None = None
    evaluation_controls: dict[str, Any] | None = None
    # preflight 가 채우는 정규화된 lane 판정. report annotation 은 이 값만 사용하므로
    # 이미 검증된 batch 위에서 절대 실패하지 않는다.
    evaluation_lane: dict[str, Any] | None = None

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
    # 끝에 추가해 기존 positional constructor의 timed_out/truncated 순서를 보존한다.
    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""
    launch_error: bool = False


@dataclass(frozen=True)
class ClaudeStreamParseResult:
    """Privacy-safe classification of one bounded Claude stream-json output."""

    status: str
    result_code: str
    error_code: str | None
    payload: dict[str, Any] | None


class _StreamDuplicateKey(ValueError):
    pass


class _StreamNonfiniteNumber(ValueError):
    pass


def _stream_result(
    status: str,
    *,
    result_code: str,
    error_code: str | None = None,
    payload: dict[str, Any] | None = None,
) -> ClaudeStreamParseResult:
    return ClaudeStreamParseResult(
        status=status,
        result_code=result_code,
        error_code=error_code,
        payload=payload,
    )


def _stream_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _StreamDuplicateKey
        obj[key] = value
    return obj


def _stream_reject_nonfinite(_value: str) -> Any:
    raise _StreamNonfiniteNumber


def _stream_contains_nonfinite(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_stream_contains_nonfinite(item) for item in value.values())
    if isinstance(value, list):
        return any(_stream_contains_nonfinite(item) for item in value)
    return False


def _stream_is_post_result_task_cleanup(
    terminal_payload: dict[str, Any], events: list[dict[str, Any]],
) -> bool:
    """Recognize Claude Code's exact bounded background-task shutdown tail."""
    if len(events) != 3:
        return False
    session_id = terminal_payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return False
    changed, updated, notification = events
    if (
        set(changed) != {"type", "subtype", "session_id", "tasks", "uuid"}
        or changed.get("type") != "system"
        or changed.get("subtype") != "background_tasks_changed"
        or changed.get("session_id") != session_id
        or changed.get("tasks") != []
        or not isinstance(changed.get("uuid"), str)
        or not changed["uuid"]
    ):
        return False
    patch = updated.get("patch")
    task_id = updated.get("task_id")
    if (
        set(updated) != {"type", "subtype", "session_id", "task_id", "patch", "uuid"}
        or updated.get("type") != "system"
        or updated.get("subtype") != "task_updated"
        or updated.get("session_id") != session_id
        or not isinstance(task_id, str)
        or not task_id
        or not isinstance(patch, dict)
        or set(patch) != {"end_time", "status"}
        or isinstance(patch.get("end_time"), bool)
        or not isinstance(patch.get("end_time"), int)
        or patch["end_time"] < 0
        or patch.get("status") != "killed"
        or not isinstance(updated.get("uuid"), str)
        or not updated["uuid"]
    ):
        return False
    return (
        set(notification) == {
            "type", "subtype", "session_id", "task_id", "tool_use_id",
            "status", "summary", "output_file", "uuid",
        }
        and notification.get("type") == "system"
        and notification.get("subtype") == "task_notification"
        and notification.get("session_id") == session_id
        and notification.get("task_id") == task_id
        and isinstance(notification.get("tool_use_id"), str)
        and bool(notification["tool_use_id"])
        and notification.get("status") == "stopped"
        and isinstance(notification.get("summary"), str)
        and isinstance(notification.get("output_file"), str)
        and isinstance(notification.get("uuid"), str)
        and bool(notification["uuid"])
    )


def parse_claude_stream_output(
    stdout: bytes | str,
    *,
    max_total_bytes: int = CLAUDE_OUTPUT_MAX_BYTES,
    max_lines: int = CLAUDE_STREAM_MAX_LINES,
    max_line_bytes: int = CLAUDE_STREAM_MAX_LINE_BYTES,
) -> ClaudeStreamParseResult:
    """Parse bounded Claude stream-json without retaining provider event text.

    The caller owns process timeout/truncation handling. This parser owns only
    strict NDJSON grammar and the final terminal-result classification. All
    failures return fixed codes rather than JSON excerpts or parse offsets.
    """
    if isinstance(stdout, str):
        try:
            raw = stdout.encode("utf-8", "strict")
        except UnicodeEncodeError:
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_invalid_utf8",
            )
    elif isinstance(stdout, bytes):
        raw = stdout
    else:
        raise TypeError("stdout must be bytes or str")

    if not raw:
        return _stream_result(
            "missing_terminal",
            result_code="missing_terminal",
            error_code="stream_missing_terminal",
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        return _stream_result(
            "invalid_stream", result_code="invalid_stream", error_code="stream_bom",
        )
    if len(raw) > max_total_bytes:
        return _stream_result(
            "invalid_stream",
            result_code="invalid_stream",
            error_code="stream_total_size_limit",
        )

    physical_lines = raw.split(b"\n")
    if physical_lines and physical_lines[-1] == b"":
        physical_lines.pop()
    if len(physical_lines) > max_lines:
        return _stream_result(
            "invalid_stream",
            result_code="invalid_stream",
            error_code="stream_line_count_limit",
        )

    terminal_payload: dict[str, Any] | None = None
    terminal_result_code: str | None = None
    terminal_status: str | None = None
    post_result_events: list[dict[str, Any]] = []
    for raw_line in physical_lines:
        # CR in a CRLF record is a delimiter byte, not part of the JSON content.
        line = raw_line[:-1] if raw_line.endswith(b"\r") else raw_line
        if len(line) > max_line_bytes:
            return _stream_result(
                "invalid_stream",
                result_code="invalid_stream",
                error_code="stream_line_size_limit",
            )
        if not line or not line.strip(b" \t\r\v\f"):
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_blank_line",
            )
        try:
            text = line.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_invalid_utf8",
            )
        try:
            event = json.loads(
                text,
                object_pairs_hook=_stream_object_no_duplicates,
                parse_constant=_stream_reject_nonfinite,
            )
        except _StreamDuplicateKey:
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_duplicate_key",
            )
        except _StreamNonfiniteNumber:
            return _stream_result(
                "invalid_stream",
                result_code="invalid_stream",
                error_code="stream_nonfinite_number",
            )
        except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_malformed_json",
            )
        try:
            contains_nonfinite = _stream_contains_nonfinite(event)
        except RecursionError:
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_malformed_json",
            )
        if contains_nonfinite:
            return _stream_result(
                "invalid_stream",
                result_code="invalid_stream",
                error_code="stream_nonfinite_number",
            )
        if not isinstance(event, dict):
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_non_object",
            )

        is_result = event.get("type") == "result"
        if terminal_payload is not None:
            if is_result:
                return _stream_result(
                    "invalid_stream",
                    result_code="invalid_stream",
                    error_code="stream_duplicate_result",
                )
            post_result_events.append(event)
            continue
        if not is_result:
            continue

        subtype = event.get("subtype")
        is_error = event.get("is_error")
        if not isinstance(is_error, bool):
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_result_shape",
            )
        if subtype == "success" and not is_error:
            terminal_status = "success"
            terminal_result_code = "success"
        elif subtype == "success" and is_error:
            terminal_status = "terminal_error"
            terminal_result_code = "success_is_error"
        elif subtype in {
            "error_during_execution",
            "error_max_turns",
            "error_max_budget_usd",
            "error_max_structured_output_retries",
        } and is_error:
            terminal_status = "terminal_error"
            terminal_result_code = str(subtype)
        else:
            return _stream_result(
                "invalid_stream", result_code="invalid_stream", error_code="stream_result_shape",
            )
        terminal_payload = event

    if terminal_payload is None or terminal_status is None or terminal_result_code is None:
        return _stream_result(
            "missing_terminal",
            result_code="missing_terminal",
            error_code="stream_missing_terminal",
        )
    if post_result_events and not _stream_is_post_result_task_cleanup(
        terminal_payload, post_result_events,
    ):
        return _stream_result(
            "invalid_stream", result_code="invalid_stream", error_code="stream_post_result",
        )
    return _stream_result(
        terminal_status,
        result_code=terminal_result_code,
        payload=terminal_payload,
    )


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


class _MeasurementDuplicateKey(ValueError):
    pass


class _MeasurementLaunchError(OSError):
    pass


class _StudyLaunchAccountingError(RuntimeError):
    pass


def _measurement_object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _MeasurementDuplicateKey(key)
        result[key] = value
    return result


def _parse_measurement_json_text(text: str, *, owner: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_measurement_object_no_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite number")),
        )
    except _MeasurementDuplicateKey as exc:
        raise SystemExit(f"{owner} contains duplicate JSON key: {exc}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{owner} must be valid JSON: {exc.msg}") from None
    except ValueError as exc:
        raise SystemExit(f"{owner} must be strict JSON: {exc}") from None


def _load_measurement_json(path: Path, *, owner: str) -> Any:
    return _parse_measurement_json_text(_read_text_no_follow(path), owner=owner)


def _measurement_parse_canonical_json_bytes(raw: bytes, *, owner: str) -> Any:
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        raise ValueError(f"{owner} is not canonical JSON")
    try:
        text = raw[:-1].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{owner} is not UTF-8") from None
    value = _parse_measurement_json_text(text, owner=owner)
    canonical = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if raw != canonical:
        raise ValueError(f"{owner} is not canonical JSON")
    return value


def _measurement_exact_object(
    value: Any,
    *,
    owner: str,
    keys: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SystemExit(f"{owner} must be a JSON object")
    actual = set(value)
    unknown = sorted(actual - keys)
    missing = sorted(keys - actual)
    if unknown:
        if owner.endswith(".measurement"):
            raise SystemExit(f"unknown measurement key: {', '.join(unknown)}")
        raise SystemExit(f"{owner} has unknown key(s): {', '.join(unknown)}")
    if missing:
        raise SystemExit(f"{owner} is missing key(s): {', '.join(missing)}")
    return value


def _measurement_safe_path(
    value: Any,
    *,
    owner: str,
    base_dir: Path,
    must_exist: bool,
) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SystemExit(f"{owner} must be a non-empty filesystem path")
    try:
        os.fsencode(value)
    except UnicodeError:
        raise SystemExit(f"{owner} is not representable on the local filesystem") from None
    raw = Path(value).expanduser()
    if not raw.is_absolute():
        if any(part in ("", ".", "..") for part in raw.parts):
            if owner.endswith(".settings_file"):
                raise SystemExit("settings_file must stay within the variant fixture directory")
            raise SystemExit(f"{owner} must not contain '.', '..', or empty path components")
        path = base_dir / raw
    else:
        path = raw
    path = Path(os.path.normpath(str(path)))
    try:
        path.relative_to(base_dir)
    except ValueError:
        # Artifact roots supplied by a test harness may be absolute, but relative
        # paths are never allowed to escape their fixture directory.
        if owner.endswith(".settings_file"):
            raise SystemExit("settings_file must stay within the variant fixture directory") from None
        if not raw.is_absolute():
            raise SystemExit(f"{owner} escapes the variant fixture directory") from None
    try:
        if must_exist:
            fd = _open_regular_no_symlink(path)
            os.close(fd)
        else:
            probe = path
            while not probe.exists() and probe != probe.parent:
                probe = probe.parent
            fd = _ensure_directory_no_symlink(probe)
            os.close(fd)
    except OSError as exc:
        try:
            is_link = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            is_link = False
        if is_link and owner.endswith(".settings_file"):
            raise SystemExit("settings_file must not be a symlink") from None
        if is_link and owner.endswith(".artifact_root"):
            raise SystemExit("artifact_root must not be a symlink") from None
        detail = exc.strerror or exc.__class__.__name__
        raise SystemExit(f"{owner} is unsafe or inaccessible: {detail}") from None
    return path


def _measurement_env_name(value: Any, *, owner: str) -> str:
    if not isinstance(value, str) or not MEASUREMENT_ENV_NAME_RE.fullmatch(value):
        raise SystemExit(f"{owner} must be an uppercase environment variable name")
    if value in MEASUREMENT_CREDENTIAL_ENV_NAMES or MEASUREMENT_SECRET_ENV_NAME_RE.search(value):
        raise SystemExit(f"unsafe environment name: {value}")
    if value in MEASUREMENT_RUNNER_ENV_NAMES:
        raise SystemExit(f"{owner} is runner-controlled and must not be configured")
    return value


def _measurement_string_tuple(
    value: Any,
    *,
    owner: str,
    maximum: int = 64,
) -> tuple[str, ...]:
    items = parse_string_list(value, field=owner.rsplit(".", 1)[-1], owner=owner.rsplit(".", 1)[0])
    if len(items) > maximum:
        raise SystemExit(f"{owner} exceeds the {maximum}-item limit")
    if len(set(items)) != len(items):
        raise SystemExit(f"{owner} must not contain duplicates")
    return tuple(items)


def _measurement_parse_identity(raw: Any, *, owner: str, variant_name: str) -> MeasurementIdentity:
    value = _measurement_exact_object(
        raw,
        owner=owner,
        keys=frozenset({"candidate_hash", "repetition", "arm", "attempt", "namespace"}),
    )
    candidate_hash = value["candidate_hash"]
    if not isinstance(candidate_hash, str) or not SHA256_HEX_PATTERN.fullmatch(candidate_hash):
        raise SystemExit(f"{owner}.candidate_hash must be 64 lowercase hexadecimal characters")
    repetition = value["repetition"]
    attempt = value["attempt"]
    if isinstance(repetition, bool) or repetition != 0:
        raise SystemExit(f"{owner}.repetition must be 0 in S001")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
        raise SystemExit(f"{owner}.attempt must be a non-negative integer")
    arm = value["arm"]
    if arm not in {"baseline", "treatment"} or arm != variant_name:
        raise SystemExit(f"{owner}.arm must be baseline or treatment and match the variant name")
    namespace = value["namespace"]
    if (
        not isinstance(namespace, str) or not namespace or "\0" in namespace
        or len(namespace.encode("utf-8")) > 256
    ):
        raise SystemExit(f"{owner}.namespace must be a bounded safe identifier")
    return MeasurementIdentity(candidate_hash, repetition, arm, attempt, namespace)


def _measurement_parse_variant(
    raw: Any,
    *,
    owner: str,
    variant_name: str,
    base_dir: Path,
) -> MeasurementVariant:
    value = _measurement_exact_object(raw, owner=owner, keys=MEASUREMENT_VARIANT_KEYS)
    if value["schema_version"] != MEASUREMENT_SUBSTRATE_SCHEMA_VERSION:
        raise SystemExit(
            f"measurement schema_version must be {MEASUREMENT_SUBSTRATE_SCHEMA_VERSION}"
        )

    settings_file = _measurement_safe_path(
        value["settings_file"], owner=f"{owner}.settings_file", base_dir=base_dir, must_exist=True,
    )
    settings_source_text = _read_text_no_follow(settings_file)
    settings_source_bytes = settings_source_text.encode("utf-8")
    settings_payload = _parse_measurement_json_text(
        settings_source_text, owner=f"{owner}.settings_file",
    )
    if not isinstance(settings_payload, dict):
        raise SystemExit(f"{owner}.settings_file must contain a JSON object")

    setting_sources = _measurement_string_tuple(
        value["setting_sources"], owner=f"{owner}.setting_sources", maximum=3,
    )
    allowed_setting_sources = {"user", "project", "local"}
    if any(item not in allowed_setting_sources for item in setting_sources):
        raise SystemExit(f"{owner}.setting_sources contains an unsupported source")

    environment = _measurement_exact_object(
        value["environment"],
        owner=f"{owner}.environment",
        keys=frozenset({"allow", "overrides"}),
    )
    allow_raw = _measurement_string_tuple(
        environment["allow"], owner=f"{owner}.environment.allow", maximum=64,
    )
    environment_allow = tuple(
        _measurement_env_name(item, owner=f"{owner}.environment.allow") for item in allow_raw
    )
    overrides_raw = environment["overrides"]
    if not isinstance(overrides_raw, dict) or len(overrides_raw) > 64:
        raise SystemExit(f"{owner}.environment.overrides must be a bounded JSON object")
    overrides: list[tuple[str, str]] = []
    for raw_name, raw_value in overrides_raw.items():
        name = _measurement_env_name(raw_name, owner=f"{owner}.environment.overrides")
        if not isinstance(raw_value, str) or len(raw_value.encode("utf-8")) > 4096:
            raise SystemExit(f"{owner}.environment.overrides values must be bounded strings")
        overrides.append((name, raw_value))

    workspace = _measurement_exact_object(
        value["workspace"], owner=f"{owner}.workspace", keys=frozenset({"mode"}),
    )
    if workspace["mode"] != "isolated":
        raise SystemExit(f"{owner}.workspace.mode must be isolated")
    session = _measurement_exact_object(
        value["session"],
        owner=f"{owner}.session",
        keys=frozenset({"mode", "persistence"}),
    )
    if session["mode"] != "isolated" or session["persistence"] != "disabled":
        raise SystemExit(f"{owner}.session must use isolated mode with disabled persistence")

    hooks = _measurement_exact_object(
        value["hook_events"],
        owner=f"{owner}.hook_events",
        keys=frozenset({"enabled", "registered_bindings", "required_event_classes"}),
    )
    if hooks["enabled"] is not True:
        raise SystemExit(f"{owner}.hook_events.enabled must be true")
    bindings_raw = hooks["registered_bindings"]
    if not isinstance(bindings_raw, list) or len(bindings_raw) > 32:
        raise SystemExit(f"{owner}.hook_events.registered_bindings must be a bounded array")
    registered_bindings: list[tuple[str, str]] = []
    for index, raw_binding in enumerate(bindings_raw):
        binding = _measurement_exact_object(
            raw_binding,
            owner=f"{owner}.hook_events.registered_bindings[{index}]",
            keys=frozenset({"hook_event", "configured_command"}),
        )
        hook_event = binding["hook_event"]
        command = binding["configured_command"]
        if hook_event not in MEASUREMENT_DOCUMENTED_HOOK_EVENTS:
            raise SystemExit(f"{owner}.hook_events.registered_bindings contains unsupported hook event")
        if not isinstance(command, str) or not command or "\0" in command or len(command.encode("utf-8")) > 4096:
            raise SystemExit(f"{owner}.hook_events.registered_bindings contains invalid configured command")
        registered_bindings.append((hook_event, command))
    if len(set(registered_bindings)) != len(registered_bindings):
        raise SystemExit(f"{owner}.hook_events.registered_bindings must not contain duplicates")
    required_event_classes = _measurement_string_tuple(
        hooks["required_event_classes"],
        owner=f"{owner}.hook_events.required_event_classes",
        maximum=32,
    )
    if any(item not in MEASUREMENT_DOCUMENTED_HOOK_EVENTS for item in required_event_classes):
        raise SystemExit(f"{owner}.hook_events.required_event_classes contains unsupported hook event")
    ordered_classes = tuple(dict.fromkeys(event for event, _command in registered_bindings))
    required_set = set(required_event_classes)
    if required_event_classes != tuple(event for event in ordered_classes if event in required_set):
        raise SystemExit(
            f"{owner}.hook_events.required_event_classes must be an ordered subset of registered hook events"
        )
    if variant_name == "baseline" and (registered_bindings or required_event_classes):
        raise SystemExit(f"{owner} baseline hook configuration must be empty")

    cli_capabilities = _measurement_string_tuple(
        value["cli_capabilities"], owner=f"{owner}.cli_capabilities", maximum=32,
    )
    for capability in cli_capabilities:
        # ``stream-json`` is a format capability rather than a long option;
        # the remaining S001 capabilities are deliberately restricted to
        # bounded long options so fixtures cannot smuggle arbitrary argv.
        if (capability != "stream-json" and not capability.startswith("--")) or len(capability) > 128:
            raise SystemExit(f"{owner}.cli_capabilities entries must be bounded long options or stream-json")
    mandatory_capabilities = {
        "--settings",
        "--setting-sources",
        "--include-hook-events",
        "--no-session-persistence",
        "stream-json",
    }
    if not mandatory_capabilities.issubset(cli_capabilities):
        missing = sorted(mandatory_capabilities - set(cli_capabilities))
        raise SystemExit(f"{owner}.cli_capabilities is missing required option(s): {', '.join(missing)}")

    identity = _measurement_parse_identity(
        value["identity"], owner=f"{owner}.identity", variant_name=variant_name,
    )
    artifact_root = _measurement_safe_path(
        value["artifact_root"],
        owner=f"{owner}.artifact_root",
        base_dir=base_dir,
        must_exist=False,
    )
    return MeasurementVariant(
        settings_file=settings_file,
        setting_sources=setting_sources,
        environment_allow=environment_allow,
        environment_overrides=tuple(overrides),
        workspace_mode=str(workspace["mode"]),
        session_mode=str(session["mode"]),
        session_persistence=str(session["persistence"]),
        hook_events_enabled=True,
        registered_bindings=tuple(registered_bindings),
        required_event_classes=required_event_classes,
        pair_registered_bindings=tuple(registered_bindings),
        cli_capabilities=cli_capabilities,
        identity=identity,
        artifact_root=artifact_root,
        settings_payload=settings_payload,
        settings_source_bytes=settings_source_bytes,
    )


def _measurement_is_registered_hook(value: Any, command: str) -> bool:
    if not isinstance(value, dict):
        return False
    return value.get("type") == "command" and value.get("command") == command


def _measurement_non_hook_source_members(raw: bytes) -> tuple[tuple[str, bytes], ...]:
    """Project exact top-level member bytes while excluding only the hooks member.

    Separating-comma whitespace is excluded from membership because adding or
    removing the hooks member necessarily changes that delimiter. All bytes
    inside every non-hook member remain literal and ordered.
    """
    stripped = raw.strip()
    if not stripped.startswith(b"{") or not stripped.endswith(b"}"):
        raise SystemExit("measurement settings file must be a JSON object")
    body = stripped[1:-1]
    members: list[bytes] = []
    start = 0
    depth = 0
    in_string = False
    escaped = False
    for index, byte in enumerate(body):
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
        elif byte in (0x7D, 0x5D):
            depth -= 1
        elif byte == 0x2C and depth == 0:
            members.append(body[start:index].strip())
            start = index + 1
    tail = body[start:].strip()
    if tail:
        members.append(tail)
    projection: list[tuple[str, bytes]] = []
    for member in members:
        try:
            parsed = json.loads(b"{" + member + b"}")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise SystemExit("measurement settings file must be strict JSON") from None
        if isinstance(parsed, dict) and set(parsed) == {"hooks"}:
            continue
        if not isinstance(parsed, dict) or len(parsed) != 1:
            raise SystemExit("measurement settings file must be a JSON object")
        projection.append((next(iter(parsed)), member))
    return tuple(sorted(projection, key=lambda item: item[0]))


def _measurement_prune_registered_hooks(
    settings: dict[str, Any], bindings: tuple[tuple[str, str], ...],
) -> dict[str, Any]:
    projected = json.loads(json.dumps(settings, ensure_ascii=False))
    hooks = projected.get("hooks")
    if not isinstance(hooks, dict):
        return projected
    commands_by_event: dict[str, set[str]] = {}
    for event, command in bindings:
        commands_by_event.setdefault(event, set()).add(command)
    for event, commands in commands_by_event.items():
        registrations = hooks.get(event)
        if not isinstance(registrations, list):
            continue
        retained_registrations: list[Any] = []
        for registration in registrations:
            if not isinstance(registration, dict) or not isinstance(registration.get("hooks"), list):
                retained_registrations.append(registration)
                continue
            retained_hooks = [
                hook for hook in registration["hooks"]
                if not any(_measurement_is_registered_hook(hook, command) for command in commands)
            ]
            if retained_hooks:
                registration["hooks"] = retained_hooks
                retained_registrations.append(registration)
        if retained_registrations:
            hooks[event] = retained_registrations
        else:
            hooks.pop(event, None)
    if not hooks:
        projected.pop("hooks", None)
    return projected


def _measurement_validate_treatment_bindings(spec: MeasurementVariant) -> dict[str, Any]:
    if not spec.registered_bindings:
        return json.loads(json.dumps(spec.settings_payload, ensure_ascii=False))
    hooks = spec.settings_payload.get("hooks")
    if not isinstance(hooks, dict):
        raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
    binding_set = set(spec.registered_bindings)
    occurrences = {binding: 0 for binding in spec.registered_bindings}
    for event in dict.fromkeys(event for event, _command in spec.registered_bindings):
        registrations = hooks.get(event)
        if not isinstance(registrations, list) or not registrations:
            raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
        for registration in registrations:
            if not isinstance(registration, dict) or not isinstance(registration.get("hooks"), list) or not registration["hooks"]:
                raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
            for hook in registration["hooks"]:
                if not isinstance(hook, dict) or hook.get("type") != "command" or not isinstance(hook.get("command"), str):
                    raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
                binding = (event, hook["command"])
                if binding not in binding_set:
                    raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
                occurrences[binding] += 1
    if any(count != 1 for count in occurrences.values()):
        raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
    return _measurement_prune_registered_hooks(spec.settings_payload, spec.registered_bindings)


def _validate_measurement_variant_set(variants: list[Variant]) -> None:
    measured = [variant for variant in variants if variant.measurement is not None]
    if not measured:
        return
    if any(variant.name not in {"baseline", "treatment"} for variant in measured):
        raise SystemExit("measurement variants must be named baseline or treatment in S001")
    if len(measured) != 2 or {variant.name for variant in measured} != {"baseline", "treatment"}:
        raise SystemExit("measurement fixture must contain exactly one baseline and treatment pair")
    by_name = {variant.name: variant.measurement for variant in measured}
    baseline = by_name["baseline"]
    treatment = by_name["treatment"]
    assert baseline is not None and treatment is not None
    derived_baseline = _measurement_validate_treatment_bindings(treatment)
    for event, command in treatment.registered_bindings:
        hooks = baseline.settings_payload.get("hooks", {})
        if isinstance(hooks, dict):
            for registrations in hooks.values():
                if isinstance(registrations, list):
                    for registration in registrations:
                        if isinstance(registration, dict) and isinstance(registration.get("hooks"), list):
                            if any(_measurement_is_registered_hook(hook, command) for hook in registration["hooks"]):
                                raise SystemExit("measurement baseline settings contain managed ContextGuard hook")
    if baseline.settings_payload != derived_baseline:
        raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
    if _measurement_non_hook_source_members(baseline.settings_source_bytes) != _measurement_non_hook_source_members(treatment.settings_source_bytes):
        raise SystemExit("measurement baseline and treatment settings differ outside registered hooks")
    object.__setattr__(baseline, "pair_registered_bindings", treatment.registered_bindings)
    object.__setattr__(treatment, "pair_registered_bindings", treatment.registered_bindings)
    parity_projection: list[tuple[str, tuple[Any, ...]]] = []
    for variant in measured:
        spec = variant.measurement
        assert spec is not None
        parity_projection.append((
            variant.name,
            (
                spec.setting_sources,
                spec.environment_allow,
                spec.environment_overrides,
                spec.workspace_mode,
                spec.session_mode,
                spec.session_persistence,
                spec.hook_events_enabled,
                spec.cli_capabilities,
                spec.identity.candidate_hash,
                spec.identity.repetition,
                spec.identity.attempt,
                spec.identity.namespace,
                spec.artifact_root,
            ),
        ))
    if len({value for _, value in parity_projection}) != 1:
        raise SystemExit("measurement baseline/treatment configuration differs beyond arm/hooks")


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
    # 결정적으로 거부 가능한 값: 임베디드 NUL 과 로컬 fs 인코딩으로 표현 불가한 문자열.
    # 이 값들은 이후 os.open 에서 ValueError/UnicodeError 로 터질 수 있으므로 미리 막는다.
    if "\x00" in raw_path:
        raise SystemExit(f"{owner} variant_prompt_files path must not contain embedded NUL")
    try:
        os.fsencode(raw_path)
    except UnicodeError:
        raise SystemExit(
            f"{owner} variant_prompt_files path is not representable on the local filesystem"
        ) from None
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

    Profiled tasks use the redacted profile owner and never echo raw task ids,
    variant labels, mapping keys, or unsafe paths. Unprofiled messages stay
    unchanged for compatibility.
    """
    known_variants = {variant.name for variant in variants}
    for task in tasks:
        profiled = task.evaluation_profile is not None
        unknown = sorted(set(task.variant_prompt_files) - known_variants)
        if unknown:
            if profiled:
                # 매핑 키·variant 라벨은 attacker-controlled 이므로 이름 대신 적색 처리한다.
                profile_reject(
                    PROFILE_REJECT_PROMPT_BINDING_INVALID,
                    profile_owner(task.id),
                    "variant_prompt_files references unknown variant(s): "
                    f"{redact_profile_labels(unknown)}",
                )
            raise SystemExit(
                f"task {task.id} variant_prompt_files references unknown variant(s): {', '.join(unknown)}"
            )
        for variant_name, raw_path in task.variant_prompt_files.items():
            owner = (
                profile_owner(task.id, variant_name)
                if profiled
                else f"task {task.id} variant {variant_name}"
            )
            try:
                validate_variant_prompt_file_path(raw_path, owner=owner)
            except SystemExit:
                if profiled:
                    # 원본 경로·라벨이 새어나가지 않도록 안정적인 프로파일 오류로 다시 쓴다.
                    profile_reject(
                        PROFILE_REJECT_PROMPT_BINDING_INVALID,
                        owner,
                        "variant_prompt_files path is unsafe or invalid",
                    )
                raise


MAX_FIXTURE_TREE_FILES = 64
MAX_FIXTURE_TREE_FILE_BYTES = 262_144
MAX_FIXTURE_TREE_TOTAL_BYTES = 1_048_576
MAX_FIXTURE_TREE_DIRECTORIES = 64
MAX_FIXTURE_TREE_DEPTH = 6
FIXTURE_TREE_PATH_COMPONENT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def validate_fixture_tree_relpath(raw_path: str, *, owner: str, field: str) -> Path:
    """Return a safe relative fixture-tree path, or fail before any file read.

    Rules are intentionally narrower than variant_prompt_files: only bounded
    ASCII components are allowed so a suite path can never be an absolute path,
    a traversal, a hidden dotfile, or a shell/argv-ambiguous value.
    """
    if not isinstance(raw_path, str):
        raise SystemExit(f"{owner} {field} must be a string")
    if "\x00" in raw_path:
        raise SystemExit(f"{owner} {field} must not contain embedded NUL")
    if raw_path != raw_path.strip() or not raw_path:
        raise SystemExit(f"{owner} {field} must not be empty or padded")
    if "\\" in raw_path:
        raise SystemExit(f"{owner} {field} must use '/' separators: {raw_path}")
    rel_path = Path(raw_path)
    if rel_path.is_absolute():
        raise SystemExit(f"{owner} {field} must be relative: {raw_path}")
    if not rel_path.parts or rel_path == Path("."):
        raise SystemExit(f"{owner} {field} must name a path")
    for part in rel_path.parts:
        if FIXTURE_TREE_PATH_COMPONENT_RE.fullmatch(part) is None:
            raise SystemExit(
                f"{owner} {field} component is not a bounded safe name: {raw_path}"
            )
    if len(rel_path.parts) > 6:
        raise SystemExit(f"{owner} {field} is nested deeper than 6 components: {raw_path}")
    return rel_path


def load_task_fixture_tree(
    task: TaskFixture, task_file_dir: Path,
) -> tuple[FixtureTreeEntry, ...]:
    """Read one task's sanitized fixture tree with bounded no-follow IO.

    Ordering is by POSIX path so the materialized workspace, the manifest, and
    the tree hash are byte-deterministic regardless of directory iteration
    order. Symlinks, non-regular files, and empty trees are refused.
    """
    if task.fixture_tree is None:
        return ()
    owner = f"task {task.id}"
    rel_root = validate_fixture_tree_relpath(
        task.fixture_tree, owner=owner, field="fixture_tree",
    )
    root = task_file_dir / rel_root
    entries: list[FixtureTreeEntry] = []
    total_bytes = 0
    directories = 0
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        current, prefix = pending.pop()
        directories += 1
        if directories > MAX_FIXTURE_TREE_DIRECTORIES:
            raise SystemExit(
                f"{owner} fixture_tree exceeds {MAX_FIXTURE_TREE_DIRECTORIES} directories"
            )
        if prefix.count("/") > MAX_FIXTURE_TREE_DEPTH:
            raise SystemExit(
                f"{owner} fixture_tree is nested deeper than {MAX_FIXTURE_TREE_DEPTH}"
            )
        try:
            dir_fd = _ensure_directory_no_symlink(current)
        except (OSError, ValueError):
            raise SystemExit(f"{owner} fixture_tree is not a readable directory") from None
        try:
            names = sorted(os.listdir(dir_fd))
        except OSError:
            raise SystemExit(f"{owner} fixture_tree could not be listed") from None
        finally:
            os.close(dir_fd)
        for name in names:
            if FIXTURE_TREE_PATH_COMPONENT_RE.fullmatch(name) is None:
                raise SystemExit(
                    f"{owner} fixture_tree contains an unsafe entry name"
                )
            child = current / name
            rel = f"{prefix}{name}"
            if child.is_symlink():
                raise SystemExit(f"{owner} fixture_tree must not contain symlinks")
            if child.is_dir():
                pending.append((child, f"{rel}/"))
                continue
            if not child.is_file():
                raise SystemExit(f"{owner} fixture_tree must contain regular files only")
            try:
                fd = _open_regular_no_symlink(child)
            except OSError:
                raise SystemExit(f"{owner} fixture_tree file could not be opened") from None
            try:
                stat_result = os.fstat(fd)
                if stat_result.st_size > MAX_FIXTURE_TREE_FILE_BYTES:
                    raise SystemExit(
                        f"{owner} fixture_tree file exceeds "
                        f"{MAX_FIXTURE_TREE_FILE_BYTES} bytes"
                    )
                # os.read 는 short read 가 허용되므로 EOF 까지 반복 읽는다. 한 번만 읽으면
                # 잘린 바이트가 온전한 fixture 로 해시/실체화될 수 있다.
                chunks: list[bytes] = []
                remaining = MAX_FIXTURE_TREE_FILE_BYTES + 1
                while remaining > 0:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            finally:
                os.close(fd)
            if len(data) > MAX_FIXTURE_TREE_FILE_BYTES:
                raise SystemExit(
                    f"{owner} fixture_tree file exceeds "
                    f"{MAX_FIXTURE_TREE_FILE_BYTES} bytes"
                )
            total_bytes += len(data)
            if total_bytes > MAX_FIXTURE_TREE_TOTAL_BYTES:
                raise SystemExit(
                    f"{owner} fixture_tree exceeds "
                    f"{MAX_FIXTURE_TREE_TOTAL_BYTES} total bytes"
                )
            entries.append(FixtureTreeEntry(
                path=rel,
                data=data,
                executable=bool(stat_result.st_mode & 0o111),
            ))
            if len(entries) > MAX_FIXTURE_TREE_FILES:
                raise SystemExit(
                    f"{owner} fixture_tree exceeds {MAX_FIXTURE_TREE_FILES} files"
                )
    if not entries:
        raise SystemExit(f"{owner} fixture_tree must contain at least one file")
    ordered = tuple(sorted(entries, key=lambda entry: entry.path))
    if any(entry.path == "check.py" for entry in ordered):
        raise SystemExit(
            f"{owner} fixture_tree must not contain the success checker; "
            "the checker is executed from a private directory outside the workspace"
        )
    return ordered


def load_task_success_checker(task: TaskFixture, task_file_dir: Path) -> bytes:
    """Read the task's success checker from outside its fixture tree.

    The checker never enters the agent-writable workspace: it is bound here by
    content, recorded in the study manifest by hash, and materialized into a
    private per-attempt directory immediately before it runs.
    """
    if task.success_checker is None:
        return b""
    owner = f"task {task.id}"
    rel = validate_fixture_tree_relpath(
        task.success_checker, owner=owner, field="success_checker",
    )
    if task.fixture_tree is not None:
        tree_root = validate_fixture_tree_relpath(
            task.fixture_tree, owner=owner, field="fixture_tree",
        )
        if rel.parts[:len(tree_root.parts)] == tree_root.parts:
            raise SystemExit(
                f"{owner} success_checker must live outside fixture_tree so the "
                "measured agent cannot rewrite it"
            )
    path = task_file_dir / rel
    try:
        fd = _open_regular_no_symlink(path)
    except OSError:
        raise SystemExit(f"{owner} success_checker could not be opened") from None
    try:
        if os.fstat(fd).st_size > MAX_FIXTURE_TREE_FILE_BYTES:
            raise SystemExit(f"{owner} success_checker is too large")
        chunks: list[bytes] = []
        remaining = MAX_FIXTURE_TREE_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if not data:
        raise SystemExit(f"{owner} success_checker is empty")
    if len(data) > MAX_FIXTURE_TREE_FILE_BYTES:
        raise SystemExit(f"{owner} success_checker is too large")
    return data


def load_task_fixture_trees(
    tasks: Sequence[TaskFixture], *, task_file_dir: Path,
) -> None:
    """Bind each declaring task's fixture-tree bytes before any provider launch."""
    for task in tasks:
        if task.fixture_tree is None:
            continue
        task.fixture_tree_entries = load_task_fixture_tree(task, task_file_dir)
        task.success_checker_bytes = load_task_success_checker(task, task_file_dir)


def fixture_tree_manifest_files(
    entries: Sequence[FixtureTreeEntry],
) -> list[dict[str, Any]]:
    return [
        {
            "path": entry.path,
            "sha256": hashlib.sha256(entry.data).hexdigest(),
            "bytes": len(entry.data),
            "executable": entry.executable,
        }
        for entry in entries
    ]


def fixture_tree_sha256(entries: Sequence[FixtureTreeEntry]) -> str:
    """Domain-separated hash over the ordered fixture-tree file bindings."""
    return hashlib.sha256(
        b"contextguard.bench.fixture-tree.v1\0"
        + json.dumps(
            fixture_tree_manifest_files(entries),
            ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def reset_task_fixture_tree(
    entries: Sequence[FixtureTreeEntry], workspace: Path,
) -> None:
    """Materialize the fixture tree into a per-attempt workspace deterministically.

    The workspace is emptied first so a resumed or retried attempt starts from
    the exact same bytes as a cold attempt. Directories are 0700, data files
    0600, and declared executables 0700; no symlink is ever created or followed.
    """
    if not entries:
        return
    if workspace.is_symlink() or not workspace.is_dir():
        raise SystemExit("fixture tree workspace must be a real directory")
    for child in sorted(workspace.iterdir(), key=lambda path: path.name):
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)
        else:
            raise SystemExit("fixture tree workspace contains an unsupported entry")
    for entry in entries:
        rel = Path(entry.path)
        target_dir = workspace
        for part in rel.parts[:-1]:
            target_dir = target_dir / part
            if target_dir.is_symlink():
                raise SystemExit("fixture tree workspace path must not be a symlink")
            if not target_dir.exists():
                target_dir.mkdir(mode=0o700)
        target = target_dir / rel.parts[-1]
        mode = 0o700 if entry.executable else 0o600
        fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        try:
            # os.write 는 short write 가 허용되므로 남은 바이트를 반복 기록한다.
            # 한 번만 호출하면 fixture 파일이 조용히 잘려 결정적 reset 이 깨질 수 있다.
            view = memoryview(entry.data)
            written = 0
            while written < len(view):
                chunk = os.write(fd, view[written:])
                if chunk <= 0:
                    raise SystemExit("fixture tree write made no progress")
                written += chunk
            os.fchmod(fd, mode)
        finally:
            os.close(fd)


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
        # evaluation_profile opt-in 을 필수 라벨(id/prompt)보다 먼저 확정한다.
        # 지원 프로파일의 구조 오류는 raw KeyError 가 아니라 안정적인 프로파일 거부로 끝낸다.
        evaluation_profile = item.get("evaluation_profile")
        profiled = evaluation_profile is not None
        if "id" not in item:
            if profiled:
                profile_reject(
                    PROFILE_REJECT_SCHEMA_INVALID,
                    profile_owner(None),
                    "task fixture fields are invalid",
                )
            raise KeyError("id")
        task_id = str(item["id"])
        owner = profile_owner(task_id) if profiled else f"task {task_id}"
        if profiled and (
            not isinstance(evaluation_profile, str)
            or evaluation_profile not in SUPPORTED_EVALUATION_PROFILE_IDS
        ):
            profile_reject(
                PROFILE_REJECT_SCHEMA_INVALID,
                owner,
                "declares an unsupported evaluation_profile id",
            )
        if "variant_prompts" in item:
            detail = "variant_prompts is not supported; use file-backed variant_prompt_files"
            if profiled:
                profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, detail)
            raise SystemExit(f"{owner} {detail}")
        effort_raw = item.get("effort")
        budget_raw = item.get("max_budget_usd")
        if budget_raw is not None:
            try:
                budget = float(budget_raw)
            except (TypeError, ValueError):
                detail = "max_budget_usd must be number or null"
                if profiled:
                    profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, detail)
                raise SystemExit(f"{owner} {detail}")
            if not math.isfinite(budget) or budget <= 0:
                detail = "max_budget_usd must be finite and > 0 (use null for unlimited)"
                if profiled:
                    profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, detail)
                raise SystemExit(f"{owner} {detail}")
        else:
            budget = None
        # profiled 경로에서는 매핑 키 등 attacker-controlled 라벨이 파서 오류에 실릴 수
        # 있으므로, 구조 필드 오류(파서 SystemExit·필수 prompt 누락 KeyError)를 안정적인
        # 프로파일 거부로 다시 쓴다. unprofiled 는 원본 예외를 그대로 재발생시킨다.
        try:
            max_turns = parse_positive_int(
                item.get("max_turns", 3), field="max_turns", owner=owner,
            )
            output_format = item.get("output_format", "json")
            if not isinstance(output_format, str) or output_format not in CLAUDE_OUTPUT_FORMATS:
                raise SystemExit(f"{owner} output_format must be 'json' or 'stream-json'")
            allowed_tools = parse_string_list(
                item.get("allowed_tools", []),
                field="allowed_tools",
                owner=owner,
            )
            variant_prompt_files = parse_string_map(
                item.get("variant_prompt_files"),
                field="variant_prompt_files",
                owner=owner,
            )
            prompt = str(item["prompt"])
            fixture_tree_raw = item.get("fixture_tree")
            success_checker_raw = item.get("success_checker")
            if fixture_tree_raw is None and success_checker_raw is not None:
                raise SystemExit(f"{owner} success_checker requires fixture_tree")
            if fixture_tree_raw is not None:
                validate_fixture_tree_relpath(
                    fixture_tree_raw, owner=owner, field="fixture_tree",
                )
                if success_checker_raw is None:
                    raise SystemExit(f"{owner} fixture_tree requires success_checker")
                validate_fixture_tree_relpath(
                    success_checker_raw, owner=owner, field="success_checker",
                )
                if item.get("success_command") is not None:
                    raise SystemExit(
                        f"{owner} fixture_tree forbids success_command; the checker "
                        "argv is derived from the bound success_checker"
                    )
                if str(item.get("success_cwd", ".")) != ".":
                    raise SystemExit(
                        f"{owner} fixture_tree requires success_cwd '.' "
                        "so the checker runs against the materialized workspace"
                    )
        except (SystemExit, KeyError):
            if profiled:
                profile_reject(
                    PROFILE_REJECT_SCHEMA_INVALID,
                    owner,
                    "task fixture fields are invalid",
                )
            raise
        fixtures.append(TaskFixture(
            evaluation_profile=evaluation_profile,
            id=task_id,
            prompt=prompt,
            model=str(item.get("model", "sonnet")),
            effort=str(effort_raw) if effort_raw is not None else None,
            max_turns=max_turns,
            max_budget_usd=budget,
            output_format=output_format,
            allowed_tools=allowed_tools,
            success_command=item.get("success_command"),
            success_cwd=str(item.get("success_cwd", ".")),
            variant_prompt_files=variant_prompt_files,
            fixture_tree=str(fixture_tree_raw) if fixture_tree_raw is not None else None,
            success_checker=(
                str(success_checker_raw) if success_checker_raw is not None else None
            ),
        ))
    if variants is not None:
        validate_variant_prompt_file_references(fixtures, variants)
    return fixtures


def parse_variants(path: Path) -> list[Variant]:
    raw = _load_measurement_json(path, owner="variants file")
    if not isinstance(raw, list):
        raise SystemExit(f"variants file must be a JSON list: {path}")
    variants: list[Variant] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SystemExit(f"variant entry must be a JSON object: {item}")
        if "measurement" in item:
            unknown = sorted(set(item) - {"name", "extra_args", "measurement"})
            if unknown:
                raise SystemExit(f"measurement variant has unknown key(s): {', '.join(unknown)}")
        name = str(item["name"])
        extra_args = validate_variant_extra_args(
            parse_string_list(
                item.get("extra_args", []),
                field="extra_args",
                owner=f"variant {name}",
            ),
            owner=f"variant {name}",
        )
        if "measurement" in item:
            for index, arg in enumerate(extra_args):
                flag = arg.split("=", 1)[0]
                if flag in MEASUREMENT_PROTECTED_VARIANT_FLAGS:
                    if flag in {"--safe-mode", "--bare"}:
                        raise SystemExit(f"unsafe Claude flag: {flag}")
                    raise SystemExit(
                        f"runner-controlled Claude flag: {flag}"
                    )
        variants.append(Variant(
            name=name,
            extra_args=extra_args,
            measurement=(
                _measurement_parse_variant(
                    item["measurement"],
                    owner=f"variant {name}.measurement",
                    variant_name=name,
                    base_dir=path.parent,
                )
                if "measurement" in item else None
            ),
        ))
    _validate_measurement_variant_set(variants)
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


def _measurement_child_env(
    spec: MeasurementVariant,
    context: MeasurementRunContext | None = None,
    *,
    existing_login_home: Path | None = None,
) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in spec.environment_allow:
        # Names were validated before this function; do not inspect values for
        # rejected auth/secret-shaped names.
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(dict(spec.environment_overrides))
    if "PATH" not in env:
        env["PATH"] = os.defpath
    if context is not None:
        env.update({
            "HOME": str(existing_login_home or context.home),
            "XDG_CONFIG_HOME": str(context.xdg_config),
            "XDG_CACHE_HOME": str(context.xdg_cache),
            "XDG_DATA_HOME": str(context.xdg_data),
            "XDG_STATE_HOME": str(context.xdg_state),
            "TMPDIR": str(context.tmp),
        })
        if existing_login_home is None:
            env["CLAUDE_CONFIG_DIR"] = str(context.session)
    return env


@contextmanager
def _measurement_preflight_env(spec: MeasurementVariant) -> Any:
    with tempfile.TemporaryDirectory(prefix="contextguard-bench-preflight-") as tmp:
        root = Path(tmp)
        names = {
            "home": root / "home",
            "xdg-config": root / "xdg-config",
            "xdg-cache": root / "xdg-cache",
            "xdg-data": root / "xdg-data",
            "xdg-state": root / "xdg-state",
            "tmp": root / "tmp",
            "workspace": root / "workspace",
            "session": root / "session",
        }
        for path in names.values():
            path.mkdir(mode=0o700)
        context = MeasurementRunContext(
            run_id="preflight",
            run_root=root,
            home=names["home"],
            xdg_config=names["xdg-config"],
            xdg_cache=names["xdg-cache"],
            xdg_data=names["xdg-data"],
            xdg_state=names["xdg-state"],
            tmp=names["tmp"],
            workspace=names["workspace"],
            session=names["session"],
            raw_path=root / "raw.ndjson",
            receipt_path=root / "receipt.json",
            index_path=root / "artifact-index.ndjson",
        )
        yield _measurement_child_env(spec, context), context.workspace


def validate_measurement_cli_capabilities(claude_bin: str, spec: MeasurementVariant) -> None:
    executable = executable_argv0(claude_bin)
    with _measurement_preflight_env(spec) as (env, cwd):
        try:
            proc = run_bounded_command(
                [executable, "--help"],
                cwd=cwd,
                timeout_seconds=10,
                max_output_bytes=MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise SystemExit(f"measurement CLI capability probe failed: {exc}") from None
    if proc.returncode != 0 or proc.timed_out or proc.output_truncated:
        raise SystemExit("measurement CLI capability probe failed")
    help_text = f"{proc.stdout}\n{proc.stderr}"
    capability_tokens = set(re.findall(r"--[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*|[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", help_text))
    missing = [capability for capability in spec.cli_capabilities if capability not in capability_tokens]
    if missing:
        raise SystemExit(f"required CLI capability unavailable: {', '.join(sorted(missing))}")


def claude_version(claude_bin: str, *, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    try:
        proc = run_bounded_command(
            [claude_bin, "--version"],
            cwd=cwd or Path.cwd(),
            timeout_seconds=5,
            max_output_bytes=VERSION_OUTPUT_MAX_BYTES,
            env=env,
        )
        return proc.stdout.strip().splitlines()[0] if proc.stdout else "unknown"
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "unknown"


def build_claude_argv(
    claude_bin: str,
    task: TaskFixture,
    variant: Variant,
    *,
    measurement_settings_file: Path | None = None,
) -> list[str]:
    """`claude -p` argv 를 빌드한다.

    fixture 에 명시되지 않은 옵션(effort, max_budget_usd) 은 argv 에서 빠진다.
    이렇게 해야 baseline variant 의 실제 의미(=defaults 그대로)가 implicit
    runner default 로 왜곡되지 않는다.
    """
    output_format = "stream-json" if variant.measurement is not None else task.output_format
    argv = [claude_bin, "-p", "--model", task.model,
            "--max-turns", str(task.max_turns), "--output-format", output_format]
    if output_format == "stream-json":
        argv.append("--verbose")
    if task.effort:
        argv.extend(["--effort", task.effort])
    if task.max_budget_usd is not None:
        argv.extend(["--max-budget-usd", str(task.max_budget_usd)])
    if task.allowed_tools:
        argv.extend(["--allowedTools", ",".join(task.allowed_tools)])
    if variant.measurement is not None:
        spec = variant.measurement
        argv.extend([
            "--settings", str(measurement_settings_file or spec.settings_file),
            "--setting-sources", ",".join(spec.setting_sources),
            "--include-hook-events",
            "--no-session-persistence",
        ])
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
    env: dict[str, str] | None = None,
    stdout_sink_fd: int | None = None,
    on_process_started: Callable[[], None] | None = None,
) -> BoundedProcessResult:
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise _MeasurementLaunchError(str(exc)) from exc
    if on_process_started is not None:
        try:
            on_process_started()
        except BaseException:
            try:
                pgid = os.getpgid(proc.pid)
            except OSError:
                pgid = proc.pid
            _signal_process_group(proc, signal.SIGKILL, pgid)
            try:
                proc.wait(timeout=PROCESS_TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                _signal_process_group(proc, signal.SIGKILL, pgid)
                proc.wait()
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            raise
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
    pending_error: BaseException | None = None
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
                accepted = chunk[:max(remaining, 0)]
                if remaining > 0:
                    buffer.extend(accepted)
                    if name == "stdout" and stdout_sink_fd is not None:
                        _measurement_write_fd(stdout_sink_fd, accepted)
                if len(chunk) > remaining:
                    output_truncated = True
                    if terminated_at is None:
                        _signal_process_group(proc, signal.SIGTERM, pgid)
                        terminated_at = time.monotonic()
    except BaseException as exc:
        pending_error = exc
        _signal_process_group(proc, signal.SIGKILL, pgid)
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
    if pending_error is not None:
        raise pending_error
    if timed_out:
        returncode = 124
    elif output_truncated:
        returncode = 125
    stdout_bytes = bytes(buffers["stdout"])
    stderr_bytes = bytes(buffers["stderr"])
    return BoundedProcessResult(
        returncode=returncode,
        stdout=stdout_bytes.decode("utf-8", "replace"),
        stderr=stderr_bytes.decode("utf-8", "replace"),
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        timed_out=timed_out,
        output_truncated=output_truncated,
        launch_error=False,
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


def run_success_command(
    task: TaskFixture,
    project_root: Path,
    *,
    env: dict[str, str] | None = None,
) -> tuple[bool, str]:
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
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return False, f"success_command failed to launch: {exc}"
    if proc.timed_out:
        return False, "success_command timed out after 600s"
    if proc.output_truncated:
        return False, f"success_command output limit exceeded ({SUCCESS_COMMAND_OUTPUT_MAX_BYTES} bytes)"
    return proc.returncode == 0, f"exit={proc.returncode}"


def run_success_command_study(
    task: TaskFixture,
    project_root: Path,
    *,
    env: dict[str, str],
) -> str:
    """Classify the frozen S002 checker contract without legacy boolean coercion."""
    if not task.success_command or is_placeholder_success_command(task.success_command):
        return "success_checker_infra_invalid"
    try:
        argv = shlex.split(task.success_command)
    except ValueError:
        return "success_checker_infra_invalid"
    if not argv or _has_shell_meta(argv):
        return "success_checker_infra_invalid"
    raw_cwd = Path(task.success_cwd)
    if raw_cwd.is_absolute() or any(part in ("", ".", "..") for part in raw_cwd.parts):
        return "success_checker_infra_invalid"
    root_fd = -1
    cwd_fd = -1
    try:
        root_fd = _ensure_directory_no_symlink(project_root)
        cwd_fd = os.dup(root_fd)
        for component in raw_cwd.parts:
            next_fd = _open_directory_at(cwd_fd, component, project_root / raw_cwd)
            os.close(cwd_fd)
            cwd_fd = next_fd
        cwd = project_root / raw_cwd
    except (OSError, ValueError):
        return "success_checker_infra_invalid"
    finally:
        if cwd_fd >= 0:
            os.close(cwd_fd)
        if root_fd >= 0:
            os.close(root_fd)
    try:
        result = run_bounded_command(
            argv,
            cwd=cwd,
            timeout_seconds=600,
            max_output_bytes=SUCCESS_COMMAND_OUTPUT_MAX_BYTES,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "success_checker_infra_invalid"
    if len(result.stdout_bytes.splitlines()) > 4096 or len(result.stderr_bytes.splitlines()) > 4096:
        return "success_checker_infra_invalid"
    if any(
        len(line) > 16_384
        for raw in (result.stdout_bytes, result.stderr_bytes)
        for line in raw.splitlines()
    ):
        return "success_checker_infra_invalid"
    return classify_success_checker(result)


def run_task_checker_study(
    task: TaskFixture,
    workspace: Path,
    *,
    env: dict[str, str],
    interpreter_binding: Mapping[str, Any] | None = None,
) -> str:
    """Run the content-bound success checker outside the measured workspace.

    The checker bytes come from the manifest-bound copy loaded before the run,
    never from the workspace, so overwriting or deleting the workspace copy
    cannot fake a success. The argv is derived here rather than taken from a
    free-form `success_command`, so a fixture cannot smuggle another command in.
    The judge runs isolated with a minimal environment: the measured agent's
    environment is deliberately not inherited, so a planted `sitecustomize.py`
    reachable through `PYTHONPATH` cannot execute inside the judge.
    """
    del env  # 측정 대상 환경은 판정기에 전달하지 않는다.
    payload = task.success_checker_bytes
    if not payload:
        return "success_checker_infra_invalid"
    checker_executable = sys.executable
    if interpreter_binding is not None:
        try:
            checker_executable = _benchmark_study_v2_assert_python_binding(
                interpreter_binding, require_current=False,
            )
        except (OSError, TypeError, ValueError):
            return "success_checker_infra_invalid"
    private_root: str | None = None
    try:
        private_root = tempfile.mkdtemp(prefix="contextguard-bench-checker-")
        os.chmod(private_root, 0o700)
        checker_path = Path(private_root) / "checker.py"
        fd = _measurement_create_exclusive(checker_path)
        try:
            _measurement_write_fd(fd, payload)
        finally:
            os.close(fd)
        os.chmod(checker_path, 0o500)
        # 판정기는 -I 로 격리 실행한다. 에이전트가 쓰기 가능한 workspace 가 PYTHONPATH/
        # PYTHONHOME/PYTHONSTARTUP 또는 sys.path[0] 로 들어오면 심어둔 sitecustomize.py 가
        # 판정기 안에서 실행되어 위협 모델이 무너진다. 환경도 물려받지 않고 최소로 만든다.
        result = run_bounded_command(
            [checker_executable, "-I", str(checker_path)],
            cwd=workspace,
            timeout_seconds=600,
            max_output_bytes=SUCCESS_COMMAND_OUTPUT_MAX_BYTES,
            env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired, ValueError, SystemExit):
        return "success_checker_infra_invalid"
    finally:
        if private_root is not None:
            shutil.rmtree(private_root, ignore_errors=True)
    if len(result.stdout_bytes.splitlines()) > 4096 or len(result.stderr_bytes.splitlines()) > 4096:
        return "success_checker_infra_invalid"
    if any(
        len(line) > 16_384
        for raw in (result.stdout_bytes, result.stderr_bytes)
        for line in raw.splitlines()
    ):
        return "success_checker_infra_invalid"
    return classify_success_checker(result)


def _measurement_create_exclusive(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = _open_regular_no_symlink(path, flags, 0o600)
    except FileExistsError:
        raise SystemExit(f"measurement artifact already exists: {path.name}") from None
    os.fchmod(fd, 0o600)
    return fd


def _measurement_write_fd(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while persisting measurement artifact")
        view = view[written:]
    os.fsync(fd)


def _measurement_write_exclusive(path: Path, payload: bytes) -> None:
    fd = _measurement_create_exclusive(path)
    try:
        _measurement_write_fd(fd, payload)
    finally:
        os.close(fd)


def _measurement_create_run_context(
    spec: MeasurementVariant, task_id: str, *, locked_root_fd: int | None = None,
) -> MeasurementRunContext:
    root_fd = locked_root_fd if locked_root_fd is not None else _ensure_directory_no_symlink(spec.artifact_root, create=True)
    owns_root_fd = locked_root_fd is None
    try:
        os.fchmod(root_fd, 0o700)
        if owns_root_fd and fcntl is not None:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
        run_id = spec.identity.run_id(task_id)
        try:
            os.mkdir("runs", 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass
        runs_fd = _open_directory_at(root_fd, "runs", spec.artifact_root / "runs")
        try:
            os.fchmod(runs_fd, 0o700)
            try:
                os.mkdir(run_id, 0o700, dir_fd=runs_fd)
            except FileExistsError:
                raise SystemExit(f"duplicate measurement run id: {run_id}") from None
            run_fd = _open_directory_at(runs_fd, run_id, spec.artifact_root / "runs" / run_id)
            try:
                os.fchmod(run_fd, 0o700)
                for name in (
                    "home",
                    "xdg-config",
                    "xdg-cache",
                    "xdg-data",
                    "xdg-state",
                    "tmp",
                    "workspace",
                    "session",
                ):
                    os.mkdir(name, 0o700, dir_fd=run_fd)
            finally:
                os.close(run_fd)
        finally:
            os.close(runs_fd)
    finally:
        if owns_root_fd:
            os.close(root_fd)
    run_root = spec.artifact_root / "runs" / run_id
    return MeasurementRunContext(
        run_id=run_id,
        run_root=run_root,
        home=run_root / "home",
        xdg_config=run_root / "xdg-config",
        xdg_cache=run_root / "xdg-cache",
        xdg_data=run_root / "xdg-data",
        xdg_state=run_root / "xdg-state",
        tmp=run_root / "tmp",
        workspace=run_root / "workspace",
        session=run_root / "session",
        raw_path=run_root / "raw.ndjson",
        receipt_path=run_root / "receipt.json",
        index_path=spec.artifact_root / "artifact-index.ndjson",
    )


def _measurement_bounded_scalar(value: Any) -> str | None:
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        return None
    if len(text) > MEASUREMENT_HOOK_TEXT_MAX_CHARS:
        return text[:MEASUREMENT_HOOK_TEXT_MAX_CHARS]
    return text


def _measurement_domain_hash(domain: bytes, *values: str) -> str:
    encoded = b"".join(
        struct.pack(">Q", len(value.encode("utf-8"))) + value.encode("utf-8")
        for value in values
    )
    return hashlib.sha256(domain + b"\0" + encoded).hexdigest()


def _measurement_binding_set_sha256(bindings: tuple[tuple[str, str], ...]) -> str:
    encoded = json.dumps(
        [list(binding) for binding in bindings], ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(
        b"contextguard.bench.binding-set.v2\0" + struct.pack(">Q", len(encoded)) + encoded
    ).hexdigest()


def _parse_measurement_hook_events(raw: bytes) -> dict[str, Any]:
    hooks: list[dict[str, Any]] = []
    states: dict[tuple[str, str], dict[str, Any]] = {}
    observed = 0
    records = 0
    failure_flags: set[str] = set()
    classification: str | None = None
    for line in raw.splitlines():
        try:
            event = json.loads(line, object_pairs_hook=_stream_object_no_duplicates, parse_constant=_stream_reject_nonfinite)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "hook_event":
            classification = classification or "invalid_hook_lifecycle"
            continue
        if event.get("type") != "system" or event.get("subtype") not in {"hook_started", "hook_progress", "hook_response"}:
            continue
        records += 1
        if records > MEASUREMENT_HOOK_MAX_EVENTS:
            failure_flags.add("hook_lifecycle_limit")
        subtype = event["subtype"]
        required = ("session_id", "hook_id", "hook_name", "hook_event", "uuid")
        invalid = False
        for field_name in required:
            value = event.get(field_name)
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MEASUREMENT_HOOK_FIELD_MAX_BYTES:
                invalid = True
        if invalid:
            failure_flags.add("invalid_hook_lifecycle")
            continue
        hook_event = event["hook_event"]
        supported = hook_event in MEASUREMENT_DOCUMENTED_HOOK_EVENTS
        if not supported:
            failure_flags.add("unexpected_hook_event_class")
        key = (event["session_id"], event["hook_id"])
        identity = (event["hook_name"], hook_event)
        if subtype == "hook_started":
            if key in states:
                failure_flags.add("invalid_hook_lifecycle")
                continue
            states[key] = {"identity": identity, "progress_count": 0}
            observed += 1
            continue
        outputs_valid = True
        for output_name in ("stdout", "stderr", "output"):
            output = event.get(output_name)
            if not isinstance(output, str):
                outputs_valid = False
            elif len(output.encode("utf-8")) > MEASUREMENT_HOOK_OUTPUT_MAX_BYTES:
                failure_flags.add("hook_payload_limit")
                outputs_valid = False
        if not outputs_valid:
            if "hook_payload_limit" not in failure_flags:
                failure_flags.add("invalid_hook_lifecycle")
            continue
        state = states.get(key)
        if state is None or state["identity"] != identity:
            failure_flags.add("invalid_hook_lifecycle")
            continue
        if subtype == "hook_progress":
            state["progress_count"] += 1
            continue
        outcome = event.get("outcome")
        exit_code = event.get("exit_code")
        if outcome not in {"success", "error", "cancelled"} or (
            exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int))
        ):
            failure_flags.add("invalid_hook_lifecycle")
            continue
        states.pop(key)
        triggering = "not_applicable"
        if hook_event == "PostToolUse":
            triggering = "succeeded"
        elif hook_event == "PostToolUseFailure":
            triggering = "failed"
        hooks.append({
            "hook_event": hook_event,
            "opaque_hook_name_sha256": _measurement_domain_hash(b"contextguard.bench.opaque-hook-name.v2", event["hook_name"]),
            "lifecycle_key_sha256": _measurement_domain_hash(b"contextguard.bench.hook-lifecycle-key.v2", event["session_id"], event["hook_id"]),
            "hook_process_outcome": outcome,
            "hook_process_exit_code": exit_code,
            "triggering_tool_outcome": triggering,
            "progress_count": state["progress_count"],
        })
    if classification is not None:
        failure_flags.add(classification)
    if states:
        failure_flags.add("invalid_hook_lifecycle")
    classification = next(
        (status for status in (
            "hook_payload_limit", "hook_lifecycle_limit", "invalid_hook_lifecycle",
            "unexpected_hook_event_class",
        ) if status in failure_flags),
        None,
    )
    return {
        "hooks": hooks, "observed": observed, "records": records,
        "classification": classification, "failure_flags": frozenset(failure_flags),
    }


def normalize_measurement_hook_events(raw: bytes) -> list[dict[str, Any]]:
    result = _parse_measurement_hook_events(raw)
    if result["classification"] is not None:
        raise ValueError(result["classification"])
    return result["hooks"]


def _measurement_resolve_terminal_status(
    *, raw_byte_limit: bool, raw_line_limit: bool, raw_line_byte_limit: bool,
    process_status: str, stream_status: str, hook_result: dict[str, Any],
    arm: str, allowed_event_classes: tuple[str, ...],
    required_event_classes: tuple[str, ...],
) -> str:
    completed_classes = {item["hook_event"] for item in hook_result["hooks"]}
    allowed_classes = set(allowed_event_classes)
    required_classes = set(required_event_classes)
    hook_process_failed = any(
        item["hook_process_outcome"] != "success" or item["hook_process_exit_code"] not in (None, 0)
        for item in hook_result["hooks"]
    )
    if raw_byte_limit:
        return "raw_byte_limit"
    if raw_line_limit:
        return "raw_line_limit"
    if raw_line_byte_limit:
        return "raw_line_byte_limit"
    if process_status == "timed_out":
        return "process_timeout"
    if process_status == "launch_error":
        return "process_launch_error"
    if process_status == "exited_nonzero":
        return "process_error"
    if stream_status == "terminal_error":
        return "terminal_error"
    if stream_status == "missing_terminal":
        return "missing_terminal"
    if stream_status != "success":
        return "invalid_stream"
    for status in (
        "hook_payload_limit", "hook_lifecycle_limit", "invalid_hook_lifecycle",
        "unexpected_hook_event_class",
    ):
        if hook_result.get("classification") == status or status in hook_result.get("failure_flags", ()):
            return status
    hook_arms = {"treatment", "legacy_trim", "bash_reference_v1"}
    unmodified_arms = {"baseline", "host_unmodified"}
    if arm in hook_arms and completed_classes - allowed_classes:
        return "unexpected_hook_event_class"
    if arm in unmodified_arms and hook_result["observed"]:
        return "baseline_hook_contamination"
    if arm in hook_arms and required_classes - completed_classes:
        return "missing_required_hook_event_class"
    if hook_process_failed:
        return "hook_process_failure"
    return "success"


def _measurement_append_index(
    path: Path, record: dict[str, Any], *, artifact_root_locked: bool = False,
) -> None:
    payload = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    parent_fd = _ensure_directory_no_symlink(path.parent)
    try:
        if fcntl is not None and not artifact_root_locked:
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
        try:
            fd = _measurement_create_exclusive(path)
        except SystemExit:
            flags = os.O_WRONLY | os.O_APPEND
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = _open_regular_no_symlink(path, flags)
            os.fchmod(fd, 0o600)
        try:
            _measurement_write_fd(fd, payload)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _measurement_receipt(
    context: MeasurementRunContext,
    task: TaskFixture,
    spec: MeasurementVariant,
    raw: bytes,
    hook_result: dict[str, Any],
    settings_bytes: bytes,
    *,
    process_status: str,
    terminal_status: str,
) -> dict[str, Any]:
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    raw_lines = len(raw.splitlines())
    allowed_classes = tuple(dict.fromkeys(event for event, _command in spec.pair_registered_bindings))
    required_classes = spec.required_event_classes
    counts = collections.Counter(item["hook_event"] for item in hook_result["hooks"])
    event_class_counts = [
        {"hook_event": event, "count": counts[event]}
        for event in MEASUREMENT_DOCUMENTED_HOOK_EVENTS
        if counts[event] or event in allowed_classes
    ]
    settings_relative = Path("session") / spec.settings_file.name
    return {
        "schema_version": MEASUREMENT_RAW_RECEIPT_SCHEMA_VERSION,
        "run_identity": {
            "candidate_hash": spec.identity.candidate_hash,
            "task": task.id,
            "repetition": spec.identity.repetition,
            "arm": spec.identity.arm,
            "attempt": spec.identity.attempt,
            "namespace": spec.identity.namespace,
            "run_id": context.run_id,
        },
        "raw_artifact": {
            "path": context.raw_path.name,
            "sha256": raw_sha256,
            "bytes": len(raw),
            "lines": raw_lines,
            "events": raw_lines,
        },
        "settings_artifact": {
            "path": settings_relative.as_posix(),
            "sha256": hashlib.sha256(settings_bytes).hexdigest(),
            "bytes": len(settings_bytes),
            "binding_set_sha256": _measurement_binding_set_sha256(spec.pair_registered_bindings),
        },
        "process_status": process_status,
        "terminal_status": terminal_status,
        "hook_summary": {
            "required_event_classes": list(required_classes),
            "observed_lifecycle_count": hook_result["observed"],
            "completed_lifecycle_count": len(hook_result["hooks"]),
            "event_class_counts": event_class_counts,
        },
        "hooks": hook_result["hooks"],
    }


def _run_measurement_fixture(
    task: TaskFixture,
    variant: Variant,
    claude_bin: str,
    project_root: Path,
) -> RunResult:
    spec = variant.measurement
    assert spec is not None
    validate_measurement_cli_capabilities(claude_bin, spec)
    root_fd = _ensure_directory_no_symlink(spec.artifact_root, create=True)
    try:
        os.fchmod(root_fd, 0o700)
        if fcntl is not None:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
        return _run_measurement_fixture_locked(
            task, variant, claude_bin, project_root, locked_root_fd=root_fd,
        )
    finally:
        os.close(root_fd)


def _run_measurement_fixture_locked(
    task: TaskFixture,
    variant: Variant,
    claude_bin: str,
    project_root: Path,
    *,
    locked_root_fd: int,
    on_process_started: Callable[[], None] | None = None,
    measurement_study: bool = False,
    workspace_overlay: Path | None = None,
    on_workspace_prepared: Callable[[Path], None] | None = None,
    checker_interpreter_binding: Mapping[str, Any] | None = None,
    existing_login_home: Path | None = None,
) -> RunResult:
    spec = variant.measurement
    assert spec is not None
    started_at = time.monotonic()
    run_id = spec.identity.run_id(task.id)
    _measurement_check_artifact_identity_locked(
        spec, task, run_id, artifact_root_locked=True,
    )
    context = _measurement_create_run_context(spec, task.id, locked_root_fd=locked_root_fd)
    # S003: 각 attempt 는 cold isolated workspace 에서 시작하므로, 선언된 fixture tree 를
    # 정확히 같은 바이트로 재구성하는 것이 결정적 reset 이다. 선언이 없으면 기존 동작 유지.
    # 분기는 선언 상태(fixture_tree)로 하고 바인딩 누락은 fail-closed 로 처리한다.
    # 바인딩 상태로 분기하면 다른 진입점이 조용히 빈 workspace 와 legacy 체커로 떨어진다.
    if task.fixture_tree is not None and not task.fixture_tree_entries:
        raise SystemExit(
            "measurement fixture tree was not bound before launch; call "
            "load_task_fixture_trees for every task declaring fixture_tree"
        )
    reset_task_fixture_tree(task.fixture_tree_entries or (), context.workspace)
    if workspace_overlay is not None:
        destination = context.workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME
        if destination.exists() or destination.is_symlink():
            raise SystemExit("measurement candidate overlay destination already exists")
        shutil.copytree(
            workspace_overlay,
            destination,
            symlinks=True,
            copy_function=shutil.copy2,
        )
    if on_workspace_prepared is not None:
        on_workspace_prepared(context.workspace)
    settings_snapshot = context.session / spec.settings_file.name
    _measurement_write_exclusive(settings_snapshot, spec.settings_source_bytes)
    try:
        _measurement_validate_snapshot(context, spec)
    except (OSError, SystemExit, TypeError, ValueError):
        raise SystemExit("measurement artifact integrity check failed") from None
    raw_fd = _measurement_create_exclusive(context.raw_path)
    argv = build_claude_argv(
        executable_argv0(claude_bin),
        task,
        variant,
        measurement_settings_file=settings_snapshot,
    )
    env = _measurement_child_env(
        spec, context, existing_login_home=existing_login_home,
    )
    try:
        try:
            proc = run_bounded_command(
                argv,
                cwd=context.workspace,
                timeout_seconds=1800,
                max_output_bytes=MEASUREMENT_RAW_MAX_BYTES,
                env=env,
                stdout_sink_fd=raw_fd,
                on_process_started=on_process_started,
            )
            raw = proc.stdout_bytes
        except _MeasurementLaunchError:
            if measurement_study:
                raise
            proc = BoundedProcessResult(126, "", "", False, False, b"", b"", True)
            raw = b""
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise SystemExit("measurement artifact integrity check failed") from None
    finally:
        os.close(raw_fd)

    try:
        settings_bytes = _measurement_validate_snapshot(context, spec)
    except (OSError, SystemExit, TypeError, ValueError):
        raise SystemExit("measurement artifact integrity check failed") from None
    parsed = parse_claude_stream_output(raw, max_line_bytes=MEASUREMENT_RAW_MAX_LINE_BYTES)
    hook_result = _parse_measurement_hook_events(raw)
    if proc.timed_out:
        process_status = "timed_out"
    elif proc.launch_error:
        process_status = "launch_error"
    elif proc.returncode == 0:
        process_status = "exited_zero"
    else:
        process_status = "exited_nonzero"
    line_count = len(raw.splitlines())
    raw_line_too_large = any(len(line) > MEASUREMENT_RAW_MAX_LINE_BYTES for line in raw.splitlines())
    terminal_status = _measurement_resolve_terminal_status(
        raw_byte_limit=proc.output_truncated,
        raw_line_limit=line_count > MEASUREMENT_RAW_MAX_LINES,
        raw_line_byte_limit=raw_line_too_large,
        process_status=process_status,
        stream_status=parsed.status,
        hook_result=hook_result,
        arm=variant.name,
        allowed_event_classes=tuple(
            dict.fromkeys(event for event, _command in spec.pair_registered_bindings)
        ),
        required_event_classes=spec.required_event_classes,
    )

    receipt = _measurement_receipt(
        context,
        task,
        spec,
        raw,
        hook_result,
        settings_bytes,
        process_status=process_status,
        terminal_status=terminal_status,
    )
    receipt_bytes = json.dumps(
        receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    _measurement_write_exclusive(context.receipt_path, receipt_bytes)
    _measurement_append_index(context.index_path, {
        "schema_version": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
        "run_id": context.run_id,
        "receipt_path": str(context.receipt_path),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "terminal_status": receipt["terminal_status"],
    }, artifact_root_locked=True)

    failure_code = None if terminal_status == "success" else terminal_status
    if failure_code is not None or parsed.payload is None:
        return RunResult(
            task_id=task.id,
            variant=variant.name,
            model=task.model,
            effort=task.effort or "",
            tokens={key: 0 for key, _ in USAGE_KEY_GROUPS},
            cost_usd=0.0,
            success=False,
            notes=failure_code or "measurement_stream_missing_payload",
            wall_time_seconds=elapsed_seconds_since(started_at),
        )

    if measurement_study:
        try:
            exact_usage = parse_measurement_terminal_usage(raw)
        except ValueError:
            return RunResult(
                task_id=task.id,
                variant=variant.name,
                model=task.model,
                effort=task.effort or "",
                tokens={key: 0 for key, _ in USAGE_KEY_GROUPS},
                cost_usd=0.0,
                success=False,
                notes="terminal_usage_infra_invalid",
                wall_time_seconds=elapsed_seconds_since(started_at),
            )
        tokens = {
            "input_tokens": exact_usage["input_tokens"],
            "output_tokens": exact_usage["output_tokens"],
            "cache_read": exact_usage["cache_read_input_tokens"],
            "cache_creation": exact_usage["cache_creation_input_tokens"],
        }
        cost, cost_available, primary_tokens_measured = 0.0, False, True
    else:
        tokens, cost, cost_available, primary_tokens_measured = collect_usage(parsed.payload)
    provider_cached_tokens, provider_cached_tokens_measured = collect_provider_cache_telemetry(parsed.payload)
    shift_metrics = collect_shift_metrics(parsed.payload)
    self_hosted_metrics = collect_self_hosted_metrics(parsed.payload)
    if measurement_study:
        # fixture tree 를 선언한 S003 task 는 매니페스트에 바인딩된 checker 바이트를
        # workspace 밖 비공개 디렉터리에서 실행한다. 그래야 측정 대상 에이전트가
        # 판정기를 덮어써서 거짓 성공을 만들 수 없다.
        if task.fixture_tree is not None:
            if not task.success_checker_bytes:
                raise SystemExit(
                    "measurement success checker was not bound before launch; call "
                    "load_task_fixture_trees for every task declaring fixture_tree"
                )
            checker_classification = run_task_checker_study(
                task, context.workspace, env=env,
                interpreter_binding=checker_interpreter_binding,
            )
        else:
            checker_classification = run_success_command_study(task, project_root, env=env)
        success = checker_classification == "task_success"
        success_note = checker_classification
    else:
        success, success_note = run_success_command(task, project_root, env=env)
    return RunResult(
        task_id=task.id,
        variant=variant.name,
        model=task.model,
        effort=task.effort or "",
        tokens=tokens,
        cost_usd=cost,
        success=success,
        notes=success_note,
        cost_measured=False,
        primary_cost_provenance=(
            PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE
            if cost_available else PRIMARY_COST_PROVENANCE_UNAVAILABLE
        ),
        primary_tokens_measured=primary_tokens_measured,
        wall_time_seconds=elapsed_seconds_since(started_at),
        turns=int(shift_metrics["turns"]),
        hook_triggers=len(hook_result["hooks"]),
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
    if variant.measurement is not None:
        return _run_measurement_fixture(task, variant, claude_bin, project_root)
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
    if task.output_format == "stream-json":
        parsed_stream = parse_claude_stream_output(proc.stdout_bytes)
        if parsed_stream.status == "terminal_error":
            return RunResult(
                task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
                tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
                success=False,
                notes=f"claude stream terminal_error:{parsed_stream.result_code}",
                wall_time_seconds=elapsed_seconds_since(started_at),
            )
        if parsed_stream.status in {"missing_terminal", "invalid_stream"}:
            return RunResult(
                task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
                tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
                success=False,
                notes=f"claude stream protocol_error:{parsed_stream.error_code}",
                wall_time_seconds=elapsed_seconds_since(started_at),
            )
        if proc.returncode != 0:
            return RunResult(
                task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
                tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
                success=False, notes="claude stream process_error:nonzero_exit_after_success",
                wall_time_seconds=elapsed_seconds_since(started_at),
            )
        if parsed_stream.payload is None:  # Defensive: status=success always carries the result.
            return RunResult(
                task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
                tokens={k: 0 for k, _ in USAGE_KEY_GROUPS}, cost_usd=0.0,
                success=False, notes="claude stream protocol_error:stream_result_shape",
                wall_time_seconds=elapsed_seconds_since(started_at),
            )
        payload = parsed_stream.payload
    else:
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
    tokens, cost, cost_available, primary_tokens_measured = collect_usage(payload)
    provider_cached_tokens, provider_cached_tokens_measured = collect_provider_cache_telemetry(payload)
    shift_metrics = collect_shift_metrics(payload)
    self_hosted_metrics = collect_self_hosted_metrics(payload)
    success, success_note = run_success_command(task, project_root)
    return RunResult(
        task_id=task.id, variant=variant.name, model=task.model, effort=task.effort,
        tokens=tokens, cost_usd=cost, success=success, notes=success_note,
        # Claude Code's `total_cost_usd`/`modelUsage.costUSD` fields are local
        # client estimates.  Keep the diagnostic value, but never promote it to
        # authoritative provider-billing evidence.
        cost_measured=False,
        primary_cost_provenance=(
            PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE
            if cost_available else PRIMARY_COST_PROVENANCE_UNAVAILABLE
        ),
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
    with csv_parent_directory_lock(csv_path, create_parent=True):
        with csv_file_lock(csv_path, create_parent=False):
            return append_csv_unlocked(
                csv_path,
                claude_ver,
                result,
                skip_existing=skip_existing,
                existing_key_cache=existing_key_cache,
                existing_key_cache_stamp=existing_key_cache_stamp,
            )


def append_csv_unlocked(
    csv_path: Path,
    claude_ver: str,
    result: RunResult,
    *,
    skip_existing: bool = False,
    existing_key_cache: set[tuple[str, str]] | None = None,
    existing_key_cache_stamp: dict[str, tuple[int, int, int, int] | None] | None = None,
) -> bool:
    """Append one row while the caller holds the CSV transaction lock."""
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
                "primary_cost_provenance": sanitize_csv_cell(result.primary_cost_provenance),
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
    result.validate_primary_cost_contract()
    return (
        result.cost_measured
        and result.external_tokens_measured
        and (result.external_tokens == 0 or result.external_cost_measured)
    )


def primary_cost_display(result: RunResult) -> str:
    """Format CLI diagnostics without overstating client-estimated billing data."""
    result.validate_primary_cost_contract()
    if result.primary_cost_provenance == PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE:
        return f"cost_estimate=${result.cost_usd:.4f}"
    if result.cost_measured:
        return f"cost=${result.cost_usd:.4f}"
    if result.cost_usd:
        return f"cost_unmeasured=${result.cost_usd:.4f}"
    return "cost=unavailable"


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
        "primary_cost_provenance": result.primary_cost_provenance,
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
                validate_primary_cost_row_contract(row, owner=f"CSV {csv_path} row {index}")
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
                validate_primary_cost_row_contract(row, owner=f"CSV {csv_path} row {index}")
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
        primary_cost_provenance=(
            PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT
            if cost_measured else PRIMARY_COST_PROVENANCE_UNAVAILABLE
        ),
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
    # Profile metadata 는 추가 필드로만 수집한다. 깊은 검증은 preflight 에서 task/prompt
    # 문맥과 함께 수행하며, 어떤 출력도 기록되기 전에 끝난다.
    # profile 오류는 evidence 파일 경로를 절대 echo 하지 않는다. 줄 번호만으로 위치를 준다.
    profile_row_owner = f"evidence line {line_number}"
    evaluation_profile = raw.get("evaluation_profile")
    if evaluation_profile is not None and (
        not isinstance(evaluation_profile, str)
        or evaluation_profile not in SUPPORTED_EVALUATION_PROFILE_IDS
    ):
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, profile_row_owner,
            "evaluation_profile is not a supported profile id",
        )
    evaluation_controls = raw.get("evaluation_controls")
    if evaluation_controls is not None and not isinstance(evaluation_controls, dict):
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, profile_row_owner,
            "evaluation_controls must be a JSON object",
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
        evaluation_profile=evaluation_profile,
        evaluation_controls=evaluation_controls,
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


def row_primary_cost_provenance(row: dict[str, str]) -> str:
    """Return a report-safe provenance value for possibly synthetic rows."""
    provenance = str(row.get("primary_cost_provenance") or "").strip()
    if provenance in {
        PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE,
        PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT,
        PRIMARY_COST_PROVENANCE_UNAVAILABLE,
    }:
        return provenance
    return PRIMARY_COST_PROVENANCE_UNAVAILABLE


def row_primary_cost_measured(row: dict[str, str]) -> bool:
    """Gate primary cost on both the measured flag and provider provenance."""
    return (
        row_bool(row, "cost_measured")
        and row_primary_cost_provenance(row) == PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT
    )


def validate_primary_cost_row_contract(row: dict[str, str], *, owner: str) -> None:
    """Fail closed when a persisted CSV row contradicts the v2 cost contract."""
    raw_provenance = str(row.get("primary_cost_provenance") or "").strip()
    allowed = {
        PRIMARY_COST_PROVENANCE_CLIENT_ESTIMATE,
        PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT,
        PRIMARY_COST_PROVENANCE_UNAVAILABLE,
    }
    if raw_provenance and raw_provenance not in allowed:
        raise SystemExit(
            f"{owner}: primary_cost_provenance must be one of "
            "client_estimate, provider_export, unavailable"
        )
    provenance = raw_provenance or PRIMARY_COST_PROVENANCE_UNAVAILABLE
    if row_bool(row, "cost_measured") != (provenance == PRIMARY_COST_PROVENANCE_PROVIDER_EXPORT):
        raise SystemExit(
            f"{owner}: cost_measured must be true exactly when "
            "primary_cost_provenance is provider_export"
        )


def row_success(row: dict[str, str]) -> bool:
    return str(row.get("success") or "").strip().lower() == "true"


def row_cost_shift_measured(row: dict[str, str]) -> bool:
    return (
        row_primary_cost_measured(row)
        and row_bool(row, "external_tokens_measured")
        and (row_int(row, "external_tokens") == 0 or row_bool(row, "external_cost_measured"))
    )


def measurement_baseline_contract() -> dict[str, Any]:
    """Describe the benchmark report's current measurement baseline contract.

    Version 2 records the append-only `primary_cost_provenance` CSV column.
    Existing CSVs must start a new file or migrate their exact header before
    append. This block does not grant token/cost savings claims by itself;
    those remain gated by matched successful tasks, measured primary
    tokens/costs, shifted-cost accounting, and quality gates.
    """
    return {
        "schema_version": MEASUREMENT_BASELINE_SCHEMA_VERSION,
        "csv_schema_unchanged": False,
        "csv_schema_change": {
            "change_type": "append_only_column",
            "added_columns": ["primary_cost_provenance"],
            "removed_columns": [],
            "migration": "start_new_csv_or_migrate_exact_header_before_append",
        },
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
            "primary_cost": ["cost_usd", "cost_measured", "primary_cost_provenance"],
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


# --- image-context evaluation profile: bounded validation + fail-closed preflight ---
#
# 검증 순서는 불변이다: 타입/바운드 검사가 항상 semantic 정책 분류보다 먼저 실행된다.
# 따라서 oversize 된 non-`deny` 정책 값이 blocked-scorecard 분기로 새어나갈 수 없다.
# 구조적으로 해석 불가능한 evidence 는 어떤 출력 바이트도 쓰이기 전에 거부(reject_prewrite)되고,
# 형식이 올바른 negative evidence 는 수용되어 blocked lane score 로 보고된다.

PROFILE_CONTROL_BLOCK_KEYS = (
    "control_provenance",
    "exact_text_fallback",
    "human_correction",
    "missed_context_review",
    "prompt_evidence",
    "protected_zone_review",
    "provider_usage",
    "shifted_cost",
    "source_omission",
)
PROFILE_NESTED_KEYS: dict[str, tuple[str, ...]] = {
    "control_provenance": ("review_source", "verifier_label"),
    "exact_text_fallback": (
        "available", "verified", "receipt_id", "content_sha256",
        "retrieval_command", "verifier_projection",
    ),
    "human_correction": ("count", "reason"),
    "missed_context_review": ("correction_required", "present", "review_completed", "summary"),
    "prompt_evidence": ("sha256", "source_label"),
    "protected_zone_review": (
        "included_prompt_like_regions", "included_protected_regions", "policy",
        "review_completed", "review_note", "reviewer_label",
    ),
    "provider_usage": ("primary_cost_measured", "primary_tokens_measured", "provider_called"),
    "shifted_cost": ("external_cost_measured", "external_tokens_measured", "status"),
    "source_omission": ("present", "transform"),
}
PROFILE_PROJECTION_KEYS = (
    "schema", "status", "blockers", "candidate_replacement", "claim_boundary", "proof_unit",
)
PROFILE_PROOF_UNIT_KEYS = (
    "status", "receipt_id", "receipt_verified", "content_hash_declared_value",
    "content_hash_verified", "rehydration_receipt_bound", "rehydration_syntax_valid",
    "rehydration_verified", "rehydration_executed", "retrieval_command",
)
PROFILE_PROOF_UNIT_REQUIRED_FLAGS = (
    "receipt_verified",
    "content_hash_verified",
    "rehydration_receipt_bound",
    "rehydration_syntax_valid",
    "rehydration_verified",
)
PROFILE_SHIFTED_COST_STATUSES = ("measured", "unmeasured")


def redact_profile_label(value: Any) -> str:
    """Bound one untrusted label so an error message can never carry a payload.

    Task ids, variant names, unknown evidence keys, and prompt-map labels are
    author-controlled. Opted-in profile diagnostics must use a fully opaque fixed
    representation for every such value — even regex-safe-looking identifiers —
    because any preserved attacker text is itself a leak channel. The stable error
    id and fixed field names carry the meaning; ``value`` is intentionally unused.
    """
    # 작성자 통제 값은 형태와 무관하게 절대 진단에 싣지 않는다.
    return PROFILE_REDACTED_PLACEHOLDER


def redact_profile_labels(values: Iterable[Any]) -> str:
    """Render a bounded, fully opaque key list for schema errors.

    The count is always truthful; each name collapses to the shared placeholder so
    no author-controlled text rides the message. The list is truncated so an
    oversized evidence object cannot flood the diagnostic.
    """
    labels = [redact_profile_label(value) for value in values]
    shown = labels[:MAX_PROFILE_ERROR_LABELS]
    overflow = len(labels) - len(shown)
    rendered = ", ".join(shown)
    if overflow > 0:
        rendered = f"{rendered}, +{overflow} more"
    return rendered


def profile_owner(task_id: Any, variant: Any = None) -> str:
    """Build the redacted owner prefix shared by every profile error."""
    owner = f"task {redact_profile_label(task_id)}"
    if variant is not None:
        owner = f"{owner} variant {redact_profile_label(variant)}"
    return owner


def profile_reject(error_id: str, owner: str, detail: str) -> "NoReturn":
    """Fail closed with a stable id and a bounded, redacted message.

    Raw policy text, prompt content, and filesystem paths are never echoed. ``owner``
    must already come from :func:`profile_owner` and ``detail`` must be a fixed
    literal or a redacted label list; the final message is sanitized again so no
    caller can smuggle a secret-shaped value through.
    """
    raise SystemExit(sanitize_note_text(f"{error_id}: {owner} {detail}"))


def profile_block(controls: dict[str, Any], key: str, *, owner: str) -> dict[str, Any]:
    if key not in controls:
        profile_reject(PROFILE_REJECT_CONTROLS_MISSING, owner, f"evaluation_controls.{key} is required")
    value = controls[key]
    if not isinstance(value, dict):
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"evaluation_controls.{key} must be an object")
    unknown = sorted(set(value) - set(PROFILE_NESTED_KEYS[key]))
    if unknown:
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, owner,
            f"evaluation_controls.{key} has unknown v1 key(s): {redact_profile_labels(unknown)}",
        )
    return value


def profile_bool(block: dict[str, Any], key: str, *, owner: str, label: str) -> bool:
    value = block.get(key)
    if not isinstance(value, bool):
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"{label}.{key} must be a boolean")
    return value


def profile_int(block: dict[str, Any], key: str, *, owner: str, label: str, maximum: int) -> int:
    value = block.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"{label}.{key} must be an integer")
    if value < 0 or value > maximum:
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"{label}.{key} is outside its allowed bounds")
    return value


def profile_text(block: dict[str, Any], key: str, *, owner: str, label: str, maximum: int) -> str:
    value = block.get(key)
    if not isinstance(value, str):
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"{label}.{key} must be a string")
    if len(value.encode("utf-8")) > maximum:
        # 값 자체는 절대 에러에 실지 않는다. 길이 위반 사실만 보고한다.
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, f"{label}.{key} exceeds its {maximum}-byte bound")
    return value


def profile_variant_prompt_sha256(task: TaskFixture, variant_name: str, *, task_file_dir: Path, owner: str) -> str:
    """SHA-256 of the selected variant prompt file, read with the existing safe reader."""
    raw_path = task.variant_prompt_files.get(variant_name)
    if not raw_path:
        profile_reject(
            PROFILE_REJECT_PROMPT_BINDING_INVALID, owner,
            "a profiled task requires a file-backed variant_prompt_files entry for every selected variant",
        )
    try:
        rel_path = validate_variant_prompt_file_path(raw_path, owner=owner)
        text = read_variant_prompt_file(
            task_file_dir / rel_path, owner=owner, display_path=str(rel_path),
        )
    except (SystemExit, ValueError, UnicodeError):
        # SystemExit: 경로/내용 누설 방지용 안정 프로파일 오류 재작성.
        # ValueError/UnicodeError: 조기 검증을 지나친 os.open NUL·인코딩 거부 등만 좁게 정규화.
        # 프로그래머 버그를 숨기지 않도록 범용 Exception 은 잡지 않는다.
        profile_reject(
            PROFILE_REJECT_PROMPT_BINDING_INVALID, owner,
            "the selected variant prompt file could not be safely read",
        )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_profile_fallback_projection(fallback: dict[str, Any], *, owner: str) -> None:
    """Validate one bounded imported local-verifier projection.

    A record that *claims* verification while contradicting its own binding fields is a
    structural rejection. Replay never authenticates the record's author and never
    rereads the artifact; this only checks internal consistency.
    """
    # 검증을 주장하려면 fallback 자체가 available 이어야 한다. available=false 인데
    # verified=true 인 레코드는 자기 모순이다.
    if fallback.get("available") is not True:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification while declaring the fallback unavailable",
        )
    # placeholder receipt/command 로는 어떤 것도 되찾을 수 없다. 검증 주장에는 실제
    # 값이 필요하다.
    for key in ("receipt_id", "retrieval_command"):
        value = fallback.get(key)
        if not isinstance(value, str) or value.strip().lower() in PROFILE_FALLBACK_PLACEHOLDER_VALUES:
            profile_reject(
                PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
                f"exact_text_fallback claims verification without an exact {key}",
            )
    projection = fallback.get("verifier_projection")
    if not isinstance(projection, dict):
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification without a bounded verifier projection",
        )
    unknown = sorted(set(projection) - set(PROFILE_PROJECTION_KEYS))
    if unknown:
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, owner,
            f"exact_text_fallback.verifier_projection has unknown v1 key(s): {redact_profile_labels(unknown)}",
        )
    if projection.get("schema") != PROOF_VERIFICATION_SCHEMA_VERSION:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "verifier projection schema does not match the local proof-verification contract",
        )
    if projection.get("status") != PROOF_VERIFICATION_VERIFIED_STATUS:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification but the verifier status is not verified",
        )
    blockers = projection.get("blockers")
    if not isinstance(blockers, list) or len(blockers) > MAX_PROFILE_BLOCKER_ITEMS:
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, "verifier projection blockers must be a bounded list")
    if blockers:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification but the verifier reports blockers",
        )
    if projection.get("candidate_replacement") is not None:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification but the verifier proposes a candidate replacement",
        )
    # 가져온 레코드는 local-only 경계를 그대로 선언해야 한다. 경계가 다르면 이 lane 이
    # 인정할 수 있는 권한 범위를 벗어난 주장이다.
    if projection.get("claim_boundary") != PROOF_VERIFICATION_CLAIM_BOUNDARY:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification without the expected local-only claim boundary",
        )
    unit = projection.get("proof_unit")
    if not isinstance(unit, dict):
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification without exactly one verified proof unit",
        )
    unknown_unit = sorted(set(unit) - set(PROFILE_PROOF_UNIT_KEYS))
    if unknown_unit:
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, owner,
            f"verifier proof_unit has unknown v1 key(s): {redact_profile_labels(unknown_unit)}",
        )
    if unit.get("status") != PROOF_VERIFICATION_VERIFIED_STATUS:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification but its proof unit is not verified",
        )
    for flag in PROFILE_PROOF_UNIT_REQUIRED_FLAGS:
        if unit.get(flag) is not True:
            profile_reject(
                PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
                f"exact_text_fallback claims verification but proof_unit.{flag} does not confirm it",
            )
    # local verifier 는 rehydration 을 실행하지 않는다. 실행했다고 주장하면 이 레코드는
    # 우리가 검증할 수 있는 evaluation-only 경계 밖의 산출물이다.
    if unit.get("rehydration_executed") is not PROOF_VERIFICATION_REHYDRATION_EXECUTED:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback claims verification but proof_unit.rehydration_executed leaves the local-only boundary",
        )
    if unit.get("receipt_id") != fallback["receipt_id"]:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback receipt id is not bound to the verified proof unit",
        )
    if unit.get("content_hash_declared_value") != fallback["content_sha256"]:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback content hash is not bound to the verified proof unit",
        )
    if unit.get("retrieval_command") != fallback["retrieval_command"]:
        profile_reject(
            PROFILE_REJECT_FALLBACK_CLAIM_INCONSISTENT, owner,
            "exact_text_fallback retrieval command is not bound to the verified proof unit",
        )


def validate_profile_row_controls(
    row: EvidenceReplayRow,
    task: TaskFixture,
    *,
    task_file_dir: Path,
) -> dict[str, Any]:
    """Validate one profiled evidence row and return its normalized lane record."""
    owner = profile_owner(task.id, row.result.variant)
    controls = row.evaluation_controls
    if controls is None:
        profile_reject(PROFILE_REJECT_CONTROLS_MISSING, owner, "evaluation_controls is required for a profiled row")
    unknown = sorted(set(controls) - set(PROFILE_CONTROL_BLOCK_KEYS))
    if unknown:
        profile_reject(
            PROFILE_REJECT_SCHEMA_INVALID, owner,
            f"evaluation_controls has unknown v1 key(s): {redact_profile_labels(unknown)}",
        )

    # --- prompt binding -------------------------------------------------
    prompt_evidence = profile_block(controls, "prompt_evidence", owner=owner)
    declared_sha = profile_text(prompt_evidence, "sha256", owner=owner, label="prompt_evidence", maximum=64)
    profile_text(prompt_evidence, "source_label", owner=owner, label="prompt_evidence", maximum=MAX_PROFILE_LABEL_CHARS)
    if not SHA256_HEX_PATTERN.match(declared_sha):
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, "prompt_evidence.sha256 must be lowercase hex SHA-256")
    actual_sha = profile_variant_prompt_sha256(task, row.result.variant, task_file_dir=task_file_dir, owner=owner)
    if declared_sha != actual_sha:
        profile_reject(
            PROFILE_REJECT_PROMPT_BINDING_INVALID, owner,
            "prompt_evidence.sha256 does not match the locally recomputed prompt hash",
        )

    # --- omission + exact-text fallback ---------------------------------
    source_omission = profile_block(controls, "source_omission", owner=owner)
    omission_present = profile_bool(source_omission, "present", owner=owner, label="source_omission")
    profile_text(source_omission, "transform", owner=owner, label="source_omission", maximum=MAX_PROFILE_LABEL_CHARS)

    fallback = profile_block(controls, "exact_text_fallback", owner=owner)
    profile_bool(fallback, "available", owner=owner, label="exact_text_fallback")
    fallback_verified = profile_bool(fallback, "verified", owner=owner, label="exact_text_fallback")
    profile_text(fallback, "receipt_id", owner=owner, label="exact_text_fallback", maximum=MAX_PROFILE_RECEIPT_ID_CHARS)
    fallback_sha = profile_text(
        fallback, "content_sha256", owner=owner, label="exact_text_fallback", maximum=MAX_PROFILE_RECEIPT_ID_CHARS,
    )
    profile_text(
        fallback, "retrieval_command", owner=owner, label="exact_text_fallback", maximum=MAX_PROFILE_COMMAND_CHARS,
    )
    if fallback_verified:
        if not SHA256_HEX_PATTERN.match(fallback_sha):
            profile_reject(
                PROFILE_REJECT_SCHEMA_INVALID, owner,
                "exact_text_fallback.content_sha256 must be lowercase hex SHA-256 when verification is claimed",
            )
        validate_profile_fallback_projection(fallback, owner=owner)
    # 생략된 원문이 있는데 통과한 attestation 이 없으면 lane 을 막는다(거부가 아니다).
    fallback_bound = (not omission_present) or fallback_verified

    # --- protected zone review ------------------------------------------
    protection = profile_block(controls, "protected_zone_review", owner=owner)
    # 바운드 검사가 정책 의미 분류보다 먼저다: oversize 값은 blocked 가 아니라 reject 다.
    policy = profile_text(
        protection, "policy", owner=owner, label="protected_zone_review", maximum=MAX_PROFILE_POLICY_CHARS,
    )
    protection_completed = profile_bool(protection, "review_completed", owner=owner, label="protected_zone_review")
    included_protected = profile_int(
        protection, "included_protected_regions", owner=owner,
        label="protected_zone_review", maximum=MAX_PROFILE_PROTECTED_REGION_COUNT,
    )
    included_prompt_like = profile_int(
        protection, "included_prompt_like_regions", owner=owner,
        label="protected_zone_review", maximum=MAX_PROFILE_PROTECTED_REGION_COUNT,
    )
    profile_text(
        protection, "reviewer_label", owner=owner, label="protected_zone_review", maximum=MAX_PROFILE_LABEL_CHARS,
    )
    profile_text(
        protection, "review_note", owner=owner, label="protected_zone_review", maximum=MAX_PROFILE_NOTE_CHARS,
    )
    protection_attested = (
        policy == PROTECTED_ZONE_DENY_POLICY
        and protection_completed
        and included_protected == 0
        and included_prompt_like == 0
    )

    # --- missed context review ------------------------------------------
    missed = profile_block(controls, "missed_context_review", owner=owner)
    missed_completed = profile_bool(missed, "review_completed", owner=owner, label="missed_context_review")
    missed_present = profile_bool(missed, "present", owner=owner, label="missed_context_review")
    profile_bool(missed, "correction_required", owner=owner, label="missed_context_review")
    profile_text(missed, "summary", owner=owner, label="missed_context_review", maximum=MAX_PROFILE_SUMMARY_CHARS)
    missed_reviewed = missed_completed and not missed_present

    # --- human correction consistency -----------------------------------
    correction = profile_block(controls, "human_correction", owner=owner)
    correction_count = profile_int(
        correction, "count", owner=owner, label="human_correction", maximum=MAX_PROFILE_CORRECTION_COUNT,
    )
    correction_reason = profile_text(
        correction, "reason", owner=owner, label="human_correction", maximum=MAX_PROFILE_NOTE_CHARS,
    )
    if correction_count != row.result.corrections:
        profile_reject(
            PROFILE_REJECT_CORRECTION_INCONSISTENT, owner,
            "human_correction.count does not equal the row's top-level corrections field",
        )
    if correction_count > 0 and (not correction_reason.strip() or correction_reason.strip().lower() == "none"):
        profile_reject(
            PROFILE_REJECT_CORRECTION_INCONSISTENT, owner,
            "a positive human_correction.count requires an explicit bounded reason",
        )

    # --- measurement flags may never upgrade the generic normalized fields
    provider_usage = profile_block(controls, "provider_usage", owner=owner)
    lane_tokens_measured = profile_bool(provider_usage, "primary_tokens_measured", owner=owner, label="provider_usage")
    lane_cost_measured = profile_bool(provider_usage, "primary_cost_measured", owner=owner, label="provider_usage")
    profile_bool(provider_usage, "provider_called", owner=owner, label="provider_usage")
    if lane_tokens_measured != row.result.primary_tokens_measured or lane_cost_measured != row.result.cost_measured:
        profile_reject(
            PROFILE_REJECT_MEASUREMENT_INCONSISTENT, owner,
            "provider_usage measurement flags contradict the generic normalized provider fields",
        )

    shifted = profile_block(controls, "shifted_cost", owner=owner)
    lane_external_tokens = profile_bool(shifted, "external_tokens_measured", owner=owner, label="shifted_cost")
    lane_external_cost = profile_bool(shifted, "external_cost_measured", owner=owner, label="shifted_cost")
    shifted_status = profile_text(
        shifted, "status", owner=owner, label="shifted_cost", maximum=MAX_PROFILE_LABEL_CHARS,
    )
    if shifted_status not in PROFILE_SHIFTED_COST_STATUSES:
        profile_reject(PROFILE_REJECT_SCHEMA_INVALID, owner, "shifted_cost.status must be measured or unmeasured")
    if (
        lane_external_tokens != row.result.external_tokens_measured
        or lane_external_cost != row.result.external_cost_measured
    ):
        profile_reject(
            PROFILE_REJECT_MEASUREMENT_INCONSISTENT, owner,
            "shifted_cost measurement flags contradict the generic normalized shifted-cost fields",
        )
    if (shifted_status == "measured") != (lane_external_tokens and lane_external_cost):
        profile_reject(
            PROFILE_REJECT_MEASUREMENT_INCONSISTENT, owner,
            "shifted_cost.status contradicts its own measurement flags",
        )

    provenance_block = profile_block(controls, "control_provenance", owner=owner)
    profile_text(
        provenance_block, "review_source", owner=owner, label="control_provenance", maximum=MAX_PROFILE_LABEL_CHARS,
    )
    profile_text(
        provenance_block, "verifier_label", owner=owner, label="control_provenance", maximum=MAX_PROFILE_LABEL_CHARS,
    )

    # 정규화된 lane 판정만 보고에 전달한다. 자유 텍스트(정책/노트/요약/라벨)는 절대
    # 포함하지 않으므로 secret-shaped 값이 report/dashboard 로 새어나갈 수 없다.
    return {
        "task_id": task.id,
        "variant": row.result.variant,
        "success": bool(row.result.success),
        "source_omission_present": omission_present,
        "fallback_bound": fallback_bound,
        "fallback_verified": fallback_verified,
        # 아무 verifier 레코드도 제출되지 않은 경우("missing")와 제출되었으나 실패를
        # 보고하는 경우("failed")는 서로 다른 증거 수준이다.
        "fallback_projection_supplied": fallback.get("verifier_projection") is not None,
        "protected_zone_attested": protection_attested,
        "missed_context_reviewed": missed_reviewed,
        # lane 이 correction 판정을 lane 데이터에서 직접 유도할 수 있도록 정규화해 넘긴다.
        "human_correction_consistent": correction_count == row.result.corrections,
        "provider_measured": bool(row.result.primary_tokens_measured and row.result.cost_measured),
        "shifted_cost_measured": bool(lane_external_tokens and lane_external_cost),
    }


def selected_profiled_task_ids(
    tasks: list[TaskFixture],
    targets: list[tuple[TaskFixture, Variant]],
) -> list[str]:
    """Profiled task ids that this invocation actually selected, in stable order."""
    profiled = {task.id for task in tasks if task.evaluation_profile is not None}
    selected = {task.id for task, _ in targets}
    return sorted(profiled & selected)


def preflight_profile_replay_mode(
    tasks: list[TaskFixture],
    targets: list[tuple[TaskFixture, Variant]],
    *,
    evidence_replay_active: bool,
) -> None:
    """Refuse a profiled task outside evidence replay, before any provider call.

    The profile is evaluation-only: it validates imported evidence and clamps every
    authority surface. Those checks live entirely on the replay path, so running a
    profiled task through the provider would execute a real run whose report never
    sees profile validation or the evaluation-only clamp. Fail closed instead, before
    the provider runtime, the lock sidecar, and the first output byte.

    This also refuses ``--dry-run``. A dry run writes nothing and spawns no provider,
    so it is not itself dangerous, but keeping the invariant absolute — a profiled task
    never enters the provider path — is what makes the boundary auditable. The useful
    preview, ``--evidence-jsonl --dry-run``, is unaffected.
    """
    if evidence_replay_active:
        return
    for task_id in selected_profiled_task_ids(tasks, targets):
        profile_reject(
            PROFILE_REJECT_REPLAY_REQUIRED, profile_owner(task_id),
            "a profiled task is evaluation-only and runs only under --evidence-jsonl replay; "
            "provider execution is refused",
        )


def preflight_profile_fresh_output(
    tasks: list[TaskFixture],
    targets: list[tuple[TaskFixture, Variant]],
    *,
    resume: bool,
    csv_has_preexisting_content: bool,
) -> None:
    """Refuse a resumed or pre-existing profiled batch before any lock/read helper.

    v1 gives up incremental replay so profile context cannot silently vanish from a
    resumed report. This must run before the resume key snapshot, which acquires the
    CSV lock and therefore creates a ``.lock`` sidecar: rejecting afterwards would
    leave a byte on disk for a run we refused.
    """
    if not (resume or csv_has_preexisting_content):
        return
    for task_id in selected_profiled_task_ids(tasks, targets):
        profile_reject(
            PROFILE_REJECT_FRESH_OUTPUT_REQUIRED, profile_owner(task_id),
            "v1 profiled replay requires a fresh empty results CSV and forbids --resume",
        )


def profile_batch_freshness_gate_unlocked(
    tasks: list[TaskFixture],
    targets: list[tuple[TaskFixture, Variant]],
    csv_path: Path,
) -> None:
    """Recheck output freshness while the caller holds the full-batch lock.

    The pre-lock gate reads the CSV without the lock, so a concurrent writer could
    still land a row between that check and the first append. One recheck under the
    caller's held parent-directory lock closes that window for the whole batch.
    """
    profiled_task_ids = selected_profiled_task_ids(tasks, targets)
    if not profiled_task_ids:
        return
    if file_has_content_no_follow(csv_path):
        profile_reject(
            PROFILE_REJECT_FRESH_OUTPUT_REQUIRED,
            profile_owner(profiled_task_ids[0]),
            "the results CSV gained content after the profiled batch was validated",
        )


def preflight_evaluation_profiles(
    tasks: list[TaskFixture],
    variants: list[Variant],
    targets: list[tuple[TaskFixture, Variant]],
    evidence_rows: list[EvidenceReplayRow],
    *,
    task_file_dir: Path,
    resume: bool,
    csv_has_preexisting_content: bool,
    baseline_variant: str = "baseline",
) -> None:
    """Validate the complete profiled batch before the first output byte is written.

    Runs before any CSV/ledger/report/dashboard write and before any lock sidecar is
    created, so a rejection leaves the filesystem byte-unchanged. Attaches the
    normalized lane record to each row, which makes report annotation infallible over
    an already-validated batch.
    """
    # 같은 gate 를 main 이 lock helper 이전에 이미 호출한다. 여기서 다시 부르는 것은
    # 이 함수를 직접 쓰는 호출자도 같은 boundary 를 얻게 하기 위한 이중 방어다.
    preflight_profile_fresh_output(
        tasks, targets, resume=resume, csv_has_preexisting_content=csv_has_preexisting_content,
    )
    profiled_tasks = {task.id: task for task in tasks if task.evaluation_profile is not None}
    rows_by_task: dict[str, list[EvidenceReplayRow]] = collections.defaultdict(list)
    for row in evidence_rows:
        rows_by_task[row.result.task_id].append(row)

    # profiled row 가 unprofiled task 에 붙는 경우도 binding 위반이다.
    for row in evidence_rows:
        task = profiled_tasks.get(row.result.task_id)
        if task is None and (row.evaluation_profile is not None or row.evaluation_controls is not None):
            profile_reject(
                PROFILE_REJECT_BINDING_MISMATCH,
                profile_owner(row.result.task_id, row.result.variant),
                "a profiled evidence row cannot be replayed against a task that does not declare the profile",
            )
    if not profiled_tasks:
        return

    variant_names = {variant.name for variant in variants}
    if baseline_variant not in variant_names or len(variant_names - {baseline_variant}) < 1:
        profile_reject(
            PROFILE_REJECT_BATCH_INCOMPLETE,
            profile_owner(next(iter(sorted(profiled_tasks)))),
            "v1 profiled replay requires the configured baseline and at least one candidate variant",
        )

    selected_by_task: dict[str, set[str]] = collections.defaultdict(set)
    for task, variant in targets:
        selected_by_task[task.id].add(variant.name)

    for task_id, task in sorted(profiled_tasks.items()):
        selected = selected_by_task.get(task_id, set())
        if not selected:
            continue
        # v1 은 부분 배치를 허용하지 않는다: 선택된 배치가 모든 variant 를 덮어야 한다.
        expected = {variant.name for variant in variants}
        if selected != expected:
            profile_reject(
                PROFILE_REJECT_BATCH_INCOMPLETE, profile_owner(task_id),
                "v1 profiled replay requires the complete baseline/candidate batch; "
                "partial variant selection is not supported",
            )
        task_rows = rows_by_task.get(task_id, [])
        # 중복/여분 row 는 coverage 집합 계산에 흡수되어 조용히 통과했다. 배치가
        # 모호하면 어떤 lane 판정도 신뢰할 수 없으므로 안정 ID 로 먼저 거부한다.
        seen_variants: set[str] = set()
        for row in task_rows:
            owner = profile_owner(task_id, row.result.variant)
            if row.result.variant in seen_variants:
                profile_reject(
                    PROFILE_REJECT_BATCH_INCOMPLETE, owner,
                    "a profiled task cannot carry duplicate evidence rows for one variant",
                )
            seen_variants.add(row.result.variant)
            if row.result.variant not in expected:
                profile_reject(
                    PROFILE_REJECT_BATCH_INCOMPLETE, owner,
                    "a profiled batch cannot carry an evidence row for an unknown variant",
                )
        for row in task_rows:
            owner = profile_owner(task_id, row.result.variant)
            if row.evaluation_profile is None and row.evaluation_controls is None:
                profile_reject(
                    PROFILE_REJECT_BATCH_INCOMPLETE, owner,
                    "a profiled task cannot mix profiled and unprofiled evidence rows",
                )
            if row.evaluation_profile != task.evaluation_profile:
                profile_reject(
                    PROFILE_REJECT_BINDING_MISMATCH, owner,
                    "the evidence row profile does not equal the task profile",
                )

        covered = {row.result.variant for row in task_rows}
        if not expected.issubset(covered):
            profile_reject(
                PROFILE_REJECT_BATCH_INCOMPLETE, profile_owner(task_id),
                "profiled replay requires complete baseline and candidate evidence coverage",
            )
        for row in task_rows:
            row.evaluation_lane = validate_profile_row_controls(row, task, task_file_dir=task_file_dir)


def build_image_context_evaluation_lane(
    replay_rows: list[EvidenceReplayRow],
    report: dict[str, Any],
) -> dict[str, Any] | None:
    """Aggregate the validated lane records into the additive report block."""
    lanes = [row.evaluation_lane for row in replay_rows if row.evaluation_lane is not None]
    if not lanes:
        return None

    provider_measured = all(lane["provider_measured"] for lane in lanes)
    shifted_measured = all(lane["shifted_cost_measured"] for lane in lanes)
    all_success = all(lane["success"] for lane in lanes)
    omission_lanes = [lane for lane in lanes if lane["source_omission_present"]]

    # generic quality gate 결과를 lane 이 그대로 소비한다. profile 이 자기만의 판정으로
    # generic regression 을 덮어쓰지 못하게 하는 것이 목적이므로, 어떤 matched pair 가
    # regression 을 보고하면 lane 도 막힌다(보수적으로 fail-closed).
    #
    # 이름 붙은 두 gate 만 매핑하면 구멍이 남는다: quality_gate 는 corrections_regression /
    # failure_rate_regression 외에도 insufficient_corrections_data 같은 값을 낼 수 있고,
    # 그때 lane 이 ready 로 올라가면 안 된다. 따라서 불변식은 "pass 가 아니면 막는다" 이며,
    # 두 이름은 이유를 드러내는 구체 blocker 로 함께 유지한다.
    generic_quality_gates: set[str] = set()
    pairs = report.get("matched_pair_evidence")
    pair_keys: set[tuple[str, str]] = set()
    if isinstance(pairs, list):
        for pair in pairs:
            if isinstance(pair, dict) and isinstance(pair.get("quality_gate"), str):
                generic_quality_gates.add(pair["quality_gate"])
                if isinstance(pair.get("task_id"), str) and isinstance(pair.get("variant"), str):
                    pair_keys.add((pair["task_id"], pair["variant"]))
    baseline_variant = report.get("baseline_variant")
    expected_pair_keys = {
        (lane["task_id"], lane["variant"])
        for lane in lanes
        if isinstance(baseline_variant, str) and lane["variant"] != baseline_variant
    }
    comparisons = report.get("comparisons")
    comparison_rows = [item for item in comparisons if isinstance(item, dict)] if isinstance(comparisons, list) else []
    expected_candidate_variants = {variant for _, variant in expected_pair_keys}
    comparison_variants = {
        item["variant"] for item in comparison_rows if isinstance(item.get("variant"), str)
    }
    all_comparisons_pass = (
        bool(comparison_rows)
        and comparison_variants == expected_candidate_variants
        and all(
            item.get("quality_gate") == GENERIC_QUALITY_GATE_PASS
            and isinstance(item.get("matched_successful_task_count"), int)
            and item["matched_successful_task_count"] > 0
            for item in comparison_rows
        )
    )
    complete_matched_pairs = bool(expected_pair_keys) and pair_keys == expected_pair_keys
    generic_quality_pass = (
        complete_matched_pairs
        and all_comparisons_pass
        and generic_quality_gates == {GENERIC_QUALITY_GATE_PASS}
    )

    gate_results = {
        # preflight 를 통과했다면 profile/prompt binding 은 이미 증명되었다.
        IMAGE_CONTEXT_GATE_PROFILE_AND_PROMPT_BINDING: True,
        IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW: all(lane["protected_zone_attested"] for lane in lanes),
        IMAGE_CONTEXT_GATE_EXACT_TEXT_FALLBACK_BINDING: all(lane["fallback_bound"] for lane in lanes),
        IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW: all(lane["missed_context_reviewed"] for lane in lanes),
        # count/reason 모순은 거부되지만, 판정은 lane 레코드에서 직접 유도한다.
        IMAGE_CONTEXT_GATE_HUMAN_CORRECTION_CONSISTENCY: all(
            lane["human_correction_consistent"] for lane in lanes
        ),
        IMAGE_CONTEXT_GATE_CORRECTIONS_REGRESSION: (
            GENERIC_QUALITY_GATE_CORRECTIONS_REGRESSION not in generic_quality_gates
        ),
        IMAGE_CONTEXT_GATE_FAILURE_RATE_REGRESSION: (
            GENERIC_QUALITY_GATE_FAILURE_RATE_REGRESSION not in generic_quality_gates
        ),
        # generic quality gate 가 pass 가 아니면 어떤 값이든 여기서 막힌다.
        IMAGE_CONTEXT_GATE_GENERIC_MATCHED_SUCCESS_AND_MEASUREMENT: (
            all_success and provider_measured and shifted_measured and generic_quality_pass
        ),
        # 이 gate 는 통과해도 권한을 주지 않는다. 경계 자체가 불변이므로 항상 참이다.
        IMAGE_CONTEXT_GATE_EVALUATION_ONLY_PROMOTION_BOUNDARY: True,
    }
    blocking_gate_ids = [gate_id for gate_id in IMAGE_CONTEXT_GATE_IDS if not gate_results[gate_id]]

    if not omission_lanes:
        fallback_level = "missing"
    elif all(lane["fallback_verified"] for lane in omission_lanes):
        fallback_level = IMPORTED_LOCAL_VERIFIER_ATTESTATION_LABEL
    elif any(
        lane["fallback_projection_supplied"] and not lane["fallback_verified"]
        for lane in omission_lanes
    ):
        # 검증 레코드가 제출되었지만 성공을 증명하지 못했다.
        fallback_level = "failed"
    else:
        # 생략은 선언되었으나 어떤 verifier attestation 도 제출되지 않았다.
        fallback_level = "missing"

    matched_task_ids = sorted({lane["task_id"] for lane in lanes})
    return {
        "schema_version": IMAGE_CONTEXT_READINESS_SCHEMA_VERSION,
        "status": PROFILE_STATUS_BLOCKED if blocking_gate_ids else PROFILE_STATUS_READY_FOR_BOUNDED_PILOT_REVIEW,
        "evaluation_only": True,
        "promotion_authority": False,
        "public_claim_allowed": False,
        "gate_ids": list(IMAGE_CONTEXT_GATE_IDS),
        "blocking_gate_ids": blocking_gate_ids,
        "matched_task_count": len(matched_task_ids),
        "evidence_levels": {
            "provider_measurement": "measured" if provider_measured else "unmeasured",
            "fallback_binding": fallback_level,
            "protected_zone": (
                "review_attested"
                if gate_results[IMAGE_CONTEXT_GATE_PROTECTED_ZONE_DENY_REVIEW] else "failed"
            ),
            "missed_context": (
                "reviewed" if gate_results[IMAGE_CONTEXT_GATE_MISSED_CONTEXT_REVIEW] else "missing"
            ),
        },
        # 표본 관측치는 어떤 승격 임계값도 정의하지 않는다.
        "sample_adequacy": {
            "matched_task_count": len(matched_task_ids),
            "profiled_row_count": len(lanes),
            "task_class_labels": matched_task_ids,
            "policy_status": PROFILE_SAMPLE_ADEQUACY_POLICY_STATUS,
        },
        "claim_boundary": IMAGE_CONTEXT_CLAIM_BOUNDARY,
    }


def clamp_report_for_evaluation_profile(report: dict[str, Any], lane: dict[str, Any]) -> None:
    """Force every public-authority surface to a non-candidate, evaluation-only value.

    Complete lane evidence may reach ``ready_for_bounded_pilot_review``; it may never
    reach promotion authority or a public claim. Pre-clamp measurements survive only in
    explicitly non-authoritative fields such as ``raw_metric_claim_status``.
    """
    report[EVALUATION_PROFILES_REPORT_KEY] = {IMAGE_CONTEXT_PROFILE_REPORT_KEY: lane}
    report["public_claim_status"] = IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
    # 콘솔이 report['claim_status'] 를 그대로 출력하므로 legacy 필드도 함께 clamp 한다.
    report["claim_status"] = IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
    report["public_claim_eligible"] = False

    # replay_evidence 는 top-level 과 같은 이름의 권한 필드를 복사해 들고 있다. 여기를
    # 함께 clamp 하지 않으면 report.json 소비자가 중첩 사본에서 candidate/eligible=true 를
    # 그대로 읽어 evaluation-only 경계를 우회한다.
    replay_evidence = report.get("replay_evidence")
    if isinstance(replay_evidence, dict):
        replay_evidence["public_claim_status"] = IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
        replay_evidence["public_claim_eligible"] = False
        replay_evidence["report_claim_gates_allow_public_claim"] = False

    readiness = report.get("public_claim_readiness")
    if isinstance(readiness, dict):
        readiness["claim_allowed"] = False
        readiness["status"] = IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
        readiness["reason"] = IMAGE_CONTEXT_PROFILE_BLOCKER_GATE_ID
        # `_observed` 라는 이름이 붙었어도 값 자체가 "..._public_claim_candidate" 라는
        # 권한 문자열이다. 그대로 두면 downstream 이 이 필드를 읽고 candidate 로 오해할
        # 수 있으므로, profiled report 에서는 관측치도 evaluation-only 로 clamp 한다.
        readiness["public_claim_status_observed"] = IMAGE_CONTEXT_EVALUATION_ONLY_CLAIM_STATUS
        readiness["public_claim_eligible_observed"] = False
        blocking = readiness.get("blocking_gate_ids")
        if isinstance(blocking, list) and IMAGE_CONTEXT_PROFILE_BLOCKER_GATE_ID not in blocking:
            blocking.append(IMAGE_CONTEXT_PROFILE_BLOCKER_GATE_ID)

    pairs = report.get("matched_pair_evidence")
    if isinstance(pairs, list):
        for pair in pairs:
            if not isinstance(pair, dict):
                continue
            boundary = pair.get("claim_boundary")
            if isinstance(boundary, dict):
                boundary["token_savings_claim_allowed"] = False
                boundary["shifted_cost_claim_allowed"] = False
                boundary["evaluation_profile"] = IMAGE_CONTEXT_EVALUATION_PROFILE_ID


def render_image_context_evaluation_section(report: dict[str, Any]) -> list[str]:
    """Bounded dashboard section: statuses and ids only, never raw evidence text."""
    profiles = report.get(EVALUATION_PROFILES_REPORT_KEY)
    if not isinstance(profiles, dict):
        return []
    lane = profiles.get(IMAGE_CONTEXT_PROFILE_REPORT_KEY)
    if not isinstance(lane, dict):
        return []
    levels = lane.get("evidence_levels") if isinstance(lane.get("evidence_levels"), dict) else {}
    blockers = lane.get("blocking_gate_ids") or []
    sample = lane.get("sample_adequacy") if isinstance(lane.get("sample_adequacy"), dict) else {}
    return [
        "## Image-context evaluation",
        "",
        f"- Schema: `{markdown_value(lane.get('schema_version'))}`",
        f"- Status: `{markdown_value(lane.get('status'))}`",
        f"- Matched tasks: {markdown_value(lane.get('matched_task_count'))}",
        f"- Evaluation only: `{markdown_value(lane.get('evaluation_only'))}`",
        f"- Promotion authority: `{markdown_value(lane.get('promotion_authority'))}`",
        f"- Public claim allowed: `{markdown_value(lane.get('public_claim_allowed'))}`",
        f"- Provider measurement: `{markdown_value(levels.get('provider_measurement'))}`",
        f"- Fallback binding: `{markdown_value(levels.get('fallback_binding'))}`",
        f"- Protected zone: `{markdown_value(levels.get('protected_zone'))}`",
        f"- Missed context: `{markdown_value(levels.get('missed_context'))}`",
        f"- Blocking gates: `{markdown_value(', '.join(str(item) for item in blockers) if blockers else 'none')}`",
        f"- Sample policy: `{markdown_value(sample.get('policy_status'))}`",
        "",
        "> Claim boundary: this lane is evaluation-only. `ready_for_bounded_pilot_review` authorizes a "
        "bounded human pilot review of imported evidence; it is not promotion, not runtime authority, "
        "not quality proof, and not a hosted API token/cost savings claim. The fallback record is an "
        "imported local-verifier attestation: replay does not authenticate its author and does not "
        "reread the artifact.",
        "",
    ]


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
        if row_primary_cost_measured(row):
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
        if row_primary_cost_measured(row):
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
        primary_cost_measured = bool(rows_for_task) and all(
            row_primary_cost_measured(row) for row in rows_for_task
        )
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
    # Additive lane block. 이미 preflight 로 검증된 batch 위에서만 동작하므로 실패하지 않는다.
    # profile 이 없는 report 는 이 블록도, clamp 도 얻지 않는다(기존 동작 그대로).
    lane = build_image_context_evaluation_lane(replay_rows, report)
    if lane is not None:
        clamp_report_for_evaluation_profile(report, lane)
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
        # profile 이 선언된 report 에만 추가되는 bounded 섹션. 원문/정책/영수증 내용은 넣지 않는다.
        *render_image_context_evaluation_section(report),
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


def _measurement_existing_context(
    spec: MeasurementVariant,
    run_id: str,
) -> MeasurementRunContext:
    run_root = spec.artifact_root / "runs" / run_id
    return MeasurementRunContext(
        run_id=run_id,
        run_root=run_root,
        home=run_root / "home",
        xdg_config=run_root / "xdg-config",
        xdg_cache=run_root / "xdg-cache",
        xdg_data=run_root / "xdg-data",
        xdg_state=run_root / "xdg-state",
        tmp=run_root / "tmp",
        workspace=run_root / "workspace",
        session=run_root / "session",
        raw_path=run_root / "raw.ndjson",
        receipt_path=run_root / "receipt.json",
        index_path=spec.artifact_root / "artifact-index.ndjson",
    )


def _measurement_read_private_raw(path: Path) -> bytes:
    fd = _open_regular_no_symlink(path)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise ValueError("raw mode")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > MEASUREMENT_RAW_MAX_BYTES:
                raise ValueError("raw size limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _measurement_read_private_file(path: Path, *, maximum: int = MAX_FIXTURE_FILE_BYTES) -> bytes:
    fd = _open_regular_no_symlink(path)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise ValueError("private file mode")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError("private file size")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _measurement_validate_snapshot(context: MeasurementRunContext, spec: MeasurementVariant) -> bytes:
    if spec.settings_file.name in {"", ".", ".."} or any(char in spec.settings_file.name for char in ("/", "\\", "\0")):
        raise ValueError("settings snapshot basename")
    snapshot = context.session / spec.settings_file.name
    raw = _measurement_read_private_file(snapshot)
    if raw != spec.settings_source_bytes:
        raise ValueError("settings snapshot source binding")
    parsed = _parse_measurement_json_text(raw.decode("utf-8"), owner="measurement settings snapshot")
    if parsed != spec.settings_payload:
        raise ValueError("settings snapshot parsed binding")
    if spec.identity.arm == "treatment":
        _measurement_validate_treatment_bindings(spec)
    return raw


def _measurement_load_index_rows(path: Path) -> list[dict[str, Any]]:
    fd = _open_regular_no_symlink(path)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise ValueError("index mode")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(MAX_FIXTURE_FILE_BYTES + 1)
        if len(raw) > MAX_FIXTURE_FILE_BYTES:
            raise ValueError("index size")
    finally:
        if fd != -1:
            os.close(fd)
    if not raw.endswith(b"\n") or b"\r" in raw or b"\n\n" in raw:
        raise ValueError("measurement artifact index is not canonical NDJSON")
    rows: list[dict[str, Any]] = []
    for line in raw[:-1].split(b"\n"):
        value = _measurement_parse_canonical_json_bytes(
            line + b"\n", owner="measurement artifact index row",
        )
        if not isinstance(value, dict):
            raise ValueError("index row")
        rows.append(value)
    return rows


def _measurement_recover_raw_only_run(
    spec: MeasurementVariant,
    task: TaskFixture,
    run_id: str,
    *,
    artifact_root_locked: bool = False,
) -> bool:
    context = _measurement_existing_context(spec, run_id)
    try:
        os.lstat(context.raw_path)
        raw_exists = True
    except FileNotFoundError:
        raw_exists = False
    try:
        os.lstat(context.receipt_path)
        receipt_exists = True
    except FileNotFoundError:
        receipt_exists = False
    if not raw_exists or receipt_exists:
        return False

    settings_bytes = _measurement_validate_snapshot(context, spec)
    raw = _measurement_read_private_raw(context.raw_path)
    lines = raw.splitlines()
    if len(lines) > MEASUREMENT_RAW_MAX_LINES or any(len(line) > MEASUREMENT_RAW_MAX_LINE_BYTES for line in lines):
        raise ValueError("raw recovery bounds")
    parsed = parse_claude_stream_output(raw, max_line_bytes=MEASUREMENT_RAW_MAX_LINE_BYTES)
    if parsed.status not in {"success", "terminal_error"}:
        raise ValueError("raw recovery stream")
    hook_result = _parse_measurement_hook_events(raw)
    if hook_result["classification"] not in {None, "unexpected_hook_event_class"}:
        raise ValueError("raw recovery hook lifecycle")
    # Raw bytes prove only what was durably observed. They cannot prove the
    # interrupted provider process return code or that no later bytes existed.
    terminal_status = "recovered_process_status_unknown"

    receipt = _measurement_receipt(
        context, task, spec, raw, hook_result, settings_bytes,
        process_status="unknown_after_crash", terminal_status=terminal_status,
    )
    receipt_bytes = json.dumps(
        receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if context.index_path.exists():
        existing_rows = _measurement_load_index_rows(context.index_path)
        if any(row.get("run_id") == run_id for row in existing_rows):
            raise ValueError("orphaned index binding")
    _measurement_write_exclusive(context.receipt_path, receipt_bytes)
    _measurement_append_index(context.index_path, {
        "schema_version": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
        "run_id": run_id,
        "receipt_path": str(context.receipt_path),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "terminal_status": terminal_status,
    }, artifact_root_locked=artifact_root_locked)
    return True


def _verify_existing_measurement_run(
    spec: MeasurementVariant, task_id: str, run_id: str, *, require_index: bool = True,
) -> dict[str, Any]:
    """Fail closed when an existing immutable run has missing or corrupt evidence."""
    context = _measurement_existing_context(spec, run_id)
    receipt_path = context.receipt_path
    raw_path = context.raw_path
    try:
        receipt_bytes = _measurement_read_private_file(receipt_path)
        receipt = _measurement_parse_canonical_json_bytes(receipt_bytes, owner="measurement receipt")
        if not isinstance(receipt, dict) or receipt.get("schema_version") != MEASUREMENT_RAW_RECEIPT_SCHEMA_VERSION:
            raise ValueError("receipt schema")
        if set(receipt) != {"schema_version", "run_identity", "raw_artifact", "settings_artifact", "process_status", "terminal_status", "hook_summary", "hooks"}:
            raise ValueError("receipt keys")
        identity = receipt.get("run_identity")
        expected_identity = {
            "candidate_hash": spec.identity.candidate_hash,
            "task": task_id,
            "repetition": spec.identity.repetition,
            "arm": spec.identity.arm,
            "attempt": spec.identity.attempt,
            "namespace": spec.identity.namespace,
            "run_id": run_id,
        }
        if identity != expected_identity:
            raise ValueError("receipt identity")
        for identity_count in (identity.get("repetition"), identity.get("attempt")):
            if isinstance(identity_count, bool) or not isinstance(identity_count, int) or identity_count < 0:
                raise ValueError("receipt identity count")
        raw_meta = receipt.get("raw_artifact")
        if not isinstance(raw_meta, dict) or set(raw_meta) != {"path", "sha256", "bytes", "lines", "events"} or raw_meta.get("path") != raw_path.name:
            raise ValueError("raw binding")
        declared_size = raw_meta.get("bytes")
        declared_sha256 = raw_meta.get("sha256")
        if (
            isinstance(declared_size, bool)
            or not isinstance(declared_size, int)
            or declared_size < 0
            or not isinstance(declared_sha256, str)
            or not SHA256_HEX_PATTERN.fullmatch(declared_sha256)
        ):
            raise ValueError("raw metadata")

        raw = _measurement_read_private_raw(raw_path)
        if len(raw) != declared_size or hashlib.sha256(raw).hexdigest() != declared_sha256:
            raise ValueError("raw digest")
        if raw_meta.get("lines") != len(raw.splitlines()) or raw_meta.get("events") != len(raw.splitlines()):
            raise ValueError("raw counts")
        for raw_count_name in ("bytes", "lines", "events"):
            raw_count = raw_meta.get(raw_count_name)
            if isinstance(raw_count, bool) or not isinstance(raw_count, int) or raw_count < 0:
                raise ValueError("raw numeric field")
        settings_bytes = _measurement_validate_snapshot(context, spec)
        settings_meta = receipt.get("settings_artifact")
        expected_settings = {
            "path": f"session/{spec.settings_file.name}",
            "sha256": hashlib.sha256(settings_bytes).hexdigest(),
            "bytes": len(settings_bytes),
            "binding_set_sha256": _measurement_binding_set_sha256(spec.pair_registered_bindings),
        }
        if settings_meta != expected_settings:
            raise ValueError("settings binding")
        settings_size = settings_meta.get("bytes") if isinstance(settings_meta, dict) else None
        if isinstance(settings_size, bool) or not isinstance(settings_size, int) or settings_size < 0:
            raise ValueError("settings numeric field")
        if receipt.get("process_status") not in {"exited_zero", "exited_nonzero", "timed_out", "launch_error", "unknown_after_crash"}:
            raise ValueError("process status")
        if receipt.get("terminal_status") not in {
            "raw_byte_limit", "raw_line_limit", "raw_line_byte_limit", "process_timeout",
            "process_launch_error", "process_error", "terminal_error", "missing_terminal",
            "invalid_stream", "hook_payload_limit", "hook_lifecycle_limit",
            "invalid_hook_lifecycle", "unexpected_hook_event_class",
            "baseline_hook_contamination", "missing_required_hook_event_class",
            "hook_process_failure", "success", "recovered_process_status_unknown",
        }:
            raise ValueError("terminal status")
        summary = receipt.get("hook_summary")
        if not isinstance(summary, dict) or set(summary) != {"required_event_classes", "observed_lifecycle_count", "completed_lifecycle_count", "event_class_counts"}:
            raise ValueError("hook summary")
        hooks = receipt.get("hooks")
        if not isinstance(hooks, list) or summary.get("completed_lifecycle_count") != len(hooks):
            raise ValueError("hook count")
        allowed_classes = list(dict.fromkeys(event for event, _command in spec.pair_registered_bindings))
        required_classes = list(spec.required_event_classes)
        if summary.get("required_event_classes") != required_classes:
            raise ValueError("required hook classes")
        for count_name in ("observed_lifecycle_count", "completed_lifecycle_count"):
            count = summary.get(count_name)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("hook summary count")
        hook_keys = {"hook_event", "opaque_hook_name_sha256", "lifecycle_key_sha256", "hook_process_outcome", "hook_process_exit_code", "triggering_tool_outcome", "progress_count"}
        if any(not isinstance(hook, dict) or set(hook) != hook_keys for hook in hooks):
            raise ValueError("hook keys")
        for hook in hooks:
            if (
                hook["hook_event"] not in MEASUREMENT_DOCUMENTED_HOOK_EVENTS
                and receipt.get("terminal_status") not in {
                    "unexpected_hook_event_class", "recovered_process_status_unknown",
                }
            ):
                raise ValueError("hook event")
            if not isinstance(hook["opaque_hook_name_sha256"], str) or not SHA256_HEX_PATTERN.fullmatch(hook["opaque_hook_name_sha256"]):
                raise ValueError("hook name hash")
            if not isinstance(hook["lifecycle_key_sha256"], str) or not SHA256_HEX_PATTERN.fullmatch(hook["lifecycle_key_sha256"]):
                raise ValueError("hook lifecycle hash")
            if hook["hook_process_outcome"] not in {"success", "error", "cancelled"}:
                raise ValueError("hook outcome")
            exit_code = hook["hook_process_exit_code"]
            if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
                raise ValueError("hook exit code")
            expected_trigger = "not_applicable"
            if hook["hook_event"] == "PostToolUse":
                expected_trigger = "succeeded"
            elif hook["hook_event"] == "PostToolUseFailure":
                expected_trigger = "failed"
            if hook["triggering_tool_outcome"] != expected_trigger:
                raise ValueError("triggering tool outcome")
            progress_count = hook["progress_count"]
            if isinstance(progress_count, bool) or not isinstance(progress_count, int) or progress_count < 0:
                raise ValueError("progress count")
        counts = collections.Counter(hook["hook_event"] for hook in hooks)
        expected_counts = [
            {"hook_event": event, "count": counts[event]}
            for event in MEASUREMENT_DOCUMENTED_HOOK_EVENTS
            if counts[event] or event in allowed_classes
        ]
        if summary.get("event_class_counts") != expected_counts:
            raise ValueError("event class counts")
        event_counts = summary.get("event_class_counts")
        if not isinstance(event_counts, list) or any(
            not isinstance(item, dict) or set(item) != {"hook_event", "count"}
            or isinstance(item.get("count"), bool) or not isinstance(item.get("count"), int)
            or item["count"] < 0
            for item in event_counts
        ):
            raise ValueError("event class count fields")
        reparsed_stream = parse_claude_stream_output(raw, max_line_bytes=MEASUREMENT_RAW_MAX_LINE_BYTES)
        reparsed_hooks = _parse_measurement_hook_events(raw)
        process_status = receipt["process_status"]
        recovered = process_status == "unknown_after_crash"
        if recovered:
            if receipt["terminal_status"] != "recovered_process_status_unknown":
                raise ValueError("recovered status pair")
            if (
                len(raw) > MEASUREMENT_RAW_MAX_BYTES
                or len(raw.splitlines()) > MEASUREMENT_RAW_MAX_LINES
                or any(len(line) > MEASUREMENT_RAW_MAX_LINE_BYTES for line in raw.splitlines())
                or reparsed_stream.status not in {"success", "terminal_error"}
                or reparsed_hooks["classification"] not in {None, "unexpected_hook_event_class"}
            ):
                raise ValueError("recovered evidence eligibility")
            expected_terminal = "recovered_process_status_unknown"
        else:
            if receipt["terminal_status"] == "recovered_process_status_unknown":
                raise ValueError("recovered status pair")
            expected_terminal = _measurement_resolve_terminal_status(
                raw_byte_limit=(receipt["terminal_status"] == "raw_byte_limit" and len(raw) == MEASUREMENT_RAW_MAX_BYTES),
                raw_line_limit=len(raw.splitlines()) > MEASUREMENT_RAW_MAX_LINES,
                raw_line_byte_limit=any(len(line) > MEASUREMENT_RAW_MAX_LINE_BYTES for line in raw.splitlines()),
                process_status=process_status,
                stream_status=reparsed_stream.status,
                hook_result=reparsed_hooks,
                arm=spec.identity.arm,
                allowed_event_classes=tuple(allowed_classes),
                required_event_classes=spec.required_event_classes,
            )
        expected_receipt = _measurement_receipt(
            context,
            TaskFixture(id=task_id, prompt=""),
            spec,
            raw,
            reparsed_hooks,
            settings_bytes,
            process_status=process_status,
            terminal_status=expected_terminal,
        )
        if receipt != expected_receipt:
            raise ValueError("receipt semantic binding")
        if not require_index:
            return receipt
        index_rows = _measurement_load_index_rows(context.index_path)
        matching_rows = [row for row in index_rows if row.get("run_id") == run_id]
        expected_index = {
            "schema_version": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
            "run_id": run_id,
            "receipt_path": str(receipt_path),
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "terminal_status": receipt.get("terminal_status"),
        }
        if matching_rows != [expected_index]:
            raise ValueError("index binding")
        return receipt
    except (OSError, SystemExit, TypeError, ValueError):
        raise SystemExit("measurement artifact integrity check failed") from None


def _measurement_check_artifact_identity_locked(
    spec: MeasurementVariant,
    task: TaskFixture,
    run_id: str,
    *,
    artifact_root_locked: bool,
) -> None:
    """Check all versioned immutable evidence while the artifact-root lock is held."""
    legacy_run_id = spec.identity.legacy_v1_run_id(task.id)
    if run_id == legacy_run_id:
        raise SystemExit("run_id_version_collision")

    legacy_root = spec.artifact_root / "runs" / legacy_run_id
    try:
        legacy_stat = os.lstat(legacy_root)
    except FileNotFoundError:
        pass
    except OSError:
        raise SystemExit("measurement artifact integrity check failed") from None
    else:
        if not stat.S_ISDIR(legacy_stat.st_mode) or stat.S_ISLNK(legacy_stat.st_mode):
            raise SystemExit("measurement artifact integrity check failed")
        raise SystemExit("legacy_v1_artifact_conflict")

    index_path = spec.artifact_root / "artifact-index.ndjson"
    try:
        index_rows = _measurement_load_index_rows(index_path)
    except FileNotFoundError:
        index_rows = []
    except (OSError, SystemExit, TypeError, ValueError, json.JSONDecodeError):
        raise SystemExit("measurement artifact integrity check failed") from None

    index_keys = {"schema_version", "run_id", "receipt_path", "receipt_sha256", "terminal_status"}
    terminal_statuses = {
        "raw_byte_limit", "raw_line_limit", "raw_line_byte_limit", "process_timeout",
        "process_launch_error", "process_error", "terminal_error", "missing_terminal",
        "invalid_stream", "hook_payload_limit", "hook_lifecycle_limit",
        "invalid_hook_lifecycle", "unexpected_hook_event_class",
        "baseline_hook_contamination", "missing_required_hook_event_class",
        "hook_process_failure", "success", "recovered_process_status_unknown",
    }
    matching_legacy_rows: list[dict[str, Any]] = []
    for row in index_rows:
        if (
            set(row) != index_keys
            or not isinstance(row.get("schema_version"), str)
            or not isinstance(row.get("run_id"), str)
            or not SHA256_HEX_PATTERN.fullmatch(row["run_id"])
            or not isinstance(row.get("receipt_path"), str)
            or not isinstance(row.get("receipt_sha256"), str)
            or not SHA256_HEX_PATTERN.fullmatch(row["receipt_sha256"])
            or row.get("terminal_status") not in terminal_statuses
        ):
            raise SystemExit("measurement artifact integrity check failed")
        schema_version = row["schema_version"]
        row_run_id = row["run_id"]
        if row_run_id == legacy_run_id and schema_version in {
            "contextguard.bench.artifact-index.v1",
            MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
        }:
            matching_legacy_rows.append(row)
        elif schema_version != MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION:
            raise SystemExit("measurement artifact integrity check failed")
    if len(matching_legacy_rows) > 1:
        raise SystemExit("measurement artifact integrity check failed")
    if matching_legacy_rows:
        raise SystemExit("legacy_v1_artifact_conflict")

    current_index_rows = [row for row in index_rows if row["run_id"] == run_id]
    if len(current_index_rows) > 1:
        raise SystemExit("measurement artifact integrity check failed")

    run_root = spec.artifact_root / "runs" / run_id
    try:
        run_stat = os.lstat(run_root)
    except FileNotFoundError:
        if current_index_rows:
            raise SystemExit("measurement artifact integrity check failed")
        return
    except OSError:
        raise SystemExit("measurement artifact integrity check failed") from None
    if not stat.S_ISDIR(run_stat.st_mode) or stat.S_ISLNK(run_stat.st_mode):
        raise SystemExit("measurement artifact integrity check failed")

    context = _measurement_existing_context(spec, run_id)
    try:
        os.lstat(context.receipt_path)
        receipt_exists = True
    except FileNotFoundError:
        receipt_exists = False
    except OSError:
        raise SystemExit("measurement artifact integrity check failed") from None
    try:
        os.lstat(context.index_path)
        index_exists = True
    except FileNotFoundError:
        index_exists = False
    except OSError:
        raise SystemExit("measurement artifact integrity check failed") from None

    try:
        if not receipt_exists:
            recovered = _measurement_recover_raw_only_run(
                spec, task, run_id, artifact_root_locked=artifact_root_locked,
            )
            if not recovered:
                raise ValueError("incomplete run")
        elif not index_exists or not current_index_rows:
            receipt = _verify_existing_measurement_run(spec, task.id, run_id, require_index=False)
            receipt_bytes = _measurement_read_private_file(context.receipt_path)
            _measurement_append_index(context.index_path, {
                "schema_version": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
                "run_id": run_id,
                "receipt_path": str(context.receipt_path),
                "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "terminal_status": receipt["terminal_status"],
            }, artifact_root_locked=artifact_root_locked)
        _verify_existing_measurement_run(spec, task.id, run_id)
    except (OSError, SystemExit, TypeError, ValueError, json.JSONDecodeError):
        raise SystemExit("measurement artifact integrity check failed") from None
    raise SystemExit(f"duplicate measurement run id: {run_id}")


def preflight_measurement_targets(
    targets: list[tuple[TaskFixture, Variant]],
    *,
    claude_bin: str,
    check_cli: bool,
) -> None:
    identities: set[tuple[str, str, int, str, int, str]] = set()
    run_locations: set[tuple[Path, str]] = set()
    checked_specs: set[tuple[str, ...]] = set()
    for task, variant in targets:
        spec = variant.measurement
        if spec is None:
            continue
        if task.output_format != "stream-json":
            raise SystemExit("measurement requires task output_format=stream-json")
        identity = spec.identity.components(task.id)
        if identity in identities:
            raise SystemExit("duplicate immutable measurement identity in selected targets")
        identities.add(identity)
        run_id = spec.identity.run_id(task.id)
        legacy_run_id = spec.identity.legacy_v1_run_id(task.id)
        if run_id == legacy_run_id:
            raise SystemExit("run_id_version_collision")
        location = (spec.artifact_root, run_id)
        if location in run_locations:
            raise SystemExit("duplicate measurement run id in selected targets")
        run_locations.add(location)
        try:
            artifact_lock_fd = _ensure_directory_no_symlink(spec.artifact_root)
        except FileNotFoundError:
            artifact_lock_fd = None
        except OSError:
            raise SystemExit("measurement artifact integrity check failed") from None
        try:
            if artifact_lock_fd is not None:
                if fcntl is not None:
                    fcntl.flock(artifact_lock_fd, fcntl.LOCK_EX)
                _measurement_check_artifact_identity_locked(
                    spec, task, run_id, artifact_root_locked=True,
                )
        finally:
            if artifact_lock_fd is not None:
                os.close(artifact_lock_fd)
        if check_cli and spec.cli_capabilities not in checked_specs:
            validate_measurement_cli_capabilities(claude_bin, spec)
            checked_specs.add(spec.cli_capabilities)


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


# --- S002 deterministic measurement-study layer ---------------------------------
#
# This surface is deliberately opt-in.  Legacy CSV/evidence execution never calls
# these helpers, so S001 and the historical benchmark contract remain unchanged.
MEASUREMENT_STUDY_PLAN_SCHEMA_VERSION = "contextguard.bench.study-plan.v1"
MEASUREMENT_STUDY_MANIFEST_SCHEMA_VERSION = "contextguard.bench.study-manifest.v1"
MEASUREMENT_STUDY_DIRECT_MANIFEST_SCHEMA_VERSION = (
    "contextguard.bench.study-manifest-direct.v1"
)
MEASUREMENT_STUDY_ATTEMPT_INDEX_SCHEMA_VERSION = "contextguard.bench.study-attempt-index.v1"
MEASUREMENT_STUDY_REPORT_SCHEMA_VERSION = "contextguard.bench.study-report.v1"
MEASUREMENT_CLI_PROBE_SCHEMA_VERSION = "contextguard.bench.cli-probe.v1"
MEASUREMENT_TERMINAL_USAGE_SCHEMA_VERSION = "contextguard.bench.terminal-usage.v1"
MEASUREMENT_STUDY_SCHEDULE_ALGORITHM = "splitmix64-balanced-pairs-v1"
MEASUREMENT_STUDY_RETRY_POLICY = "one_retry_after_valid_task_failure_v1"
MEASUREMENT_STUDY_INFERENCE_SEED = 0x434F4E5445585447
MEASUREMENT_STUDY_CORRECTION_SEED = 0x434F525245435433
# Public semantic aliases use the frozen plan terminology.
MEASUREMENT_INFERENCE_SEED = MEASUREMENT_STUDY_INFERENCE_SEED
MEASUREMENT_CORRECTION_SHUFFLE_SEED = MEASUREMENT_STUDY_CORRECTION_SEED
MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES = 10_000
MEASUREMENT_STUDY_CLAIM = (
    "Token savings demonstrated only for the exact frozen 12-task suite under "
    "manifest <sha256>."
)
MEASUREMENT_TERMINAL_USAGE_GOLDEN_SHA256 = (
    "e3bf1b6b4f6e40c5c79e6ecf0ca847a0417b905bcf2e095993b0ccb4b8cd134c"
)
SPLITMIX64_MASK = (1 << 64) - 1
SPLITMIX64_INCREMENT = 0x9E3779B97F4A7C15
SPLITMIX64_MULTIPLIER_1 = 0xBF58476D1CE4E5B9
SPLITMIX64_MULTIPLIER_2 = 0x94D049BB133111EB
MEASUREMENT_STUDY_ARMS = ("baseline", "treatment")
MEASUREMENT_STUDY_PLAN_KEYS = frozenset({
    "schema_version",
    "namespace",
    "schedule_seed",
    "inference_seed",
    "correction_shuffle_seed",
    "repetitions",
    "max_attempts_per_arm_unit",
    "retry_policy",
})
MEASUREMENT_STUDY_USAGE_KEYS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)
MEASUREMENT_STUDY_STATE_TRANSITIONS = {
    "planned": frozenset({"launch_reserved", "prelaunch_refused"}),
    "conditional": frozenset({"eligible", "not_needed", "blocked_study_invalid"}),
    "eligible": frozenset({"launch_reserved", "prelaunch_refused"}),
    "launch_reserved": frozenset({"launched", "prelaunch_refused"}),
    "launched": frozenset({"terminal"}),
}
MEASUREMENT_STUDY_TERMINAL_STATES = frozenset({
    "terminal", "prelaunch_refused", "not_needed", "blocked_study_invalid",
})
MEASUREMENT_STUDY_PRELAUNCH_REASONS = frozenset({
    "process_creation_failed", "validation_refused",
})
MEASUREMENT_STUDY_BLOCKED_REASONS = frozenset({"initial_attempt_infra_invalid"})
MEASUREMENT_STUDY_TERMINAL_CLASSIFICATIONS = frozenset({
    "success",
    "valid_task_failure_v1",
    "study_infra_invalid",
    "launch_accounting_failure",
    "post_launch_infra_invalid",
    "recovered_process_status_unknown",
})
MEASUREMENT_STUDY_PROBE_LAYOUT = (
    "cwd", "home", "xdg-config", "xdg-cache", "xdg-data", "xdg-state", "tmp",
    "claude-config",
)


def _study_canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8") + b"\n"


def _study_sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _study_domain_hash(label: str, value: Any) -> str:
    raw = _study_canonical_json_bytes(value)
    return hashlib.sha256(label.encode("ascii") + b"\0" + raw).hexdigest()


def load_measurement_study_plan(path: Path) -> dict[str, Any]:
    raw = _read_text_no_follow(path).encode("utf-8")
    value = _parse_measurement_json_text(raw.decode("utf-8"), owner="measurement study plan")
    canonical = _study_canonical_json_bytes(value)
    if raw not in {canonical, canonical[:-1]}:
        raise SystemExit("measurement study plan must be canonical JSON")
    plan = _measurement_exact_object(
        value, owner="measurement study plan", keys=MEASUREMENT_STUDY_PLAN_KEYS,
    )
    if plan["schema_version"] != MEASUREMENT_STUDY_PLAN_SCHEMA_VERSION:
        raise SystemExit("unsupported measurement study plan schema")
    namespace = plan["namespace"]
    if not isinstance(namespace, str) or not MEASUREMENT_ID_NAMESPACE_RE.fullmatch(namespace):
        raise SystemExit("measurement study plan namespace is invalid")
    seed = plan["schedule_seed"]
    if not isinstance(seed, str) or re.fullmatch(r"0x[0-9A-F]{16}", seed) is None:
        raise SystemExit("measurement study plan schedule_seed must be 0x plus 16 uppercase hex digits")
    exact = {
        "inference_seed": "0x434F4E5445585447",
        "correction_shuffle_seed": "0x434F525245435433",
        "repetitions": 3,
        "max_attempts_per_arm_unit": 2,
        "retry_policy": MEASUREMENT_STUDY_RETRY_POLICY,
    }
    for key, expected in exact.items():
        if plan[key] != expected or (
            isinstance(expected, int) and isinstance(plan[key], bool)
        ):
            raise SystemExit(f"measurement study plan {key} must equal {expected!r}")
    normalized = dict(plan)
    normalized["schedule_seed_int"] = int(seed, 16)
    normalized["source_sha256"] = _study_sha256_bytes(raw)
    return normalized


def splitmix64_next(state: int) -> tuple[int, int]:
    if isinstance(state, bool) or not isinstance(state, int):
        raise TypeError("SplitMix64 state must be an integer")
    state = (state + SPLITMIX64_INCREMENT) & SPLITMIX64_MASK
    value = state
    value = ((value ^ (value >> 30)) * SPLITMIX64_MULTIPLIER_1) & SPLITMIX64_MASK
    value = ((value ^ (value >> 27)) * SPLITMIX64_MULTIPLIER_2) & SPLITMIX64_MASK
    value = (value ^ (value >> 31)) & SPLITMIX64_MASK
    return state, value


def splitmix64_bounded(state: int, bound: int) -> tuple[int, int]:
    if isinstance(bound, bool) or not isinstance(bound, int) or bound <= 0:
        raise ValueError("SplitMix64 bound must be a positive integer")
    limit = (1 << 64) - ((1 << 64) % bound)
    while True:
        state, value = splitmix64_next(state)
        if value < limit:
            return state, value % bound


def generate_balanced_study_schedule(
    task_ids: list[str],
    repetitions: int,
    seed: int | str | None = None,
    *,
    schedule_seed: int | str | None = None,
    namespace: str | None = None,
    candidate_hash: str | None = None,
) -> list[dict[str, Any]]:
    if len(task_ids) != 12 or len(set(task_ids)) != 12:
        raise ValueError("measurement study requires exactly 12 unique ordered task ids")
    if any(not isinstance(task_id, str) or not task_id for task_id in task_ids):
        raise ValueError("measurement study task ids must be non-empty strings")
    if repetitions != 3:
        raise ValueError("measurement study requires exactly three repetitions")
    selected_seed = schedule_seed if schedule_seed is not None else seed
    if selected_seed is None:
        raise ValueError("measurement study schedule seed is required")
    seed_int = int(selected_seed, 16) if isinstance(selected_seed, str) else selected_seed
    choices = [0] * 18 + [1] * 18
    state = seed_int & SPLITMIX64_MASK
    for index in range(len(choices) - 1, 0, -1):
        state, selected = splitmix64_bounded(state, index + 1)
        choices[index], choices[selected] = choices[selected], choices[index]
    rows: list[dict[str, Any]] = []
    for index, (task_id, repetition) in enumerate(
        (task_id, repetition)
        for task_id in task_ids
        for repetition in range(repetitions)
    ):
        first, second = (
            MEASUREMENT_STUDY_ARMS
            if choices[index] == 0
            else tuple(reversed(MEASUREMENT_STUDY_ARMS))
        )
        row = {
            "pair_id": _study_domain_hash(
                "contextguard.bench.pair-id.v1", [task_id, repetition],
            ),
            "task_id": task_id,
            "repetition": repetition,
            "first_arm": first,
            "second_arm": second,
        }
        if namespace is not None and candidate_hash is not None:
            row["task"] = task_id
            row["run_ids"] = [
                MeasurementIdentity(
                    candidate_hash=candidate_hash,
                    repetition=repetition,
                    arm=arm,
                    attempt=0,
                    namespace=namespace,
                ).run_id(task_id)
                for arm in (first, second)
            ]
        rows.append(row)
    if sum(row["first_arm"] == "baseline" for row in rows) != 18:
        raise AssertionError("balanced schedule construction failed")
    return rows


def generate_measurement_study_slots(
    task_ids: list[str],
    schedule: list[dict[str, Any]] | None = None,
    *,
    candidate_hash: str,
    namespace: str,
    repetitions: int = 3,
    arms: Sequence[str] = MEASUREMENT_STUDY_ARMS,
) -> list[dict[str, Any]]:
    if schedule is None:
        if repetitions != 3 or tuple(arms) != MEASUREMENT_STUDY_ARMS:
            raise ValueError("measurement study slot dimensions are frozen")
        schedule = [
            {
                "pair_id": _study_domain_hash(
                    "contextguard.bench.pair-id.v1", [task_id, repetition],
                ),
                "task_id": task_id,
                "repetition": repetition,
                "first_arm": arms[0],
                "second_arm": arms[1],
            }
            for task_id in task_ids for repetition in range(repetitions)
        ]
    expected_order = [
        (task_id, repetition) for task_id in task_ids for repetition in range(3)
    ]
    if [(row.get("task_id"), row.get("repetition")) for row in schedule] != expected_order:
        raise ValueError("measurement study schedule task/repetition order drift")
    initial: list[dict[str, Any]] = []
    conditional: list[dict[str, Any]] = []
    all_run_ids: set[str] = set()
    legacy_ids: set[str] = set()
    for row in schedule:
        if {row.get("first_arm"), row.get("second_arm")} != set(MEASUREMENT_STUDY_ARMS):
            raise ValueError("measurement study schedule arm imbalance")
        for arm in (row["first_arm"], row["second_arm"]):
            for attempt, state, destination in (
                (0, "planned", initial), (1, "conditional", conditional),
            ):
                identity = MeasurementIdentity(
                    candidate_hash=candidate_hash,
                    repetition=row["repetition"],
                    arm=arm,
                    attempt=attempt,
                    namespace=namespace,
                )
                run_id = identity.run_id(row["task_id"])
                legacy_id = identity.legacy_v1_run_id(row["task_id"])
                if run_id in all_run_ids or legacy_id in legacy_ids or run_id in legacy_ids:
                    raise ValueError("measurement study run id collision")
                all_run_ids.add(run_id)
                legacy_ids.add(legacy_id)
                destination.append({
                    "pair_id": row["pair_id"],
                    "task_id": row["task_id"],
                    "repetition": row["repetition"],
                    "arm": arm,
                    "attempt": attempt,
                    "run_id": run_id,
                    "state": state,
                })
    slots = initial + conditional
    validate_measurement_study_slots(slots, task_ids=task_ids)
    return slots


def validate_measurement_study_slots(
    slots: Sequence[Mapping[str, Any]],
    *,
    task_ids: Sequence[str] | None = None,
    repetitions: int = 3,
    manifest_hash: str | None = None,
) -> tuple[Mapping[str, Any], ...] | None:
    if len(slots) != 144:
        raise ValueError("measurement study manifest must contain exactly 144 slots")
    required = {
        "pair_id", "task_id", "repetition", "arm", "attempt", "run_id", "state",
    }
    if manifest_hash is not None:
        required.add("study_manifest_sha256")
    if task_ids is None:
        task_ids = list(dict.fromkeys(str(slot.get("task_id")) for slot in slots))
    run_ids: set[str] = set()
    expected: set[tuple[str, int, str, int]] = set()
    for task_id in task_ids:
        for repetition in range(repetitions):
            for arm in MEASUREMENT_STUDY_ARMS:
                for attempt in (0, 1):
                    expected.add((task_id, repetition, arm, attempt))
    actual: set[tuple[str, int, str, int]] = set()
    for slot in slots:
        if set(slot) != required:
            raise ValueError("measurement study slot schema mismatch")
        if manifest_hash is not None and slot.get("study_manifest_sha256") != manifest_hash:
            raise ValueError("measurement study slot manifest mismatch")
        key = (slot["task_id"], slot["repetition"], slot["arm"], slot["attempt"])
        if key in actual:
            raise ValueError("duplicate measurement study slot")
        actual.add(key)
        if slot["run_id"] in run_ids:
            raise ValueError("duplicate measurement study run id")
        run_ids.add(slot["run_id"])
        expected_state = "planned" if slot["attempt"] == 0 else "conditional"
        if slot["state"] != expected_state:
            raise ValueError("measurement study slot initial state mismatch")
    if actual != expected:
        raise ValueError("measurement study slot coverage mismatch")
    if manifest_hash is not None:
        return tuple(slots)
    return None


def parse_measurement_terminal_usage(raw: bytes | str) -> dict[str, int]:
    parsed = parse_claude_stream_output(raw)
    if parsed.payload is None or parsed.payload.get("type") != "result":
        raise ValueError("measurement terminal usage requires one terminal result record")
    usage = parsed.payload.get("usage")
    # Claude Code may add diagnostic telemetry beside the four accounting
    # buckets. Only the frozen required buckets participate in the estimator.
    if not isinstance(usage, dict) or not set(MEASUREMENT_STUDY_USAGE_KEYS).issubset(usage):
        raise ValueError("measurement terminal usage must contain all four required buckets")
    result: dict[str, int] = {}
    total = 0
    for key in MEASUREMENT_STUDY_USAGE_KEYS:
        value = usage[key]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("measurement terminal usage buckets must be JSON integers")
        if value < 0 or value > MAX_USAGE_TOKEN_COUNT:
            raise ValueError("measurement terminal usage bucket is outside its allowed range")
        total += value
        if total > MAX_USAGE_TOKEN_COUNT:
            raise ValueError("measurement terminal usage sum exceeds its allowed range")
        result[key] = value
    result["primary_tokens"] = total
    return result


def type7_quantile(
    values: Sequence[float | Fraction], probability: float | Fraction,
) -> float | Fraction:
    if not values:
        raise ValueError("Type-7 quantile requires at least one value")
    if not 0 <= probability <= 1:
        raise ValueError("quantile probability is outside [0,1]")
    exact = isinstance(probability, Fraction) or all(
        isinstance(value, (int, Fraction)) and not isinstance(value, bool)
        for value in values
    )
    ordered = sorted(
        Fraction(value) if exact else float(value) for value in values
    )
    if any(not math.isfinite(float(value)) for value in ordered):
        raise ValueError("quantile values must be finite")
    probability_value = Fraction(probability) if exact else float(probability)
    h = (len(ordered) - 1) * probability_value
    lower = h.numerator // h.denominator if isinstance(h, Fraction) else math.floor(h)
    upper = lower if h == lower else lower + 1
    fraction = h - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def bootstrap_task_cluster(
    values_by_task: Sequence[Sequence[float]] | None = None,
    *,
    seed: int | str = MEASUREMENT_STUDY_INFERENCE_SEED,
    resamples: int = MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES,
    token_differences: Sequence[Sequence[int]] | None = None,
    retry_differences: Sequence[Sequence[int]] | None = None,
    replicates: int | None = None,
) -> dict[str, Any]:
    direct_mode = token_differences is not None or retry_differences is not None
    if direct_mode:
        if token_differences is None or retry_differences is None:
            raise ValueError("both bootstrap difference matrices are required")
        values_by_task = token_differences
        resamples = replicates if replicates is not None else resamples
    if values_by_task is None:
        raise ValueError("bootstrap values are required")
    if len(values_by_task) != 12 or any(len(row) != 3 for row in values_by_task):
        raise ValueError("task-cluster bootstrap requires exactly 12 x 3 values")
    if resamples != MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES:
        raise ValueError("measurement study bootstrap requires exactly 10,000 resamples")
    seed_int = int(seed, 16) if isinstance(seed, str) else seed
    state = seed_int & SPLITMIX64_MASK
    indices = bytearray()
    exact_mode = direct_mode or all(
        all(isinstance(value, (int, Fraction)) and not isinstance(value, bool) for value in row)
        for row in values_by_task
    )
    estimates: list[Any] = []
    task_means = (
        [sum(Fraction(value) for value in row) / 3 for row in values_by_task]
        if exact_mode
        else [sum(float(value) for value in row) / 3.0 for row in values_by_task]
    )
    for _ in range(resamples):
        sampled_total: Any = Fraction(0) if exact_mode else 0.0
        for _ in range(12):
            state, task_index = splitmix64_bounded(state, 12)
            indices.append(task_index)
            sampled_total += task_means[task_index]
        estimates.append(sampled_total / (12 if exact_mode else 12.0))
    result = {
        "point": sum(task_means) / (12 if exact_mode else 12.0),
        "q025": type7_quantile(
            estimates, Fraction(1, 40) if exact_mode else 0.025,
        ),
        "q975": type7_quantile(
            estimates, Fraction(39, 40) if exact_mode else 0.975,
        ),
        "sampled_index_sha256": hashlib.sha256(indices).hexdigest(),
        "sampled_index_prefix": list(indices[:36]),
        "resamples": resamples,
        "task_draws_per_resample": 12,
    }
    if direct_mode:
        retry_result = bootstrap_task_cluster(
            retry_differences, seed=seed_int, resamples=resamples,
        )
        result.update({
            "sampled_task_indices": list(indices),
            "token_q025": result["q025"],
            "token_q975": result["q975"],
            "retry_q025": retry_result["q025"],
            "retry_q975": retry_result["q975"],
        })
    return result


def _valid_measurement_attempt_sequence(
    consumed: Sequence[Mapping[str, Any]],
    *,
    status_key: str,
    successful_key: str | None = None,
) -> bool:
    attempt_numbers = [row.get("attempt") for row in consumed]
    if not all(
        isinstance(attempt, int) and not isinstance(attempt, bool)
        for attempt in attempt_numbers
    ):
        return False
    statuses = [row.get(status_key) for row in consumed]
    if attempt_numbers == [0]:
        expected_statuses = ["success"]
        expected_success = [True]
    elif attempt_numbers == [0, 1]:
        expected_statuses = ["valid_task_failure_v1", "success"]
        expected_success = [False, True]
    else:
        return False
    if statuses != expected_statuses:
        return False
    if successful_key is None:
        return True
    return [
        row.get(successful_key) is True for row in consumed
    ] == expected_success


def compute_measurement_study_estimators(
    attempts: Sequence[Mapping[str, Any]],
    *,
    task_order: Sequence[str] | None = None,
) -> dict[str, Any]:
    if attempts and "task" in attempts[0]:
        grouped_direct: dict[
            tuple[str, int, str], list[Mapping[str, Any]]
        ] = collections.defaultdict(list)
        for row in attempts:
            grouped_direct[
                (str(row["task"]), int(row["repetition"]), str(row["arm"]))
            ].append(row)
        tasks_direct = list(task_order) if task_order is not None else list(
            dict.fromkeys(str(row["task"]) for row in attempts)
        )
        arm_totals: dict[str, dict[str, Any]] = {}
        token_differences: list[list[int]] = []
        retry_differences: list[list[int]] = []
        paired_units = 0
        complete = len(tasks_direct) == 12
        for task in tasks_direct:
            task_tokens: list[int] = []
            task_retries: list[int] = []
            for repetition in range(3):
                unit: dict[str, tuple[int, int]] = {}
                for arm in MEASUREMENT_STUDY_ARMS:
                    rows = sorted(
                        grouped_direct.get((task, repetition, arm), ()),
                        key=lambda row: int(row["attempt"]),
                    )
                    consumed = [row for row in rows if row.get("consumed") is True]
                    successful = [
                        row for row in consumed
                        if row.get("terminal_status") == "success"
                    ]
                    valid = (
                        _valid_measurement_attempt_sequence(
                            consumed, status_key="terminal_status",
                        )
                        and len(successful) == 1
                        and successful[0] is consumed[-1]
                    )
                    attempt_tokens: list[int] = []
                    for row in consumed:
                        usage = row.get("usage")
                        if (
                            not isinstance(usage, Mapping)
                            or set(usage) != set(MEASUREMENT_STUDY_USAGE_KEYS)
                        ):
                            valid = False
                            break
                        values = list(usage.values())
                        if any(
                            isinstance(value, bool) or not isinstance(value, int) or value < 0
                            for value in values
                        ):
                            valid = False
                            break
                        attempt_tokens.append(sum(values))
                    if valid:
                        primary_tokens = sum(attempt_tokens)
                        unit[arm] = (primary_tokens, int(len(consumed) > 1))
                        arm_totals[f"{task}:{repetition}:{arm}"] = {
                            "attempt_tokens": attempt_tokens,
                            "primary_tokens": primary_tokens,
                            "retried": len(consumed) > 1,
                        }
                if set(unit) == set(MEASUREMENT_STUDY_ARMS):
                    paired_units += 1
                    task_tokens.append(unit["treatment"][0] - unit["baseline"][0])
                    task_retries.append(unit["treatment"][1] - unit["baseline"][1])
                else:
                    complete = False
            if len(task_tokens) == 3:
                token_differences.append(task_tokens)
                retry_differences.append(task_retries)
            else:
                complete = False
        result_direct: dict[str, Any] = {
            "complete_pairs": complete and paired_units == 36,
            "paired_unit_count": paired_units,
            "consumed_attempt_count": sum(
                row.get("consumed") is True for row in attempts
            ),
            "arm_unit_totals": arm_totals,
            "delta": None,
            "gamma": None,
            "delta_q025": None,
            "delta_q975": None,
            "gamma_q025": None,
            "gamma_q975": None,
        }
        if result_direct["complete_pairs"]:
            bootstrap = bootstrap_task_cluster(
                token_differences=token_differences,
                retry_differences=retry_differences,
                seed=MEASUREMENT_STUDY_INFERENCE_SEED,
                replicates=MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES,
            )
            result_direct.update({
                "delta": sum(
                    sum(Fraction(value) for value in row) / 3
                    for row in token_differences
                ) / 12,
                "gamma": sum(
                    sum(Fraction(value) for value in row) / 3
                    for row in retry_differences
                ) / 12,
                "delta_q025": bootstrap["token_q025"],
                "delta_q975": bootstrap["token_q975"],
                "gamma_q025": bootstrap["retry_q025"],
                "gamma_q975": bootstrap["retry_q975"],
            })
        return result_direct
    invalid = {
        "valid": False, "reason": "incomplete_or_invalid_pair", "paired_units": 0,
        "delta": None, "gamma": None, "m_retry": 0,
        "task_deltas": None, "task_gammas": None,
    }
    grouped: dict[tuple[str, int, str], list[Mapping[str, Any]]] = collections.defaultdict(list)
    for row in attempts:
        grouped[(str(row["task_id"]), int(row["repetition"]), str(row["arm"]))].append(row)
    tasks = list(task_order) if task_order is not None else list(dict.fromkeys(
        str(row["task_id"]) for row in attempts
    ))
    if len(tasks) != len(set(tasks)):
        return invalid
    if len(tasks) != 12:
        return invalid
    task_deltas: list[list[float]] = []
    task_gammas: list[list[float]] = []
    paired = 0
    for task_id in tasks:
        deltas: list[float] = []
        gammas: list[float] = []
        for repetition in range(3):
            costs: dict[str, int] = {}
            retry_indicators: dict[str, int] = {}
            for arm in MEASUREMENT_STUDY_ARMS:
                rows = sorted(grouped.get((task_id, repetition, arm), []), key=lambda row: int(row["attempt"]))
                consumed = [row for row in rows if row.get("consumed") is True]
                if not _valid_measurement_attempt_sequence(
                    consumed,
                    status_key="terminal_classification",
                    successful_key="successful",
                ):
                    return invalid
                tokens: list[int] = []
                for row in consumed:
                    value = row.get("primary_tokens")
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        return invalid
                    tokens.append(value)
                costs[arm] = sum(tokens)
                retry_indicators[arm] = int(len(consumed) > 1)
            deltas.append(float(costs["treatment"] - costs["baseline"]))
            gammas.append(float(retry_indicators["treatment"] - retry_indicators["baseline"]))
            paired += 1
        task_deltas.append(deltas)
        task_gammas.append(gammas)
    return {
        "valid": True,
        "reason": None,
        "paired_units": paired,
        "delta": sum(sum(row) / 3.0 for row in task_deltas) / 12.0,
        "gamma": sum(sum(row) / 3.0 for row in task_gammas) / 12.0,
        "m_retry": 0,
        "task_deltas": task_deltas,
        "task_gammas": task_gammas,
    }


def build_blinded_correction_packets(
    outputs: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if len(outputs) != 72:
        raise ValueError("correction packetization requires exactly 72 outputs")
    direct_mode = any("task" in row and "task_id" not in row for row in outputs)
    expected = {
        (task_id, repetition, arm)
        for task_id in {str(row.get("task_id", row.get("task"))) for row in outputs}
        for repetition in range(3)
        for arm in MEASUREMENT_STUDY_ARMS
    }
    actual = {
        (str(row.get("task_id", row.get("task"))), row.get("repetition"), row.get("arm"))
        for row in outputs
    }
    if len({key[0] for key in expected}) != 12 or actual != expected:
        raise ValueError("correction packet coverage mismatch")
    task_order = list(dict.fromkeys(
        str(row.get("task_id", row.get("task"))) for row in outputs
    ))
    expected_order = [
        (task_id, repetition, arm)
        for task_id in task_order
        for repetition in range(3)
        for arm in MEASUREMENT_STUDY_ARMS
    ]
    observed_order = [
        (
            str(row.get("task_id", row.get("task"))),
            row.get("repetition"),
            row.get("arm"),
        )
        for row in outputs
    ]
    if observed_order != expected_order:
        raise ValueError("correction packet order mismatch")
    packets: list[dict[str, Any]] = []
    for index, row in enumerate(outputs):
        output = row.get("output")
        if not isinstance(output, str):
            raise ValueError("correction output must be text")
        packets.append(
            {
                "packet_id": f"A{index + 1:03d}",
                "source_index": index,
                "output": output,
            }
            if direct_mode else {"original_index": index, "output": output}
        )
    return packets


def shuffle_correction_packets(
    packets: Sequence[Mapping[str, Any]],
    seed: int | str = MEASUREMENT_STUDY_CORRECTION_SEED,
    *,
    packet_id_map: Mapping[str, int] | None = None,
) -> list[dict[str, Any]]:
    if len(packets) != 72:
        raise ValueError("correction shuffle requires exactly 72 packets")
    direct_mode = bool(packets and "packet_id" in packets[0])
    if direct_mode:
        expected_map = {
            str(packet.get("packet_id")): int(packet.get("source_index", index))
            for index, packet in enumerate(packets)
        }
        if packet_id_map is not None and dict(packet_id_map) != expected_map:
            raise ValueError("correction packet identity map mismatch")
    elif packet_id_map is not None:
        raise ValueError("correction packet identity map is unavailable")
    permutation = correction_packet_permutation(72, seed=seed)
    assert isinstance(permutation, list)
    if direct_mode:
        return [
            {
                "assessment_id": f"A{position + 1:03d}",
                "output": packets[original]["output"],
            }
            for position, original in enumerate(permutation)
        ]
    return [
        {"assessment_id": f"A{position + 1:03d}", "output": packets[original]["output"]}
        for position, original in enumerate(permutation)
    ]


def correction_packet_identity_map(
    packets: Sequence[Mapping[str, Any]],
    seed: int | str = MEASUREMENT_STUDY_CORRECTION_SEED,
) -> dict[str, str]:
    if len(packets) != 72:
        raise ValueError("correction identity map requires exactly 72 packets")
    packet_ids = [packet.get("packet_id") for packet in packets]
    if (
        any(not isinstance(packet_id, str) for packet_id in packet_ids)
        or len(set(packet_ids)) != 72
    ):
        raise ValueError("correction identity map packet ids are invalid")
    permutation = correction_packet_permutation(72, seed=seed)
    assert isinstance(permutation, list)
    return {
        f"A{position + 1:03d}": str(packet_ids[original])
        for position, original in enumerate(permutation)
    }


def correction_packet_permutation(
    count: int | None = None,
    *,
    seed: int | str = MEASUREMENT_STUDY_CORRECTION_SEED,
) -> dict[str, Any] | list[int]:
    packet_count = 72 if count is None else count
    if packet_count != 72:
        raise ValueError("correction permutation requires exactly 72 packets")
    permutation = list(range(packet_count))
    seed_int = int(seed, 16) if isinstance(seed, str) else seed
    state = seed_int & SPLITMIX64_MASK
    for index in range(71, 0, -1):
        state, selected = splitmix64_bounded(state, index + 1)
        permutation[index], permutation[selected] = permutation[selected], permutation[index]
    if count is not None:
        return permutation
    return {
        "permutation": permutation,
        "prefix": permutation[:18],
        "sha256": hashlib.sha256(bytes(permutation)).hexdigest(),
    }


def resolve_correction_scores(scores: Sequence[int]) -> int:
    if len(scores) != 3:
        raise ValueError("correction resolution requires exactly three sealed scores")
    if any(isinstance(score, bool) or score not in (0, 1, 2) for score in scores):
        raise ValueError("correction score must be one of 0, 1, or 2")
    counts = collections.Counter(scores)
    for score, count in counts.items():
        if count >= 2:
            return score
    return 1


def compute_correction_non_regression(
    records: Sequence[Mapping[str, Any]] | None,
    *,
    task_order: Sequence[str] | None = None,
) -> dict[str, Any]:
    if records is None:
        return {"measured": False, "valid": False}
    if not records:
        return {
            "measured": True, "valid": False,
            "severity_point": None, "severity_q975": None,
            "incidence_point": None, "incidence_q975": None,
        }
    if "packet_id" in records[0] and "score" in records[0]:
        if len(records) != 72:
            raise ValueError("correction inference requires exactly 72 records")
        scores = [record.get("score") for record in records]
        if any(
            isinstance(score, bool) or not isinstance(score, int) or score not in (0, 1, 2)
            for score in scores
        ):
            raise ValueError("resolved correction score is invalid")
        # Packet IDs are assigned in source task/repetition/arm order before
        # shuffling, so restore that order before paired inference.
        by_packet = {str(record["packet_id"]): int(record["score"]) for record in records}
        if set(by_packet) != {f"A{i:03d}" for i in range(1, 73)}:
            raise ValueError("resolved correction packet coverage mismatch")
        differences: list[list[int]] = []
        for task_index in range(12):
            row: list[int] = []
            for repetition in range(3):
                base = 1 + (task_index * 3 + repetition) * 2
                row.append(
                    by_packet[f"A{base + 1:03d}"] - by_packet[f"A{base:03d}"]
                )
            differences.append(row)
        bootstrap = bootstrap_task_cluster(differences)
        incidence_differences = [
            [
                int(by_packet[f"A{2 + (task * 3 + rep) * 2:03d}"] > 0)
                - int(by_packet[f"A{1 + (task * 3 + rep) * 2:03d}"] > 0)
                for rep in range(3)
            ]
            for task in range(12)
        ]
        incidence = bootstrap_task_cluster(incidence_differences)
        baseline_severity_2 = sum(
            by_packet[f"A{1 + index * 2:03d}"] == 2 for index in range(36)
        )
        treatment_severity_2 = sum(
            by_packet[f"A{2 + index * 2:03d}"] == 2 for index in range(36)
        )
        return {
            "measured": True,
            "valid": True,
            "severity_point": bootstrap["point"],
            "severity_q975": bootstrap["q975"],
            "incidence_point": incidence["point"],
            "incidence_q975": incidence["q975"],
            "treatment_severity_2": treatment_severity_2,
            "baseline_severity_2": baseline_severity_2,
            "non_regression": (
                bootstrap["point"] <= 0 and bootstrap["q975"] <= 0
                and incidence["point"] <= 0 and incidence["q975"] <= 0
                and treatment_severity_2 <= baseline_severity_2
            ),
        }
    if len(records) != 72:
        raise ValueError("correction inference requires exactly 72 records")
    grouped: dict[tuple[str, int, str], int | None] = {}
    for record in records:
        task_id = record.get("task_id")
        repetition = record.get("repetition")
        arm = record.get("arm")
        if (
            not isinstance(task_id, str) or not task_id
            or isinstance(repetition, bool) or not isinstance(repetition, int)
            or repetition not in (0, 1, 2)
            or arm not in MEASUREMENT_STUDY_ARMS
        ):
            raise ValueError("correction record identity is invalid")
        key = (task_id, repetition, str(arm))
        if key in grouped:
            raise ValueError("duplicate correction arm-unit")
        severity = record.get("severity")
        if severity is not None and (
            isinstance(severity, bool) or not isinstance(severity, int) or severity not in (0, 1, 2)
        ):
            raise ValueError("correction severity must be nullable or 0, 1, 2")
        grouped[key] = severity
    tasks = list(task_order) if task_order is not None else list(dict.fromkeys(
        str(record.get("task_id")) for record in records
    ))
    expected = {
        (task, repetition, arm)
        for task in tasks for repetition in range(3) for arm in MEASUREMENT_STUDY_ARMS
    }
    if len(tasks) != 12 or set(grouped) != expected:
        raise ValueError("correction inference coverage mismatch")
    if any(value is None for value in grouped.values()):
        return {
            "measured": False,
            "severity_point": None,
            "severity_q975": None,
            "incidence_point": None,
            "incidence_q975": None,
            "treatment_severity_2": None,
            "baseline_severity_2": None,
            "non_regression": False,
        }
    severity_differences: list[list[float]] = []
    incidence_differences: list[list[float]] = []
    for task in tasks:
        task_severity: list[float] = []
        task_incidence: list[float] = []
        for repetition in range(3):
            baseline = grouped[(task, repetition, "baseline")]
            treatment = grouped[(task, repetition, "treatment")]
            assert baseline is not None and treatment is not None
            task_severity.append(float(treatment - baseline))
            task_incidence.append(float(int(treatment > 0) - int(baseline > 0)))
        severity_differences.append(task_severity)
        incidence_differences.append(task_incidence)
    severity_bootstrap = bootstrap_task_cluster(severity_differences)
    incidence_bootstrap = bootstrap_task_cluster(incidence_differences)
    treatment_severity_2 = sum(
        value == 2 for (task, repetition, arm), value in grouped.items() if arm == "treatment"
    )
    baseline_severity_2 = sum(
        value == 2 for (task, repetition, arm), value in grouped.items() if arm == "baseline"
    )
    non_regression = bool(
        severity_bootstrap["point"] <= 0
        and severity_bootstrap["q975"] <= 0
        and incidence_bootstrap["point"] <= 0
        and incidence_bootstrap["q975"] <= 0
        and treatment_severity_2 <= baseline_severity_2
    )
    return {
        "measured": True,
        "severity_point": severity_bootstrap["point"],
        "severity_q975": severity_bootstrap["q975"],
        "incidence_point": incidence_bootstrap["point"],
        "incidence_q975": incidence_bootstrap["q975"],
        "treatment_severity_2": treatment_severity_2,
        "baseline_severity_2": baseline_severity_2,
        "non_regression": non_regression,
    }


def append_study_attempt_event(path: Path, event: Mapping[str, Any]) -> None:
    payload = _study_canonical_json_bytes(dict(event))
    parent_fd = _ensure_directory_no_symlink(path.parent, create=True)
    fd = -1
    try:
        if fcntl is not None:
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = _open_regular_no_symlink(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        _measurement_write_fd(fd, payload)
        # A provider launch may follow this reservation immediately. Persist the
        # directory entry as well as the file bytes so a power loss cannot make
        # an already-consumed identity appear unreserved after restart.
        os.fsync(parent_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def fold_study_attempt_events(
    slots: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]] | None = None,
    *,
    manifest_sha256: str | None = None,
) -> dict[Any, dict[str, Any]]:
    if events is None:
        direct_events = slots
        folded_direct: dict[tuple[str, int], dict[str, Any]] = {}
        for event in direct_events:
            run_id = event.get("run_id")
            attempt = event.get("attempt")
            if not isinstance(run_id, str) or isinstance(attempt, bool) or not isinstance(attempt, int):
                raise ValueError("attempt event identity is invalid")
            key = (run_id, attempt)
            current = folded_direct.get(key)
            if current is not None:
                allowed = MEASUREMENT_STUDY_STATE_TRANSITIONS.get(
                    str(current.get("state")), frozenset()
                )
                if event.get("state") not in allowed:
                    raise ValueError("invalid direct attempt state transition")
            folded_direct[key] = dict(event)
        return folded_direct
    if manifest_sha256 is None:
        raise ValueError("manifest hash is required")
    folded = {str(slot["run_id"]): dict(slot) for slot in slots}
    identity_keys = (
        "pair_id", "run_id", "task_id", "repetition", "arm", "attempt",
    )
    base_keys = {
        "schema_version", "manifest_sha256", *identity_keys, "state",
    }
    for event in events:
        if event.get("schema_version") != MEASUREMENT_STUDY_ATTEMPT_INDEX_SCHEMA_VERSION:
            raise ValueError("attempt event schema mismatch")
        run_id = event.get("run_id")
        if run_id not in folded:
            raise ValueError("attempt event references a foreign run id")
        if (
            event.get("manifest_sha256") != manifest_sha256
            or not isinstance(manifest_sha256, str)
            or SHA256_HEX_PATTERN.fullmatch(manifest_sha256) is None
        ):
            raise ValueError("attempt event references a foreign manifest")
        if any(event.get(key) != folded[run_id].get(key) for key in identity_keys):
            raise ValueError("attempt event identity differs from its immutable slot")
        current = str(folded[run_id]["state"])
        new_state = event.get("state")
        extras_by_state = {
            "launch_reserved": {"consumed"},
            "launched": {"consumed"},
            "eligible": {"consumed"},
            "not_needed": {"consumed"},
            "prelaunch_refused": {"consumed", "reason"},
            "blocked_study_invalid": {"consumed", "reason"},
            "terminal": {
                "consumed", "terminal_classification", "successful",
                "primary_tokens", "token_buckets", "receipt_sha256",
                "artifact_index_sha256",
            },
        }
        if new_state not in extras_by_state or set(event) != base_keys | extras_by_state[new_state]:
            raise ValueError("attempt event keys differ from the exact state schema")
        consumed = event.get("consumed")
        if consumed is not (new_state in {"launched", "terminal"}):
            raise ValueError("attempt event consumed flag contradicts its state")
        if (
            new_state == "prelaunch_refused"
            and event.get("reason") not in MEASUREMENT_STUDY_PRELAUNCH_REASONS
        ):
            raise ValueError("attempt event prelaunch reason is invalid")
        if (
            new_state == "blocked_study_invalid"
            and event.get("reason") not in MEASUREMENT_STUDY_BLOCKED_REASONS
        ):
            raise ValueError("attempt event blocked reason is invalid")
        if new_state not in MEASUREMENT_STUDY_STATE_TRANSITIONS.get(current, frozenset()):
            raise ValueError(f"invalid attempt state transition: {current} -> {new_state}")
        if new_state == "terminal":
            classification = event.get("terminal_classification")
            if classification not in MEASUREMENT_STUDY_TERMINAL_CLASSIFICATIONS:
                raise ValueError("terminal attempt classification is invalid")
            successful = event.get("successful")
            if not isinstance(successful, bool) or successful is not (classification == "success"):
                raise ValueError("terminal attempt success flag contradicts its classification")
            primary_tokens = event.get("primary_tokens")
            buckets = event.get("token_buckets")
            if (
                isinstance(primary_tokens, bool)
                or not isinstance(primary_tokens, int)
                or primary_tokens < 0
                or primary_tokens > MAX_USAGE_TOKEN_COUNT
                or not isinstance(buckets, dict)
                or set(buckets) != set(MEASUREMENT_STUDY_USAGE_KEYS)
                or any(
                    isinstance(value, bool) or not isinstance(value, int)
                    or value < 0 or value > MAX_USAGE_TOKEN_COUNT
                    for value in buckets.values()
                )
                or sum(buckets.values()) != primary_tokens
            ):
                raise ValueError("terminal attempt token accounting is invalid")
            nullable_hashes = (
                classification in {
                    "launch_accounting_failure",
                    "post_launch_infra_invalid",
                    "recovered_process_status_unknown",
                }
            )
            for key in ("receipt_sha256", "artifact_index_sha256"):
                value = event.get(key)
                if value is None and nullable_hashes:
                    continue
                if not isinstance(value, str) or SHA256_HEX_PATTERN.fullmatch(value) is None:
                    raise ValueError(f"terminal attempt {key} is invalid")
        evidence = {
            key: value for key, value in event.items()
            if key not in {
                "schema_version", "manifest_sha256", *identity_keys, "state",
            }
        }
        folded[run_id]["state"] = new_state
        folded[run_id].update(evidence)
    return folded


def classify_success_checker(result: BoundedProcessResult) -> str:
    if result.launch_error or result.timed_out or result.output_truncated or result.returncode < 0:
        return "success_checker_infra_invalid"
    if result.returncode == 0:
        return "task_success"
    if result.returncode == 1:
        return "valid_task_failure_v1"
    return "success_checker_infra_invalid"


def create_measurement_probe_layout(
    parent: Path | None = None,
) -> tuple[Path, dict[str, Path]] | dict[str, str]:
    root = Path(tempfile.mkdtemp(
        prefix="contextguard-study-probe-",
        dir=str(parent) if parent is not None else None,
    ))
    os.chmod(root, 0o700)
    paths = {name: root / name for name in MEASUREMENT_STUDY_PROBE_LAYOUT}
    for path in paths.values():
        path.mkdir(mode=0o700)
    validate_measurement_probe_layout(root, paths)
    if parent is not None:
        return {"root": str(root), **{name: str(path) for name, path in paths.items()}}
    return root, paths


def validate_measurement_probe_layout(
    root: Path | Mapping[str, str],
    paths: Mapping[str, Path] | None = None,
) -> None | dict[str, Any]:
    direct_mode = paths is None and isinstance(root, Mapping)
    if direct_mode:
        layout = root
        root = Path(str(layout.get("root")))
        paths = {
            name: Path(str(layout.get(name)))
            for name in MEASUREMENT_STUDY_PROBE_LAYOUT
        }
    assert isinstance(root, Path) and paths is not None
    error_type = ValueError if direct_mode else SystemExit
    if set(paths) != set(MEASUREMENT_STUDY_PROBE_LAYOUT):
        raise error_type("measurement CLI probe layout names differ")
    root_stat = os.lstat(root)
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_IMODE(root_stat.st_mode) != 0o700:
        raise error_type("measurement CLI probe root integrity failure")
    physical_root = root.resolve(strict=True)
    for name in MEASUREMENT_STUDY_PROBE_LAYOUT:
        path = paths[name]
        item_stat = os.lstat(path)
        if (
            path.name != name
            or path.parent.resolve(strict=True) != physical_root
            or stat.S_ISLNK(item_stat.st_mode)
            or not stat.S_ISDIR(item_stat.st_mode)
            or stat.S_IMODE(item_stat.st_mode) != 0o700
        ):
            raise error_type("measurement CLI probe layout integrity failure")
    if direct_mode:
        return {
            "paths": {
                name: f"<probe-root>/{name}"
                for name in MEASUREMENT_STUDY_PROBE_LAYOUT
            }
        }
    return None


def _study_validate_probe_output(
    result: BoundedProcessResult,
    *,
    kind: str,
) -> bytes:
    if (
        result.returncode != 0 or result.timed_out or result.output_truncated
        or result.stderr_bytes
    ):
        raise SystemExit(f"measurement CLI {kind} probe failed")
    raw = result.stdout_bytes
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n") or b"\r" in raw:
        raise SystemExit(f"measurement CLI {kind} probe output shape invalid")
    lines = raw.splitlines()
    if not raw or len(lines) > 4096 or any(len(line) > 16384 for line in lines):
        raise SystemExit(f"measurement CLI {kind} probe output bounds invalid")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise SystemExit(f"measurement CLI {kind} probe output is not UTF-8") from None
    if kind == "version" and (len(lines) != 1 or len(raw) > 512 or not lines[0]):
        raise SystemExit("measurement CLI version probe output shape invalid")
    return raw


def run_measurement_cli_probes(
    claude_bin: str,
    required_capabilities: Sequence[str] = (),
    *,
    run_command: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if run_command is not None:
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": "<probe-root>/home",
            "XDG_CONFIG_HOME": "<probe-root>/xdg-config",
            "XDG_CACHE_HOME": "<probe-root>/xdg-cache",
            "XDG_DATA_HOME": "<probe-root>/xdg-data",
            "XDG_STATE_HOME": "<probe-root>/xdg-state",
            "TMPDIR": "<probe-root>/tmp",
            "CLAUDE_CONFIG_DIR": "<probe-root>/claude-config",
            "NO_COLOR": "1",
        }
        results = [
            run_command(
                [claude_bin, flag],
                cwd=Path("<probe-root>/cwd"),
                timeout_seconds=10.0,
                max_output_bytes=MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES,
                env=dict(env),
            )
            for flag in ("--version", "--help")
        ]
        normalized = [
            result if isinstance(result, Mapping) else vars(result)
            for result in results
        ]
        for result in normalized:
            if (
                result.get("returncode") != 0
                or result.get("timed_out") is True
                or result.get("output_truncated") is True
            ):
                raise ValueError("measurement CLI metadata probe failed")
        version_text = str(normalized[0].get("stdout", ""))
        help_text = str(normalized[1].get("stdout", ""))
        return {
            "schema_version": MEASUREMENT_CLI_PROBE_SCHEMA_VERSION,
            "version_stdout_sha256": _study_sha256_bytes(version_text.encode()),
            "help_stdout_sha256": _study_sha256_bytes(help_text.encode()),
            "environment_names": sorted(env),
            "paths": {
                name: f"<probe-root>/{name}"
                for name in MEASUREMENT_STUDY_PROBE_LAYOUT
            },
            "capabilities": list(required_capabilities),
        }
    executable = executable_argv0(claude_bin)
    executable_path = Path(executable)
    if not executable_path.is_file():
        raise SystemExit("measurement CLI executable not found")
    root, paths = create_measurement_probe_layout()
    try:
        validate_measurement_probe_layout(root, paths)
        runtime_directories = [str(executable_path.parent)]
        invoked = shutil.which(claude_bin)
        if invoked is not None:
            runtime_directories.append(str(Path(invoked).absolute().parent))
        for runtime_name in ("node", "python3"):
            runtime = shutil.which(runtime_name)
            if runtime is not None:
                runtime_directories.append(str(Path(runtime).absolute().parent))
        runtime_directories.extend(("/usr/bin", "/bin", "/usr/sbin", "/sbin"))
        path_value = os.pathsep.join(dict.fromkeys(runtime_directories))
        env = {
            "PATH": path_value,
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": str(paths["home"]),
            "XDG_CONFIG_HOME": str(paths["xdg-config"]),
            "XDG_CACHE_HOME": str(paths["xdg-cache"]),
            "XDG_DATA_HOME": str(paths["xdg-data"]),
            "XDG_STATE_HOME": str(paths["xdg-state"]),
            "TMPDIR": str(paths["tmp"]),
            "CLAUDE_CONFIG_DIR": str(paths["claude-config"]),
            "NO_COLOR": "1",
        }
        results: list[BoundedProcessResult] = []
        for flag in ("--version", "--help"):
            results.append(run_bounded_command(
                [executable, flag],
                cwd=paths["cwd"],
                timeout_seconds=10,
                max_output_bytes=MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES,
                env=env,
            ))
        version_raw = _study_validate_probe_output(results[0], kind="version")
        help_raw = _study_validate_probe_output(results[1], kind="help")
        help_text = help_raw.decode("utf-8")
        capability_tokens = set(re.findall(
            r"--[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*|[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*",
            help_text,
        ))
        missing = [
            capability for capability in required_capabilities
            if capability not in capability_tokens
        ]
        if missing:
            raise SystemExit("measurement CLI required capability unavailable")
        canonical_env = {
            key: (
                value.replace(str(root), "<probe-root>", 1)
                if value.startswith(str(root)) else value
            )
            for key, value in env.items()
        }
        return {
            "schema_version": MEASUREMENT_CLI_PROBE_SCHEMA_VERSION,
            "executable": str(executable_path.resolve(strict=True)),
            "argv": [[executable, "--version"], [executable, "--help"]],
            "version": version_raw.decode("utf-8").rstrip("\n"),
            "version_stdout_sha256": _study_sha256_bytes(version_raw),
            "version_stdout_bytes": len(version_raw),
            "help_stdout_sha256": _study_sha256_bytes(help_raw),
            "help_stdout_bytes": len(help_raw),
            "capabilities": sorted(set(required_capabilities)),
            "cwd": "<probe-root>/cwd",
            "environment": canonical_env,
            "environment_names": sorted(env),
            "limits": {
                "timeout_seconds": 10.0,
                "stdout_max_bytes": 65_536,
                "stderr_max_bytes": 65_536,
                "max_lines": 4096,
                "max_line_bytes": 16_384,
            },
            "layout": list(MEASUREMENT_STUDY_PROBE_LAYOUT),
            "root_mode": "0700",
        }
    finally:
        shutil.rmtree(root)


def _study_task_manifest(task: TaskFixture, task_dir: Path) -> dict[str, Any]:
    variant_prompts: list[dict[str, Any]] = []
    for name, rel in task.variant_prompt_files.items():
        path = task_dir / validate_variant_prompt_file_path(rel, owner=f"task {task.id}")
        raw = _read_text_no_follow(path).encode("utf-8")
        variant_prompts.append({
            "variant": name,
            "path": str(path.resolve()),
            "sha256": _study_sha256_bytes(raw),
            "bytes": len(raw),
        })
    if task.fixture_tree is None:
        fixture_tree: dict[str, Any] | None = None
        success_checker: dict[str, Any] | None = None
    else:
        entries = task.fixture_tree_entries
        if entries is None:
            # 매니페스트 해시와 workspace 실체화가 서로 다른 read 에서 나오지 않도록,
            # 바인딩된 바이트만 신뢰하고 누락은 fail-closed 로 처리한다.
            raise SystemExit(
                f"task {task.id} fixture tree must be bound before manifest binding; "
                "call load_task_fixture_trees first"
            )
        fixture_tree = {
            "root": task.fixture_tree,
            "files": fixture_tree_manifest_files(entries),
            "file_count": len(entries),
            "total_bytes": sum(len(entry.data) for entry in entries),
            "tree_sha256": fixture_tree_sha256(entries),
            "reset": "deterministic_cold_workspace_materialization_v1",
        }
        if task.success_checker is None:
            success_checker = None
        else:
            payload = task.success_checker_bytes
            if payload is None:
                raise SystemExit(
                    f"task {task.id} success checker must be bound before manifest "
                    "binding; call load_task_fixture_trees first"
                )
            success_checker = {
                "path": task.success_checker,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "inside_fixture_tree": False,
                "execution": "private_per_attempt_directory_outside_workspace_v1",
                "argv": "interpreter_plus_bound_checker_copy",
            }
    return {
        "id": task.id,
        "prompt_sha256": _study_sha256_bytes(task.prompt.encode("utf-8")),
        "prompt_bytes": len(task.prompt.encode("utf-8")),
        "model": task.model,
        "effort": task.effort,
        "max_turns": task.max_turns,
        "max_budget_usd": task.max_budget_usd,
        "allowed_tools": task.allowed_tools,
        "output_format": task.output_format,
        "success_command": task.success_command,
        "success_cwd": task.success_cwd,
        "variant_prompts": variant_prompts,
        "fixture_tree": fixture_tree,
        "success_checker": success_checker,
    }


def _study_variant_manifest(variant: Variant) -> dict[str, Any]:
    result: dict[str, Any] = {"name": variant.name, "extra_args": variant.extra_args}
    if variant.measurement is None:
        result["measurement"] = None
        return result
    spec = variant.measurement
    result["measurement"] = {
        "settings_source": {
            "path": str(spec.settings_file.resolve()),
            "sha256": _study_sha256_bytes(spec.settings_source_bytes),
            "bytes": len(spec.settings_source_bytes),
        },
        "executed_snapshot": {
            "path": f"runs/{{run_id}}/session/{spec.settings_file.name}",
            "sha256": _study_sha256_bytes(spec.settings_source_bytes),
            "bytes": len(spec.settings_source_bytes),
        },
        "setting_sources": list(spec.setting_sources),
        "environment_allow": list(spec.environment_allow),
        "environment_overrides": [list(item) for item in spec.environment_overrides],
        "workspace_mode": spec.workspace_mode,
        "session_mode": spec.session_mode,
        "session_persistence": spec.session_persistence,
        "hook_events_enabled": spec.hook_events_enabled,
        "registered_bindings": [list(item) for item in spec.registered_bindings],
        "binding_set_sha256": _measurement_binding_set_sha256(spec.registered_bindings),
        "required_event_classes": list(spec.required_event_classes),
        "cli_capabilities": list(spec.cli_capabilities),
        "candidate_hash": spec.identity.candidate_hash,
        "artifact_root": str(spec.artifact_root.resolve()),
    }
    return result


def build_measurement_study_manifest(
    *,
    plan: Mapping[str, Any] | None = None,
    tasks: Sequence[TaskFixture] | Mapping[str, Any] | None = None,
    variants: Sequence[Variant] | Mapping[str, Any] | None = None,
    tasks_path: Path | None = None,
    variants_path: Path | None = None,
    plan_path: Path | None = None,
    project_root: Path | None = None,
    output_root: Path | None = None,
    probe: Mapping[str, Any] | None = None,
    study_plan: Mapping[str, Any] | None = None,
    cli_probe: Mapping[str, Any] | None = None,
    runner_sha256: str | None = None,
    mirror_sha256: str | None = None,
    canonical_bytes: bool = False,
) -> dict[str, Any] | bytes:
    if study_plan is not None:
        direct_manifest = {
            "schema_version": MEASUREMENT_STUDY_DIRECT_MANIFEST_SCHEMA_VERSION,
            "study_plan": dict(study_plan),
            "tasks": dict(tasks) if isinstance(tasks, Mapping) else tasks,
            "variants": dict(variants) if isinstance(variants, Mapping) else variants,
            "cli_probe": dict(cli_probe or {}),
            "runner_sha256": runner_sha256,
            "mirror_sha256": mirror_sha256,
        }
        validate_measurement_study_manifest(direct_manifest)
        if canonical_bytes:
            return json.dumps(
                direct_manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        return direct_manifest
    if (
        plan is None or tasks is None or variants is None or tasks_path is None
        or variants_path is None or plan_path is None or project_root is None
        or output_root is None or probe is None
        or isinstance(tasks, Mapping) or isinstance(variants, Mapping)
    ):
        raise TypeError("production manifest arguments are required")
    if len(tasks) != 12 or len(variants) != 2:
        raise SystemExit("measurement study requires exactly 12 tasks and two variants")
    names = [variant.name for variant in variants]
    if names != ["baseline", "treatment"]:
        raise SystemExit("measurement study variants must be ordered baseline then treatment")
    if any(variant.measurement is None for variant in variants):
        raise SystemExit("measurement study requires S001 measurement variants")
    candidate_hashes = {
        variant.measurement.identity.candidate_hash
        for variant in variants if variant.measurement is not None
    }
    if len(candidate_hashes) != 1:
        raise SystemExit("measurement study arm candidate hashes differ")
    candidate_hash = next(iter(candidate_hashes))
    schedule = generate_balanced_study_schedule(
        [task.id for task in tasks], 3, int(plan["schedule_seed_int"]),
    )
    slots = generate_measurement_study_slots(
        [task.id for task in tasks], schedule,
        candidate_hash=candidate_hash, namespace=str(plan["namespace"]),
    )
    invoked_path = Path(__file__).resolve()
    repo_root = next(
        (
            parent for parent in (invoked_path.parent, *invoked_path.parents)
            if (parent / "context-guard-kit/benchmark_runner.py").is_file()
            and (parent / "plugins/context-guard/bin/context-guard-bench").is_file()
        ),
        None,
    )
    if repo_root is None:
        raise SystemExit("benchmark runner repository layout unavailable")
    runner_path = repo_root / "context-guard-kit/benchmark_runner.py"
    plugin_path = repo_root / "plugins/context-guard/bin/context-guard-bench"
    runner_raw = _read_bytes_no_follow(runner_path, max_bytes=2_000_000)
    plugin_raw = _read_bytes_no_follow(plugin_path, max_bytes=2_000_000)
    if runner_raw != plugin_raw:
        raise SystemExit("canonical and packaged benchmark runners differ")
    plan_public = {key: plan[key] for key in MEASUREMENT_STUDY_PLAN_KEYS}
    task_raw = _read_bytes_no_follow(tasks_path)
    variant_raw = _read_bytes_no_follow(variants_path)
    plan_raw = _read_bytes_no_follow(plan_path)
    manifest = {
        "schema_version": MEASUREMENT_STUDY_MANIFEST_SCHEMA_VERSION,
        "inputs": {
            "runner": {"sha256": _study_sha256_bytes(runner_raw), "bytes": len(runner_raw)},
            "packaged_runner": {"sha256": _study_sha256_bytes(plugin_raw), "bytes": len(plugin_raw)},
            "tasks": {
                "path": str(tasks_path.resolve()), "sha256": _study_sha256_bytes(task_raw),
                "bytes": len(task_raw),
            },
            "variants": {
                "path": str(variants_path.resolve()), "sha256": _study_sha256_bytes(variant_raw),
                "bytes": len(variant_raw),
            },
            "study_plan": {
                "path": str(plan_path.resolve()), "sha256": _study_sha256_bytes(plan_raw),
                "bytes": len(plan_raw),
            },
            "project_root": str(project_root.resolve()),
            "output_root": str(output_root.resolve()),
            "ordered_task_ids": [task.id for task in tasks],
            "task_definitions": [_study_task_manifest(task, tasks_path.parent) for task in tasks],
            "variant_definitions": [_study_variant_manifest(variant) for variant in variants],
            "cli_probe": dict(probe),
        },
        "plan": plan_public,
        "schedule": schedule,
        "schedule_sha256": _study_sha256_bytes(_study_canonical_json_bytes(schedule)),
        "slots": slots,
        "contracts": {
            "measurement_substrate_schema": MEASUREMENT_SUBSTRATE_SCHEMA_VERSION,
            "raw_receipt_schema": MEASUREMENT_RAW_RECEIPT_SCHEMA_VERSION,
            "artifact_index_schema": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
            "artifact_index_event_binding": "canonical-index-row-sha256-v1",
            "attempt_index_schema": MEASUREMENT_STUDY_ATTEMPT_INDEX_SCHEMA_VERSION,
            "terminal_usage_schema": MEASUREMENT_TERMINAL_USAGE_SCHEMA_VERSION,
            "terminal_usage_golden_sha256": MEASUREMENT_TERMINAL_USAGE_GOLDEN_SHA256,
            "schedule_algorithm": MEASUREMENT_STUDY_SCHEDULE_ALGORITHM,
            "splitmix64": {
                "increment": f"0x{SPLITMIX64_INCREMENT:016X}",
                "multiplier_1": f"0x{SPLITMIX64_MULTIPLIER_1:016X}",
                "multiplier_2": f"0x{SPLITMIX64_MULTIPLIER_2:016X}",
                "shifts": [30, 27, 31],
            },
            "bootstrap": {
                "resamples": 10_000,
                "tasks": 12,
                "quantile": "Hyndman-Fan-Type-7",
                "inference_seed": "0x434F4E5445585447",
                "sampled_index_sha256": "017b0afdad8afb5ae59c4edf651be4b15c8dbcd94b8bda453b646360736bfc38",
            },
            "terminal_status_precedence": [
                "raw_byte_limit", "raw_line_limit", "raw_line_byte_limit",
                "process_timeout", "process_launch_error", "process_error",
                "terminal_error", "missing_terminal", "invalid_stream",
                "hook_payload_limit", "hook_lifecycle_limit",
                "invalid_hook_lifecycle", "unexpected_hook_event_class",
                "baseline_hook_contamination", "missing_required_hook_event_class",
                "hook_process_failure", "success", "recovered_process_status_unknown",
            ],
            "terminal_usage": {
                "record_type": "result",
                "object_path": "$.usage",
                "keys": list(MEASUREMENT_STUDY_USAGE_KEYS),
                "additional_fields": "ignored_not_counted_v1",
                "integer_grammar": "0|[1-9][0-9]*",
                "maximum": MAX_USAGE_TOKEN_COUNT,
                "formula": "P=input_tokens+cache_creation_input_tokens+cache_read_input_tokens+output_tokens",
            },
            "retry": {
                "policy": MEASUREMENT_STUDY_RETRY_POLICY,
                "maximum_attempts_per_arm_unit": 2,
                "eligible_classification": "valid_task_failure_v1",
                "checker_success_exit": 0,
                "checker_retry_exit": 1,
                "other_checker_outcome": "success_checker_infra_invalid",
                "m_retry": 0,
            },
            "estimators": {
                "C": "sum(P for every consumed attempt through the successful attempt)",
                "D": "C(treatment,t,r)-C(baseline,t,r)",
                "Delta": "mean_over_tasks(mean_over_repetitions(D))",
                "I": "1 iff consumed attempts > 1 obtained the successful result",
                "Gamma": "mean_over_tasks(mean_over_repetitions(I_treatment-I_baseline))",
            },
            "correction": {
                "nullable": True,
                "rubric": [0, 1, 2, "U"],
                "packet_count": 72,
                "packet_ids": "A001..A072",
                "packet_fields": ["assessment_id", "output"],
                "shuffle": "splitmix64-unbiased-descending-fisher-yates-v1",
                "shuffle_seed": "0x434F525245435433",
                "permutation_sha256": "ff687c7901de0f9eefcf03b07d58350247931d265ed60c040c46153ea67eed91",
                "permutation_prefix": [
                    52, 27, 31, 69, 17, 8, 10, 14, 61,
                    48, 33, 53, 50, 51, 11, 30, 4, 40,
                ],
                "resolution": "three-sealed-scores-majority-or-all-distinct-median-v1",
                "severity_formula": "Theta_severity=mean_t(mean_r(S_treatment-S_baseline))",
                "incidence_formula": "Theta_incidence=mean_t(mean_r(K_treatment-K_baseline))",
            },
            "correction_resolution": "three-sealed-scores-majority-or-all-distinct-median-v1",
            "report": {
                "schema_version": MEASUREMENT_STUDY_REPORT_SCHEMA_VERSION,
                "artifact_path": "study-report.json",
                "positive_verdict": "demonstrated_token_savings_for_frozen_suite",
                "inconclusive_verdict": "inconclusive",
            },
            "claim_scope": MEASUREMENT_STUDY_CLAIM,
            "consumption_rule": "process-created-is-consumed-v1",
        },
        "provenance": "synthetic_offline_measurement_enablement",
    }
    return manifest


def validate_measurement_study_manifest(
    manifest: Mapping[str, Any] | bytes,
    *,
    expected: Mapping[str, Any] | None = None,
) -> None | dict[str, Any]:
    if isinstance(manifest, bytes):
        try:
            decoded = json.loads(
                manifest.decode("utf-8"),
                object_pairs_hook=_measurement_object_no_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("measurement study manifest is invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("measurement study manifest must be an object")
        canonical_direct = json.dumps(
            decoded,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if manifest != canonical_direct:
            raise ValueError("measurement study manifest must be canonical JSON")
        validate_measurement_study_manifest(decoded)
        if expected is not None and decoded != dict(expected):
            raise ValueError("measurement study manifest input drift")
        return decoded
    direct_required = {
        "schema_version", "study_plan", "tasks", "variants", "cli_probe",
        "runner_sha256", "mirror_sha256",
    }
    if set(manifest) == direct_required:
        if (
            manifest["schema_version"]
            != MEASUREMENT_STUDY_DIRECT_MANIFEST_SCHEMA_VERSION
        ):
            raise ValueError("measurement study manifest version mismatch")
        study_plan = manifest["study_plan"]
        if not isinstance(study_plan, Mapping) or set(study_plan) != set(
            MEASUREMENT_STUDY_PLAN_KEYS
        ):
            raise ValueError("measurement study direct manifest study_plan schema mismatch")
        if (
            study_plan.get("schema_version")
            != MEASUREMENT_STUDY_PLAN_SCHEMA_VERSION
            or not isinstance(study_plan.get("namespace"), str)
            or MEASUREMENT_ID_NAMESPACE_RE.fullmatch(
                str(study_plan.get("namespace"))
            )
            is None
            or not isinstance(study_plan.get("schedule_seed"), str)
            or re.fullmatch(
                r"0x[0-9A-F]{16}", str(study_plan.get("schedule_seed"))
            )
            is None
        ):
            raise ValueError("measurement study direct manifest study_plan is invalid")
        direct_plan_exact = {
            "inference_seed": "0x434F4E5445585447",
            "correction_shuffle_seed": "0x434F525245435433",
            "repetitions": 3,
            "max_attempts_per_arm_unit": 2,
            "retry_policy": MEASUREMENT_STUDY_RETRY_POLICY,
        }
        if any(
            study_plan.get(key) != value
            or (
                isinstance(value, int)
                and isinstance(study_plan.get(key), bool)
            )
            for key, value in direct_plan_exact.items()
        ):
            raise ValueError("measurement study direct manifest study_plan is invalid")
        tasks_direct = manifest["tasks"]
        task_ids = (
            tasks_direct.get("task_ids")
            if isinstance(tasks_direct, Mapping)
            and set(tasks_direct) == {"task_ids"}
            else None
        )
        if (
            not isinstance(task_ids, list)
            or len(task_ids) != 12
            or len(task_ids) != len(set(task_ids))
            or any(not isinstance(task_id, str) or not task_id for task_id in task_ids)
        ):
            raise ValueError("measurement study direct manifest tasks schema mismatch")
        variants_direct = manifest["variants"]
        if (
            not isinstance(variants_direct, Mapping)
            or set(variants_direct) != {"arms"}
            or variants_direct.get("arms") != list(MEASUREMENT_STUDY_ARMS)
        ):
            raise ValueError("measurement study direct manifest variants schema mismatch")
        cli_probe_direct = manifest["cli_probe"]
        if (
            not isinstance(cli_probe_direct, Mapping)
            or cli_probe_direct.get("schema_version")
            != MEASUREMENT_CLI_PROBE_SCHEMA_VERSION
        ):
            raise ValueError("measurement study direct manifest cli_probe schema mismatch")
        for key in ("runner_sha256", "mirror_sha256"):
            value = manifest[key]
            if not isinstance(value, str) or SHA256_HEX_PATTERN.fullmatch(value) is None:
                raise ValueError(f"measurement study manifest {key} is invalid")
        if manifest["runner_sha256"] != manifest["mirror_sha256"]:
            raise ValueError("measurement study direct manifest runner parity mismatch")
        return None
    required = {
        "schema_version", "inputs", "plan", "schedule", "schedule_sha256", "slots",
        "contracts", "provenance",
    }
    if set(manifest) != required:
        raise ValueError("measurement study manifest schema mismatch")
    if manifest["schema_version"] != MEASUREMENT_STUDY_MANIFEST_SCHEMA_VERSION:
        raise ValueError("measurement study manifest version mismatch")
    task_ids = manifest["inputs"].get("ordered_task_ids")
    if not isinstance(task_ids, list):
        raise ValueError("measurement study manifest task order missing")
    validate_measurement_study_slots(manifest["slots"], task_ids=task_ids)
    if _study_sha256_bytes(_study_canonical_json_bytes(manifest["schedule"])) != manifest["schedule_sha256"]:
        raise ValueError("measurement study schedule hash mismatch")
    if expected is not None and _study_canonical_json_bytes(manifest) != _study_canonical_json_bytes(expected):
        raise ValueError("measurement study manifest input drift")


def _study_write_private(path: Path, value: Any) -> None:
    _measurement_write_exclusive(path, _study_canonical_json_bytes(value))


def _study_event(slot: Mapping[str, Any], manifest_sha256: str, state: str, **extra: Any) -> dict[str, Any]:
    event = {
        "schema_version": MEASUREMENT_STUDY_ATTEMPT_INDEX_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "pair_id": slot["pair_id"],
        "run_id": slot["run_id"],
        "task_id": slot["task_id"],
        "repetition": slot["repetition"],
        "arm": slot["arm"],
        "attempt": slot["attempt"],
        "state": state,
    }
    event.update(extra)
    return event


def _study_artifact_index_row_sha256(
    spec: MeasurementVariant,
    run_id: str,
    receipt_sha256: str,
    terminal_status: str,
) -> str:
    context = _measurement_existing_context(spec, run_id)
    row = {
        "schema_version": MEASUREMENT_ARTIFACT_INDEX_SCHEMA_VERSION,
        "run_id": run_id,
        "receipt_path": str(context.receipt_path),
        "receipt_sha256": receipt_sha256,
        "terminal_status": terminal_status,
    }
    return _study_sha256_bytes(_study_canonical_json_bytes(row))


def _study_read_attempt_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = _measurement_read_private_file(path, maximum=MEASUREMENT_RAW_MAX_BYTES)
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        value = _parse_measurement_json_text(line.decode("utf-8"), owner="measurement study attempt")
        if not isinstance(value, dict):
            raise SystemExit("measurement study attempt row must be an object")
        if line + b"\n" != _study_canonical_json_bytes(value):
            raise SystemExit("measurement study attempt row must be canonical JSON")
        events.append(value)
    return events


def _study_variant_for_slot(variant: Variant, slot: Mapping[str, Any]) -> Variant:
    spec = variant.measurement
    if spec is None:
        raise SystemExit("measurement study requires S001 measurement variants")
    identity = replace(
        spec.identity,
        repetition=int(slot["repetition"]),
        arm=str(slot["arm"]),
        attempt=int(slot["attempt"]),
    )
    return replace(variant, measurement=replace(spec, identity=identity))


def _run_measurement_study_slot(
    *,
    slot: Mapping[str, Any],
    task: TaskFixture | None = None,
    variant: Variant | None = None,
    claude_bin: str | None = None,
    project_root: Path | None = None,
    attempts_path: Path | None = None,
    manifest_sha256: str | None = None,
    validate_slot: Callable[[Mapping[str, Any]], None] | None = None,
    launch: Callable[[Mapping[str, Any]], Any] | None = None,
    append_event: Callable[..., Any] | None = None,
    after_launch: Callable[..., Any] | None = None,
    terminate: Callable[..., Any] | None = None,
    reap: Callable[..., Any] | None = None,
) -> str | dict[str, Any]:
    if validate_slot is not None or launch is not None:
        try:
            if validate_slot is not None:
                validate_slot(slot)
        except (OSError, RuntimeError, ValueError):
            return {
                "state": "prelaunch_refused",
                "consumed": False,
                "reason": "slot_validation_refused",
            }
        if launch is None:
            raise ValueError("direct study slot launch callback is required")
        process = launch(slot)
        try:
            if append_event is not None:
                append_event({
                    "run_id": slot["run_id"],
                    "state": "launched",
                    "consumed": True,
                })
            if after_launch is not None:
                after_launch(process)
        except BaseException:
            if terminate is not None:
                terminate(process)
            if reap is not None:
                reap(process)
            if append_event is not None:
                append_event({
                    "run_id": slot["run_id"],
                    "state": "terminal",
                    "consumed": True,
                    "terminal_status": "post_launch_accounting_failure",
                })
            return {
                "state": "invalid",
                "consumed": True,
                "reason": "post_launch_accounting_failure",
            }
        return {"state": "launched", "consumed": True}
    if (
        task is None or variant is None or claude_bin is None
        or project_root is None or attempts_path is None or manifest_sha256 is None
    ):
        raise TypeError("production study slot arguments are required")
    study_variant = _study_variant_for_slot(variant, slot)
    spec = study_variant.measurement
    assert spec is not None
    process_was_launched = False

    def launched() -> None:
        nonlocal process_was_launched
        try:
            append_study_attempt_event(
                attempts_path,
                _study_event(slot, manifest_sha256, "launched", consumed=True),
            )
            process_was_launched = True
        except BaseException as exc:
            raise _StudyLaunchAccountingError from exc

    try:
        root_fd = _ensure_directory_no_symlink(spec.artifact_root, create=True)
        try:
            os.fchmod(root_fd, 0o700)
            if fcntl is not None:
                fcntl.flock(root_fd, fcntl.LOCK_EX)
            append_study_attempt_event(
                attempts_path,
                _study_event(
                    slot,
                    manifest_sha256,
                    "launch_reserved",
                    consumed=False,
                ),
            )
            result = _run_measurement_fixture_locked(
                task,
                study_variant,
                claude_bin,
                project_root,
                locked_root_fd=root_fd,
                on_process_started=launched,
                measurement_study=True,
            )
        finally:
            os.close(root_fd)
    except _StudyLaunchAccountingError:
        # Popen succeeded and run_bounded_command already killed/reaped the group.
        # Persisting consumed/unknown is mandatory before returning.
        append_study_attempt_event(
            attempts_path,
            _study_event(
                slot, manifest_sha256, "launched",
                consumed=True,
            ),
        )
        append_study_attempt_event(
            attempts_path,
            _study_event(
                slot, manifest_sha256, "terminal",
                consumed=True, terminal_classification="launch_accounting_failure",
                successful=False, primary_tokens=0,
                token_buckets={key: 0 for key in MEASUREMENT_STUDY_USAGE_KEYS},
                receipt_sha256=None,
                artifact_index_sha256=None,
            ),
        )
        return "study_infra_invalid"
    except _MeasurementLaunchError:
        append_study_attempt_event(
            attempts_path,
            _study_event(
                slot, manifest_sha256, "prelaunch_refused",
                consumed=False, reason="process_creation_failed",
            ),
        )
        return "prelaunch_refused"
    except (KeyError, OSError, SystemExit, TypeError, ValueError):
        if process_was_launched:
            append_study_attempt_event(
                attempts_path,
                _study_event(
                    slot, manifest_sha256, "terminal",
                    consumed=True, terminal_classification="post_launch_infra_invalid",
                    successful=False, primary_tokens=0,
                    token_buckets={key: 0 for key in MEASUREMENT_STUDY_USAGE_KEYS},
                    receipt_sha256=None,
                    artifact_index_sha256=None,
                ),
            )
            return "study_infra_invalid"
        append_study_attempt_event(
            attempts_path,
            _study_event(
                slot, manifest_sha256, "prelaunch_refused",
                consumed=False, reason="validation_refused",
            ),
        )
        return "prelaunch_refused"

    classification = (
        "success"
        if result.notes == "task_success"
        else (
            "valid_task_failure_v1"
            if result.notes == "valid_task_failure_v1"
            else "study_infra_invalid"
        )
    )
    receipt_sha256 = None
    artifact_index_sha256 = None
    try:
        receipt_path = _measurement_existing_context(
            spec, str(slot["run_id"])
        ).receipt_path
        if not receipt_path.exists():
            raise ValueError("measurement receipt is missing after launch")
        receipt_bytes = _measurement_read_private_file(receipt_path)
        receipt_sha256 = _study_sha256_bytes(receipt_bytes)
        receipt = _measurement_parse_canonical_json_bytes(
            receipt_bytes, owner="measurement receipt",
        )
        artifact_index_sha256 = _study_artifact_index_row_sha256(
            spec, str(slot["run_id"]), receipt_sha256, str(receipt["terminal_status"]),
        )
    except (OSError, SystemExit, TypeError, ValueError):
        classification = "post_launch_infra_invalid"
        receipt_sha256 = None
        artifact_index_sha256 = None
    terminal_event = _study_event(
        slot,
        manifest_sha256,
        "terminal",
        consumed=True,
        terminal_classification=classification,
        successful=classification == "success",
        primary_tokens=sum(result.tokens.values()),
        token_buckets={
            "input_tokens": result.tokens["input_tokens"],
            "cache_creation_input_tokens": result.tokens["cache_creation"],
            "cache_read_input_tokens": result.tokens["cache_read"],
            "output_tokens": result.tokens["output_tokens"],
        },
        receipt_sha256=receipt_sha256,
        artifact_index_sha256=artifact_index_sha256,
    )
    append_study_attempt_event(attempts_path, terminal_event)
    return classification


def _execute_measurement_study(
    *,
    manifest: Mapping[str, Any],
    tasks: Sequence[TaskFixture] | None = None,
    variants: Sequence[Variant] | None = None,
    claude_bin: str | None = None,
    project_root: Path | None = None,
    attempts_path: Path | None = None,
    manifest_sha256: str | None = None,
    action: str | None = None,
    folded_attempts: Mapping[Any, Mapping[str, Any]] | None = None,
    run_slot: Callable[[Mapping[str, Any]], Any] | None = None,
) -> None | dict[str, Any]:
    if action is not None or folded_attempts is not None or run_slot is not None:
        folded_direct = dict(folded_attempts or {})
        rows = list(folded_direct.values())
        consumed = sum(row.get("consumed") is True for row in rows)
        invalid_statuses = {
            "success_checker_infra_invalid",
            "study_infra_invalid",
            "launch_accounting_failure",
            "post_launch_infra_invalid",
            "recovered_process_status_unknown",
        }
        study_valid = not any(
            row.get("state") == "prelaunch_refused"
            or row.get("terminal_status") in invalid_statuses
            for row in rows
        )
        failed_consumed = [
            row for row in rows
            if row.get("consumed") is True
            and row.get("terminal_status") == "valid_task_failure_v1"
        ]
        if len(failed_consumed) > 1:
            study_valid = False
        candidates = [
            row for row in rows
            if row.get("attempt") == 1 and row.get("state") == "eligible"
        ]
        candidates.extend(
            slot for slot in manifest.get("slots", ())
            if slot.get("attempt") == 1 and slot.get("state") == "eligible"
            and not any(row.get("run_id") == slot.get("run_id") for row in candidates)
        )
        selected: list[str] = []
        if study_valid and failed_consumed and run_slot is not None:
            for slot in candidates:
                result = run_slot(slot)
                selected.append(str(slot["run_id"]))
                if isinstance(result, Mapping) and result.get("state") == "invalid":
                    study_valid = False
        return {
            "action": action,
            "study_valid": study_valid,
            "selected_run_ids": selected,
            "consumed_attempt_count": consumed,
        }
    if (
        tasks is None or variants is None or claude_bin is None
        or project_root is None or attempts_path is None or manifest_sha256 is None
    ):
        raise TypeError("production study execution arguments are required")
    tasks_by_id = {task.id: task for task in tasks}
    variants_by_arm = {
        "baseline": variants[0],
        "treatment": variants[1],
    }
    slots = list(manifest["slots"])
    retry_by_unit = {
        (slot["task_id"], slot["repetition"], slot["arm"]): slot
        for slot in slots if slot["attempt"] == 1
    }
    events = _study_read_attempt_events(attempts_path)
    folded = fold_study_attempt_events(slots, events, manifest_sha256=manifest_sha256)
    for initial in (slot for slot in slots if slot["attempt"] == 0):
        retry = retry_by_unit[(initial["task_id"], initial["repetition"], initial["arm"])]
        initial_state = folded[initial["run_id"]]["state"]
        retry_state = folded[retry["run_id"]]["state"]
        if retry_state != "conditional":
            continue
        classification = folded[initial["run_id"]].get("terminal_classification")
        if initial_state == "terminal" and classification == "success":
            append_study_attempt_event(
                attempts_path,
                _study_event(retry, manifest_sha256, "not_needed", consumed=False),
            )
        elif initial_state == "terminal" and classification == "valid_task_failure_v1":
            append_study_attempt_event(
                attempts_path,
                _study_event(retry, manifest_sha256, "eligible", consumed=False),
            )
        elif initial_state in {"terminal", "prelaunch_refused"}:
            append_study_attempt_event(
                attempts_path,
                _study_event(
                    retry, manifest_sha256, "blocked_study_invalid",
                    consumed=False, reason="initial_attempt_infra_invalid",
                ),
            )
            return
    events = _study_read_attempt_events(attempts_path)
    folded = fold_study_attempt_events(slots, events, manifest_sha256=manifest_sha256)

    # First finish any retry that was durably made eligible before a crash.
    for retry in (slot for slot in slots if slot["attempt"] == 1):
        if folded[retry["run_id"]]["state"] == "eligible":
            outcome = _run_measurement_study_slot(
                slot=retry, task=tasks_by_id[retry["task_id"]],
                variant=variants_by_arm[retry["arm"]], claude_bin=claude_bin,
                project_root=project_root, attempts_path=attempts_path,
                manifest_sha256=manifest_sha256,
            )
            if outcome != "success":
                return

    events = _study_read_attempt_events(attempts_path)
    folded = fold_study_attempt_events(slots, events, manifest_sha256=manifest_sha256)
    for initial in (slot for slot in slots if slot["attempt"] == 0):
        if folded[initial["run_id"]]["state"] != "planned":
            continue
        outcome = _run_measurement_study_slot(
            slot=initial, task=tasks_by_id[initial["task_id"]],
            variant=variants_by_arm[initial["arm"]], claude_bin=claude_bin,
            project_root=project_root, attempts_path=attempts_path,
            manifest_sha256=manifest_sha256,
        )
        retry = retry_by_unit[(initial["task_id"], initial["repetition"], initial["arm"])]
        if outcome == "success":
            append_study_attempt_event(
                attempts_path,
                _study_event(retry, manifest_sha256, "not_needed", consumed=False),
            )
        elif outcome == "valid_task_failure_v1":
            append_study_attempt_event(
                attempts_path,
                _study_event(retry, manifest_sha256, "eligible", consumed=False),
            )
            retry_outcome = _run_measurement_study_slot(
                slot=retry, task=tasks_by_id[retry["task_id"]],
                variant=variants_by_arm[retry["arm"]], claude_bin=claude_bin,
                project_root=project_root, attempts_path=attempts_path,
                manifest_sha256=manifest_sha256,
            )
            if retry_outcome != "success":
                return
        else:
            append_study_attempt_event(
                attempts_path,
                _study_event(
                    retry, manifest_sha256, "blocked_study_invalid",
                    consumed=False, reason="initial_attempt_infra_invalid",
                ),
            )
            return


def _study_revalidate_terminal_evidence(
    evidence: Mapping[str, Any] | None = None,
    *,
    expected: Mapping[str, Any] | None = None,
    manifest: Mapping[str, Any] | None = None,
    folded: Mapping[str, Mapping[str, Any]] | None = None,
    tasks: Sequence[TaskFixture] | None = None,
    variants: Sequence[Variant] | None = None,
) -> None | dict[str, Any]:
    if evidence is not None:
        if expected is None or dict(evidence) != dict(expected):
            raise ValueError("terminal evidence binding mismatch")
        return dict(evidence)
    if manifest is None or folded is None or tasks is None or variants is None:
        raise TypeError("production evidence validation arguments are required")
    tasks_by_id = {task.id: task for task in tasks}
    variants_by_arm = {"baseline": variants[0], "treatment": variants[1]}
    slots_by_run = {slot["run_id"]: slot for slot in manifest["slots"]}
    for run_id, row in folded.items():
        if row["state"] != "terminal":
            continue
        classification = row.get("terminal_classification")
        receipt_sha256 = row.get("receipt_sha256")
        if classification in {"launch_accounting_failure", "post_launch_infra_invalid"}:
            continue
        if classification == "recovered_process_status_unknown" and receipt_sha256 is None:
            continue
        if not isinstance(receipt_sha256, str) or SHA256_HEX_PATTERN.fullmatch(receipt_sha256) is None:
            raise SystemExit("measurement study terminal receipt binding missing")
        slot = slots_by_run[run_id]
        variant = _study_variant_for_slot(variants_by_arm[slot["arm"]], slot)
        spec = variant.measurement
        assert spec is not None
        receipt = _verify_existing_measurement_run(spec, slot["task_id"], run_id)
        context = _measurement_existing_context(spec, run_id)
        receipt_bytes = _measurement_read_private_file(context.receipt_path)
        if _study_sha256_bytes(receipt_bytes) != receipt_sha256:
            raise SystemExit("measurement study receipt hash mismatch")
        expected_index_sha256 = _study_artifact_index_row_sha256(
            spec, run_id, receipt_sha256, str(receipt["terminal_status"]),
        )
        if row.get("artifact_index_sha256") != expected_index_sha256:
            raise SystemExit("measurement study artifact-index hash mismatch")
        if classification in {"success", "valid_task_failure_v1"}:
            if receipt.get("terminal_status") != "success":
                raise SystemExit("measurement study terminal classification mismatch")
            usage = parse_measurement_terminal_usage(_measurement_read_private_raw(context.raw_path))
            expected_buckets = {key: usage[key] for key in MEASUREMENT_STUDY_USAGE_KEYS}
            if row.get("token_buckets") != expected_buckets or row.get("primary_tokens") != usage["primary_tokens"]:
                raise SystemExit("measurement study terminal usage binding mismatch")
        elif receipt.get("terminal_status") == "success":
            # A success receipt followed by a checker/schema failure is allowed,
            # but it can never be silently relabeled as a successful arm-unit.
            if row.get("successful") is True:
                raise SystemExit("measurement study invalid attempt marked successful")


def _study_fold_interrupted_launches(
    events: Sequence[Mapping[str, Any]] | None = None,
    *,
    raw_run_ids: set[str] | None = None,
    manifest: Mapping[str, Any] | None = None,
    folded: Mapping[str, Mapping[str, Any]] | None = None,
    tasks: Sequence[TaskFixture] | None = None,
    variants: Sequence[Variant] | None = None,
    attempts_path: Path | None = None,
    manifest_sha256: str | None = None,
) -> bool | dict[Any, dict[str, Any]]:
    if events is not None:
        recovered = fold_study_attempt_events(events)
        for key, row in recovered.items():
            if row.get("state") in {"launch_reserved", "launched"} and (
                raw_run_ids is None or str(row.get("run_id")) in raw_run_ids
            ):
                row.update({
                    "state": "terminal",
                    "terminal_status": "recovered_process_status_unknown",
                    "consumed": True,
                })
        return recovered
    if (
        manifest is None or folded is None or tasks is None or variants is None
        or attempts_path is None or manifest_sha256 is None
    ):
        raise TypeError("production interrupted-launch arguments are required")
    tasks_by_id = {task.id: task for task in tasks}
    variants_by_arm = {"baseline": variants[0], "treatment": variants[1]}
    recovered_any = False
    for slot in manifest["slots"]:
        folded_state = folded[slot["run_id"]]["state"]
        if folded_state not in {"launch_reserved", "launched"}:
            continue
        if folded_state == "launch_reserved":
            append_study_attempt_event(
                attempts_path,
                _study_event(
                    slot,
                    manifest_sha256,
                    "launched",
                    consumed=True,
                ),
            )
        variant = _study_variant_for_slot(variants_by_arm[slot["arm"]], slot)
        spec = variant.measurement
        assert spec is not None
        try:
            root_fd = _ensure_directory_no_symlink(spec.artifact_root, create=False)
            try:
                if fcntl is not None:
                    fcntl.flock(root_fd, fcntl.LOCK_EX)
                _measurement_recover_raw_only_run(
                    spec,
                    tasks_by_id[slot["task_id"]],
                    slot["run_id"],
                    artifact_root_locked=True,
                )
            finally:
                os.close(root_fd)
        except (OSError, SystemExit, TypeError, ValueError):
            # The launch is still irrevocably consumed.  Evidence corruption is
            # represented in the study index and can never authorize relaunch.
            pass
        receipt_sha256 = None
        artifact_index_sha256 = None
        context = _measurement_existing_context(spec, slot["run_id"])
        try:
            receipt_bytes = _measurement_read_private_file(context.receipt_path)
            receipt = _verify_existing_measurement_run(spec, slot["task_id"], slot["run_id"])
            receipt_sha256 = _study_sha256_bytes(receipt_bytes)
            artifact_index_sha256 = _study_artifact_index_row_sha256(
                spec,
                str(slot["run_id"]),
                receipt_sha256,
                str(receipt["terminal_status"]),
            )
        except (OSError, SystemExit, TypeError, ValueError):
            receipt_sha256 = None
            artifact_index_sha256 = None
        append_study_attempt_event(
            attempts_path,
            _study_event(
                slot,
                manifest_sha256,
                "terminal",
                consumed=True,
                terminal_classification="recovered_process_status_unknown",
                successful=False,
                primary_tokens=0,
                token_buckets={key: 0 for key in MEASUREMENT_STUDY_USAGE_KEYS},
                receipt_sha256=receipt_sha256,
                artifact_index_sha256=artifact_index_sha256,
            ),
        )
        recovered_any = True
    return recovered_any


def _analyze_measurement_study(
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]] | None = None,
    manifest_sha256: str | None = None,
    corrections: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    *,
    folded_attempts: Mapping[Any, Mapping[str, Any]] | None = None,
    estimator: Mapping[str, Any] | None = None,
    provenance: str | None = None,
) -> dict[str, Any]:
    if folded_attempts is not None or estimator is not None:
        folded_direct = dict(folded_attempts or {})
        estimates_direct = dict(estimator or {})
        complete = estimates_direct.get("complete_pairs") is True
        token_gate = bool(
            complete
            and estimates_direct.get("delta_q975") is not None
            and estimates_direct["delta_q975"] < 0
        )
        retry_gate = bool(
            complete
            and estimates_direct.get("gamma") is not None
            and estimates_direct.get("gamma_q975") is not None
            and estimates_direct["gamma"] <= 0
            and estimates_direct["gamma_q975"] <= 0
        )
        correction_gate = False
        if isinstance(corrections, Mapping) and corrections.get("measured") is True:
            if "non_regression" in corrections:
                correction_gate = corrections.get("non_regression") is True
            elif all(
                corrections.get(key) is not None and corrections[key] <= 0
                for key in (
                    "severity_point", "severity_q975",
                    "incidence_point", "incidence_q975",
                )
            ):
                correction_gate = True
        valid = complete and token_gate and retry_gate and correction_gate
        manifest_hash = str(manifest.get("sha256", ""))
        synthetic = provenance == "synthetic_offline"
        return {
            "schema_version": MEASUREMENT_STUDY_REPORT_SCHEMA_VERSION,
            "manifest_sha256": manifest_hash,
            "valid": valid,
            "verdict": "synthetic_offline_contract_pass" if valid else "inconclusive",
            "consumed_attempt_count": sum(
                row.get("consumed") is True for row in folded_direct.values()
            ),
            "gates": {
                "complete_pairs": complete,
                "token_upper_bound_strictly_negative": token_gate,
                "retry_non_regression": retry_gate,
                "correction_non_regression": correction_gate,
            },
            "estimates": estimates_direct,
            "corrections": corrections,
            "claim": None,
            "claim_scope": (
                "synthetic_offline_only_no_empirical_savings_claim"
                if synthetic else "frozen_suite_only"
            ),
            "provenance": provenance or "synthetic_offline_measurement_enablement",
        }
    if events is None or manifest_sha256 is None:
        raise TypeError("production analysis events and manifest hash are required")
    folded = fold_study_attempt_events(
        manifest["slots"], events, manifest_sha256=manifest_sha256,
    )
    attempts: list[dict[str, Any]] = []
    bucket_totals = {key: 0 for key in MEASUREMENT_STUDY_USAGE_KEYS}
    for slot in manifest["slots"]:
        row = folded[slot["run_id"]]
        if row["state"] != "terminal":
            continue
        buckets = row.get("token_buckets")
        if not isinstance(buckets, dict) or set(buckets) != set(MEASUREMENT_STUDY_USAGE_KEYS):
            continue
        for key in bucket_totals:
            bucket_totals[key] += int(buckets[key])
        attempts.append({
            "task_id": row["task_id"],
            "repetition": row["repetition"],
            "arm": row["arm"],
            "attempt": row["attempt"],
            "consumed": row.get("consumed") is True,
            "successful": row.get("terminal_classification") == "success",
            "terminal_classification": row.get("terminal_classification"),
            "primary_tokens": row.get("primary_tokens"),
        })
    inputs = manifest.get("inputs")
    manifest_task_order = (
        inputs.get("ordered_task_ids")
        if isinstance(inputs, dict) and isinstance(inputs.get("ordered_task_ids"), list)
        else None
    )
    task_order = (
        list(manifest_task_order)
        if manifest_task_order is not None
        else list(dict.fromkeys(str(slot["task_id"]) for slot in manifest["slots"]))
    )
    estimates = compute_measurement_study_estimators(attempts, task_order=task_order)
    bootstrap_delta = (
        bootstrap_task_cluster(estimates["task_deltas"])
        if estimates["valid"] else None
    )
    bootstrap_gamma = (
        bootstrap_task_cluster(estimates["task_gammas"])
        if estimates["valid"] else None
    )
    token_gate = bool(
        estimates["valid"] and bootstrap_delta is not None and bootstrap_delta["q975"] < 0
    )
    retry_gate = bool(
        estimates["valid"] and estimates["gamma"] <= 0
        and bootstrap_gamma is not None and bootstrap_gamma["q975"] <= 0
    )
    correction_result = (
        compute_correction_non_regression(corrections, task_order=task_order)
        if corrections is not None else None
    )
    correction_gate = (
        correction_result["non_regression"]
        if correction_result is not None and correction_result["measured"] else None
    )
    valid = bool(estimates["valid"] and token_gate and retry_gate and correction_gate is True)
    permutation = correction_packet_permutation()
    failure_reasons = collections.Counter(
        str(row.get("reason") or row.get("terminal_classification"))
        for row in folded.values()
        if row.get("reason") is not None
        or (
            row.get("terminal_classification") is not None
            and row.get("terminal_classification") != "success"
        )
    )
    receipt_hashes = [
        row["receipt_sha256"]
        for slot in manifest["slots"]
        for row in [folded[slot["run_id"]]]
        if isinstance(row.get("receipt_sha256"), str)
    ]
    artifact_index_hashes = [
        row["artifact_index_sha256"]
        for slot in manifest["slots"]
        for row in [folded[slot["run_id"]]]
        if isinstance(row.get("artifact_index_sha256"), str)
    ]
    schedule = manifest.get("schedule", [])
    schedule_sha256 = manifest.get("schedule_sha256")
    if not isinstance(schedule_sha256, str):
        schedule_sha256 = _study_sha256_bytes(_study_canonical_json_bytes(schedule))
    manifest_input_hashes: dict[str, Any] = {}
    if isinstance(inputs, dict):
        for name in ("runner", "packaged_runner", "tasks", "variants", "study_plan"):
            item = inputs.get(name)
            if isinstance(item, dict) and isinstance(item.get("sha256"), str):
                manifest_input_hashes[name] = item["sha256"]
        variant_definitions = inputs.get("variant_definitions")
        if isinstance(variant_definitions, list):
            manifest_input_hashes["arms"] = [
                {
                    "name": item.get("name"),
                    "candidate_hash": (
                        item.get("measurement", {}).get("candidate_hash")
                        if isinstance(item, dict) and isinstance(item.get("measurement"), dict)
                        else None
                    ),
                    "settings_source_sha256": (
                        item["measurement"].get("settings_source", {}).get("sha256")
                        if isinstance(item, dict)
                        and isinstance(item.get("measurement"), dict)
                        and isinstance(item["measurement"].get("settings_source"), dict)
                        else None
                    ),
                    "executed_snapshot_sha256": (
                        item["measurement"].get("executed_snapshot", {}).get("sha256")
                        if isinstance(item, dict)
                        and isinstance(item.get("measurement"), dict)
                        and isinstance(item["measurement"].get("executed_snapshot"), dict)
                        else None
                    ),
                    "binding_set_sha256": (
                        item["measurement"].get("binding_set_sha256")
                        if isinstance(item, dict) and isinstance(item.get("measurement"), dict)
                        else None
                    ),
                }
                for item in variant_definitions
            ]
    return {
        "schema_version": MEASUREMENT_STUDY_REPORT_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "valid": valid,
        "verdict": (
            "demonstrated_token_savings_for_frozen_suite"
            if valid else "inconclusive"
        ),
        "attempt_counts": {
            "consumed": sum(row.get("consumed") is True for row in folded.values()),
            "terminal": sum(row["state"] in MEASUREMENT_STUDY_TERMINAL_STATES for row in folded.values()),
            "total_slots": 144,
        },
        "token_buckets": bucket_totals,
        "estimates": estimates,
        "bootstrap_delta": bootstrap_delta,
        "bootstrap_gamma": bootstrap_gamma,
        "gates": {
            "complete_pairs": estimates["valid"],
            "token_upper_bound_strictly_negative": token_gate,
            "retry_non_regression": retry_gate,
            "correction_non_regression": correction_gate,
        },
        "corrections": correction_result,
        "correction_input_sha256": (
            _study_sha256_bytes(_study_canonical_json_bytes(list(corrections)))
            if corrections is not None else None
        ),
        "observability": {
            "schedule_sha256": schedule_sha256,
            "sampled_index_sha256": (
                bootstrap_delta["sampled_index_sha256"]
                if bootstrap_delta is not None else None
            ),
            "correction_permutation_sha256": permutation["sha256"],
            "correction_permutation_prefix": permutation["prefix"],
            "receipt_sha256": receipt_hashes,
            "artifact_index_sha256": artifact_index_hashes,
            "failure_reasons": [
                {"reason": reason, "count": failure_reasons[reason]}
                for reason in sorted(failure_reasons)
            ],
            "attempt_index_sha256": _study_sha256_bytes(
                b"".join(_study_canonical_json_bytes(dict(event)) for event in events)
            ),
            "manifest_input_hashes": manifest_input_hashes,
        },
        "methods": {
            "token_formula": (
                "P=input_tokens+cache_creation_input_tokens+"
                "cache_read_input_tokens+output_tokens"
            ),
            "arm_cost_formula": "C=sum(P for every consumed attempt through success)",
            "paired_formula": "D=C(treatment)-C(baseline)",
            "delta_formula": "Delta=mean_task(mean_repetition(D))",
            "retry_formula": "Gamma=mean_task(mean_repetition(I_treatment-I_baseline))",
            "bootstrap": "SplitMix64-v1;10000x12-task-cluster;Hyndman-Fan-Type-7",
            "correction_formula": (
                "severity/incidence treatment-minus-baseline task-cluster upper bounds"
            ),
            "token_upper_rule": "q0.975(Delta*)<0",
            "retry_upper_rule": "Gamma<=0 and q0.975(Gamma*)<=0",
            "correction_rule": (
                "points_and_q0.975<=0_and_treatment_severity2<=baseline_severity2"
            ),
        },
        "claim": MEASUREMENT_STUDY_CLAIM.replace("<sha256>", manifest_sha256) if valid else None,
        "provenance": "synthetic_offline_measurement_enablement",
    }


def run_measurement_study_action(
    args: argparse.Namespace | None = None,
    *,
    action: str | None = None,
    study_plan: Mapping[str, Any] | None = None,
    task_ids: Sequence[str] | None = None,
    variants: Sequence[str] | None = None,
    output_root: Path | None = None,
    claude_bin: str = "claude",
    expected_cli_probe: Mapping[str, Any] | None = None,
    cli_probe_runner: Callable[..., Mapping[str, Any]] | None = None,
    cli_probe_result: Mapping[str, Any] | None = None,
    write_artifact: Callable[[Path, Any], Any] | None = None,
    perform_action: Callable[..., Any] | None = None,
    probe_layout: Mapping[str, str] | None = None,
    prior_probe_roots: set[str] | None = None,
) -> int | dict[str, Any]:
    if args is None:
        if (
            action not in {"prepare", "run", "resume", "analyze"}
            or study_plan is None or task_ids is None or variants is None
            or output_root is None
        ):
            raise ValueError("direct measurement study action arguments are incomplete")
        if len(task_ids) != 12 or tuple(variants) != MEASUREMENT_STUDY_ARMS:
            raise ValueError("measurement study dimensions differ from the frozen contract")
        if probe_layout is not None:
            canonical_layout = validate_measurement_probe_layout(probe_layout)
            assert isinstance(canonical_layout, dict)
            root_text = str(probe_layout["root"])
            if prior_probe_roots is not None and root_text in prior_probe_roots:
                raise ValueError("measurement CLI probe root reuse is forbidden")
        probe_runner = cli_probe_runner or run_measurement_cli_probes
        actual_probe = (
            dict(cli_probe_result)
            if cli_probe_result is not None
            else dict(probe_runner(claude_bin))
        )
        if expected_cli_probe is not None and actual_probe != dict(expected_cli_probe):
            raise ValueError("measurement CLI probe drift")
        if perform_action is not None:
            return perform_action(
                action=action,
                study_plan=study_plan,
                task_ids=task_ids,
                variants=variants,
                output_root=output_root,
                cli_probe=actual_probe,
            )
        result = {"action": action, "cli_probe": actual_probe}
        if write_artifact is not None:
            write_artifact(output_root / "study-manifest.json", result)
        return result
    plan = load_measurement_study_plan(args.measurement_study_plan)
    variants = parse_variants(args.variants)
    tasks = parse_tasks(args.tasks, variants=variants)
    # 모든 action 이 같은 바인딩된 바이트를 쓰도록 여기서 한 번만 읽는다. 매니페스트 해시와
    # workspace 실체화가 서로 다른 read 에서 갈라지지 않게 하는 단일 진실 소스.
    load_task_fixture_trees(tasks, task_file_dir=args.tasks.parent)
    output_root = args.measurement_study_output_root
    manifest_path = output_root / "study-manifest.json"
    attempts_path = output_root / "attempts.jsonl"
    report_path = output_root / "study-report.json"
    if args.measurement_study_action == "prepare":
        if output_root.exists() and (
            output_root.is_symlink() or not output_root.is_dir() or any(output_root.iterdir())
        ):
            raise SystemExit("measurement study prepare output root must be new or empty")
    required_capabilities = sorted({
        capability
        for variant in variants if variant.measurement is not None
        for capability in variant.measurement.cli_capabilities
    })
    probe = run_measurement_cli_probes(args.claude_bin, required_capabilities)
    manifest = build_measurement_study_manifest(
        plan=plan, tasks=tasks, variants=variants,
        tasks_path=args.tasks, variants_path=args.variants,
        plan_path=args.measurement_study_plan, project_root=args.project_root,
        output_root=output_root, probe=probe,
    )
    validate_measurement_study_manifest(manifest)
    if args.measurement_study_action == "prepare":
        output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(output_root, 0o700)
        _study_write_private(manifest_path, manifest)
        return 0
    if not manifest_path.exists():
        raise SystemExit("measurement study manifest is required")
    raw_manifest = _measurement_read_private_file(manifest_path)
    existing = _measurement_parse_canonical_json_bytes(raw_manifest, owner="measurement study manifest")
    validate_measurement_study_manifest(existing, expected=manifest)
    manifest_sha256 = _study_sha256_bytes(raw_manifest)
    if args.measurement_study_action in {"run", "resume"}:
        if args.measurement_study_action == "run" and attempts_path.exists() and attempts_path.stat().st_size:
            raise SystemExit("measurement study run requires an absent or empty attempt index")
        if args.measurement_study_action == "resume" and not attempts_path.exists():
            raise SystemExit("measurement study resume requires an existing attempt index")
        load_variant_prompt_files_for_targets(
            [(task, variant) for task in tasks for variant in variants],
            task_file_dir=args.tasks.parent,
        )
        existing_events = _study_read_attempt_events(attempts_path)
        folded = fold_study_attempt_events(
            existing["slots"], existing_events, manifest_sha256=manifest_sha256,
        )
        _study_revalidate_terminal_evidence(
            manifest=existing, folded=folded, tasks=tasks, variants=variants,
        )
        if args.measurement_study_action == "resume" and _study_fold_interrupted_launches(
            manifest=existing,
            folded=folded,
            tasks=tasks,
            variants=variants,
            attempts_path=attempts_path,
            manifest_sha256=manifest_sha256,
        ):
            return 0
        _execute_measurement_study(
            manifest=existing,
            tasks=tasks,
            variants=variants,
            claude_bin=args.claude_bin,
            project_root=Path(os.path.abspath(args.project_root)),
            attempts_path=attempts_path,
            manifest_sha256=manifest_sha256,
        )
        return 0
    if not attempts_path.exists():
        raise SystemExit("measurement study attempt index is required")
    events = _study_read_attempt_events(attempts_path)
    folded = fold_study_attempt_events(
        existing["slots"], events, manifest_sha256=manifest_sha256,
    )
    _study_revalidate_terminal_evidence(
        manifest=existing, folded=folded, tasks=tasks, variants=variants,
    )
    report = _analyze_measurement_study(existing, events, manifest_sha256)
    _study_write_private(report_path, report)
    return 0


# V2 is a separately-versioned analytical surface.  It intentionally does not
# alter the frozen S001--S003 runner, manifest, or report contracts above.
BENCHMARK_STUDY_V2_PLAN_SCHEMA_VERSION = "contextguard.bench.study-plan.v2"
BENCHMARK_STUDY_V2_SCHEDULE_ALGORITHM = "splitmix64-blocked-three-arm-v1"
BENCHMARK_STUDY_V2_ARMS = (
    "host_unmodified", "legacy_trim", "bash_reference_v1",
)
BENCHMARK_STUDY_V2_PRIMARY_CONTRAST = ("host_unmodified", "bash_reference_v1")
BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST = ("legacy_trim", "bash_reference_v1")
BENCHMARK_STUDY_V2_RETRY_POLICY = "retain_valid_unfavorable_attempts_v1"
BENCHMARK_STUDY_V2_EVIDENCE_FORBIDDEN_KEYS = frozenset({
    "prompt", "output", "command", "command_hash", "command_sha256", "path",
    "project_id", "capabilities", "credential", "credentials", "token", "secret",
})
BENCHMARK_STUDY_V2_HANDLE_RE = re.compile(r"(?i)\bcgr1p(?:[_-]|\b)")
BENCHMARK_STUDY_V2_REVISION_KEYS = frozenset({
    "backend_revision", "model_revision", "cli_version",
})
BENCHMARK_STUDY_V2_REVISION_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,127}"
)
BENCHMARK_STUDY_V2_SECRET_SHAPE_RE = re.compile(
    r"(?i)(?:"
    r"\bsk-[A-Za-z0-9_-]{16,}"
    r"|\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{16,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{16,}"
    r"|\bnpm_[A-Za-z0-9]{16,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{16,}"
    r"|\bA[KS]IA[0-9A-Z]{16}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}"
    r"|\bya29\.[0-9A-Za-z_-]{16,}"
    r"|\bbearer\s+[0-9A-Za-z._~+/-]+=*"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)
BENCHMARK_STUDY_V2_CHECKER_BINDING_DOMAIN = (
    "contextguard.bench.v2.checker-binding.v1"
)
BENCHMARK_STUDY_V2_CORPUS_TASK_ORDER_DOMAIN = (
    "contextguard.bench.v2.corpus-task-order.v1"
)


def _benchmark_study_v2_seed(seed: int | str) -> int:
    if isinstance(seed, str):
        if re.fullmatch(r"0x[0-9A-F]{16}", seed) is None:
            raise ValueError("v2 schedule seed must be frozen uppercase 64-bit hex")
        return int(seed, 16)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= SPLITMIX64_MASK:
        raise ValueError("v2 schedule seed must be an unsigned 64-bit integer")
    return seed


def _benchmark_study_v2_task_ids(task_ids: Sequence[str]) -> list[str]:
    normalized = list(task_ids)
    if len(normalized) != 12 or len(set(normalized)) != 12:
        raise ValueError("v2 study requires exactly 12 unique ordered task ids")
    if any(not isinstance(task_id, str) or not task_id for task_id in normalized):
        raise ValueError("v2 study task ids must be non-empty strings")
    return normalized


def generate_benchmark_study_v2_schedule(
    task_ids: Sequence[str], *, repetitions: int, schedule_seed: int | str,
) -> list[dict[str, Any]]:
    """Create the pre-randomized 3-arm order for each task/repetition block."""
    tasks = _benchmark_study_v2_task_ids(task_ids)
    if repetitions != 3:
        raise ValueError("v2 study requires exactly three repetitions")
    state = _benchmark_study_v2_seed(schedule_seed)
    schedule: list[dict[str, Any]] = []
    for task_id in tasks:
        for repetition in range(repetitions):
            arm_order = list(BENCHMARK_STUDY_V2_ARMS)
            for index in range(len(arm_order) - 1, 0, -1):
                state, selected = splitmix64_bounded(state, index + 1)
                arm_order[index], arm_order[selected] = arm_order[selected], arm_order[index]
            schedule.append({
                "block_id": _study_domain_hash(
                    "contextguard.bench.v2.block-id.v1", [task_id, repetition],
                ),
                "task_id": task_id,
                "repetition": repetition,
                "arm_order": arm_order,
            })
    return schedule


def generate_benchmark_study_v2_slots(
    task_ids: Sequence[str], schedule: Sequence[Mapping[str, Any]], *,
    candidate_hash: str, namespace: str,
) -> list[dict[str, Any]]:
    """Materialize immutable initial/retry identities without replacement."""
    tasks = _benchmark_study_v2_task_ids(task_ids)
    if SHA256_HEX_PATTERN.fullmatch(candidate_hash) is None:
        raise ValueError("v2 candidate hash is invalid")
    if not isinstance(namespace, str) or not MEASUREMENT_ID_NAMESPACE_RE.fullmatch(namespace):
        raise ValueError("v2 namespace is invalid")
    expected_blocks = [(task, repetition) for task in tasks for repetition in range(3)]
    if [(row.get("task_id"), row.get("repetition")) for row in schedule] != expected_blocks:
        raise ValueError("v2 schedule task/repetition order drift")
    initial: list[dict[str, Any]] = []
    retry: list[dict[str, Any]] = []
    seen: set[str] = set()
    for block in schedule:
        arm_order = block.get("arm_order")
        if not isinstance(arm_order, list) or set(arm_order) != set(BENCHMARK_STUDY_V2_ARMS) or len(arm_order) != 3:
            raise ValueError("v2 block arm order is invalid")
        for arm in arm_order:
            for attempt, state, destination in ((0, "planned", initial), (1, "conditional", retry)):
                run_id = MeasurementIdentity(
                    candidate_hash=candidate_hash, repetition=int(block["repetition"]),
                    arm=arm, attempt=attempt, namespace=namespace,
                ).run_id(str(block["task_id"]))
                if run_id in seen:
                    raise ValueError("v2 run identity collision")
                seen.add(run_id)
                destination.append({
                    "block_id": block["block_id"], "task_id": block["task_id"],
                    "repetition": block["repetition"], "arm": arm, "attempt": attempt,
                    "run_id": run_id, "state": state,
                })
    slots = initial + retry
    validate_benchmark_study_v2_slots(slots, task_ids=tasks)
    return slots


def validate_benchmark_study_v2_slots(
    slots: Sequence[Mapping[str, Any]], *, task_ids: Sequence[str],
) -> None:
    tasks = _benchmark_study_v2_task_ids(task_ids)
    if len(slots) != 216:
        raise ValueError("v2 study requires exactly 216 immutable slots")
    expected = {
        (task, repetition, arm, attempt)
        for task in tasks for repetition in range(3)
        for arm in BENCHMARK_STUDY_V2_ARMS for attempt in (0, 1)
    }
    observed: set[tuple[str, int, str, int]] = set()
    run_ids: set[str] = set()
    required = {"block_id", "task_id", "repetition", "arm", "attempt", "run_id", "state"}
    for slot in slots:
        if set(slot) != required:
            raise ValueError("v2 slot schema mismatch")
        key = (slot["task_id"], slot["repetition"], slot["arm"], slot["attempt"])
        if key in observed or key not in expected or slot["run_id"] in run_ids:
            raise ValueError("v2 slot identity mismatch")
        if slot["state"] != ("planned" if slot["attempt"] == 0 else "conditional"):
            raise ValueError("v2 slot state mismatch")
        if not isinstance(slot["run_id"], str) or SHA256_HEX_PATTERN.fullmatch(slot["run_id"]) is None:
            raise ValueError("v2 slot run id is invalid")
        observed.add(key)
        run_ids.add(slot["run_id"])
    if observed != expected:
        raise ValueError("v2 slot coverage mismatch")


def benchmark_study_v2_contrasts(_values: Mapping[str, Any] | None = None) -> dict[str, list[str]]:
    """Expose the single product contrast separately from its diagnostic control."""
    return {
        "primary": list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST),
        "diagnostic": list(BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST),
    }


def _benchmark_study_v2_cluster_interval(values_by_task: Sequence[Sequence[float]]) -> dict[str, Any]:
    task_count = len(values_by_task)
    if task_count < 2 or any(len(row) != 3 for row in values_by_task):
        raise ValueError("v2 task-cluster interval requires task x 3 values")
    task_means = [sum(float(value) for value in row) / 3.0 for row in values_by_task]
    state = MEASUREMENT_STUDY_INFERENCE_SEED
    estimates: list[float] = []
    for _ in range(MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES):
        total = 0.0
        for _ in range(task_count):
            state, index = splitmix64_bounded(state, task_count)
            total += task_means[index]
        estimates.append(total / task_count)
    return {
        "method": "task_cluster_bootstrap_v2",
        "point": sum(task_means) / task_count,
        "q025": float(type7_quantile(estimates, 0.025)),
        "q975": float(type7_quantile(estimates, 0.975)),
        "task_count": task_count,
        "resamples": MEASUREMENT_STUDY_BOOTSTRAP_RESAMPLES,
    }


def infer_benchmark_study_v2_binary(
    rows: Sequence[Mapping[str, Any]], *, task_order: Sequence[str], ni_margin: float = 0.10,
) -> dict[str, Any]:
    """Exact task-cluster sign-permutation inference for the product contrast."""
    tasks = _benchmark_study_v2_task_ids(task_order)
    if not isinstance(ni_margin, (int, float)) or isinstance(ni_margin, bool) or not 0 <= ni_margin < 1:
        raise ValueError("v2 non-inferiority margin is invalid")
    units: dict[tuple[str, int, str], bool] = {}
    for row in rows:
        task_id, repetition, arm, success = row.get("task_id"), row.get("repetition"), row.get("arm"), row.get("success")
        if task_id not in tasks or repetition not in (0, 1, 2) or arm not in BENCHMARK_STUDY_V2_PRIMARY_CONTRAST or not isinstance(success, bool):
            raise ValueError("v2 binary outcome identity is invalid")
        key = (str(task_id), int(repetition), str(arm))
        if key in units:
            raise ValueError("duplicate v2 binary outcome")
        units[key] = success
    expected = {
        (task, repetition, arm) for task in tasks for repetition in range(3)
        for arm in BENCHMARK_STUDY_V2_PRIMARY_CONTRAST
    }
    if set(units) != expected:
        raise ValueError("v2 binary outcome coverage is incomplete")
    task_deltas = [
        sum(
            int(units[(task, repetition, "bash_reference_v1")])
            - int(units[(task, repetition, "host_unmodified")])
            for repetition in range(3)
        ) / 3.0
        for task in tasks
    ]
    point = sum(task_deltas) / len(tasks)
    all_success = all(units.values())
    # At the NI boundary, reference-minus-host plus the frozen margin has mean
    # zero. Sign-flip that centered task effect, never the nested run rows.
    centered_deltas = [value + float(ni_margin) for value in task_deltas]
    outcomes = []
    for mask in range(1 << len(tasks)):
        outcomes.append(sum(
            (-value if mask & (1 << index) else value)
            for index, value in enumerate(centered_deltas)
        ) / len(tasks))
    observed_statistic = point + float(ni_margin)
    p_value = (
        sum(value >= observed_statistic for value in outcomes) + 1
    ) / (len(outcomes) + 1)
    return {
        "method": "exact_task_cluster_sign_permutation_v1",
        "contrast": list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST),
        "task_ids_sha256": _study_domain_hash(
            "contextguard.bench.v2.task-order.v1", tasks,
        ),
        "point": point,
        "ni_margin": float(ni_margin),
        "p_value": p_value,
        "task_count": len(tasks),
        "degenerate_all_success": all_success,
        "noninferiority_pass": bool(not all_success and point > -float(ni_margin) and p_value < 0.05),
    }


def compute_benchmark_study_v2_effects(
    records: Sequence[Mapping[str, Any]], *, task_order: Sequence[str],
) -> dict[str, Any]:
    """Retain every valid terminal attempt and derive task-clustered effects."""
    tasks = _benchmark_study_v2_task_ids(task_order)
    grouped: dict[tuple[str, int, str], list[Mapping[str, Any]]] = collections.defaultdict(list)
    for record in records:
        task_id, repetition, arm = record.get("task_id"), record.get("repetition"), record.get("arm")
        if task_id not in tasks or repetition not in (0, 1, 2) or arm not in BENCHMARK_STUDY_V2_ARMS:
            raise ValueError("v2 effect record identity is invalid")
        grouped[(str(task_id), int(repetition), str(arm))].append(record)
    token_deltas: list[list[float]] = []
    diagnostic_token_deltas: list[list[float]] = []
    metric_deltas: dict[str, list[list[float]]] = {"correction": [], "retrieval": []}
    diagnostic_metric_deltas: dict[str, list[list[float]]] = {
        "correction": [], "retrieval": [],
    }
    metric_available = {"correction": True, "retrieval": True}
    retained_unfavorable = 0
    for task in tasks:
        per_task: list[float] = []
        diagnostic_per_task: list[float] = []
        per_task_metrics: dict[str, list[float]] = {"correction": [], "retrieval": []}
        diagnostic_per_task_metrics: dict[str, list[float]] = {
            "correction": [], "retrieval": [],
        }
        for repetition in range(3):
            costs: dict[str, float] = {}
            metrics: dict[str, dict[str, float]] = {"correction": {}, "retrieval": {}}
            for arm in BENCHMARK_STUDY_V2_ARMS:
                attempts = sorted(grouped.get((task, repetition, arm), ()), key=lambda row: int(row.get("attempt", -1)))
                if not attempts or [row.get("attempt") for row in attempts] not in ([0], [0, 1]):
                    raise ValueError("v2 attempts are incomplete or replaced")
                values = []
                for row in attempts:
                    token = row.get("tokens")
                    if (
                        isinstance(token, bool)
                        or not isinstance(token, (int, float))
                        or not math.isfinite(float(token))
                        or token < 0
                    ):
                        raise ValueError("v2 token value is invalid")
                    if row.get("terminal_status") != "success" or row.get("success") is not True:
                        retained_unfavorable += 1
                    values.append(float(token))
                costs[arm] = sum(values)
                for metric in metrics:
                    attempt_values = [row.get(metric) for row in attempts]
                    if any(
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(float(value))
                        or value < 0
                        for value in attempt_values
                    ):
                        metric_available[metric] = False
                        continue
                    metrics[metric][arm] = sum(
                        float(value) for value in attempt_values
                    )
            per_task.append(costs["host_unmodified"] - costs["bash_reference_v1"])
            diagnostic_per_task.append(
                costs["legacy_trim"] - costs["bash_reference_v1"]
            )
            for metric, values in metrics.items():
                if set(values) == set(BENCHMARK_STUDY_V2_ARMS):
                    per_task_metrics[metric].append(
                        values["host_unmodified"] - values["bash_reference_v1"]
                    )
                    diagnostic_per_task_metrics[metric].append(
                        values["legacy_trim"] - values["bash_reference_v1"]
                    )
        token_deltas.append(per_task)
        diagnostic_token_deltas.append(diagnostic_per_task)
        for metric in metric_deltas:
            if len(per_task_metrics[metric]) == 3:
                metric_deltas[metric].append(per_task_metrics[metric])
                diagnostic_metric_deltas[metric].append(
                    diagnostic_per_task_metrics[metric]
                )
            else:
                metric_available[metric] = False
    metric_effects = {
        f"{metric}_effect": (
            _benchmark_study_v2_cluster_interval(metric_deltas[metric])
            if metric_available[metric] and len(metric_deltas[metric]) == len(tasks)
            else {"method": "unavailable", "point": None, "q025": None, "q975": None}
        )
        for metric in metric_deltas
    }
    diagnostic_metric_effects = {
        f"diagnostic_{metric}_effect": (
            _benchmark_study_v2_cluster_interval(diagnostic_metric_deltas[metric])
            if metric_available[metric]
            and len(diagnostic_metric_deltas[metric]) == len(tasks)
            else {"method": "unavailable", "point": None, "q025": None, "q975": None}
        )
        for metric in diagnostic_metric_deltas
    }
    return {
        "primary_contrast": list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST),
        "diagnostic_contrast": list(BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST),
        "task_ids_sha256": _study_domain_hash(
            "contextguard.bench.v2.task-order.v1", tasks,
        ),
        "retained_unfavorable_runs": retained_unfavorable,
        "token_effect": _benchmark_study_v2_cluster_interval(token_deltas),
        "diagnostic_token_effect": _benchmark_study_v2_cluster_interval(
            diagnostic_token_deltas
        ),
        "quality_gate": False,
        "failure_gate": False,
        "correction_gate": False,
        "retrieval_gate": False,
        "shifted_cost_gate": False,
        **metric_effects,
        **diagnostic_metric_effects,
    }


def make_benchmark_study_v2_plan(
    *, schedule_seed: str, required_task_count: int, corpus_sha256: str = "0" * 64,
    checker_sha256: str = "0" * 64, task_ids_sha256: str = "0" * 64,
    ni_margin: float = 0.10,
) -> dict[str, Any]:
    """Build the immutable, a-priori v2 analysis plan for a frozen corpus."""
    plan = {
        "schema_version": BENCHMARK_STUDY_V2_PLAN_SCHEMA_VERSION,
        "arms": list(BENCHMARK_STUDY_V2_ARMS), "schedule_seed": schedule_seed,
        "repetitions": 3, "max_attempts_per_arm_unit": 2,
        "retry_policy": BENCHMARK_STUDY_V2_RETRY_POLICY,
        "corpus_sha256": corpus_sha256, "checker_sha256": checker_sha256,
        "task_ids_sha256": task_ids_sha256,
        "primary_contrast": list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST),
        "diagnostic_contrast": list(BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST),
        "noninferiority_margin": ni_margin,
        "power": {
            "claim_capable": False,
            "method": "not_estimated_without_independent_effect_model_v1",
            "reason": "fixed_12_task_corpus_is_descriptive_only",
            "required_task_count": required_task_count,
        },
        "exclusions": "none_after_schedule_except_prelaunch_refusal_v1",
        "missing_data": "incomplete_primary_pair_is_descriptive_only_v1",
        "contamination": "any_contamination_blocks_claim_v1",
        "stopping": "fixed_task_count_no_optional_stopping_v1",
        "model_cli_fields": ["model_revision", "backend_revision", "cli_version"],
        "gates": ["quality", "failure", "correction", "retrieval", "shifted_cost"],
    }
    validate_benchmark_study_v2_plan(plan)
    return plan


def validate_benchmark_study_v2_plan(plan: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "arms", "schedule_seed", "repetitions", "max_attempts_per_arm_unit", "retry_policy",
        "corpus_sha256", "checker_sha256", "task_ids_sha256", "primary_contrast", "diagnostic_contrast", "noninferiority_margin",
        "power", "exclusions", "missing_data", "contamination", "stopping", "model_cli_fields", "gates",
    }
    if set(plan) != required or plan.get("schema_version") != BENCHMARK_STUDY_V2_PLAN_SCHEMA_VERSION:
        raise ValueError("v2 study plan schema mismatch")
    _benchmark_study_v2_seed(plan["schedule_seed"])
    if plan["arms"] != list(BENCHMARK_STUDY_V2_ARMS) or plan["primary_contrast"] != list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST) or plan["diagnostic_contrast"] != list(BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST):
        raise ValueError("v2 study arms or contrasts drifted")
    if plan["repetitions"] != 3 or plan["max_attempts_per_arm_unit"] != 2 or plan["retry_policy"] != BENCHMARK_STUDY_V2_RETRY_POLICY:
        raise ValueError("v2 study retry contract drifted")
    if any(not isinstance(plan[key], str) or SHA256_HEX_PATTERN.fullmatch(plan[key]) is None for key in ("corpus_sha256", "checker_sha256", "task_ids_sha256")):
        raise ValueError("v2 corpus/checker/task-order binding is invalid")
    if not isinstance(plan["noninferiority_margin"], (int, float)) or isinstance(plan["noninferiority_margin"], bool) or not 0 <= plan["noninferiority_margin"] < 1:
        raise ValueError("v2 non-inferiority margin is invalid")
    power = plan["power"]
    if (
        not isinstance(power, Mapping)
        or set(power) != {"claim_capable", "method", "reason", "required_task_count"}
        or power.get("claim_capable") is not False
        or power.get("method") != "not_estimated_without_independent_effect_model_v1"
        or power.get("reason") != "fixed_12_task_corpus_is_descriptive_only"
        or power.get("required_task_count") != 12
    ):
        raise ValueError("v2 descriptive sample-size contract is unavailable or invalid")
    if plan["model_cli_fields"] != ["model_revision", "backend_revision", "cli_version"] or plan["gates"] != ["quality", "failure", "correction", "retrieval", "shifted_cost"]:
        raise ValueError("v2 provenance or gate contract drifted")
    frozen_text = {
        "exclusions": "none_after_schedule_except_prelaunch_refusal_v1",
        "missing_data": "incomplete_primary_pair_is_descriptive_only_v1",
        "contamination": "any_contamination_blocks_claim_v1",
        "stopping": "fixed_task_count_no_optional_stopping_v1",
    }
    if any(plan[key] != expected for key, expected in frozen_text.items()):
        raise ValueError("v2 study plan operational rule drifted")


def load_benchmark_study_v2_plan(path: Path) -> dict[str, Any]:
    """Load only canonical JSON so a plan's signed-by-bytes form is stable."""
    raw = _read_bytes_no_follow(path, max_bytes=100_000)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("v2 study plan is invalid JSON") from exc
    if not isinstance(value, dict) or raw != _study_canonical_json_bytes(value):
        raise ValueError("v2 study plan must be canonical JSON")
    validate_benchmark_study_v2_plan(value)
    return value


def validate_benchmark_study_v2_bindings(
    plan: Mapping[str, Any], *, corpus_bytes: bytes,
    checker_binding: Mapping[str, Any],
) -> None:
    """Bind the raw corpus and domain-separated ordered checker inventory."""
    validate_benchmark_study_v2_plan(plan)
    if not isinstance(corpus_bytes, bytes):
        raise ValueError("v2 corpus/checker binding bytes are invalid")
    validate_benchmark_study_v2_checker_binding(checker_binding)
    try:
        task_ids = _benchmark_study_v2_task_ids_from_corpus(corpus_bytes)
    except ValueError as exc:
        raise ValueError("v2 corpus/checker/task-order binding drift") from exc
    if (
        _study_sha256_bytes(corpus_bytes) != plan["corpus_sha256"]
        or checker_binding["sha256"] != plan["checker_sha256"]
        or _benchmark_study_v2_task_ids_sha256(task_ids)
        != plan["task_ids_sha256"]
    ):
        raise ValueError("v2 corpus/checker/task-order binding drift")


def validate_benchmark_study_v2_checker_binding(
    binding: Mapping[str, Any],
) -> None:
    """Validate the filename/size/content inventory before trusting its digest."""
    if not isinstance(binding, Mapping) or set(binding) != {
        "domain", "files", "sha256",
    }:
        raise ValueError("v2 checker binding schema is invalid")
    files = binding["files"]
    if (
        binding["domain"] != BENCHMARK_STUDY_V2_CHECKER_BINDING_DOMAIN
        or not isinstance(files, list)
        or len(files) != 12
    ):
        raise ValueError("v2 checker binding inventory is invalid")
    filenames: list[str] = []
    for entry in files:
        if not isinstance(entry, Mapping) or set(entry) != {
            "filename", "size", "sha256",
        }:
            raise ValueError("v2 checker binding entry is invalid")
        filename, size, digest = (
            entry["filename"], entry["size"], entry["sha256"],
        )
        if (
            not isinstance(filename, str)
            or not filename.endswith(".py")
            or Path(filename).name != filename
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_FIXTURE_FILE_BYTES
            or not isinstance(digest, str)
            or SHA256_HEX_PATTERN.fullmatch(digest) is None
        ):
            raise ValueError("v2 checker binding entry is invalid")
        filenames.append(filename)
    if filenames != sorted(filenames) or len(set(filenames)) != len(filenames):
        raise ValueError("v2 checker binding order is invalid")
    expected = _study_domain_hash(
        BENCHMARK_STUDY_V2_CHECKER_BINDING_DOMAIN, files,
    )
    if binding["sha256"] != expected:
        raise ValueError("v2 checker binding digest is invalid")


def validate_benchmark_study_v2_evidence_metadata(metadata: Mapping[str, Any]) -> None:
    """Fail closed before potentially sensitive execution evidence reaches a report."""
    def visit(value: Any, key: str = "") -> None:
        key_lower = key.lower()
        # `tokens` is the aggregate study metric, not a credential-shaped token.
        # All other token-bearing field names remain forbidden.
        if key_lower == "tokens" and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or value < 0
        ):
            raise ValueError("unsafe evidence token metric is invalid")
        if (
            key_lower != "tokens"
            and any(forbidden in key_lower for forbidden in BENCHMARK_STUDY_V2_EVIDENCE_FORBIDDEN_KEYS)
        ):
            raise ValueError("unsafe evidence field is forbidden")
        if isinstance(value, str):
            if (
                BENCHMARK_STUDY_V2_HANDLE_RE.search(value)
                or BENCHMARK_STUDY_V2_SECRET_SHAPE_RE.search(value)
            ):
                raise ValueError("unsafe evidence secret-shaped value is forbidden")
            if (
                key_lower in BENCHMARK_STUDY_V2_REVISION_KEYS
                and BENCHMARK_STUDY_V2_REVISION_RE.fullmatch(value) is None
            ):
                raise ValueError("unsafe evidence revision format is invalid")
        if isinstance(value, Mapping):
            for child_key, child in value.items():
                if not isinstance(child_key, str):
                    raise ValueError("unsafe evidence key is invalid")
                visit(child, child_key)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child, key)
    visit(metadata)


def redact_benchmark_study_v2_evidence(value: str) -> str:
    """Safe display helper for planted/accidental cgr1p handles; reports still reject them."""
    return BENCHMARK_STUDY_V2_HANDLE_RE.sub("[REDACTED_HANDLE]", value)


def evaluate_benchmark_study_v2_claim_readiness(
    *, plan: Mapping[str, Any], task_ids: Sequence[str], binary_inference: Mapping[str, Any],
    effects: Mapping[str, Any], provenance: Mapping[str, Any],
    binary_rows: Sequence[Mapping[str, Any]] | None = None,
    effect_records: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a fail-closed product-claim gate; diagnostic results are ignored."""
    validate_benchmark_study_v2_plan(plan)
    unique_tasks = list(dict.fromkeys(task_ids))
    task_order: list[str] | None = None
    try:
        task_order = _benchmark_study_v2_task_ids(task_ids)
    except (TypeError, ValueError):
        pass
    power_ready = bool(
        plan["power"].get("claim_capable") is True
        and len(unique_tasks) >= int(plan["power"]["required_task_count"])
    )
    provenance_safe = True
    try:
        validate_benchmark_study_v2_evidence_metadata(provenance)
    except (TypeError, ValueError):
        provenance_safe = False
    provider_ready = bool(
        provenance_safe
        and provenance.get("source") == "provider_export"
        and provenance.get("complete_provider_export") is True
        and isinstance(provenance.get("backend_revision"), str) and provenance["backend_revision"]
        and isinstance(provenance.get("model_revision"), str) and provenance["model_revision"]
        and isinstance(provenance.get("cli_version"), str) and provenance["cli_version"]
    )
    recomputed_inference: dict[str, Any] | None = None
    if task_order is not None and binary_rows is not None:
        try:
            recomputed_inference = infer_benchmark_study_v2_binary(
                binary_rows,
                task_order=task_order,
                ni_margin=float(plan["noninferiority_margin"]),
            )
        except (AttributeError, TypeError, ValueError):
            pass
    binary_ready = bool(
        recomputed_inference is not None
        and dict(binary_inference) == recomputed_inference
        and recomputed_inference["degenerate_all_success"] is False
        and recomputed_inference["noninferiority_pass"] is True
    )

    recomputed_effects: dict[str, Any] | None = None
    if task_order is not None and effect_records is not None:
        try:
            recomputed_effects = compute_benchmark_study_v2_effects(
                effect_records, task_order=task_order,
            )
        except (AttributeError, TypeError, ValueError):
            pass
    bound_effect_fields = (
        "primary_contrast", "diagnostic_contrast", "task_ids_sha256",
        "retained_unfavorable_runs", "token_effect", "diagnostic_token_effect",
        "correction_effect", "diagnostic_correction_effect",
        "retrieval_effect", "diagnostic_retrieval_effect",
    )
    effects_bound = bool(
        recomputed_effects is not None
        and all(
            effects.get(field) == recomputed_effects.get(field)
            for field in bound_effect_fields
        )
    )

    def interval_gate(field: str, *, strict: bool) -> bool:
        if recomputed_effects is None:
            return False
        interval = recomputed_effects.get(field)
        if not isinstance(interval, Mapping) or interval.get("method") != "task_cluster_bootstrap_v2":
            return False
        lower = interval.get("q025")
        if isinstance(lower, bool) or not isinstance(lower, (int, float)) or not math.isfinite(float(lower)):
            return False
        return bool(lower > 0 if strict else lower >= 0)

    derived_gates = {
        "quality": binary_ready,
        "failure": binary_ready,
        "correction": interval_gate("correction_effect", strict=False),
        "retrieval": interval_gate("retrieval_effect", strict=False),
        "shifted_cost": interval_gate("token_effect", strict=True),
    }
    effect_ready = bool(effects_bound and all(derived_gates.values()))
    contamination_ready = provenance.get("contaminated") is False
    mixed_versions_ready = provenance.get("mixed_versions") is False
    missing_data_ready = provenance.get("missing_primary_data") is False
    unmet = []
    for name, value in (("power", power_ready), ("provider_provenance", provider_ready), ("binary_inference", binary_ready), ("effect_gates", effect_ready), ("contamination", contamination_ready), ("mixed_versions", mixed_versions_ready), ("missing_data", missing_data_ready)):
        if not value:
            unmet.append(name)
    return {
        "claim_ready": not unmet,
        "descriptive_only": bool(unmet),
        "unmet_gates": unmet,
        "primary_contrast": list(BENCHMARK_STUDY_V2_PRIMARY_CONTRAST),
        "diagnostic_contrast": list(BENCHMARK_STUDY_V2_DIAGNOSTIC_CONTRAST),
        "derived_gates": derived_gates,
        "backend_revision": provenance.get("backend_revision") if provider_ready else "unavailable",
        "model_revision": provenance.get("model_revision") if provider_ready else "unavailable",
    }


BENCHMARK_STUDY_V2_EXEC_MANIFEST_SCHEMA_VERSION = "contextguard.bench.study-manifest.v4"
BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION = "contextguard.bench.study-attempt.v3"
BENCHMARK_STUDY_V2_REPORT_SCHEMA_VERSION = "contextguard.bench.study-report.v4"
BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION = (
    "contextguard.bench.study-invalid-decision.v1"
)
BENCHMARK_STUDY_V2_CANDIDATE_SCHEMA_VERSION = "contextguard-npm-candidate-set/v1"
BENCHMARK_STUDY_V2_CANDIDATE_NAMES = (
    "@ictechgy/context-guard-receipt", "@ictechgy/context-guard",
)
BENCHMARK_STUDY_V2_OVERLAY_NAME = "node_modules"
BENCHMARK_STUDY_V2_REWRITE_COMMAND = (
    "./node_modules/.bin/context-guard-rewrite-bash"
)
BENCHMARK_STUDY_V2_CLI_BINDING_SCHEMA_VERSION = (
    "contextguard.bench.cli-binding.v2"
)
BENCHMARK_STUDY_V2_AUTH_CONTEXT_SCHEMA_VERSION = (
    "contextguard.bench.auth-context.v1"
)
BENCHMARK_STUDY_V2_CLI_CAPABILITIES = (
    "--settings", "--setting-sources", "--include-hook-events",
    "--no-session-persistence", "stream-json",
)
BENCHMARK_STUDY_V2_CLI_MAX_BYTES = 1_073_741_824
BENCHMARK_STUDY_V2_CANARY_EVENT_SCHEMA_VERSION = (
    "contextguard.bench.canary-event.v2"
)
BENCHMARK_STUDY_V2_CANARY_EVIDENCE_SCHEMA_VERSION = (
    "contextguard.bench.canary-evidence.v3"
)
BENCHMARK_STUDY_V2_CANARY_ARMS = ("legacy_trim", "bash_reference_v1")
BENCHMARK_STUDY_V2_CANARY_TASK_ID = "contextguard-v2-bash-canary"
BENCHMARK_STUDY_V2_CANARY_MAX_BUDGET_USD = 0.75
BENCHMARK_STUDY_V2_CANARY_MARKER = b"contextguard-v2-host-pretooluse-canary\n"
BENCHMARK_STUDY_V2_CANARY_COMMAND = (
    "python3 -c 'from pathlib import Path;"
    "Path(\"contextguard-v2-canary.txt\").write_bytes("
    "b\"contextguard-v2-host-pretooluse-canary\\n\")'"
)
BENCHMARK_STUDY_V2_CANARY_PROMPT = (
    "Use the Bash tool exactly once to run this command, then reply done: "
    + BENCHMARK_STUDY_V2_CANARY_COMMAND
)
BENCHMARK_STUDY_V2_CANARY_CHECKER = (
    b"from pathlib import Path\n"
    b"try:\n"
    b"    value = Path('contextguard-v2-canary.txt').read_bytes()\n"
    b"except OSError:\n"
    b"    raise SystemExit(1)\n"
    b"raise SystemExit(0 if value == b'contextguard-v2-host-pretooluse-canary\\n' else 1)\n"
)


def _benchmark_study_v2_canary_contract() -> dict[str, Any]:
    fixture = b"This workspace is used only for the discarded v2 Bash-hook canary.\n"
    return {
        "schema_version": "contextguard.bench.canary-contract.v2",
        "task_id": BENCHMARK_STUDY_V2_CANARY_TASK_ID,
        "prompt_sha256": _study_sha256_bytes(
            BENCHMARK_STUDY_V2_CANARY_PROMPT.encode("utf-8")
        ),
        "fixture_sha256": _study_sha256_bytes(fixture),
        "checker_sha256": _study_sha256_bytes(BENCHMARK_STUDY_V2_CANARY_CHECKER),
        "marker_sha256": _study_sha256_bytes(BENCHMARK_STUDY_V2_CANARY_MARKER),
        "arms": list(BENCHMARK_STUDY_V2_CANARY_ARMS),
        "required_event_classes": ["PreToolUse"],
        "max_budget_usd": BENCHMARK_STUDY_V2_CANARY_MAX_BUDGET_USD,
        "provider_calls": 2,
        "discarded": True,
        "excluded_from_analysis": True,
    }


def _benchmark_study_v2_canary_task() -> TaskFixture:
    fixture = b"This workspace is used only for the discarded v2 Bash-hook canary.\n"
    return TaskFixture(
        id=BENCHMARK_STUDY_V2_CANARY_TASK_ID,
        prompt=BENCHMARK_STUDY_V2_CANARY_PROMPT,
        model="sonnet", max_turns=2,
        max_budget_usd=BENCHMARK_STUDY_V2_CANARY_MAX_BUDGET_USD,
        allowed_tools=["Bash"],
        fixture_tree="inline-canary-fixture",
        success_checker="inline-canary-checker.py",
        fixture_tree_entries=(
            FixtureTreeEntry(path="CANARY.md", data=fixture, executable=False),
        ),
        success_checker_bytes=BENCHMARK_STUDY_V2_CANARY_CHECKER,
    )


def _benchmark_study_v2_output_root(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError("v2 output root must not be a symlink")
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise ValueError("v2 output root is unavailable") from exc


@contextmanager
def _benchmark_study_v2_action_lock(output_root: Path) -> Iterable[None]:
    """Serialize every canary/run/resume/analyze mutation for one study root."""
    root = _benchmark_study_v2_output_root(output_root)
    try:
        root_fd = _ensure_directory_no_symlink(root, create=False)
    except (OSError, SystemExit, ValueError) as exc:
        raise ValueError(
            "v2 executable study requires a prepared output root"
        ) from exc
    lock_fd = -1
    locked = False
    try:
        if fcntl is None:
            raise ValueError("v2 lifecycle locking is unavailable")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        lock_fd = _open_regular_no_symlink(
            root / ".study-v2-action.lock", flags, 0o600,
        )
        os.fchmod(lock_fd, 0o600)
        os.fsync(root_fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError) as exc:
            raise ValueError("another v2 lifecycle action is already active") from exc
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(root_fd)


def _benchmark_study_v2_validate_cli_binding(binding: Mapping[str, Any]) -> None:
    required = {
        "schema_version", "executable", "executable_bytes",
        "executable_sha256", "bundle", "probe",
    }
    probe = binding.get("probe")
    bundle = binding.get("bundle")
    if (
        set(binding) != required
        or binding.get("schema_version")
        != BENCHMARK_STUDY_V2_CLI_BINDING_SCHEMA_VERSION
        or not isinstance(binding.get("executable"), str)
        or not Path(str(binding.get("executable"))).is_absolute()
        or isinstance(binding.get("executable_bytes"), bool)
        or not isinstance(binding.get("executable_bytes"), int)
        or not 0 < int(binding["executable_bytes"]) <= BENCHMARK_STUDY_V2_CLI_MAX_BYTES
        or not isinstance(binding.get("executable_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["executable_sha256"])) is None
        or not isinstance(probe, Mapping)
        or probe.get("schema_version") != MEASUREMENT_CLI_PROBE_SCHEMA_VERSION
        or probe.get("executable") != binding.get("executable")
        or probe.get("capabilities") != sorted(BENCHMARK_STUDY_V2_CLI_CAPABILITIES)
        or "version" in probe
        or not isinstance(bundle, Mapping)
        or set(bundle) != {
            "scope", "root", "file_count", "total_bytes", "sha256",
        }
        or bundle.get("scope") != "single-native-executable-v1"
        or not isinstance(bundle.get("root"), str)
        or not Path(str(bundle["root"])).is_absolute()
        or isinstance(bundle.get("file_count"), bool)
        or not isinstance(bundle.get("file_count"), int)
        or not 0 < bundle["file_count"] <= 100_000
        or isinstance(bundle.get("total_bytes"), bool)
        or not isinstance(bundle.get("total_bytes"), int)
        or not 0 < bundle["total_bytes"] <= 2_147_483_648
        or not isinstance(bundle.get("sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(bundle["sha256"]) is None
        or bundle.get("root") != binding.get("executable")
        or bundle.get("file_count") != 1
        or bundle.get("total_bytes") != binding.get("executable_bytes")
        or bundle.get("sha256") != binding.get("executable_sha256")
    ):
        raise ValueError("v2 CLI binding schema mismatch")


def _benchmark_study_v2_cli_stat_guard(path: Path) -> dict[str, int | str]:
    fd = _open_regular_no_symlink(path)
    try:
        item = os.fstat(fd)
        if item.st_size <= 0 or item.st_size > BENCHMARK_STUDY_V2_CLI_MAX_BYTES:
            raise ValueError("v2 CLI executable size is unsupported")
        return {
            "executable": str(path.resolve(strict=True)),
            "device": int(item.st_dev), "inode": int(item.st_ino),
            "bytes": int(item.st_size),
            "mtime_ns": int(item.st_mtime_ns), "ctime_ns": int(item.st_ctime_ns),
        }
    finally:
        os.close(fd)


def _benchmark_study_v2_cli_file_binding(
    path: Path,
) -> tuple[dict[str, Any], dict[str, int | str]]:
    """Hash a large native CLI through a bounded no-follow fd without buffering it."""
    fd = _open_regular_no_symlink(path)
    try:
        before = os.fstat(fd)
        if before.st_size <= 0 or before.st_size > BENCHMARK_STUDY_V2_CLI_MAX_BYTES:
            raise ValueError("v2 CLI executable size is unsupported")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > BENCHMARK_STUDY_V2_CLI_MAX_BYTES:
                raise ValueError("v2 CLI executable size is unsupported")
            digest.update(chunk)
        after = os.fstat(fd)
        stat_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if total != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stat_fields
        ):
            raise ValueError("v2 CLI executable changed while hashing")
        executable = str(path.resolve(strict=True))
        return (
            {
                "executable": executable,
                "executable_bytes": total,
                "executable_sha256": digest.hexdigest(),
            },
            {
                "executable": executable,
                "device": int(after.st_dev), "inode": int(after.st_ino),
                "bytes": int(after.st_size),
                "mtime_ns": int(after.st_mtime_ns),
                "ctime_ns": int(after.st_ctime_ns),
            },
        )
    finally:
        os.close(fd)


def _benchmark_study_v2_read_executable_shebang(path: Path) -> str | None:
    fd = _open_regular_no_symlink(path)
    try:
        raw = os.read(fd, 4096)
    finally:
        os.close(fd)
    first = raw.splitlines()[0] if raw else b""
    if not first.startswith(b"#!"):
        return None
    try:
        value = first[2:].decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        raise ValueError("v2 CLI shebang is not UTF-8") from None
    if not value or len(value) > 512:
        raise ValueError("v2 CLI shebang is invalid")
    return value


def _benchmark_study_v2_cli_bundle_binding(
    executable: Path, shebang: str | None,
) -> dict[str, Any]:
    if shebang is not None:
        raise ValueError("v2 executable study requires a native executable")
    file_binding, _guard = _benchmark_study_v2_cli_file_binding(executable)
    return {
        "scope": "single-native-executable-v1",
        "root": str(executable), "file_count": 1,
        "total_bytes": file_binding["executable_bytes"],
        "sha256": file_binding["executable_sha256"],
    }


def _benchmark_study_v2_cli_bundle_stat_guard(
    bundle: Mapping[str, Any],
) -> dict[str, Any]:
    """Detect a native executable replacement between action hash and launch."""
    if bundle.get("scope") != "single-native-executable-v1":
        raise ValueError("v2 CLI bundle scope is invalid")
    item = _benchmark_study_v2_cli_stat_guard(Path(str(bundle["root"])))
    return {
        "entry_count": 1,
        "sha256": _study_domain_hash(
            "contextguard.bench.v2.cli-bundle-stat.v1", item,
        ),
    }


def _benchmark_study_v2_execution_environment(
    cli_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Freeze the PATH and interpreters used by the CLI and Python hook."""
    _benchmark_study_v2_validate_cli_binding(cli_binding)
    names = ["python3"]
    bindings: list[dict[str, Any]] = []
    lookup_directories: list[str] = []
    for name in dict.fromkeys(names):
        lookup = shutil.which(name)
        if lookup is None:
            raise ValueError(f"v2 required runtime unavailable: {name}")
        lookup_path = Path(lookup).absolute()
        resolved = lookup_path.resolve(strict=True)
        file_binding, _guard = _benchmark_study_v2_cli_file_binding(resolved)
        lookup_directories.append(str(lookup_path.parent))
        bindings.append({
            "name": name, "lookup_path": str(lookup_path),
            **file_binding,
        })
    path_value = os.pathsep.join(dict.fromkeys(
        lookup_directories + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    ))
    return {
        "schema_version": "contextguard.bench.execution-environment.v3",
        "values": {
            "PATH": path_value,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        "runtime_bindings": bindings,
    }


def _benchmark_study_v2_validate_execution_environment(
    binding: Mapping[str, Any],
) -> None:
    values = binding.get("values")
    runtimes = binding.get("runtime_bindings")
    if (
        set(binding) != {"schema_version", "values", "runtime_bindings"}
        or binding.get("schema_version")
        != "contextguard.bench.execution-environment.v3"
        or not isinstance(values, Mapping)
        or set(values) != {"PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE"}
        or values.get("LANG") != "C" or values.get("LC_ALL") != "C"
        or values.get("PYTHONDONTWRITEBYTECODE") != "1"
        or not isinstance(values.get("PATH"), str) or not values["PATH"]
        or any(
            not part or not Path(part).is_absolute()
            for part in str(values["PATH"]).split(os.pathsep)
        )
        or not isinstance(runtimes, list) or not runtimes
    ):
        raise ValueError("v2 execution environment binding schema mismatch")
    seen: set[str] = set()
    for runtime in runtimes:
        if (
            not isinstance(runtime, Mapping)
            or set(runtime) != {
                "name", "lookup_path", "executable", "executable_bytes",
                "executable_sha256",
            }
            or not isinstance(runtime.get("name"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+", str(runtime["name"]))
            or runtime["name"] in seen
            or not isinstance(runtime.get("lookup_path"), str)
            or not Path(str(runtime["lookup_path"])).is_absolute()
            or not isinstance(runtime.get("executable"), str)
            or not Path(str(runtime["executable"])).is_absolute()
            or isinstance(runtime.get("executable_bytes"), bool)
            or not isinstance(runtime.get("executable_bytes"), int)
            or not 0 < runtime["executable_bytes"] <= BENCHMARK_STUDY_V2_CLI_MAX_BYTES
            or not isinstance(runtime.get("executable_sha256"), str)
            or SHA256_HEX_PATTERN.fullmatch(runtime["executable_sha256"]) is None
        ):
            raise ValueError("v2 runtime interpreter binding schema mismatch")
        seen.add(str(runtime["name"]))


def _benchmark_study_v2_assert_execution_environment(
    binding: Mapping[str, Any],
) -> dict[str, dict[str, int | str]]:
    _benchmark_study_v2_validate_execution_environment(binding)
    path_value = str(binding["values"]["PATH"])
    guards: dict[str, dict[str, int | str]] = {}
    for runtime in binding["runtime_bindings"]:
        found = shutil.which(str(runtime["name"]), path=path_value)
        if found is None or str(Path(found).absolute()) != runtime["lookup_path"]:
            raise ValueError("v2 runtime interpreter lookup drift")
        current, _guard = _benchmark_study_v2_cli_file_binding(
            Path(str(runtime["executable"]))
        )
        expected = {
            key: runtime[key]
            for key in ("executable", "executable_bytes", "executable_sha256")
        }
        if current != expected or Path(found).resolve(strict=True) != Path(
            str(runtime["executable"])
        ):
            raise ValueError("v2 runtime interpreter binding drift")
        guards[str(runtime["name"])] = _benchmark_study_v2_cli_stat_guard(
            Path(str(runtime["executable"]))
        )
    return guards


def _benchmark_study_v2_assert_runtime_stat_guards(
    binding: Mapping[str, Any],
    guards: Mapping[str, Mapping[str, int | str]],
) -> None:
    _benchmark_study_v2_validate_execution_environment(binding)
    runtimes = binding["runtime_bindings"]
    if set(guards) != {str(runtime["name"]) for runtime in runtimes}:
        raise ValueError("v2 runtime interpreter guard mismatch")
    for runtime in runtimes:
        name = str(runtime["name"])
        guard = guards[name]
        found = shutil.which(
            name, path=str(binding["values"]["PATH"]),
        )
        if (
            found is None
            or str(Path(found).absolute()) != runtime["lookup_path"]
            or Path(found).resolve(strict=True) != Path(str(runtime["executable"]))
            or guard.get("executable") != runtime["executable"]
            or guard.get("bytes") != runtime["executable_bytes"]
            or _benchmark_study_v2_cli_stat_guard(
                Path(str(runtime["executable"]))
            ) != dict(guard)
        ):
            raise ValueError("v2 runtime interpreter changed before launch")


def _benchmark_study_v2_auth_home_binding(home: Path) -> tuple[Path, dict[str, Any]]:
    if "CLAUDE_CONFIG_DIR" in os.environ:
        raise ValueError("v2 existing-login mode requires CLAUDE_CONFIG_DIR to be unset")
    if not home.is_absolute() or "\0" in str(home):
        raise ValueError("v2 existing-login HOME must be an absolute path")
    resolved = home.resolve(strict=True)
    directory_fd = _ensure_directory_no_symlink(resolved, create=False)
    try:
        item = os.fstat(directory_fd)
    finally:
        os.close(directory_fd)
    mode = stat.S_IMODE(item.st_mode)
    if (
        not stat.S_ISDIR(item.st_mode)
        or item.st_uid != os.geteuid()
        or mode & 0o022
    ):
        raise ValueError("v2 existing-login HOME is not a private owned directory")
    return resolved, {
        "device": item.st_dev,
        "inode": item.st_ino,
        "uid": item.st_uid,
        "mode": mode,
    }


def _benchmark_study_v2_validate_auth_context(binding: Mapping[str, Any]) -> None:
    if (
        set(binding) != {
            "schema_version", "mode", "home_path_sha256", "home_stat",
            "identity_sha256", "auth_method", "api_provider",
            "credential_environment",
        }
        or binding.get("schema_version")
        != BENCHMARK_STUDY_V2_AUTH_CONTEXT_SCHEMA_VERSION
        or binding.get("mode") != "existing_cli_login_v1"
        or not isinstance(binding.get("home_path_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["home_path_sha256"])) is None
        or not isinstance(binding.get("identity_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["identity_sha256"])) is None
        or binding.get("auth_method") != "claude.ai"
        or binding.get("api_provider") != "firstParty"
        or binding.get("credential_environment") != "forbidden"
    ):
        raise ValueError("v2 auth context binding schema mismatch")
    home_stat = binding.get("home_stat")
    if (
        not isinstance(home_stat, Mapping)
        or set(home_stat) != {"device", "inode", "uid", "mode"}
        or any(isinstance(value, bool) or not isinstance(value, int) or value < 0
               for value in home_stat.values())
        or int(home_stat["uid"]) != os.geteuid()
        or int(home_stat["mode"]) & 0o022
    ):
        raise ValueError("v2 auth HOME binding schema mismatch")


def _benchmark_study_v2_auth_context(
    claude_bin: str,
    execution_environment: Mapping[str, Any],
    auth_home: Path,
) -> tuple[Path, dict[str, Any]]:
    _benchmark_study_v2_validate_execution_environment(execution_environment)
    resolved_home, home_stat = _benchmark_study_v2_auth_home_binding(auth_home)
    with tempfile.TemporaryDirectory(prefix="contextguard-v2-auth-probe-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        paths = {
            name: root / name
            for name in (
                "cwd", "xdg-config", "xdg-cache", "xdg-data", "xdg-state", "tmp",
            )
        }
        for path in paths.values():
            path.mkdir(mode=0o700)
        env = dict(execution_environment["values"])
        env.update({
            "HOME": str(resolved_home),
            "XDG_CONFIG_HOME": str(paths["xdg-config"]),
            "XDG_CACHE_HOME": str(paths["xdg-cache"]),
            "XDG_DATA_HOME": str(paths["xdg-data"]),
            "XDG_STATE_HOME": str(paths["xdg-state"]),
            "TMPDIR": str(paths["tmp"]),
            "NO_COLOR": "1",
        })
        result = run_bounded_command(
            [executable_argv0(claude_bin), "auth", "status", "--json"],
            cwd=paths["cwd"], timeout_seconds=10,
            max_output_bytes=MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES, env=env,
        )
    if (
        result.returncode != 0 or result.timed_out or result.output_truncated
        or result.launch_error or result.stderr_bytes
        or not 0 < len(result.stdout_bytes) <= 4096
    ):
        raise ValueError("v2 existing Claude login is unavailable")
    try:
        status_payload = json.loads(result.stdout_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("v2 existing Claude login status is invalid") from None
    identity_keys = {
        "loggedIn", "authMethod", "apiProvider", "email", "orgId",
        "orgName", "subscriptionType",
    }
    if (
        not isinstance(status_payload, Mapping)
        or set(status_payload) != identity_keys
        or status_payload.get("loggedIn") is not True
        or status_payload.get("authMethod") != "claude.ai"
        or status_payload.get("apiProvider") != "firstParty"
        or any(
            not isinstance(status_payload.get(key), str)
            or len(str(status_payload[key]).encode("utf-8")) > 1024
            or "\0" in str(status_payload[key])
            for key in ("email", "orgId", "orgName", "subscriptionType")
        )
    ):
        raise ValueError("v2 existing Claude login status is unsupported")
    private_identity = {
        key: status_payload[key]
        for key in (
            "authMethod", "apiProvider", "email", "orgId", "orgName",
            "subscriptionType",
        )
    }
    binding = {
        "schema_version": BENCHMARK_STUDY_V2_AUTH_CONTEXT_SCHEMA_VERSION,
        "mode": "existing_cli_login_v1",
        "home_path_sha256": _study_domain_hash(
            "contextguard.bench.v2.auth-home-path.v1", str(resolved_home),
        ),
        "home_stat": home_stat,
        "identity_sha256": _study_domain_hash(
            "contextguard.bench.v2.auth-identity.v1", private_identity,
        ),
        "auth_method": "claude.ai",
        "api_provider": "firstParty",
        "credential_environment": "forbidden",
    }
    _benchmark_study_v2_validate_auth_context(binding)
    return resolved_home, binding


def _benchmark_study_v2_assert_auth_context(
    claude_bin: str,
    execution_environment: Mapping[str, Any],
    expected: Mapping[str, Any],
    auth_home: Path,
) -> Path:
    _benchmark_study_v2_validate_auth_context(expected)
    try:
        resolved_home, actual = _benchmark_study_v2_auth_context(
            claude_bin, execution_environment, auth_home,
        )
    except (OSError, SystemExit, TypeError, ValueError) as exc:
        raise ValueError("v2 existing Claude login binding drift") from exc
    if actual != dict(expected):
        raise ValueError("v2 existing Claude login binding drift")
    return resolved_home


def _benchmark_study_v2_cli_binding(claude_bin: str) -> dict[str, Any]:
    """Bind the exact executable bytes and isolated version/help capability probes."""
    executable = Path(executable_argv0(claude_bin))
    file_binding, stat_guard = _benchmark_study_v2_cli_file_binding(executable)
    shebang = _benchmark_study_v2_read_executable_shebang(executable)
    if shebang is not None:
        raise ValueError(
            "v2 executable study requires a native executable; script launcher "
            "dependency closure cannot be proven"
        )
    bundle = _benchmark_study_v2_cli_bundle_binding(executable, shebang)
    probe = run_measurement_cli_probes(
        str(executable), BENCHMARK_STUDY_V2_CLI_CAPABILITIES,
    )
    # Bind exact version bytes by hash/length without persisting arbitrary CLI
    # display text that could contain a secret-shaped value.
    probe.pop("version", None)
    if _benchmark_study_v2_cli_stat_guard(executable) != stat_guard:
        raise ValueError("v2 CLI executable changed during capability probes")
    binding = {
        "schema_version": BENCHMARK_STUDY_V2_CLI_BINDING_SCHEMA_VERSION,
        **file_binding,
        "bundle": bundle,
        "probe": probe,
    }
    _benchmark_study_v2_validate_cli_binding(binding)
    return binding


def _benchmark_study_v2_assert_cli_binding(
    claude_bin: str, expected: Mapping[str, Any],
) -> dict[str, Any]:
    """Refuse a changed or incompatible CLI before reserving any identity."""
    _benchmark_study_v2_validate_cli_binding(expected)
    try:
        actual = _benchmark_study_v2_cli_binding(claude_bin)
    except (OSError, SystemExit, TypeError, ValueError) as exc:
        raise ValueError("v2 CLI binding drift") from exc
    if actual != dict(expected):
        raise ValueError("v2 CLI binding drift")
    guard: dict[str, Any] = _benchmark_study_v2_cli_stat_guard(
        Path(str(actual["executable"]))
    )
    guard["bundle_stat_guard"] = _benchmark_study_v2_cli_bundle_stat_guard(
        actual["bundle"]
    )
    return guard


def _benchmark_study_v2_assert_cli_executable_bytes(
    expected: Mapping[str, Any], stat_guard: Mapping[str, Any],
) -> None:
    """Repeat a cheap post-hash file-identity check before provider reservation."""
    _benchmark_study_v2_validate_cli_binding(expected)
    if (
        stat_guard.get("executable") != expected["executable"]
        or stat_guard.get("bytes") != expected["executable_bytes"]
        or _benchmark_study_v2_cli_stat_guard(
            Path(str(expected["executable"]))
        ) != {
            key: stat_guard[key]
            for key in ("executable", "device", "inode", "bytes", "mtime_ns", "ctime_ns")
        }
        or stat_guard.get("bundle_stat_guard")
        != _benchmark_study_v2_cli_bundle_stat_guard(expected["bundle"])
    ):
        raise ValueError("v2 CLI executable bytes drift")


def _benchmark_study_v2_python_binding() -> dict[str, Any]:
    invoked_python = Path(sys.executable).absolute()
    resolved_python = invoked_python.resolve(strict=True)
    python_file, _guard = _benchmark_study_v2_cli_file_binding(resolved_python)
    return {
        "invoked_path": str(invoked_python),
        **python_file,
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag,
        "version_info": [
            sys.version_info.major, sys.version_info.minor,
            sys.version_info.micro, sys.version_info.releaselevel,
            sys.version_info.serial,
        ],
        "version_sha256": _study_sha256_bytes(sys.version.encode("utf-8")),
        "flags_sha256": _study_domain_hash(
            "contextguard.bench.v2.python-flags.v1", list(sys.flags),
        ),
        "prefix": sys.prefix,
        "base_prefix": sys.base_prefix,
    }


def _benchmark_study_v2_runner_binding() -> dict[str, Any]:
    path = Path(__file__).resolve(strict=True)
    raw = _read_bytes_no_follow(path, max_bytes=4_000_000)
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": _study_sha256_bytes(raw),
        "python": _benchmark_study_v2_python_binding(),
    }


def _benchmark_study_v2_assert_python_binding(
    binding: Mapping[str, Any], *, require_current: bool,
) -> str:
    required = {
        "invoked_path", "executable", "executable_bytes", "executable_sha256",
        "implementation", "cache_tag", "version_info", "version_sha256",
        "flags_sha256", "prefix", "base_prefix",
    }
    if (
        set(binding) != required
        or not isinstance(binding.get("invoked_path"), str)
        or not Path(str(binding["invoked_path"])).is_absolute()
        or not isinstance(binding.get("executable"), str)
        or not Path(str(binding["executable"])).is_absolute()
        or isinstance(binding.get("executable_bytes"), bool)
        or not isinstance(binding.get("executable_bytes"), int)
        or not 0 < int(binding["executable_bytes"]) <= BENCHMARK_STUDY_V2_CLI_MAX_BYTES
        or not isinstance(binding.get("executable_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["executable_sha256"])) is None
        or not isinstance(binding.get("implementation"), str)
        or not binding["implementation"]
        or not isinstance(binding.get("cache_tag"), (str, type(None)))
        or not isinstance(binding.get("version_info"), list)
        or len(binding["version_info"]) != 5
        or any(
            isinstance(value, bool) or not isinstance(value, (int, str))
            for value in binding["version_info"]
        )
        or not isinstance(binding.get("version_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["version_sha256"])) is None
        or not isinstance(binding.get("flags_sha256"), str)
        or SHA256_HEX_PATTERN.fullmatch(str(binding["flags_sha256"])) is None
        or not isinstance(binding.get("prefix"), str)
        or not isinstance(binding.get("base_prefix"), str)
    ):
        raise ValueError("v2 runner Python binding schema mismatch")
    executable = Path(str(binding["executable"]))
    current_file, _guard = _benchmark_study_v2_cli_file_binding(executable)
    expected_file = {
        key: binding[key]
        for key in ("executable", "executable_bytes", "executable_sha256")
    }
    if current_file != expected_file:
        raise ValueError("v2 runner Python binding drift")
    if require_current:
        invoked = Path(sys.executable).absolute()
        try:
            resolved = invoked.resolve(strict=True)
        except OSError as exc:
            raise ValueError("v2 runner Python binding drift") from exc
        if (
            str(invoked) != binding["invoked_path"]
            or str(resolved) != binding["executable"]
            or sys.implementation.name != binding["implementation"]
            or sys.implementation.cache_tag != binding["cache_tag"]
            or [
                sys.version_info.major, sys.version_info.minor,
                sys.version_info.micro, sys.version_info.releaselevel,
                sys.version_info.serial,
            ] != binding["version_info"]
            or _study_sha256_bytes(sys.version.encode("utf-8"))
            != binding["version_sha256"]
            or _study_domain_hash(
                "contextguard.bench.v2.python-flags.v1", list(sys.flags),
            ) != binding["flags_sha256"]
            or sys.prefix != binding["prefix"]
            or sys.base_prefix != binding["base_prefix"]
        ):
            raise ValueError("v2 runner Python binding drift")
    return str(executable)


def _benchmark_study_v2_read_canonical(path: Path, *, owner: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    raw = _read_bytes_no_follow(path, max_bytes=maximum)
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_measurement_object_no_duplicates,
            parse_constant=_stream_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{owner} is invalid JSON") from exc
    if not isinstance(value, dict) or raw != _study_canonical_json_bytes(value):
        raise ValueError(f"{owner} must be exact canonical JSON bytes")
    return value, raw


def verify_benchmark_study_v2_candidate(
    manifest_path: Path, *, checksum_path: Path | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify the build-once candidate as inert bytes; never import its code."""
    manifest, manifest_raw = _benchmark_study_v2_read_canonical(
        manifest_path, owner="v2 candidate manifest", maximum=1_000_000,
    )
    required = {
        "build_policy", "commit_sha", "exact_dependency", "packages",
        "policy_sha256", "receipt_package_files_sha256", "protocol",
        "repository", "schema_version", "tool_versions",
    }
    if set(manifest) != required or manifest.get("schema_version") != BENCHMARK_STUDY_V2_CANDIDATE_SCHEMA_VERSION:
        raise ValueError("v2 candidate manifest schema mismatch")
    if manifest.get("build_policy") != {
        "ignore_scripts": True, "lockfiles": [], "network": "offline",
        "package_build_count": 1,
    }:
        raise ValueError("v2 candidate build policy mismatch")
    if manifest.get("protocol") != {
        "maximum": 1, "minimum": 1, "name": "bash_reference_v1",
    }:
        raise ValueError("v2 candidate protocol mismatch")
    if (
        manifest.get("repository") != "ictechgy/context-guard"
        or not isinstance(manifest.get("commit_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", manifest["commit_sha"]) is None
        or not isinstance(manifest.get("tool_versions"), dict)
        or not manifest["tool_versions"]
        or any(
            not isinstance(key, str) or not key or len(key) > 64
            or not isinstance(value, str) or not value or len(value) > 128
            for key, value in manifest["tool_versions"].items()
        )
        or any(
            not isinstance(manifest.get(key), str)
            or SHA256_HEX_PATTERN.fullmatch(manifest[key]) is None
            for key in ("policy_sha256", "receipt_package_files_sha256")
        )
    ):
        raise ValueError("v2 candidate build provenance is invalid")
    manifest_sha256 = _study_sha256_bytes(manifest_raw)
    if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256:
        raise ValueError("v2 candidate canonical manifest hash drift")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or len(packages) != 2:
        raise ValueError("v2 candidate must bind exactly two tarballs")
    records: list[dict[str, Any]] = []
    checksum_rows: list[str] = []
    for index, package in enumerate(packages):
        if not isinstance(package, dict) or set(package) != {
            "filename", "integrity", "name", "sha256", "size_bytes", "version",
        }:
            raise ValueError("v2 candidate tarball record schema mismatch")
        filename = package.get("filename")
        digest = package.get("sha256")
        size = package.get("size_bytes")
        if (
            package.get("name") != BENCHMARK_STUDY_V2_CANDIDATE_NAMES[index]
            or not isinstance(filename, str) or Path(filename).name != filename
            or not isinstance(digest, str) or SHA256_HEX_PATTERN.fullmatch(digest) is None
            or isinstance(size, bool) or not isinstance(size, int) or size <= 0
            or not isinstance(package.get("version"), str) or not package["version"]
        ):
            raise ValueError("v2 candidate tarball identity is invalid")
        tarball_path = manifest_path.parent / filename
        raw = _read_bytes_no_follow(tarball_path, max_bytes=100_000_000)
        sri = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii")
        if len(raw) != size or _study_sha256_bytes(raw) != digest or package.get("integrity") != sri:
            raise ValueError("v2 candidate tarball size, SHA-256, or SRI mismatch")
        checksum_rows.append(f"{digest}  {filename}\n")
        records.append({**package, "path": str(tarball_path.resolve())})
    if len({record["filename"] for record in records}) != 2 or manifest.get("exact_dependency") != {
        "name": BENCHMARK_STUDY_V2_CANDIDATE_NAMES[0],
        "version": records[0]["version"],
    }:
        raise ValueError("v2 candidate exact dependency binding mismatch")
    checksum = checksum_path or manifest_path.with_name("candidate-sha256sums.txt")
    checksum_raw = _read_bytes_no_follow(checksum, max_bytes=10_000)
    expected_checksum = "".join(checksum_rows).encode("ascii")
    if checksum_raw != expected_checksum:
        raise ValueError("v2 candidate checksum document mismatch")
    return {
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": manifest_sha256,
        "manifest_bytes": len(manifest_raw),
        "checksum_path": str(checksum.resolve()),
        "checksum_sha256": _study_sha256_bytes(checksum_raw),
        "packages": records,
    }


def _benchmark_study_v2_tarball_inventory(path: Path) -> dict[str, Any]:
    """Inventory regular npm package members without extracting candidate code."""
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for index, member in enumerate(archive):
                if index >= 10_000:
                    raise ValueError("v2 candidate tarball has too many members")
                raw_parts = member.name.split("/")
                if (
                    not raw_parts
                    or raw_parts[0] != "package"
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or any(
                        ord(character) < 0x20 or ord(character) == 0x7F
                        for character in member.name
                    )
                ):
                    raise ValueError("v2 candidate tarball member path is invalid")
                if len(raw_parts) == 1:
                    if not member.isdir():
                        raise ValueError("v2 candidate tarball package root is invalid")
                    continue
                relative = PurePosixPath(*raw_parts[1:]).as_posix()
                if relative in seen:
                    raise ValueError("v2 candidate tarball has duplicate members")
                if member.isdir():
                    continue
                if not member.isreg() or member.size < 0 or member.size > 100_000_000:
                    raise ValueError("v2 candidate tarball member type is unsupported")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("v2 candidate tarball member is unreadable")
                raw = stream.read(member.size + 1)
                if len(raw) != member.size:
                    raise ValueError("v2 candidate tarball member size drift")
                total_bytes += len(raw)
                if total_bytes > 100_000_000:
                    raise ValueError("v2 candidate tarball expanded size exceeds limit")
                seen.add(relative)
                files.append({
                    "path": relative,
                    "bytes": len(raw),
                    "sha256": _study_sha256_bytes(raw),
                    "executable": bool(member.mode & 0o111),
                    "kind": "file",
                    "target": None,
                })
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("v2 candidate tarball is not a readable npm archive") from exc
    files.sort(key=lambda item: item["path"])
    if not files:
        raise ValueError("v2 candidate tarball package is empty")
    return {
        "files": files,
        "file_count": len(files),
        "sha256": _study_domain_hash("contextguard.bench.v2.inventory.v1", files),
    }


def _benchmark_study_v2_verify_installed_packages(
    overlay_root: Path, candidate: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the executed package bytes to the two already-verified tarballs."""
    bindings: list[dict[str, Any]] = []
    installed_documents: dict[str, dict[str, Any]] = {}
    allowed_overlay_paths: set[str] = set()
    for record in candidate["packages"]:
        name = record["name"]
        package_root = overlay_root.joinpath(*str(name).split("/"))
        expected = _benchmark_study_v2_tarball_inventory(Path(record["path"]))
        actual = _benchmark_study_v2_inventory(package_root)
        if actual != expected:
            raise ValueError("v2 installed package bytes differ from candidate tarball")
        package_raw = _read_bytes_no_follow(
            package_root / "package.json", max_bytes=128 * 1024,
        )
        try:
            document = json.loads(
                package_raw.decode("utf-8"),
                object_pairs_hook=_measurement_object_no_duplicates,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("v2 installed package metadata is invalid") from exc
        if (
            not isinstance(document, dict)
            or document.get("name") != name
            or document.get("version") != record["version"]
        ):
            raise ValueError("v2 installed package identity differs from candidate")
        installed_documents[str(name)] = document
        allowed_overlay_paths.update(
            f"{name}/{item['path']}" for item in expected["files"]
        )
        bindings.append({
            "name": name,
            "version": record["version"],
            "inventory_sha256": actual["sha256"],
        })
    root_document = installed_documents[BENCHMARK_STUDY_V2_CANDIDATE_NAMES[1]]
    receipt_record = candidate["packages"][0]
    if root_document.get("dependencies") != {
        BENCHMARK_STUDY_V2_CANDIDATE_NAMES[0]: receipt_record["version"],
    }:
        raise ValueError("v2 installed root exact dependency binding mismatch")
    required_bins = ("context-guard", "context-guard-rewrite-bash")
    root_bin_map = root_document.get("bin")
    if not isinstance(root_bin_map, dict) or any(
        not isinstance(root_bin_map.get(name), str) for name in required_bins
    ):
        raise ValueError("v2 installed root package lacks required public bins")
    bin_bindings: list[dict[str, str]] = []
    seen_bin_names: set[str] = set()
    for package_name in sorted(installed_documents):
        bin_map = installed_documents[package_name].get("bin", {})
        if not isinstance(bin_map, dict):
            raise ValueError("v2 installed package bin metadata is invalid")
        package_root = overlay_root.joinpath(*package_name.split("/"))
        for bin_name, relative_target in sorted(bin_map.items()):
            if (
                not isinstance(bin_name, str)
                or not bin_name
                or "/" in bin_name
                or bin_name in {".", ".."}
                or bin_name in seen_bin_names
                or not isinstance(relative_target, str)
            ):
                raise ValueError("v2 installed package bin metadata is invalid")
            target_parts = relative_target.split("/")
            target_path = PurePosixPath(relative_target)
            if (
                target_path.is_absolute()
                or not target_parts
                or any(part in {"", ".", ".."} for part in target_parts)
            ):
                raise ValueError("v2 installed package bin target is unsafe")
            package_relative_target = (
                PurePosixPath(package_name) / target_path
            ).as_posix()
            if package_relative_target not in allowed_overlay_paths:
                raise ValueError("v2 installed package bin target is not in its tarball")
            link_relative = f".bin/{bin_name}"
            link = overlay_root / ".bin" / bin_name
            expected_raw_target = (
                PurePosixPath("..") / package_name / target_path
            ).as_posix()
            try:
                raw_target = os.readlink(link)
                resolved = link.resolve(strict=True)
                expected_target = (package_root / Path(*target_parts)).resolve(
                    strict=True
                )
            except OSError as exc:
                raise ValueError("v2 installed public bin link is unavailable") from exc
            if raw_target != expected_raw_target or resolved != expected_target:
                raise ValueError(
                    "v2 installed public bin link differs from package metadata"
                )
            seen_bin_names.add(bin_name)
            allowed_overlay_paths.add(link_relative)
            bin_bindings.append({
                "name": bin_name,
                "package": package_name,
                "target": expected_raw_target,
            })
    actual_overlay = _benchmark_study_v2_inventory(overlay_root)
    actual_overlay_paths = {item["path"] for item in actual_overlay["files"]}
    if actual_overlay_paths - allowed_overlay_paths:
        raise ValueError("v2 candidate install contains an unverified overlay path")
    if actual_overlay_paths != allowed_overlay_paths:
        raise ValueError("v2 candidate install is missing a verified overlay path")
    return {
        "packages": bindings,
        "bins": bin_bindings,
        "sha256": _study_domain_hash(
            "contextguard.bench.v2.installed-packages.v2",
            {"packages": bindings, "bins": bin_bindings},
        ),
    }


def _benchmark_study_v2_inventory(root: Path, *, reject_symlinks: bool = False) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("v2 inventory root must be a real directory")
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        mode = os.lstat(path).st_mode
        if stat.S_ISLNK(mode):
            if reject_symlinks:
                raise ValueError("v2 physical overlay must not contain symlinks")
            raw_target = os.readlink(path)
            if Path(raw_target).is_absolute():
                raise ValueError("v2 candidate overlay symlink must be relative")
            target = path.resolve(strict=True)
            try:
                target.relative_to(root.resolve(strict=True))
            except ValueError:
                raise ValueError("v2 candidate overlay symlink escapes the install root") from None
            if not target.is_file():
                raise ValueError("v2 candidate overlay symlink must resolve to an internal file")
            raw = _read_bytes_no_follow(target, max_bytes=100_000_000)
            executable = bool(target.stat().st_mode & 0o111)
            kind = "symlink"
        elif stat.S_ISREG(mode):
            raw = _read_bytes_no_follow(path, max_bytes=100_000_000)
            executable = bool(mode & 0o111)
            raw_target = None
            kind = "file"
        elif stat.S_ISDIR(mode):
            continue
        else:
            raise ValueError("v2 inventory contains an unsupported filesystem entry")
        files.append({
            "path": rel, "bytes": len(raw), "sha256": _study_sha256_bytes(raw),
            "executable": executable, "kind": kind, "target": raw_target,
        })
    if not files:
        raise ValueError("v2 candidate overlay is empty")
    return {
        "files": files,
        "file_count": len(files),
        "sha256": _study_domain_hash("contextguard.bench.v2.inventory.v1", files),
    }


def _benchmark_study_v2_verify_physical_copy(
    source: Path, destination: Path, *, expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source_inventory = _benchmark_study_v2_inventory(source)
    if expected is not None and source_inventory != dict(expected):
        raise ValueError("v2 staged candidate changed before the attempt copy")
    destination_inventory = _benchmark_study_v2_inventory(destination)
    if destination_inventory != source_inventory:
        raise ValueError("v2 candidate overlay copy differs from installed candidate")
    for item in source_inventory["files"]:
        if item["kind"] != "file":
            continue
        source_path = source / item["path"]
        destination_path = destination / item["path"]
        if source_path.stat().st_dev == destination_path.stat().st_dev and source_path.stat().st_ino == destination_path.stat().st_ino:
            raise ValueError("v2 candidate overlay contains a hardlink to the staged install")
    return destination_inventory


def _benchmark_study_v2_expected_pre_workspace(
    task: TaskFixture, *, install_root: Path,
    expected_overlay_inventory: Mapping[str, Any],
) -> dict[str, Any]:
    """Re-materialize the bound cold workspace without invoking candidate code."""
    with tempfile.TemporaryDirectory(prefix="contextguard-v2-pre-workspace-") as temp:
        workspace = Path(temp).resolve()
        os.chmod(workspace, 0o700)
        reset_task_fixture_tree(task.fixture_tree_entries or (), workspace)
        overlay = workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME
        shutil.copytree(
            install_root, overlay, symlinks=True, copy_function=shutil.copy2,
        )
        _benchmark_study_v2_verify_physical_copy(
            install_root, overlay, expected=expected_overlay_inventory,
        )
        return _benchmark_study_v2_inventory(workspace)


def _benchmark_study_v2_settings() -> dict[str, dict[str, Any]]:
    common: dict[str, Any] = {
        "model": "sonnet",
        "permissions": {"allow": ["Bash", "Edit", "Glob", "Grep", "Read", "Write"]},
    }
    result = {"host_unmodified": json.loads(json.dumps(common))}
    for arm, suffix in (("legacy_trim", ""), ("bash_reference_v1", " --bash-reference-v1")):
        settings = json.loads(json.dumps(common))
        settings["hooks"] = {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": BENCHMARK_STUDY_V2_REWRITE_COMMAND + suffix,
                }],
            }],
        }
        result[arm] = settings
    return result


def _benchmark_study_v2_write_settings(output_root: Path) -> dict[str, Any]:
    settings_root = output_root / "inputs" / "settings-v2"
    settings_root.mkdir(mode=0o700, parents=True)
    bindings: dict[str, Any] = {}
    for arm, value in _benchmark_study_v2_settings().items():
        path = settings_root / f"{arm}.settings.json"
        raw = _study_canonical_json_bytes(value)
        _measurement_write_exclusive(path, raw)
        bindings[arm] = {
            "path": str(path.resolve()), "sha256": _study_sha256_bytes(raw),
            "bytes": len(raw),
            "bash_hook": arm != "host_unmodified",
            "bash_reference_v1": arm == "bash_reference_v1",
        }
    return bindings


def _benchmark_study_v2_install_candidate(
    *, npm_bin: str, candidate: Mapping[str, Any], output_root: Path,
) -> tuple[Path, dict[str, Any]]:
    install_root = output_root / "candidate-install"
    install_root.mkdir(mode=0o700)
    isolated = output_root / "npm-isolation"
    isolated.mkdir(mode=0o700)
    for name in ("home", "cache", "tmp"):
        (isolated / name).mkdir(mode=0o700)
    root_package = next(
        record for record in candidate["packages"]
        if record["name"] == "@ictechgy/context-guard"
    )
    receipt_package = next(
        record for record in candidate["packages"]
        if record["name"] == "@ictechgy/context-guard-receipt"
    )
    npm_executable = executable_argv0(npm_bin)
    runtime_directories = [str(Path(npm_executable).parent)]
    node_executable = shutil.which("node")
    if node_executable is not None:
        runtime_directories.append(str(Path(node_executable).resolve().parent))
    runtime_directories.extend(os.defpath.split(os.pathsep))
    runtime_path = os.pathsep.join(dict.fromkeys(runtime_directories))
    argv = [
        npm_executable, "install", "--offline", "--ignore-scripts",
        "--no-audit", "--fund=false", "--package-lock=false",
        "--prefix", str(install_root.resolve()),
        str(root_package["path"]), str(receipt_package["path"]),
    ]
    env = {
        "PATH": runtime_path, "HOME": str((isolated / "home").resolve()),
        "TMPDIR": str((isolated / "tmp").resolve()),
        "NPM_CONFIG_CACHE": str((isolated / "cache").resolve()),
        "NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_PACKAGE_LOCK": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NPM_CONFIG_REGISTRY": "https://registry.invalid/",
    }
    result = run_bounded_command(
        argv, cwd=output_root, timeout_seconds=180,
        max_output_bytes=MEASUREMENT_CLI_PROBE_OUTPUT_MAX_BYTES, env=env,
    )
    if result.returncode != 0 or result.timed_out or result.output_truncated:
        raise ValueError("v2 candidate offline npm install failed")
    overlay_root = install_root / "node_modules"
    hidden_lock = overlay_root / ".package-lock.json"
    hidden_lock_removed = False
    try:
        hidden_lock_mode = os.lstat(hidden_lock).st_mode
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(hidden_lock_mode):
            raise ValueError("v2 npm hidden lockfile has an unsupported type")
        hidden_lock.unlink()
        hidden_lock_removed = True
    inventory = _benchmark_study_v2_inventory(overlay_root)
    installed_packages = _benchmark_study_v2_verify_installed_packages(
        overlay_root, candidate,
    )
    receipt = {
        "schema_version": "contextguard.bench.candidate-install.v2",
        "install_count": 1,
        "network": "offline",
        "ignore_scripts": True,
        "no_audit": True,
        "fund": False,
        "hidden_lockfile_removed": hidden_lock_removed,
        "candidate_manifest_sha256": candidate["manifest_sha256"],
        "argv_policy": [
            "install", "--offline", "--ignore-scripts", "--no-audit",
            "--fund=false", "--package-lock=false",
        ],
        "inventory": inventory,
        "installed_packages": installed_packages,
    }
    _study_write_private(output_root / "candidate-install-receipt.json", receipt)
    return overlay_root, receipt


def prepare_benchmark_study_v2_executable(
    *, output_root: Path, plan_path: Path, tasks_path: Path, checkers_dir: Path,
    candidate_manifest_path: Path, candidate_checksum_path: Path | None,
    expected_candidate_hash: str, npm_bin: str, claude_bin: str,
    auth_home: Path,
) -> dict[str, Any]:
    output_root = _benchmark_study_v2_output_root(output_root)
    if output_root.exists() and (
        output_root.is_symlink() or not output_root.is_dir() or any(output_root.iterdir())
    ):
        raise ValueError("v2 prepare output root must be new or empty")
    # Candidate validation is deliberately first and performs no candidate import.
    candidate = verify_benchmark_study_v2_candidate(
        candidate_manifest_path, checksum_path=candidate_checksum_path,
        expected_manifest_sha256=expected_candidate_hash,
    )
    plan = load_benchmark_study_v2_plan(plan_path)
    corpus_bytes = _read_bytes_no_follow(tasks_path, max_bytes=MAX_FIXTURE_FILE_BYTES)
    checker_binding = benchmark_study_v2_checker_binding(checkers_dir)
    validate_benchmark_study_v2_bindings(
        plan, corpus_bytes=corpus_bytes, checker_binding=checker_binding,
    )
    tasks = parse_tasks(tasks_path)
    load_task_fixture_trees(tasks, task_file_dir=tasks_path.parent)
    task_definitions = [
        _study_task_manifest(task, tasks_path.parent) for task in tasks
    ]
    task_ids = _benchmark_study_v2_task_ids_from_corpus(corpus_bytes)
    if [task.id for task in tasks] != task_ids:
        raise ValueError("v2 parsed task order differs from the bound corpus")
    cli_binding = _benchmark_study_v2_cli_binding(claude_bin)
    execution_environment = _benchmark_study_v2_execution_environment(cli_binding)
    _benchmark_study_v2_assert_execution_environment(execution_environment)
    _resolved_auth_home, auth_context = _benchmark_study_v2_auth_context(
        claude_bin, execution_environment, auth_home,
    )
    runner_binding = _benchmark_study_v2_runner_binding()
    schedule = generate_benchmark_study_v2_schedule(
        task_ids, repetitions=3, schedule_seed=plan["schedule_seed"],
    )
    slots = generate_benchmark_study_v2_slots(
        task_ids, schedule, candidate_hash=candidate["manifest_sha256"],
        namespace=BENCHMARK_STUDY_V2_NAMESPACE,
    )
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output_root, 0o700)
    settings = _benchmark_study_v2_write_settings(output_root)
    install_root, install_receipt = _benchmark_study_v2_install_candidate(
        npm_bin=npm_bin, candidate=candidate, output_root=output_root,
    )
    manifest = {
        "schema_version": BENCHMARK_STUDY_V2_EXEC_MANIFEST_SCHEMA_VERSION,
        "plan": plan,
        "plan_sha256": _study_sha256_bytes(_study_canonical_json_bytes(plan)),
        "inputs": {
            "plan_path": str(plan_path.resolve()),
            "tasks_path": str(tasks_path.resolve()),
            "tasks_sha256": _study_sha256_bytes(corpus_bytes),
            "task_definitions": task_definitions,
            "checkers_dir": str(checkers_dir.resolve()),
            "checker_binding": checker_binding,
            "cli_binding": cli_binding,
            "execution_environment": execution_environment,
            "auth_context": auth_context,
            "runner_binding": runner_binding,
            "canary_contract": _benchmark_study_v2_canary_contract(),
            "candidate": candidate,
            "candidate_install_root": str(install_root.resolve()),
            "candidate_install_receipt_sha256": _study_sha256_bytes(
                _study_canonical_json_bytes(install_receipt)
            ),
            "candidate_overlay_inventory": install_receipt["inventory"],
            "settings": settings,
            "namespace": BENCHMARK_STUDY_V2_NAMESPACE,
            "task_ids": task_ids,
            "task_ids_sha256": _benchmark_study_v2_task_ids_sha256(task_ids),
        },
        "schedule": schedule,
        "slots": slots,
        "execution": {
            "identities": 216, "initial_calls": 108,
            "retry": "exactly_after_valid_initial_failure_v1",
            "resume": "never_replay_launched_identity_v1",
            "attempt_schema_version": BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION,
            "invalid_decision_schema_version": (
                BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION
            ),
            "candidate_imported": False, "candidate_install_count": 1,
            "overlay_copy": "physical_copy_no_hardlinks_v1",
        },
    }
    _study_write_private(output_root / "study-manifest.json", manifest)
    return manifest


def load_benchmark_study_v2_executable_manifest(output_root: Path, *, revalidate_external: bool) -> tuple[dict[str, Any], str]:
    output_root = _benchmark_study_v2_output_root(output_root)
    manifest_path = output_root / "study-manifest.json"
    if not manifest_path.exists():
        raise ValueError("v2 executable study requires a prepared output root")
    manifest, raw = _benchmark_study_v2_read_canonical(
        manifest_path, owner="v2 executable manifest", maximum=2_000_000,
    )
    if set(manifest) != {"schema_version", "plan", "plan_sha256", "inputs", "schedule", "slots", "execution"} or manifest.get("schema_version") != BENCHMARK_STUDY_V2_EXEC_MANIFEST_SCHEMA_VERSION:
        raise ValueError("v2 executable manifest schema mismatch")
    validate_benchmark_study_v2_plan(manifest["plan"])
    if manifest["plan_sha256"] != _study_sha256_bytes(_study_canonical_json_bytes(manifest["plan"])):
        raise ValueError("v2 executable plan binding mismatch")
    inputs = manifest["inputs"]
    required_inputs = {
        "plan_path", "tasks_path", "tasks_sha256", "task_definitions",
        "checkers_dir", "checker_binding", "cli_binding", "execution_environment",
        "auth_context", "runner_binding", "canary_contract", "candidate",
        "candidate_install_root", "candidate_install_receipt_sha256",
        "candidate_overlay_inventory", "settings", "namespace", "task_ids",
        "task_ids_sha256",
    }
    if set(inputs) != required_inputs:
        raise ValueError("v2 executable input schema mismatch")
    _benchmark_study_v2_validate_cli_binding(inputs["cli_binding"])
    _benchmark_study_v2_validate_execution_environment(
        inputs["execution_environment"]
    )
    _benchmark_study_v2_validate_auth_context(inputs["auth_context"])
    if inputs["runner_binding"] != _benchmark_study_v2_runner_binding():
        raise ValueError("v2 benchmark runner binding drift")
    if inputs["canary_contract"] != _benchmark_study_v2_canary_contract():
        raise ValueError("v2 canary contract binding mismatch")
    if (
        not isinstance(inputs["task_definitions"], list)
        or len(inputs["task_definitions"]) != 12
    ):
        raise ValueError("v2 executable task definition binding mismatch")
    task_ids = _benchmark_study_v2_task_ids(inputs["task_ids"])
    task_definition_ids = [
        item.get("id") if isinstance(item, Mapping) else None
        for item in inputs["task_definitions"]
    ]
    if (
        inputs.get("namespace") != BENCHMARK_STUDY_V2_NAMESPACE
        or inputs.get("tasks_sha256") != manifest["plan"]["corpus_sha256"]
        or not isinstance(inputs.get("checker_binding"), Mapping)
        or inputs["checker_binding"].get("sha256")
        != manifest["plan"]["checker_sha256"]
        or inputs.get("task_ids_sha256") != manifest["plan"]["task_ids_sha256"]
        or inputs.get("task_ids_sha256")
        != _benchmark_study_v2_task_ids_sha256(task_ids)
        or task_definition_ids != task_ids
    ):
        raise ValueError("v2 executable task order or namespace binding mismatch")
    if manifest["execution"] != {
        "identities": 216, "initial_calls": 108,
        "retry": "exactly_after_valid_initial_failure_v1",
        "resume": "never_replay_launched_identity_v1",
        "attempt_schema_version": BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION,
        "invalid_decision_schema_version": (
            BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION
        ),
        "candidate_imported": False, "candidate_install_count": 1,
        "overlay_copy": "physical_copy_no_hardlinks_v1",
    }:
        raise ValueError("v2 executable lifecycle contract drift")
    settings = inputs.get("settings")
    expected_settings = _benchmark_study_v2_settings()
    if not isinstance(settings, Mapping) or set(settings) != set(BENCHMARK_STUDY_V2_ARMS):
        raise ValueError("v2 settings arm binding mismatch")
    for arm in BENCHMARK_STUDY_V2_ARMS:
        binding = settings[arm]
        expected_path = output_root / "inputs" / "settings-v2" / f"{arm}.settings.json"
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {
                "path", "sha256", "bytes", "bash_hook", "bash_reference_v1",
            }
            or binding.get("path") != str(expected_path.resolve())
            or binding.get("bash_hook") is not (arm != "host_unmodified")
            or binding.get("bash_reference_v1") is not (arm == "bash_reference_v1")
        ):
            raise ValueError(f"v2 {arm} settings binding mismatch")
        raw_settings = _read_bytes_no_follow(expected_path, max_bytes=100_000)
        expected_raw = _study_canonical_json_bytes(expected_settings[arm])
        if (
            raw_settings != expected_raw
            or binding.get("sha256") != _study_sha256_bytes(expected_raw)
            or binding.get("bytes") != len(expected_raw)
        ):
            raise ValueError(f"v2 {arm} settings policy drift")
    install_receipt, install_receipt_raw = _benchmark_study_v2_read_canonical(
        output_root / "candidate-install-receipt.json",
        owner="v2 candidate install receipt", maximum=2_000_000,
    )
    if (
        set(install_receipt) != {
            "schema_version", "install_count", "network", "ignore_scripts",
            "no_audit", "fund", "hidden_lockfile_removed",
            "candidate_manifest_sha256", "argv_policy", "inventory",
            "installed_packages",
        }
        or install_receipt.get("schema_version")
        != "contextguard.bench.candidate-install.v2"
        or install_receipt.get("install_count") != 1
        or install_receipt.get("network") != "offline"
        or install_receipt.get("ignore_scripts") is not True
        or install_receipt.get("no_audit") is not True
        or install_receipt.get("fund") is not False
        or not isinstance(install_receipt.get("hidden_lockfile_removed"), bool)
        or install_receipt.get("argv_policy") != [
            "install", "--offline", "--ignore-scripts", "--no-audit",
            "--fund=false", "--package-lock=false",
        ]
        or _study_sha256_bytes(install_receipt_raw)
        != inputs.get("candidate_install_receipt_sha256")
        or install_receipt.get("candidate_manifest_sha256")
        != inputs.get("candidate", {}).get("manifest_sha256")
        or install_receipt.get("inventory")
        != inputs.get("candidate_overlay_inventory")
    ):
        raise ValueError("v2 candidate install receipt binding mismatch")
    expected_schedule = generate_benchmark_study_v2_schedule(
        task_ids, repetitions=3, schedule_seed=manifest["plan"]["schedule_seed"],
    )
    expected_slots = generate_benchmark_study_v2_slots(
        task_ids, expected_schedule,
        candidate_hash=inputs["candidate"]["manifest_sha256"],
        namespace=inputs["namespace"],
    )
    if manifest["schedule"] != expected_schedule or manifest["slots"] != expected_slots:
        raise ValueError("v2 executable schedule or identity drift")
    if revalidate_external:
        _benchmark_study_v2_assert_execution_environment(
            inputs["execution_environment"]
        )
        external_plan = load_benchmark_study_v2_plan(Path(inputs["plan_path"]))
        if external_plan != manifest["plan"]:
            raise ValueError("v2 external study plan binding drift")
        corpus = _read_bytes_no_follow(Path(inputs["tasks_path"]), max_bytes=MAX_FIXTURE_FILE_BYTES)
        if _study_sha256_bytes(corpus) != inputs["tasks_sha256"]:
            raise ValueError("v2 task corpus binding drift")
        checker = benchmark_study_v2_checker_binding(Path(inputs["checkers_dir"]))
        if checker != inputs["checker_binding"]:
            raise ValueError("v2 checker inventory binding drift")
        validate_benchmark_study_v2_bindings(
            manifest["plan"], corpus_bytes=corpus, checker_binding=checker,
        )
        tasks = parse_tasks(Path(inputs["tasks_path"]))
        load_task_fixture_trees(
            tasks, task_file_dir=Path(inputs["tasks_path"]).parent,
        )
        task_definitions = [
            _study_task_manifest(task, Path(inputs["tasks_path"]).parent)
            for task in tasks
        ]
        if task_definitions != inputs["task_definitions"]:
            raise ValueError("v2 task fixture or checker binding drift")
        if [task.id for task in tasks] != task_ids:
            raise ValueError("v2 external task order binding drift")
        candidate = verify_benchmark_study_v2_candidate(
            Path(inputs["candidate"]["manifest_path"]),
            checksum_path=Path(inputs["candidate"]["checksum_path"]),
            expected_manifest_sha256=inputs["candidate"]["manifest_sha256"],
        )
        if candidate != inputs["candidate"]:
            raise ValueError("v2 candidate binding drift")
        if _benchmark_study_v2_verify_installed_packages(
            Path(inputs["candidate_install_root"]), candidate,
        ) != install_receipt["installed_packages"]:
            raise ValueError("v2 installed candidate package binding drift")
        if _benchmark_study_v2_inventory(Path(inputs["candidate_install_root"])) != inputs["candidate_overlay_inventory"]:
            raise ValueError("v2 installed candidate inventory drift")
        for arm, binding in inputs["settings"].items():
            raw_settings = _read_bytes_no_follow(Path(binding["path"]), max_bytes=100_000)
            if _study_sha256_bytes(raw_settings) != binding["sha256"] or len(raw_settings) != binding["bytes"]:
                raise ValueError(f"v2 {arm} settings drift")
    return manifest, _study_sha256_bytes(raw)


def _benchmark_study_v2_variants(manifest: Mapping[str, Any], output_root: Path) -> dict[str, Variant]:
    output_root = _benchmark_study_v2_output_root(output_root)
    result: dict[str, Variant] = {}
    artifact_root = output_root / "artifacts"
    for arm in BENCHMARK_STUDY_V2_ARMS:
        binding = manifest["inputs"]["settings"][arm]
        settings_path = Path(binding["path"])
        settings_raw = _read_bytes_no_follow(settings_path, max_bytes=100_000)
        settings_payload = json.loads(settings_raw)
        command = BENCHMARK_STUDY_V2_REWRITE_COMMAND + (
            " --bash-reference-v1" if arm == "bash_reference_v1" else ""
        )
        registered = () if arm == "host_unmodified" else (("PreToolUse", command),)
        identity = MeasurementIdentity(
            candidate_hash=manifest["inputs"]["candidate"]["manifest_sha256"],
            repetition=0, arm=arm, attempt=0,
            namespace=manifest["inputs"]["namespace"],
        )
        result[arm] = Variant(
            name=arm,
            measurement=MeasurementVariant(
                settings_file=settings_path,
                setting_sources=("project",), environment_allow=(),
                environment_overrides=tuple(
                    (name, str(manifest["inputs"]["execution_environment"]["values"][name]))
                    for name in sorted(
                        manifest["inputs"]["execution_environment"]["values"]
                    )
                ),
                workspace_mode="isolated",
                session_mode="isolated", session_persistence="disabled",
                hook_events_enabled=True, registered_bindings=registered,
                required_event_classes=(), pair_registered_bindings=registered,
                cli_capabilities=(
                    "--settings", "--setting-sources", "--include-hook-events",
                    "--no-session-persistence", "stream-json",
                ),
                identity=identity, artifact_root=artifact_root,
                settings_payload=settings_payload, settings_source_bytes=settings_raw,
            ),
        )
    return result


def _benchmark_study_v2_canary_variants(
    manifest: Mapping[str, Any], output_root: Path,
) -> dict[str, Variant]:
    analytic = _benchmark_study_v2_variants(manifest, output_root)
    result: dict[str, Variant] = {}
    for arm in BENCHMARK_STUDY_V2_CANARY_ARMS:
        base = analytic[arm].measurement
        assert base is not None
        identity = MeasurementIdentity(
            candidate_hash=manifest["inputs"]["candidate"]["manifest_sha256"],
            repetition=0, arm=arm, attempt=0,
            namespace=f"{manifest['inputs']['namespace']}.canary",
        )
        result[arm] = Variant(
            name=arm,
            measurement=replace(
                base,
                required_event_classes=("PreToolUse",),
                identity=identity,
                artifact_root=output_root / "canary-artifacts",
            ),
        )
    return result


def _benchmark_study_v2_canary_base_event(
    *, arm: str, run_id: str, manifest_sha256: str, state: str,
    **extra: Any,
) -> dict[str, Any]:
    event = {
        "schema_version": BENCHMARK_STUDY_V2_CANARY_EVENT_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "arm": arm, "run_id": run_id, "state": state,
    }
    event.update(extra)
    return event


def _benchmark_study_v2_read_canary_events(
    path: Path, *, manifest_sha256: str,
    variants: Mapping[str, Variant],
) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = _measurement_read_private_file(path, maximum=200_000)
    expected_run_ids = {}
    for arm, variant in variants.items():
        spec = variant.measurement
        assert spec is not None
        expected_run_ids[arm] = spec.identity.run_id(BENCHMARK_STUDY_V2_CANARY_TASK_ID)
    base_keys = {"schema_version", "manifest_sha256", "arm", "run_id", "state"}
    workspace_keys = base_keys | {
        "pre_workspace_inventory_sha256", "pre_overlay_inventory_sha256",
    }
    terminal_keys = base_keys | {
        "passed", "measurement_terminal_status", "checker_status",
        "receipt_sha256", "pre_workspace_inventory_sha256",
        "post_workspace_inventory_sha256", "pre_overlay_inventory_sha256",
        "post_overlay_inventory_sha256", "pretooluse_event_count",
    }
    states: dict[str, list[str]] = collections.defaultdict(list)
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        try:
            row = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_measurement_object_no_duplicates,
                parse_constant=_stream_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("v2 canary event ledger is invalid JSONL") from exc
        if not isinstance(row, dict) or line + b"\n" != _study_canonical_json_bytes(row):
            raise ValueError("v2 canary event ledger must be canonical JSONL")
        arm = row.get("arm")
        state = row.get("state")
        if (
            row.get("schema_version") != BENCHMARK_STUDY_V2_CANARY_EVENT_SCHEMA_VERSION
            or row.get("manifest_sha256") != manifest_sha256
            or arm not in BENCHMARK_STUDY_V2_CANARY_ARMS
            or row.get("run_id") != expected_run_ids.get(str(arm))
            or state not in {"launch_reserved", "workspace_prepared", "launched", "terminal"}
        ):
            raise ValueError("v2 canary event binding mismatch")
        expected_keys = (
            workspace_keys if state == "workspace_prepared"
            else terminal_keys if state == "terminal" else base_keys
        )
        if set(row) != expected_keys:
            raise ValueError("v2 canary event schema mismatch")
        previous = states[str(arm)]
        expected_previous = {
            "launch_reserved": [],
            "workspace_prepared": ["launch_reserved"],
            "launched": ["launch_reserved", "workspace_prepared"],
            "terminal": ["launch_reserved", "workspace_prepared", "launched"],
        }[str(state)]
        if previous != expected_previous:
            raise ValueError("v2 canary event state transition is invalid")
        if state in {"workspace_prepared", "terminal"}:
            hash_fields = (
                ("pre_workspace_inventory_sha256", "pre_overlay_inventory_sha256")
                if state == "workspace_prepared" else (
                    "receipt_sha256", "pre_workspace_inventory_sha256",
                    "post_workspace_inventory_sha256", "pre_overlay_inventory_sha256",
                    "post_overlay_inventory_sha256",
                )
            )
            if any(
                not isinstance(row.get(field), str)
                or SHA256_HEX_PATTERN.fullmatch(str(row[field])) is None
                for field in hash_fields
            ):
                raise ValueError("v2 canary evidence hash is invalid")
        if state == "terminal" and (
            not isinstance(row.get("passed"), bool)
            or row.get("measurement_terminal_status") not in {
                "success", "raw_byte_limit", "raw_line_limit", "raw_line_byte_limit",
                "process_timeout", "process_launch_error", "process_error",
                "terminal_error", "missing_terminal", "invalid_stream",
                "hook_payload_limit", "hook_lifecycle_limit", "invalid_hook_lifecycle",
                "unexpected_hook_event_class", "missing_required_hook_event_class",
                "hook_process_failure",
            }
            or row.get("checker_status") not in {
                "task_success", "valid_task_failure_v1", "success_checker_infra_invalid",
                "not_run",
            }
            or isinstance(row.get("pretooluse_event_count"), bool)
            or not isinstance(row.get("pretooluse_event_count"), int)
            or row["pretooluse_event_count"] < 0
        ):
            raise ValueError("v2 canary terminal evidence is invalid")
        previous.append(str(state))
        rows.append(row)
    return rows


def _benchmark_study_v2_derive_canary_terminal(
    *, manifest: Mapping[str, Any], manifest_sha256: str, output_root: Path,
    arm: str, variant: Variant, task: TaskFixture,
    workspace_event: Mapping[str, Any],
) -> dict[str, Any]:
    spec = variant.measurement
    assert spec is not None
    run_id = spec.identity.run_id(task.id)
    receipt = _verify_existing_measurement_run(
        spec, task.id, run_id, require_index=True,
    )
    context = _measurement_existing_context(spec, run_id)
    receipt_raw = _measurement_read_private_file(context.receipt_path)
    expected_overlay = manifest["inputs"]["candidate_overlay_inventory"]
    expected_pre = _benchmark_study_v2_expected_pre_workspace(
        task,
        install_root=Path(manifest["inputs"]["candidate_install_root"]),
        expected_overlay_inventory=expected_overlay,
    )
    post_workspace = _benchmark_study_v2_inventory(context.workspace)
    post_overlay = _benchmark_study_v2_inventory(
        context.workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME,
    )
    checker = (
        run_task_checker_study(
            task, context.workspace, env={},
            interpreter_binding=manifest["inputs"]["runner_binding"]["python"],
        )
        if receipt["terminal_status"] == "success" else "not_run"
    )
    summary = receipt["hook_summary"]
    counts = {
        row["hook_event"]: row["count"]
        for row in summary["event_class_counts"]
    }
    pretooluse_count = int(counts.get("PreToolUse", 0))
    pre_bound = bool(
        workspace_event.get("pre_workspace_inventory_sha256") == expected_pre["sha256"]
        and workspace_event.get("pre_overlay_inventory_sha256") == expected_overlay["sha256"]
    )
    hooks_valid = bool(
        summary["required_event_classes"] == ["PreToolUse"]
        and pretooluse_count >= 1
        and set(counts) == {"PreToolUse"}
        and all(
            hook["hook_event"] == "PreToolUse"
            and hook["hook_process_outcome"] == "success"
            and hook["hook_process_exit_code"] in (None, 0)
            for hook in receipt["hooks"]
        )
    )
    passed = bool(
        receipt["terminal_status"] == "success"
        and checker == "task_success" and hooks_valid and pre_bound
        and post_overlay == expected_overlay
    )
    return _benchmark_study_v2_canary_base_event(
        arm=arm, run_id=run_id, manifest_sha256=manifest_sha256,
        state="terminal", passed=passed,
        measurement_terminal_status=receipt["terminal_status"],
        checker_status=checker,
        receipt_sha256=_study_sha256_bytes(receipt_raw),
        pre_workspace_inventory_sha256=str(
            workspace_event["pre_workspace_inventory_sha256"]
        ),
        post_workspace_inventory_sha256=post_workspace["sha256"],
        pre_overlay_inventory_sha256=str(
            workspace_event["pre_overlay_inventory_sha256"]
        ),
        post_overlay_inventory_sha256=post_overlay["sha256"],
        pretooluse_event_count=pretooluse_count,
    )


def _benchmark_study_v2_expected_canary_evidence(
    *, manifest: Mapping[str, Any], manifest_sha256: str, output_root: Path,
    rows: Sequence[Mapping[str, Any]], variants: Mapping[str, Variant],
) -> dict[str, Any]:
    task = _benchmark_study_v2_canary_task()
    by_arm: dict[str, list[Mapping[str, Any]]] = {
        arm: [row for row in rows if row["arm"] == arm]
        for arm in BENCHMARK_STUDY_V2_CANARY_ARMS
    }
    records: list[dict[str, Any]] = []
    for arm in BENCHMARK_STUDY_V2_CANARY_ARMS:
        arm_rows = by_arm[arm]
        if [row["state"] for row in arm_rows] != [
            "launch_reserved", "workspace_prepared", "launched", "terminal",
        ]:
            raise ValueError("v2 canary evidence is incomplete")
        recomputed = _benchmark_study_v2_derive_canary_terminal(
            manifest=manifest, manifest_sha256=manifest_sha256,
            output_root=output_root, arm=arm, variant=variants[arm], task=task,
            workspace_event=arm_rows[1],
        )
        if recomputed != dict(arm_rows[-1]) or recomputed["passed"] is not True:
            raise ValueError("v2 canary terminal evidence did not pass")
        spec = variants[arm].measurement
        assert spec is not None
        records.append({
            "arm": arm, "run_id": recomputed["run_id"], "passed": True,
            "settings_sha256": manifest["inputs"]["settings"][arm]["sha256"],
            "settings_binding_set_sha256": _measurement_binding_set_sha256(
                spec.registered_bindings
            ),
            "required_event_classes": ["PreToolUse"],
            "pretooluse_event_count": recomputed["pretooluse_event_count"],
            "receipt_sha256": recomputed["receipt_sha256"],
            "pre_overlay_inventory_sha256": recomputed[
                "pre_overlay_inventory_sha256"
            ],
            "post_overlay_inventory_sha256": recomputed[
                "post_overlay_inventory_sha256"
            ],
        })
    return {
        "schema_version": BENCHMARK_STUDY_V2_CANARY_EVIDENCE_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256,
        "canary_contract_sha256": _study_domain_hash(
            "contextguard.bench.v2.canary-contract.v1",
            manifest["inputs"]["canary_contract"],
        ),
        "cli_binding_sha256": _study_domain_hash(
            "contextguard.bench.v2.cli-binding.v1",
            manifest["inputs"]["cli_binding"],
        ),
        "auth_context_sha256": _study_domain_hash(
            "contextguard.bench.v2.auth-context.v1",
            manifest["inputs"]["auth_context"],
        ),
        "candidate_manifest_sha256": manifest["inputs"]["candidate"][
            "manifest_sha256"
        ],
        "candidate_overlay_sha256": manifest["inputs"][
            "candidate_overlay_inventory"
        ]["sha256"],
        "discarded": True, "excluded_from_analysis": True,
        "provider_calls": 2, "arms": records,
    }


def _benchmark_study_v2_verify_canary_evidence(
    *, manifest: Mapping[str, Any], manifest_sha256: str, output_root: Path,
) -> tuple[dict[str, Any], str]:
    variants = _benchmark_study_v2_canary_variants(manifest, output_root)
    rows = _benchmark_study_v2_read_canary_events(
        output_root / "canary-events.jsonl",
        manifest_sha256=manifest_sha256, variants=variants,
    )
    expected = _benchmark_study_v2_expected_canary_evidence(
        manifest=manifest, manifest_sha256=manifest_sha256,
        output_root=output_root, rows=rows, variants=variants,
    )
    observed, raw = _benchmark_study_v2_read_canonical(
        output_root / "canary-evidence.json",
        owner="v2 canary evidence", maximum=200_000,
    )
    if observed != expected:
        raise ValueError("v2 canary evidence binding mismatch")
    return observed, _study_sha256_bytes(raw)


def _benchmark_study_v2_run_canary_arm(
    *, manifest: Mapping[str, Any], manifest_sha256: str, output_root: Path,
    arm: str, variant: Variant, task: TaskFixture, claude_bin: str,
    cli_stat_guard: Mapping[str, Any],
    runtime_stat_guards: Mapping[str, Mapping[str, int | str]],
    auth_home: Path,
) -> dict[str, Any]:
    spec = variant.measurement
    assert spec is not None
    run_id = spec.identity.run_id(task.id)
    ledger_path = output_root / "canary-events.jsonl"
    _benchmark_study_v2_assert_cli_executable_bytes(
        manifest["inputs"]["cli_binding"], cli_stat_guard,
    )
    _benchmark_study_v2_assert_runtime_stat_guards(
        manifest["inputs"]["execution_environment"], runtime_stat_guards,
    )
    resolved_auth_home = _benchmark_study_v2_assert_auth_context(
        claude_bin, manifest["inputs"]["execution_environment"],
        manifest["inputs"]["auth_context"], auth_home,
    )
    append_study_attempt_event(
        ledger_path,
        _benchmark_study_v2_canary_base_event(
            arm=arm, run_id=run_id, manifest_sha256=manifest_sha256,
            state="launch_reserved",
        ),
    )
    pre: dict[str, Any] = {}

    def prepared(workspace: Path) -> None:
        overlay = workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME
        overlay_inventory = _benchmark_study_v2_verify_physical_copy(
            Path(manifest["inputs"]["candidate_install_root"]), overlay,
            expected=manifest["inputs"]["candidate_overlay_inventory"],
        )
        workspace_inventory = _benchmark_study_v2_inventory(workspace)
        pre.update({"overlay": overlay_inventory, "workspace": workspace_inventory})
        append_study_attempt_event(
            ledger_path,
            _benchmark_study_v2_canary_base_event(
                arm=arm, run_id=run_id, manifest_sha256=manifest_sha256,
                state="workspace_prepared",
                pre_workspace_inventory_sha256=workspace_inventory["sha256"],
                pre_overlay_inventory_sha256=overlay_inventory["sha256"],
            ),
        )

    def launched() -> None:
        append_study_attempt_event(
            ledger_path,
            _benchmark_study_v2_canary_base_event(
                arm=arm, run_id=run_id, manifest_sha256=manifest_sha256,
                state="launched",
            ),
        )

    root_fd = _ensure_directory_no_symlink(spec.artifact_root, create=True)
    try:
        os.fchmod(root_fd, 0o700)
        if fcntl is not None:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
        _run_measurement_fixture_locked(
            task, variant, claude_bin, Path(manifest_sha256),
            locked_root_fd=root_fd, on_process_started=launched,
            measurement_study=True,
            workspace_overlay=Path(manifest["inputs"]["candidate_install_root"]),
            on_workspace_prepared=prepared,
            checker_interpreter_binding=manifest["inputs"]["runner_binding"][
                "python"
            ],
            existing_login_home=resolved_auth_home,
        )
    finally:
        os.close(root_fd)
    if set(pre) != {"overlay", "workspace"}:
        raise ValueError("v2 canary workspace was not prepared")
    workspace_event = _benchmark_study_v2_canary_base_event(
        arm=arm, run_id=run_id, manifest_sha256=manifest_sha256,
        state="workspace_prepared",
        pre_workspace_inventory_sha256=pre["workspace"]["sha256"],
        pre_overlay_inventory_sha256=pre["overlay"]["sha256"],
    )
    terminal = _benchmark_study_v2_derive_canary_terminal(
        manifest=manifest, manifest_sha256=manifest_sha256,
        output_root=output_root, arm=arm, variant=variant, task=task,
        workspace_event=workspace_event,
    )
    append_study_attempt_event(ledger_path, terminal)
    if terminal["passed"] is not True:
        raise ValueError(f"v2 {arm} host PreToolUse canary failed")
    return terminal


def execute_benchmark_study_v2_canary(
    *, output_root: Path, claude_bin: str, auth_home: Path,
) -> dict[str, Any]:
    with _benchmark_study_v2_action_lock(output_root):
        return _execute_benchmark_study_v2_canary_unlocked(
            output_root=output_root, claude_bin=claude_bin,
            auth_home=auth_home,
        )


def _execute_benchmark_study_v2_canary_unlocked(
    *, output_root: Path, claude_bin: str, auth_home: Path,
) -> dict[str, Any]:
    output_root = _benchmark_study_v2_output_root(output_root)
    manifest, manifest_sha256 = load_benchmark_study_v2_executable_manifest(
        output_root, revalidate_external=True,
    )
    attempts_path = output_root / "attempts.jsonl"
    if attempts_path.exists() and attempts_path.stat().st_size:
        raise ValueError("v2 canary must finish before analytic attempts")
    cli_stat_guard = _benchmark_study_v2_assert_cli_binding(
        claude_bin, manifest["inputs"]["cli_binding"],
    )
    runtime_stat_guards = _benchmark_study_v2_assert_execution_environment(
        manifest["inputs"]["execution_environment"]
    )
    bound_claude_bin = str(cli_stat_guard["executable"])
    resolved_auth_home = _benchmark_study_v2_assert_auth_context(
        bound_claude_bin, manifest["inputs"]["execution_environment"],
        manifest["inputs"]["auth_context"], auth_home,
    )
    variants = _benchmark_study_v2_canary_variants(manifest, output_root)
    task = _benchmark_study_v2_canary_task()
    ledger_path = output_root / "canary-events.jsonl"
    launched_now = 0
    for arm in BENCHMARK_STUDY_V2_CANARY_ARMS:
        rows = _benchmark_study_v2_read_canary_events(
            ledger_path, manifest_sha256=manifest_sha256, variants=variants,
        )
        arm_rows = [row for row in rows if row["arm"] == arm]
        if arm_rows and arm_rows[-1]["state"] == "terminal":
            if arm_rows[-1]["passed"] is not True:
                raise ValueError(f"v2 {arm} canary terminal did not pass")
            continue
        if arm_rows:
            if arm_rows[-1]["state"] != "launched":
                raise ValueError("v2 canary reserved identity cannot be replayed")
            try:
                recovered = _benchmark_study_v2_derive_canary_terminal(
                    manifest=manifest, manifest_sha256=manifest_sha256,
                    output_root=output_root, arm=arm, variant=variants[arm],
                    task=task, workspace_event=arm_rows[1],
                )
            except (OSError, SystemExit, TypeError, ValueError) as exc:
                raise ValueError("v2 launched canary cannot be safely recovered") from exc
            append_study_attempt_event(ledger_path, recovered)
            if recovered["passed"] is not True:
                raise ValueError(f"v2 {arm} recovered canary did not pass")
            continue
        _benchmark_study_v2_run_canary_arm(
            manifest=manifest, manifest_sha256=manifest_sha256,
            output_root=output_root, arm=arm, variant=variants[arm], task=task,
            claude_bin=bound_claude_bin, cli_stat_guard=cli_stat_guard,
            runtime_stat_guards=runtime_stat_guards,
            auth_home=resolved_auth_home,
        )
        launched_now += 1
    rows = _benchmark_study_v2_read_canary_events(
        ledger_path, manifest_sha256=manifest_sha256, variants=variants,
    )
    expected = _benchmark_study_v2_expected_canary_evidence(
        manifest=manifest, manifest_sha256=manifest_sha256,
        output_root=output_root, rows=rows, variants=variants,
    )
    evidence_path = output_root / "canary-evidence.json"
    if evidence_path.exists():
        observed, _raw = _benchmark_study_v2_read_canonical(
            evidence_path, owner="v2 canary evidence", maximum=200_000,
        )
        if observed != expected:
            raise ValueError("v2 canary evidence binding mismatch")
    else:
        _study_write_private(evidence_path, expected)
    _observed, evidence_sha256 = _benchmark_study_v2_verify_canary_evidence(
        manifest=manifest, manifest_sha256=manifest_sha256,
        output_root=output_root,
    )
    return {
        "provider_process_calls": launched_now,
        "discarded_provider_calls": 2,
        "canary_evidence_sha256": evidence_sha256,
    }


def _benchmark_study_v2_revalidate_terminal_evidence(
    *, manifest: Mapping[str, Any], output_root: Path,
    rows: Sequence[Mapping[str, Any]], tasks_by_id: Mapping[str, TaskFixture],
    variants: Mapping[str, Variant],
) -> None:
    slots = {slot["run_id"]: slot for slot in manifest["slots"]}
    install_root = Path(manifest["inputs"]["candidate_install_root"])
    expected_overlay = manifest["inputs"]["candidate_overlay_inventory"]
    expected_pre_by_task: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["state"] != "terminal" or row["terminal_status"] == "recovered_process_status_unknown":
            continue
        slot = slots[row["run_id"]]
        task_id = str(slot["task_id"])
        if task_id not in expected_pre_by_task:
            expected_pre_by_task[task_id] = _benchmark_study_v2_expected_pre_workspace(
                tasks_by_id[task_id], install_root=install_root,
                expected_overlay_inventory=expected_overlay,
            )
        if (
            row["pre_workspace_inventory_sha256"]
            != expected_pre_by_task[task_id]["sha256"]
        ):
            raise ValueError("v2 pre-launch workspace inventory drift")
        study_variant = _study_variant_for_slot(variants[slot["arm"]], slot)
        spec = study_variant.measurement
        assert spec is not None
        receipt = _verify_existing_measurement_run(
            spec, task_id, str(slot["run_id"]), require_index=True,
        )
        context = _measurement_existing_context(spec, str(slot["run_id"]))
        receipt_raw = _measurement_read_private_file(context.receipt_path)
        raw = _measurement_read_private_raw(context.raw_path)
        if _study_sha256_bytes(receipt_raw) != row["receipt_sha256"]:
            raise ValueError("v2 attempt receipt hash differs from immutable receipt")
        if receipt["terminal_status"] != row["provider_terminal_status"]:
            raise ValueError("v2 attempt provider terminal differs from immutable receipt")
        if receipt["terminal_status"] == "success":
            usage = parse_measurement_terminal_usage(raw)
            expected_buckets = {
                key: usage[key] for key in MEASUREMENT_STUDY_USAGE_KEYS
            }
            checker = run_task_checker_study(
                tasks_by_id[task_id], context.workspace, env={},
                interpreter_binding=manifest["inputs"]["runner_binding"][
                    "python"
                ],
            )
        else:
            expected_buckets = {key: 0 for key in MEASUREMENT_STUDY_USAGE_KEYS}
            checker = "not_run"
        if row["token_buckets"] != expected_buckets or row["primary_tokens"] != sum(expected_buckets.values()):
            raise ValueError("v2 attempt tokens differ from provider terminal usage")
        if row["checker_status"] != checker:
            raise ValueError("v2 attempt checker status differs from the bound checker")
        derived = (
            "success" if receipt["terminal_status"] == "success" and checker == "task_success"
            else "valid_task_failure_v1"
            if receipt["terminal_status"] == "success" and checker == "valid_task_failure_v1"
            else "study_infra_invalid"
        )
        if (
            row["post_overlay_inventory_sha256"]
            != row["pre_overlay_inventory_sha256"]
        ):
            derived = "study_infra_invalid"
        if row["terminal_status"] != derived or row["success"] is not (derived == "success"):
            raise ValueError("v2 attempt outcome was not derived from provider plus checker")
        workspace_inventory = _benchmark_study_v2_inventory(context.workspace)
        overlay_inventory = _benchmark_study_v2_inventory(
            context.workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME,
        )
        overlay_drifted = (
            overlay_inventory != manifest["inputs"]["candidate_overlay_inventory"]
        )
        if (
            workspace_inventory["sha256"] != row["post_workspace_inventory_sha256"]
            or overlay_inventory["sha256"] != row["post_overlay_inventory_sha256"]
            or (
                overlay_drifted
                and row["terminal_status"] != "study_infra_invalid"
            )
        ):
            raise ValueError("v2 terminal workspace or overlay inventory drift")


def _benchmark_study_v2_read_attempts(path: Path, *, manifest: Mapping[str, Any], manifest_sha256: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    raw = _measurement_read_private_file(path, maximum=4_000_000)
    slots = {slot["run_id"]: slot for slot in manifest["slots"]}
    rows: list[dict[str, Any]] = []
    states: dict[str, list[str]] = collections.defaultdict(list)
    base_keys = {
        "schema_version", "manifest_sha256", "run_id", "task_id",
        "repetition", "arm", "attempt", "state",
    }
    terminal_keys = base_keys | {
        "terminal_status", "provider_terminal_status", "checker_status",
        "success", "token_buckets", "primary_tokens", "correction",
        "retrieval", "shifted_cost", "pre_workspace_inventory_sha256",
        "post_workspace_inventory_sha256", "pre_overlay_inventory_sha256",
        "post_overlay_inventory_sha256", "receipt_sha256",
    }
    blocked_keys = base_keys | {"reason"}
    for line in raw.splitlines():
        try:
            row = json.loads(line.decode("utf-8"), object_pairs_hook=_measurement_object_no_duplicates)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("v2 attempt index is invalid JSONL") from exc
        if not isinstance(row, dict) or line + b"\n" != _study_canonical_json_bytes(row):
            raise ValueError("v2 attempt index must be canonical JSONL")
        slot = slots.get(row.get("run_id"))
        if row.get("schema_version") != BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION or row.get("manifest_sha256") != manifest_sha256 or slot is None:
            raise ValueError("v2 attempt index binding mismatch")
        if any(row.get(key) != slot.get(key) for key in ("task_id", "repetition", "arm", "attempt")):
            raise ValueError("v2 attempt identity mismatch")
        state = row.get("state")
        if state not in {
            "launch_reserved", "launched", "terminal", "not_needed",
            "blocked_study_invalid",
        }:
            raise ValueError("v2 attempt state is invalid")
        expected_keys = (
            terminal_keys if state == "terminal"
            else blocked_keys if state == "blocked_study_invalid"
            else base_keys
        )
        if set(row) != expected_keys:
            raise ValueError("v2 attempt state has an inexact key schema")
        previous = states[row["run_id"]]
        if (
            (state == "launch_reserved" and previous)
            or (state == "launched" and previous != ["launch_reserved"])
            or (state == "terminal" and previous not in (["launch_reserved"], ["launch_reserved", "launched"]))
            or (state in {"not_needed", "blocked_study_invalid"} and previous)
        ):
            raise ValueError("v2 attempt state transition is invalid")
        if state in {"not_needed", "blocked_study_invalid"} and row["attempt"] != 1:
            raise ValueError("v2 non-launched final state is only valid for a retry")
        if state == "blocked_study_invalid" and row["reason"] != "initial_study_invalid":
            raise ValueError("v2 blocked retry reason is invalid")
        previous.append(state)
        if state == "terminal":
            status = row["terminal_status"]
            if status not in {
                "success", "valid_task_failure_v1", "study_infra_invalid",
            } or not isinstance(row["success"], bool) or row["success"] is not (status == "success"):
                raise ValueError("v2 attempt success/classification binding is invalid")
            buckets = row["token_buckets"]
            if not isinstance(buckets, dict) or set(buckets) != set(MEASUREMENT_STUDY_USAGE_KEYS):
                raise ValueError("v2 attempt token bucket schema is invalid")
            total = 0
            for key in MEASUREMENT_STUDY_USAGE_KEYS:
                value = buckets[key]
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_USAGE_TOKEN_COUNT:
                    raise ValueError("v2 attempt token bucket is invalid")
                total += value
            if total > MAX_USAGE_TOKEN_COUNT or row["primary_tokens"] != total:
                raise ValueError("v2 attempt primary token sum is invalid")
            if any(row[field] is not None for field in ("correction", "retrieval", "shifted_cost")):
                raise ValueError("v2 absent observer must remain null")
            hash_fields = (
                "pre_workspace_inventory_sha256", "post_workspace_inventory_sha256",
                "pre_overlay_inventory_sha256", "post_overlay_inventory_sha256",
                "receipt_sha256",
            )
            if any(
                not isinstance(row[field], str)
                or SHA256_HEX_PATTERN.fullmatch(row[field]) is None
                for field in hash_fields
            ):
                raise ValueError("v2 terminal evidence hash is invalid")
            expected_overlay_sha256 = manifest["inputs"][
                "candidate_overlay_inventory"
            ]["sha256"]
            if (
                row["pre_overlay_inventory_sha256"] != expected_overlay_sha256
                or (
                    row["post_overlay_inventory_sha256"]
                    != row["pre_overlay_inventory_sha256"]
                    and status != "study_infra_invalid"
                )
            ):
                raise ValueError("v2 terminal overlay binding is invalid")
            if status == "success" and not (
                row["provider_terminal_status"] == "success"
                and row["checker_status"] == "task_success"
            ):
                raise ValueError("v2 successful outcome lacks provider/checker evidence")
            if status == "valid_task_failure_v1" and not (
                row["provider_terminal_status"] == "success"
                and row["checker_status"] == "valid_task_failure_v1"
            ):
                raise ValueError("v2 valid failure lacks provider/checker evidence")
        rows.append(row)
    terminal_by_unit = {
        (row["task_id"], row["repetition"], row["arm"]): row
        for row in rows
        if row["attempt"] == 0 and row["state"] == "terminal"
    }
    for row in rows:
        if row["attempt"] != 1:
            continue
        initial = terminal_by_unit.get((row["task_id"], row["repetition"], row["arm"]))
        if row["state"] == "not_needed" and (
            initial is None or initial["terminal_status"] != "success"
        ):
            raise ValueError("v2 not-needed retry lacks a successful initial")
        if row["state"] == "blocked_study_invalid" and (
            initial is None
            or initial["terminal_status"] != "study_infra_invalid"
        ):
            raise ValueError("v2 blocked retry lacks an invalid initial")
        if row["state"] in {"launch_reserved", "launched", "terminal"} and (
            initial is None or initial["terminal_status"] != "valid_task_failure_v1"
        ):
            raise ValueError("v2 launched retry lacks a valid failed initial")
    return rows


def _benchmark_study_v2_event(slot: Mapping[str, Any], manifest_sha256: str, state: str, **extra: Any) -> dict[str, Any]:
    event = {
        "schema_version": BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION,
        "manifest_sha256": manifest_sha256, "run_id": slot["run_id"],
        "task_id": slot["task_id"], "repetition": slot["repetition"],
        "arm": slot["arm"], "attempt": slot["attempt"], "state": state,
    }
    event.update(extra)
    return event


def _benchmark_study_v2_run_slot(
    *, slot: Mapping[str, Any], task: TaskFixture, variant: Variant,
    claude_bin: str, attempts_path: Path, manifest_sha256: str,
    install_root: Path, expected_overlay_inventory: Mapping[str, Any],
    cli_binding: Mapping[str, Any],
    cli_stat_guard: Mapping[str, Any],
    execution_environment: Mapping[str, Any],
    runtime_stat_guards: Mapping[str, Mapping[str, int | str]],
    checker_interpreter_binding: Mapping[str, Any],
    auth_context: Mapping[str, Any],
    auth_home: Path,
) -> str:
    study_variant = _study_variant_for_slot(variant, slot)
    spec = study_variant.measurement
    assert spec is not None
    pre: dict[str, Any] = {}

    def prepared(workspace: Path) -> None:
        overlay = workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME
        pre["overlay"] = _benchmark_study_v2_verify_physical_copy(
            install_root, overlay, expected=expected_overlay_inventory,
        )
        pre["workspace"] = _benchmark_study_v2_inventory(workspace)

    def launched() -> None:
        append_study_attempt_event(
            attempts_path,
            _benchmark_study_v2_event(slot, manifest_sha256, "launched"),
        )

    # Durable reservation precedes Popen. Resume treats even a reservation-only
    # identity as consumed/unknown, so a provider that started while launched
    # accounting failed can never be invoked twice.
    _benchmark_study_v2_assert_cli_executable_bytes(cli_binding, cli_stat_guard)
    _benchmark_study_v2_assert_runtime_stat_guards(
        execution_environment, runtime_stat_guards,
    )
    resolved_auth_home = _benchmark_study_v2_assert_auth_context(
        claude_bin, execution_environment, auth_context, auth_home,
    )
    append_study_attempt_event(
        attempts_path,
        _benchmark_study_v2_event(slot, manifest_sha256, "launch_reserved"),
    )
    root_fd = _ensure_directory_no_symlink(spec.artifact_root, create=True)
    try:
        os.fchmod(root_fd, 0o700)
        if fcntl is not None:
            fcntl.flock(root_fd, fcntl.LOCK_EX)
        result = _run_measurement_fixture_locked(
            task, study_variant, claude_bin, Path(manifest_sha256),
            locked_root_fd=root_fd, on_process_started=launched,
            measurement_study=True, workspace_overlay=install_root,
            on_workspace_prepared=prepared,
            checker_interpreter_binding=checker_interpreter_binding,
            existing_login_home=resolved_auth_home,
        )
    finally:
        os.close(root_fd)
    context = _measurement_existing_context(spec, str(slot["run_id"]))
    post_workspace = _benchmark_study_v2_inventory(context.workspace)
    post_overlay = _benchmark_study_v2_inventory(
        context.workspace / BENCHMARK_STUDY_V2_OVERLAY_NAME,
    )
    if _benchmark_study_v2_inventory(install_root) != dict(expected_overlay_inventory):
        raise ValueError("v2 staged candidate changed during an attempt")
    receipt_raw = _measurement_read_private_file(context.receipt_path)
    receipt = _measurement_parse_canonical_json_bytes(receipt_raw, owner="v2 measurement receipt")
    provider_terminal = str(receipt["terminal_status"])
    checker_status = result.notes if provider_terminal == "success" else "not_run"
    if provider_terminal == "success" and checker_status == "task_success":
        classification = "success"
    elif provider_terminal == "success" and checker_status == "valid_task_failure_v1":
        classification = "valid_task_failure_v1"
    else:
        classification = "study_infra_invalid"
    if post_overlay != pre.get("overlay"):
        classification = "study_infra_invalid"
    token_buckets = {
        "input_tokens": result.tokens["input_tokens"],
        "cache_creation_input_tokens": result.tokens["cache_creation"],
        "cache_read_input_tokens": result.tokens["cache_read"],
        "output_tokens": result.tokens["output_tokens"],
    }
    append_study_attempt_event(
        attempts_path,
        _benchmark_study_v2_event(
            slot, manifest_sha256, "terminal",
            terminal_status=classification,
            provider_terminal_status=provider_terminal,
            checker_status=checker_status,
            success=classification == "success",
            token_buckets=token_buckets,
            primary_tokens=sum(token_buckets.values()),
            correction=None, retrieval=None, shifted_cost=None,
            pre_workspace_inventory_sha256=pre["workspace"]["sha256"],
            post_workspace_inventory_sha256=post_workspace["sha256"],
            pre_overlay_inventory_sha256=pre["overlay"]["sha256"],
            post_overlay_inventory_sha256=post_overlay["sha256"],
            receipt_sha256=_study_sha256_bytes(receipt_raw),
        ),
    )
    return classification


def execute_benchmark_study_v2(
    *, output_root: Path, claude_bin: str, resume: bool, auth_home: Path,
) -> dict[str, int]:
    with _benchmark_study_v2_action_lock(output_root):
        return _execute_benchmark_study_v2_unlocked(
            output_root=output_root, claude_bin=claude_bin, resume=resume,
            auth_home=auth_home,
        )


def _execute_benchmark_study_v2_unlocked(
    *, output_root: Path, claude_bin: str, resume: bool, auth_home: Path,
) -> dict[str, int]:
    output_root = _benchmark_study_v2_output_root(output_root)
    # Revalidate every inert candidate byte and installed overlay before a provider launch.
    manifest, manifest_sha256 = load_benchmark_study_v2_executable_manifest(
        output_root, revalidate_external=True,
    )
    cli_stat_guard = _benchmark_study_v2_assert_cli_binding(
        claude_bin, manifest["inputs"]["cli_binding"],
    )
    runtime_stat_guards = _benchmark_study_v2_assert_execution_environment(
        manifest["inputs"]["execution_environment"]
    )
    bound_claude_bin = str(cli_stat_guard["executable"])
    resolved_auth_home = _benchmark_study_v2_assert_auth_context(
        bound_claude_bin, manifest["inputs"]["execution_environment"],
        manifest["inputs"]["auth_context"], auth_home,
    )
    attempts_path = output_root / "attempts.jsonl"
    if not resume and attempts_path.exists() and attempts_path.stat().st_size:
        raise ValueError("v2 run requires an absent or empty attempt index")
    if resume and not attempts_path.exists():
        raise ValueError("v2 resume requires an existing attempt index")
    _canary_evidence, _canary_evidence_sha256 = (
        _benchmark_study_v2_verify_canary_evidence(
            manifest=manifest, manifest_sha256=manifest_sha256,
            output_root=output_root,
        )
    )
    tasks = parse_tasks(Path(manifest["inputs"]["tasks_path"]))
    load_task_fixture_trees(tasks, task_file_dir=Path(manifest["inputs"]["tasks_path"]).parent)
    tasks_by_id = {task.id: task for task in tasks}
    variants = _benchmark_study_v2_variants(manifest, output_root)
    rows = _benchmark_study_v2_read_attempts(
        attempts_path, manifest=manifest, manifest_sha256=manifest_sha256,
    )
    _benchmark_study_v2_revalidate_terminal_evidence(
        manifest=manifest, output_root=output_root, rows=rows,
        tasks_by_id=tasks_by_id, variants=variants,
    )
    launched = {
        row["run_id"] for row in rows
        if row["state"] in {"launch_reserved", "launched", "terminal"}
    }
    accounted = {row["run_id"] for row in rows}
    terminal = {row["run_id"]: row for row in rows if row["state"] == "terminal"}
    ambiguous_run_ids = sorted(launched - set(terminal))
    if ambiguous_run_ids:
        raise ValueError(
            "v2 ambiguous provider process state permanently blocks this study root"
        )
    retry_by_unit = {
        (slot["task_id"], slot["repetition"], slot["arm"]): slot
        for slot in manifest["slots"] if slot["attempt"] == 1
    }
    install_root = Path(manifest["inputs"]["candidate_install_root"])
    calls_before = len(launched)
    for initial in (slot for slot in manifest["slots"] if slot["attempt"] == 0):
        if initial["run_id"] not in launched:
            _benchmark_study_v2_run_slot(
                slot=initial, task=tasks_by_id[initial["task_id"]],
                variant=variants[initial["arm"]], claude_bin=bound_claude_bin,
                attempts_path=attempts_path, manifest_sha256=manifest_sha256,
                install_root=install_root,
                expected_overlay_inventory=manifest["inputs"]["candidate_overlay_inventory"],
                cli_binding=manifest["inputs"]["cli_binding"],
                cli_stat_guard=cli_stat_guard,
                execution_environment=manifest["inputs"]["execution_environment"],
                runtime_stat_guards=runtime_stat_guards,
                checker_interpreter_binding=manifest["inputs"]["runner_binding"][
                    "python"
                ],
                auth_context=manifest["inputs"]["auth_context"],
                auth_home=resolved_auth_home,
            )
            launched.add(initial["run_id"])
            terminal = {
                row["run_id"]: row for row in _benchmark_study_v2_read_attempts(
                    attempts_path, manifest=manifest, manifest_sha256=manifest_sha256,
                ) if row["state"] == "terminal"
            }
        initial_row = terminal.get(initial["run_id"])
        if initial_row is None:
            continue
        retry = retry_by_unit[(initial["task_id"], initial["repetition"], initial["arm"])]
        if initial_row.get("terminal_status") != "valid_task_failure_v1":
            state = (
                "not_needed"
                if initial_row.get("terminal_status") == "success"
                else "blocked_study_invalid"
            )
            if retry["run_id"] not in accounted:
                extra = {"reason": "initial_study_invalid"} if state == "blocked_study_invalid" else {}
                append_study_attempt_event(
                    attempts_path,
                    _benchmark_study_v2_event(
                        retry, manifest_sha256, state, **extra,
                    ),
                )
                accounted.add(retry["run_id"])
            if state == "blocked_study_invalid":
                raise ValueError(
                    "v2 terminal infrastructure-invalid evidence permanently "
                    "blocks later provider launches"
                )
            continue
        if retry["run_id"] in accounted:
            continue
        # A failed retry is retained, but it never stops later scheduled blocks.
        _benchmark_study_v2_run_slot(
            slot=retry, task=tasks_by_id[retry["task_id"]],
            variant=variants[retry["arm"]], claude_bin=bound_claude_bin,
            attempts_path=attempts_path, manifest_sha256=manifest_sha256,
            install_root=install_root,
            expected_overlay_inventory=manifest["inputs"]["candidate_overlay_inventory"],
            cli_binding=manifest["inputs"]["cli_binding"],
            cli_stat_guard=cli_stat_guard,
            execution_environment=manifest["inputs"]["execution_environment"],
            runtime_stat_guards=runtime_stat_guards,
            checker_interpreter_binding=manifest["inputs"]["runner_binding"][
                "python"
            ],
            auth_context=manifest["inputs"]["auth_context"],
            auth_home=resolved_auth_home,
        )
        launched.add(retry["run_id"])
        accounted.add(retry["run_id"])
        terminal = {
            row["run_id"]: row for row in _benchmark_study_v2_read_attempts(
                attempts_path, manifest=manifest, manifest_sha256=manifest_sha256,
            ) if row["state"] == "terminal"
        }
    final_rows = _benchmark_study_v2_read_attempts(
        attempts_path, manifest=manifest, manifest_sha256=manifest_sha256,
    )
    final_states = {row["run_id"]: row["state"] for row in final_rows}
    return {
        "provider_process_calls": len(launched) - calls_before,
        "launched_identities": len(launched),
        "accounted_identities": len(final_states),
    }


def analyze_benchmark_study_v2_executable(
    *, output_root: Path, claude_bin: str,
) -> dict[str, Any]:
    with _benchmark_study_v2_action_lock(output_root):
        return _analyze_benchmark_study_v2_executable_unlocked(
            output_root=output_root, claude_bin=claude_bin,
        )


def _benchmark_study_v2_ledger_binding(
    path: Path, *, maximum: int,
) -> dict[str, Any]:
    if not path.exists():
        return {"bytes": 0, "record_count": 0, "sha256": None}
    raw = _measurement_read_private_file(path, maximum=maximum)
    return {
        "bytes": len(raw), "record_count": len(raw.splitlines()),
        "sha256": _study_sha256_bytes(raw),
    }


def _benchmark_study_v2_invalid_canary_decision(
    *, output_root: Path, manifest: Mapping[str, Any],
    manifest_sha256: str, rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    final_by_arm = {str(row["arm"]): row for row in rows}
    ambiguous = [
        final_by_arm[arm] for arm in BENCHMARK_STUDY_V2_CANARY_ARMS
        if arm in final_by_arm and final_by_arm[arm]["state"] != "terminal"
    ]
    failed = [
        final_by_arm[arm] for arm in BENCHMARK_STUDY_V2_CANARY_ARMS
        if arm in final_by_arm
        and final_by_arm[arm]["state"] == "terminal"
        and final_by_arm[arm]["passed"] is not True
    ]
    if not ambiguous and not failed:
        return None
    return {
        "schema_version": BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION,
        "study_version": "v2", "decision": "P1-X",
        "stop_reason": (
            "ambiguous_canary_process_state" if ambiguous
            else "failed_canary_terminal_evidence"
        ),
        "manifest_sha256": manifest_sha256,
        "attempt_schema_version": BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION,
        "consumed_identity_count": len(final_by_arm),
        "accounted_identity_count": sum(
            row["state"] == "terminal" for row in final_by_arm.values()
        ),
        "ambiguous_identities": [{
            "arm": row["arm"], "run_id": row["run_id"],
            "state": row["state"],
        } for row in ambiguous],
        "failed_canary_identities": [{
            "arm": row["arm"], "run_id": row["run_id"],
            "state": row["state"],
        } for row in failed],
        "ledgers": {
            "attempts": _benchmark_study_v2_ledger_binding(
                output_root / "attempts.jsonl", maximum=4_000_000,
            ),
            "canary_events": _benchmark_study_v2_ledger_binding(
                output_root / "canary-events.jsonl", maximum=200_000,
            ),
        },
        "canary_evidence_sha256": None,
        "descriptive_only": True, "claim_allowed": False, "claim": None,
    }


def _benchmark_study_v2_invalid_analytic_decision(
    *, output_root: Path, manifest: Mapping[str, Any],
    manifest_sha256: str, rows: Sequence[Mapping[str, Any]],
    canary_evidence_sha256: str,
) -> dict[str, Any] | None:
    final_by_run = {str(row["run_id"]): row for row in rows}
    ambiguous = [
        final_by_run[str(slot["run_id"])]
        for slot in manifest["slots"]
        if str(slot["run_id"]) in final_by_run
        and final_by_run[str(slot["run_id"])]["state"]
        in {"launch_reserved", "launched"}
    ]
    failed = [
        row for row in final_by_run.values()
        if row["state"] == "terminal"
        and row["terminal_status"] == "study_infra_invalid"
    ]
    if not ambiguous and not failed:
        return None
    attempts_path = output_root / "attempts.jsonl"
    return {
        "schema_version": BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION,
        "study_version": "v2", "decision": "P1-X",
        "stop_reason": (
            "ambiguous_analytic_process_state" if ambiguous
            else "terminal_analytic_infrastructure_invalid"
        ),
        "manifest_sha256": manifest_sha256,
        "attempt_schema_version": BENCHMARK_STUDY_V2_ATTEMPT_SCHEMA_VERSION,
        "consumed_identity_count": sum(
            row["state"] in {"launch_reserved", "launched", "terminal"}
            for row in final_by_run.values()
        ),
        "accounted_identity_count": len(final_by_run),
        "ambiguous_identities": [{
            "arm": row["arm"], "attempt": row["attempt"],
            "repetition": row["repetition"], "run_id": row["run_id"],
            "state": row["state"], "task_id": row["task_id"],
        } for row in ambiguous],
        "failed_analytic_identities": [{
            "arm": row["arm"], "attempt": row["attempt"],
            "repetition": row["repetition"], "run_id": row["run_id"],
            "state": row["state"], "task_id": row["task_id"],
            "terminal_status": row["terminal_status"],
        } for row in failed],
        "ledgers": {
            "attempts": _benchmark_study_v2_ledger_binding(
                attempts_path, maximum=4_000_000,
            ),
            "canary_events": _benchmark_study_v2_ledger_binding(
                output_root / "canary-events.jsonl", maximum=200_000,
            ),
        },
        "canary_evidence_sha256": canary_evidence_sha256,
        "descriptive_only": True, "claim_allowed": False, "claim": None,
    }


def _analyze_benchmark_study_v2_executable_unlocked(
    *, output_root: Path, claude_bin: str,
) -> dict[str, Any]:
    output_root = _benchmark_study_v2_output_root(output_root)
    manifest, manifest_sha256 = load_benchmark_study_v2_executable_manifest(
        output_root, revalidate_external=True,
    )
    _benchmark_study_v2_assert_cli_binding(
        claude_bin, manifest["inputs"]["cli_binding"],
    )
    canary_variants = _benchmark_study_v2_canary_variants(manifest, output_root)
    canary_rows = _benchmark_study_v2_read_canary_events(
        output_root / "canary-events.jsonl",
        manifest_sha256=manifest_sha256, variants=canary_variants,
    )
    invalid_canary_decision = _benchmark_study_v2_invalid_canary_decision(
        output_root=output_root, manifest=manifest,
        manifest_sha256=manifest_sha256, rows=canary_rows,
    )
    if invalid_canary_decision is not None:
        return invalid_canary_decision
    _canary_evidence, canary_evidence_sha256 = (
        _benchmark_study_v2_verify_canary_evidence(
            manifest=manifest, manifest_sha256=manifest_sha256,
            output_root=output_root,
        )
    )
    rows = _benchmark_study_v2_read_attempts(
        output_root / "attempts.jsonl", manifest=manifest,
        manifest_sha256=manifest_sha256,
    )
    tasks = parse_tasks(Path(manifest["inputs"]["tasks_path"]))
    load_task_fixture_trees(
        tasks, task_file_dir=Path(manifest["inputs"]["tasks_path"]).parent,
    )
    _benchmark_study_v2_revalidate_terminal_evidence(
        manifest=manifest, output_root=output_root, rows=rows,
        tasks_by_id={task.id: task for task in tasks},
        variants=_benchmark_study_v2_variants(manifest, output_root),
    )
    invalid_decision = _benchmark_study_v2_invalid_analytic_decision(
        output_root=output_root, manifest=manifest,
        manifest_sha256=manifest_sha256, rows=rows,
        canary_evidence_sha256=canary_evidence_sha256,
    )
    if invalid_decision is not None:
        return invalid_decision
    terminal_rows = [row for row in rows if row["state"] == "terminal"]
    final_states = {row["run_id"]: row["state"] for row in rows}
    if len(final_states) != 216 or any(
        state not in {"terminal", "not_needed", "blocked_study_invalid"}
        for state in final_states.values()
    ):
        raise ValueError("v2 analysis requires final accounting for all 216 identities")
    identity_state_counts = dict(sorted(collections.Counter(final_states.values()).items()))
    if any(
        row["terminal_status"] not in {"success", "valid_task_failure_v1"}
        for row in terminal_rows
    ):
        raise ValueError("v2 analysis refuses infrastructure-invalid or recovered attempts")
    initial = [row for row in terminal_rows if row["attempt"] == 0]
    if len(initial) != 108:
        raise ValueError("v2 analysis requires all 108 initial provider calls")
    by_unit = {(row["task_id"], row["repetition"], row["arm"]): row for row in initial}
    expected_retries = {
        key for key, row in by_unit.items()
        if row["terminal_status"] == "valid_task_failure_v1"
    }
    retry_rows = [row for row in terminal_rows if row["attempt"] == 1]
    if {(row["task_id"], row["repetition"], row["arm"]) for row in retry_rows} != expected_retries:
        raise ValueError("v2 analysis retry coverage is incomplete or replaced")
    effect_rows = [{
        "task_id": row["task_id"], "repetition": row["repetition"],
        "arm": row["arm"], "attempt": row["attempt"],
        "terminal_status": row["terminal_status"], "success": row["success"],
        "tokens": row["primary_tokens"], "correction": row["correction"],
        "retrieval": row["retrieval"],
    } for row in terminal_rows]
    terminal_by_unit = dict(by_unit)
    for row in retry_rows:
        terminal_by_unit[(row["task_id"], row["repetition"], row["arm"])] = row
    binary_rows = [
        {"task_id": row["task_id"], "repetition": row["repetition"],
         "arm": row["arm"], "success": row["success"]}
        for row in terminal_by_unit.values()
        if row["arm"] in BENCHMARK_STUDY_V2_PRIMARY_CONTRAST
    ]
    inference = infer_benchmark_study_v2_binary(
        binary_rows, task_order=manifest["inputs"]["task_ids"],
        ni_margin=float(manifest["plan"]["noninferiority_margin"]),
    )
    effects = compute_benchmark_study_v2_effects(
        effect_rows, task_order=manifest["inputs"]["task_ids"],
    )
    unavailable = {"available": False, "value": None, "reason": "observer_absent"}
    return {
        "schema_version": BENCHMARK_STUDY_V2_REPORT_SCHEMA_VERSION,
        "study_version": "v2", "decision": "P1-F",
        "manifest_sha256": manifest_sha256,
        "record_count": len(terminal_rows), "initial_provider_calls": 108,
        "retry_provider_calls": len(retry_rows),
        "discarded_canary_provider_calls": 2,
        "identity_state_counts": identity_state_counts,
        "binary_inference": inference, "effects": effects,
        "observers": {
            "correction": dict(unavailable), "retrieval": dict(unavailable),
            "shifted_cost": dict(unavailable),
        },
        "descriptive_only": True, "claim_allowed": False, "claim": None,
        "claim_readiness": {
            "claim_ready": False, "descriptive_only": True,
            "claim_allowed": False, "unmet_gates": ["power"],
        },
        "provenance": {
            "source": "direct_cli_plus_bound_checker",
            "success_source": "provider_terminal_usage_and_bound_checker",
            "provider_success_boolean_trusted": False,
            "cli_binding_sha256": _study_domain_hash(
                "contextguard.bench.v2.cli-binding.v1",
                manifest["inputs"]["cli_binding"],
            ),
            "auth_context_sha256": _study_domain_hash(
                "contextguard.bench.v2.auth-context.v1",
                manifest["inputs"]["auth_context"],
            ),
            "cli_version_stdout_sha256": manifest["inputs"]["cli_binding"][
                "probe"
            ]["version_stdout_sha256"],
            "backend_revision": "unavailable",
            "model_revision": "unavailable",
            "canary_evidence_sha256": canary_evidence_sha256,
            "canary_discarded_from_analysis": True,
        },
    }


BENCHMARK_STUDY_V2_NAMESPACE = "contextguard.bench.v2"


def _benchmark_study_v2_task_ids_from_corpus(corpus_bytes: bytes) -> list[str]:
    try:
        corpus = json.loads(corpus_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("v2 task corpus is invalid JSON") from exc
    if not isinstance(corpus, list):
        raise ValueError("v2 task corpus is not a list")
    return _benchmark_study_v2_task_ids([
        row.get("id") if isinstance(row, Mapping) else None for row in corpus
    ])


def _benchmark_study_v2_task_ids_sha256(task_ids: Sequence[str]) -> str:
    return _study_domain_hash(
        BENCHMARK_STUDY_V2_CORPUS_TASK_ORDER_DOMAIN,
        _benchmark_study_v2_task_ids(task_ids),
    )


def benchmark_study_v2_checker_binding(checkers_dir: Path) -> dict[str, Any]:
    """Hash an ordered relative filename/size/content-digest checker inventory."""
    directory_fd = _ensure_directory_no_symlink(checkers_dir, create=False)
    try:
        names = sorted(
            entry.name for entry in checkers_dir.iterdir()
            if entry.name.endswith(".py") and entry.is_file() and not entry.is_symlink()
        )
    finally:
        os.close(directory_fd)
    if len(names) != 12:
        raise ValueError("v2 checker directory must contain exactly 12 regular Python files")
    files = []
    for name in names:
        raw = _read_bytes_no_follow(
            checkers_dir / name, max_bytes=MAX_FIXTURE_FILE_BYTES,
        )
        files.append({
            "filename": name,
            "size": len(raw),
            "sha256": _study_sha256_bytes(raw),
        })
    binding = {
        "domain": BENCHMARK_STUDY_V2_CHECKER_BINDING_DOMAIN,
        "files": files,
        "sha256": _study_domain_hash(
            BENCHMARK_STUDY_V2_CHECKER_BINDING_DOMAIN, files,
        ),
    }
    validate_benchmark_study_v2_checker_binding(binding)
    return binding


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tasks", default=None, type=Path, help="task fixture JSON")
    parser.add_argument("--variants", default=None, type=Path, help="variant fixture JSON")
    parser.add_argument("--csv", default=None, type=Path,
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
    parser.add_argument("--measurement-study-plan", default=None, type=Path,
                        help="exact S002 measurement study plan JSON")
    parser.add_argument(
        "--measurement-study-action",
        default=None,
        choices=("prepare", "run", "resume", "analyze"),
        help="S002 measurement study action",
    )
    parser.add_argument("--measurement-study-output-root", default=None, type=Path,
                        help="private S002 measurement study artifact directory")
    parser.add_argument(
        "--study-v2-action", default=None,
        choices=("prepare", "canary", "run", "resume", "analyze"),
        help="prepare, canary, run, resume, or analyze the executable additive v2 study",
    )
    parser.add_argument("--study-v2-plan", default=None, type=Path,
                        help="canonical v2 study plan used only by --study-v2-action prepare")
    parser.add_argument("--study-v2-tasks", default=None, type=Path,
                        help="frozen v2 task corpus used only by --study-v2-action prepare")
    parser.add_argument("--study-v2-checkers-dir", default=None, type=Path,
                        help="frozen v2 checker directory used only by --study-v2-action prepare")
    parser.add_argument("--study-v2-candidate-hash", default=None,
                        help="exact candidate SHA-256 used only by --study-v2-action prepare")
    parser.add_argument("--study-v2-output-root", default=None, type=Path,
                        help="private executable v2 lifecycle directory")
    parser.add_argument("--study-v2-candidate-manifest", default=None, type=Path,
                        help="canonical build-once npm candidate manifest used by v2 prepare")
    parser.add_argument("--study-v2-candidate-checksums", default=None, type=Path,
                        help="exact candidate checksum document (default: manifest sibling)")
    parser.add_argument("--study-v2-npm-bin", default="npm",
                        help="npm executable used once for the offline candidate install")
    parser.add_argument(
        "--study-v2-use-existing-login", action="store_true",
        help=(
            "allow executable v2 provider actions to reuse the exact CLI's "
            "existing first-party login without importing credential environment variables"
        ),
    )
    args = parser.parse_args(argv)

    require_no_follow_file_ops_supported()
    v2_values = (
        args.study_v2_action, args.study_v2_plan, args.study_v2_tasks,
        args.study_v2_checkers_dir, args.study_v2_candidate_hash,
        args.study_v2_output_root, args.study_v2_candidate_manifest,
        args.study_v2_candidate_checksums,
    )
    if args.study_v2_use_existing_login and args.study_v2_action is None:
        parser.error("--study-v2-use-existing-login requires --study-v2-action")
    if any(value is not None for value in v2_values):
        if args.study_v2_action is None:
            parser.error("--study-v2-action is required when any --study-v2-* option is used")
        conflicts = [
            name for name, active in (
                ("--tasks", args.tasks is not None), ("--variants", args.variants is not None),
                ("--csv", args.csv is not None), ("--task-id", args.task_id is not None),
                ("--variant", args.variant is not None), ("--dry-run", args.dry_run),
                ("--resume", args.resume), ("--ledger-jsonl", args.ledger_jsonl is not None),
                ("--report-json", args.report_json is not None),
                ("--dashboard-md", args.dashboard_md is not None),
                ("--evidence-jsonl", args.evidence_jsonl is not None),
                ("--measurement-study-plan", args.measurement_study_plan is not None),
                ("--measurement-study-action", args.measurement_study_action is not None),
                ("--measurement-study-output-root", args.measurement_study_output_root is not None),
            ) if active
        ]
        if conflicts:
            parser.error(f"v2 executable mode conflicts with {', '.join(conflicts)}")
        if args.study_v2_output_root is None:
            parser.error("v2 executable actions require --study-v2-output-root")
        if (
            args.study_v2_action != "analyze"
            and not args.study_v2_use_existing_login
        ):
            parser.error(
                "v2 prepare/canary/run/resume requires "
                "--study-v2-use-existing-login"
            )
        auth_home = Path(os.environ.get("HOME", ""))
        if args.study_v2_action == "prepare":
            required = (
                args.study_v2_plan, args.study_v2_tasks, args.study_v2_checkers_dir,
                args.study_v2_candidate_hash, args.study_v2_candidate_manifest,
            )
            forbidden = ()
        else:
            required = (args.study_v2_output_root,)
            forbidden = (
                args.study_v2_plan, args.study_v2_tasks, args.study_v2_checkers_dir,
                args.study_v2_candidate_hash, args.study_v2_candidate_manifest,
                args.study_v2_candidate_checksums,
            )
        if not all(value is not None for value in required) or any(value is not None for value in forbidden):
            parser.error("v2 executable action has incomplete or conflicting arguments")
        try:
            if args.study_v2_action == "prepare":
                prepare_benchmark_study_v2_executable(
                    output_root=args.study_v2_output_root,
                    plan_path=args.study_v2_plan, tasks_path=args.study_v2_tasks,
                    checkers_dir=args.study_v2_checkers_dir,
                    candidate_manifest_path=args.study_v2_candidate_manifest,
                    candidate_checksum_path=args.study_v2_candidate_checksums,
                    expected_candidate_hash=args.study_v2_candidate_hash,
                    npm_bin=args.study_v2_npm_bin,
                    claude_bin=args.claude_bin,
                    auth_home=auth_home,
                )
                print(f"prepared executable v2 study: {args.study_v2_output_root}")
            elif args.study_v2_action == "canary":
                summary = execute_benchmark_study_v2_canary(
                    output_root=args.study_v2_output_root,
                    claude_bin=args.claude_bin,
                    auth_home=auth_home,
                )
                print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
            elif args.study_v2_action in {"run", "resume"}:
                summary = execute_benchmark_study_v2(
                    output_root=args.study_v2_output_root,
                    claude_bin=args.claude_bin,
                    resume=args.study_v2_action == "resume",
                    auth_home=auth_home,
                )
                print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
            else:
                report = analyze_benchmark_study_v2_executable(
                    output_root=args.study_v2_output_root,
                    claude_bin=args.claude_bin,
                )
                report_name = (
                    "study-invalid-decision.json"
                    if report.get("schema_version")
                    == BENCHMARK_STUDY_V2_INVALID_DECISION_SCHEMA_VERSION
                    else "study-report.json"
                )
                _study_write_private(
                    args.study_v2_output_root / report_name, report,
                )
                print(
                    "analyzed executable v2 study: "
                    f"{args.study_v2_output_root / report_name}"
                )
                if report_name == "study-invalid-decision.json":
                    return 3
            return 0
        except (OSError, SystemExit, TypeError, ValueError) as exc:
            print(f"v2 executable study refused: {exc}", file=sys.stderr)
            return 2
    if args.tasks is None or args.variants is None:
        parser.error("--tasks and --variants are required outside study modes")
    study_values = (
        args.measurement_study_plan,
        args.measurement_study_action,
        args.measurement_study_output_root,
    )
    if any(value is not None for value in study_values):
        if not all(value is not None for value in study_values):
            parser.error(
                "--measurement-study-plan, --measurement-study-action, and "
                "--measurement-study-output-root are all-or-none"
            )
        conflicts = [
            name for name, active in (
                ("--task-id", args.task_id is not None),
                ("--variant", args.variant is not None),
                ("--resume", args.resume),
                ("--evidence-jsonl", args.evidence_jsonl is not None),
                ("--dry-run", args.dry_run),
                ("--ledger-jsonl", args.ledger_jsonl is not None),
                ("--report-json", args.report_json is not None),
                ("--dashboard-md", args.dashboard_md is not None),
                ("--csv", args.csv is not None),
                ("--baseline-variant", args.baseline_variant != "baseline"),
            ) if active
        ]
        if conflicts:
            parser.error(f"measurement study mode conflicts with {', '.join(conflicts)}")
        return run_measurement_study_action(args)
    args.csv = args.csv or Path("bench/results.csv")
    validate_distinct_output_paths(args.csv, args.ledger_jsonl, args.report_json, args.dashboard_md)

    variants = parse_variants(args.variants)
    tasks = parse_tasks(args.tasks, variants=variants)
    targets = filter_targets(tasks, variants, args.task_id, args.variant)
    if not targets:
        if args.dry_run and (not tasks or not variants):
            print("completed 0 run(s) (dry-run; no CSV writes)")
            return 0
        print("no (task, variant) targets matched the filters", file=sys.stderr)
        return 1
    target_task_ids = {task.id for task, _variant in targets}
    load_task_fixture_trees(
        [task for task in tasks if task.id in target_task_ids],
        task_file_dir=args.tasks.parent,
    )
    preflight_measurement_targets(
        targets,
        claude_bin=args.claude_bin,
        check_cli=not args.dry_run and args.evidence_jsonl is None,
    )

    # profile gate 는 어떤 lock/read helper 보다 먼저 끝난다. existing_keys_snapshot 은
    # CSV lock sidecar 를 만들기 때문에, 그 뒤에서 거부하면 우리가 거절한 실행이 이미
    # 파일 시스템에 바이트를 남긴 뒤가 된다.
    #
    # replay 경계는 --dry-run 에도 적용한다. dry-run 이 provider 를 부르지 않는 것은
    # 맞지만, 불변식을 "profiled task 는 provider 경로에 진입하지 않는다" 로 단순하게
    # 유지하는 편이 감사 가능하고 fail-closed 다. 의미 있는 미리보기인
    # `--evidence-jsonl --dry-run` 은 그대로 동작한다.
    preflight_profile_replay_mode(tasks, targets, evidence_replay_active=args.evidence_jsonl is not None)
    # 반대로 freshness 는 출력을 쓰는 실행에만 의미가 있다. dry-run 은 CSV/ledger/report 를
    # 하나도 쓰지 않으므로 기존 CSV 가 있어도 잃을 profile 문맥이 없다.
    if not args.dry_run:
        preflight_profile_fresh_output(
            tasks,
            targets,
            resume=args.resume,
            csv_has_preexisting_content=file_has_content_no_follow(args.csv),
        )

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
            print("completed 0 run(s) (dry-run; no CSV writes)")
            return 0
        csv_had_preexisting_content = file_has_content_no_follow(args.csv)
        evidence_rows = read_evidence_jsonl(args.evidence_jsonl)
        # 완전한 profile preflight 는 첫 append_csv 이전, 그리고 어떤 lock sidecar 도
        # 만들어지기 전에 끝난다. 실패 시 파일 시스템은 바이트 단위로 그대로 남는다.
        preflight_evaluation_profiles(
            tasks,
            variants,
            targets,
            evidence_rows,
            task_file_dir=args.tasks.parent,
            resume=args.resume,
            csv_has_preexisting_content=csv_had_preexisting_content,
            baseline_variant=args.baseline_variant,
        )
        runnable_targets = resume_runnable_targets(
            args.csv,
            targets,
            resume=args.resume,
            existing_key_cache=skip_keys,
            existing_key_cache_stamp=skip_keys_stamp,
        )
        evidence_by_key = validate_evidence_coverage(evidence_rows, runnable_targets)
        profiled_batch = bool(selected_profiled_task_ids(tasks, targets))
        runnable_keys = {(task.id, variant.name) for task, variant in runnable_targets}
        claude_ver = "evidence-replay"
        completed = 0
        replay_rows_written: list[EvidenceReplayRow] = []
        pending_ledger_rows: list[tuple[EvidenceReplayRow, RunResult]] = []
        batch_lock = csv_parent_directory_lock(args.csv, create_parent=True) if profiled_batch else nullcontext()
        with batch_lock:
            if profiled_batch:
                # The same stable lock covers the raced freshness recheck and every
                # row. No sidecar is created, and no foreign append can land between
                # profiled rows because append_csv takes this lock first.
                profile_batch_freshness_gate_unlocked(tasks, targets, args.csv)
            for task, variant in targets:
                if args.resume and (task.id, variant.name) not in runnable_keys:
                    print(f"skip {task.id}/{variant.name} (already in {args.csv})")
                    continue
                evidence = evidence_by_key[(task.id, variant.name)]
                print(f"replay {task.id}/{variant.name} ...", flush=True)
                result = run_evidence_fixture(task, variant, evidence)
                writer = append_csv_unlocked if profiled_batch else append_csv
                wrote = writer(
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
                        pending_ledger_rows.append((evidence, result))
                completed += 1
                status = "ok" if result.success else "FAIL"
                suffix = "" if wrote else " (CSV not updated; row already present)"
                print(
                    f"  {status} tokens={sum(result.tokens.values())} {primary_cost_display(result)} "
                    f"wall_time={result.wall_time_seconds:.3f}s {sanitize_note_text(result.notes)}{suffix}"
                )
        # Ledger/report/dashboard writes happen after the CSV batch lock so distinct
        # outputs in the same directory cannot deadlock on the directory inode.
        for evidence, result in pending_ledger_rows:
            append_cost_shift_ledger(
                args.ledger_jsonl,
                claude_ver,
                result,
                replay_provenance=evidence.provenance_payload(),
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
    if args.dry_run:
        claude_ver = "dry-run"
    elif not runnable_targets:
        claude_ver = "skipped"
    else:
        measurement_spec = next(
            (variant.measurement for _, variant in runnable_targets if variant.measurement is not None),
            None,
        )
        if measurement_spec is None:
            claude_ver = claude_version(args.claude_bin)
        else:
            with _measurement_preflight_env(measurement_spec) as (version_env, version_cwd):
                claude_ver = claude_version(
                    executable_argv0(args.claude_bin), env=version_env, cwd=version_cwd,
                )

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
            f"  {status} tokens={sum(result.tokens.values())} {primary_cost_display(result)} "
            f"wall_time={result.wall_time_seconds:.3f}s {sanitize_note_text(result.notes)}{suffix}"
        )
    target = args.csv if not args.dry_run else None
    if (args.report_json is not None or args.dashboard_md is not None) and not args.dry_run:
        report = write_report_outputs(args.csv, args.report_json, args.dashboard_md, args.baseline_variant)
        if args.report_json is not None:
            print(f"report {args.report_json}: {report['claim_status']}")
        if args.dashboard_md is not None:
            print(f"dashboard {args.dashboard_md}: {report_public_claim_status(report)[0]}")
    if target is None:
        print(f"completed {completed} run(s) (dry-run; no CSV writes)")
    else:
        print(f"completed {completed} run(s); results in {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
