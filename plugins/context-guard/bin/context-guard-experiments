#!/usr/bin/env python3
"""Default-off ContextGuard experimental feature registry.

The registry is intentionally passive: it records explicit project-local opt-in
state for experimental lanes, but it does not activate runtime behavior by
itself.  Individual helpers must still require their own explicit experimental
flags before changing stable behavior.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import socket
from socketserver import TCPServer
from pathlib import Path
import unicodedata
import stat
import sys
import time
from typing import Any, NoReturn
import unicodedata
from urllib.parse import urlparse

TOOL_NAME = "context-guard-experiments"
CONFIG_SCHEMA_VERSION = "contextguard.experiments.v1"
DEFAULT_CONFIG = Path(".context-guard") / "experiments.json"
MAX_CONFIG_BYTES = 64_000
MAX_CONTEXT_DIFF_INPUT_BYTES = 256_000
MAX_CONTEXT_DIFF_REPLACEMENT_BYTES = 128_000
MAX_CONTEXT_DIFF_ARTIFACT_METADATA_BYTES = 64_000
DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR = Path(".context-guard") / "artifacts"
LEGACY_CONTEXT_DIFF_ARTIFACT_DIR = Path(".claude-token-optimizer") / "artifacts"
MAX_VISUAL_OCR_TEXT_BYTES = 64_000
MAX_LEARNED_COMPRESSION_INPUT_BYTES = 128_000
MAX_LEARNED_COMPRESSION_REPLACEMENT_BYTES = 64_000
MAX_LEARNED_COMPRESSION_ARTIFACT_METADATA_BYTES = 64_000
IMAGE_CONTEXT_PACK_MAX_DIMENSION = 16_384
MAX_SELF_HOSTED_METRICS_INPUT_BYTES = 64_000
SELF_HOSTED_METRICS_SCHEMA_VERSION = "contextguard.bench.self-hosted-metrics.v1"
SELF_HOSTED_METRICS_KEY = "self_hosted_metrics"
SELF_HOSTED_METRICS_CLAIM_BOUNDARY = "self_hosted_metrics_only_not_hosted_api_token_or_cost_savings"
BENCH_RUN_EVIDENCE_SCHEMA_VERSION = "contextguard.bench.run-evidence.v1"
MAX_SELF_HOSTED_LABEL_CHARS = 120
MAX_SELF_HOSTED_LATENCY_MS = 7 * 24 * 60 * 60 * 1000
MAX_SELF_HOSTED_MEMORY_MB = 10_000_000
MAX_SELF_HOSTED_ENERGY_WH = 1_000_000
MAX_SELF_HOSTED_LOCAL_COST_USD = 1_000_000
MAX_SELF_HOSTED_TOKENS_PER_SECOND = 10_000_000
TOKEN_PROXY_BYTES_PER_TOKEN = 4
MAX_SELF_HOSTED_JSON_DEPTH = 100
MAX_SELF_HOSTED_JSON_NODES = 10_000
LOCAL_PROXY_SCHEMA_VERSION = "contextguard.experiments.local-proxy-plan.v1"
LOCAL_PROXY_GATE_SCHEMA_VERSION = "contextguard.experiments.local-proxy-gate.v1"
LOCAL_PROXY_FORWARD_SCHEMA_VERSION = "contextguard.experiments.local-proxy-forward.v1"
LOCAL_PROXY_DIAGNOSTIC_SCHEMA_VERSION = "contextguard.experiments.local-proxy-forward-diagnostic.v1"
LOCAL_PROXY_READY_SCHEMA_VERSION = "contextguard.experiments.local-proxy-ready.v1"
LOCAL_PROXY_EXTERNAL_DESIGN_SCHEMA_VERSION = "contextguard.experiments.local-proxy-external-forwarding-design.v1"
LOCAL_PROXY_RESPONSE_SANDBOX_SCHEMA_VERSION = "contextguard.experiments.local-proxy-response-sandbox.v1"
IMAGE_CONTEXT_PACK_PLAN_SCHEMA_VERSION = "contextguard.experiments.image-context-pack-plan.v1"
SEMANTIC_CHECKPOINT_PLAN_SCHEMA_VERSION = "contextguard.experiments.semantic-checkpoint-plan.v1"
PROOF_CARRYING_CONTEXT_PLAN_SCHEMA_VERSION = "contextguard.experiments.proof-carrying-context-plan.v1"
PROOF_CARRYING_CONTEXT_UNIT_SCHEMA_VERSION = "contextguard.proof-unit.v1"
PROOF_CARRYING_CONTEXT_DETAILED_UNIT_CAP = 64
PROOF_CARRYING_CONTEXT_UNIT_JSON_BYTE_CAP = 8192
PROOF_UNIT_JSON_MAX_DEPTH = 100
SEMANTIC_GC_PLAN_SCHEMA_VERSION = "contextguard.experiments.semantic-gc-plan.v1"
SEMANTIC_GC_UNIT_SCHEMA_VERSION = "contextguard.semantic-gc-unit.v1"
SEMANTIC_GC_DETAILED_UNIT_CAP = 64
SEMANTIC_GC_UNIT_JSON_BYTE_CAP = 8192
SEMANTIC_GC_JSON_MAX_DEPTH = 100
SEMANTIC_GC_PROCESS_EXIT_CONTRACT = (
    "exit code 0 means ready_for_plan_review; exit code 2 means a blocked plan was emitted"
)
JSON_SAFE_INTEGER_MAX = 9_007_199_254_740_991
PROOF_SOURCE_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,119}$")
PROOF_RECEIPT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
PROOF_CONTENT_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
PROOF_CAPTURED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PROOF_UNIT_ALLOWED_FIELDS = frozenset({
    "source_label",
    "receipt_id",
    "content_sha256",
    "safe_range",
    "captured_at",
    "transform_policy",
    "rehydrate_command",
})
PROOF_READINESS_BLOCKER_ORDER = (
    "missing_proof_unit",
    "too_many_proof_units",
    "proof_unit_json_too_large",
    "invalid_proof_unit_unicode",
    "invalid_proof_unit_json",
    "duplicate_proof_unit_keys",
    "proof_unit_json_nesting_too_deep",
    "nonfinite_proof_unit_number",
    "proof_unit_not_object",
    "unknown_proof_unit_fields",
    "missing_source_label",
    "invalid_source_label",
    "missing_receipt",
    "invalid_receipt",
    "missing_content_sha256",
    "invalid_content_sha256",
    "missing_timestamp",
    "invalid_timestamp",
    "missing_transform_policy",
    "invalid_transform_policy",
    "invalid_safe_range",
    "missing_safe_range_for_transform_policy",
    "missing_rehydrate_command",
    "invalid_rehydrate_command",
    "rehydrate_receipt_mismatch",
    "receipt_hash_conflict",
    "protected_zone_denial_required",
    "missing_provider_measurement_boundary",
)
PROOF_WARNING_ORDER = (
    "protected_zone_compliance_not_checked",
    "safe_range_bounds_not_checked",
    "receipt_storage_not_checked",
    "content_hash_not_verified",
    "rehydrate_command_not_executed",
    "timestamp_freshness_not_checked",
    "safe_range_omitted",
    "duplicate_proof_unit",
)
SEMANTIC_GC_UNIT_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
SEMANTIC_GC_SOURCE_LABEL_RE = re.compile(r"^[A-Za-z0-9._:/ -]{1,128}$")
SEMANTIC_GC_RECEIPT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
SEMANTIC_GC_CONTENT_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SEMANTIC_GC_ALLOWED_FIELDS = frozenset({
    "schema", "unit_id", "references", "is_root", "protected_zone",
    "content_sha256", "provenance", "missed_context_note", "exact_fallback_command",
})
SEMANTIC_GC_BLOCKER_ORDER = (
    "no_context_units", "unit_limit_exceeded", "invalid_context_unit_json",
    "duplicate_json_key", "context_unit_depth_exceeded", "nonfinite_json_number",
    "invalid_unicode_scalar", "decoder_recursion_limit", "invalid_context_unit_schema",
    "unknown_context_unit_field", "missing_unit_id", "invalid_unit_id",
    "duplicate_unit_id", "invalid_references", "duplicate_reference", "unknown_reference",
    "ambiguous_reference",
    "invalid_root_flag", "invalid_protected_zone_flag", "no_declared_root",
    "graph_evaluation_suppressed", "protected_zone_policy_required",
    "invalid_content_sha256", "missing_provenance", "invalid_provenance",
    "invalid_source_label", "invalid_receipt_id", "missing_missed_context_note",
    "invalid_missed_context_note", "missing_exact_fallback", "invalid_exact_fallback",
    "fallback_receipt_mismatch", "provider_boundary_ack_required", "human_review_ack_required",
)
SEMANTIC_GC_WARNING_ORDER = (
    "plan_only_no_omission", "caller_declared_graph_unverified",
    "semantic_relevance_not_evaluated", "provider_boundary_not_verified",
    "provenance_not_verified_externally", "fallback_not_executed",
    "human_review_still_required", "accepted_notes_are_untrusted",
    "duplicate_content_sha256", "duplicate_receipt_id",
    "protected_unreachable_excluded", "no_sweep_candidates",
)
IMAGE_CONTEXT_PACK_PROVIDER_BOUNDARY = "provider-measured-matched-tasks-required"
LOCAL_PROXY_DEFAULT_BIND_HOST = "127.0.0.1"
LOCAL_PROXY_DEFAULT_BIND_PORT = 0
LOCAL_PROXY_DEFAULT_TARGET_HOST = "127.0.0.1"
LOCAL_PROXY_DEFAULT_TARGET_PORT = 0
LOCAL_PROXY_LOCALHOST_NAMES = {"localhost"}
LOCAL_PROXY_TRUE_VALUES = {"1", "on", "true", "yes", "y"}
LOCAL_PROXY_FALSE_VALUES = {"", "0", "false", "n", "no", "off"}
LOCAL_PROXY_DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
LOCAL_PROXY_DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
LOCAL_PROXY_MAX_FORWARD_BYTES = 2 * 1024 * 1024
LOCAL_PROXY_DEFAULT_TIMEOUT_SECONDS = 5.0
LOCAL_PROXY_MAX_TIMEOUT_SECONDS = 30.0
LOCAL_PROXY_RESPONSE_SANDBOX_SCOPE = "local_proxy_sanitized_response_body"
LOCAL_PROXY_EXTERNAL_ALLOWED_SCHEMES = {"https"}
LOCAL_PROXY_EXTERNAL_CREDENTIAL_REDACTION_POLICY = "strip-sensitive-headers"
LOCAL_PROXY_EXTERNAL_PROVIDER_EVIDENCE_BOUNDARY = "diagnostic-only-provider-measured-required"
LOCAL_PROXY_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-anthropic-api-key",
    "x-openai-api-key",
    "openai-api-key",
    "cookie",
    "set-cookie",
}
LOCAL_PROXY_NONCE_HEADER = "X-ContextGuard-Proxy-Nonce"
LOCAL_PROXY_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
ALLOWED_FIRST_COMPONENT_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}
DIR_FD_OPEN_SUPPORTED = os.open in getattr(os, "supports_dir_fd", set())
DIR_FD_MKDIR_SUPPORTED = os.mkdir in getattr(os, "supports_dir_fd", set())
DIR_FD_STAT_NOFOLLOW_SUPPORTED = (
    os.stat in getattr(os, "supports_dir_fd", set())
    and os.stat in getattr(os, "supports_follow_symlinks", set())
)
NO_FOLLOW_SUPPORTED = hasattr(os, "O_NOFOLLOW")


@dataclass(frozen=True)
class Experiment:
    id: str
    name: str
    summary: str
    stability: str
    default_enabled: bool
    risk_level: str
    claim_boundary: str
    gate_requirements: tuple[str, ...]
    runtime_status: str = "metadata-only"
    commands: tuple[str, ...] = ()
    opt_in_flags: tuple[str, ...] = ()
    config_effect: str = (
        "Registry enablement records project-local intent only; helpers still require explicit experimental flags."
    )
    evidence_contract: str = "Evidence is local metadata only unless a later story adds a measured runtime gate."

    def to_json(self, *, enabled: bool = False) -> dict[str, Any]:
        data = asdict(self)
        for key in ("gate_requirements", "commands", "opt_in_flags"):
            data[key] = list(getattr(self, key))
        data["enabled"] = bool(enabled)
        return data


EXPERIMENTS: tuple[Experiment, ...] = (
    Experiment(
        id="output-receipt-trim",
        name="Receipt-backed output trimming",
        summary="Opt-in digest output with local artifact receipts and exact re-expand instructions.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Local output-size reduction only; no hosted API token/cost savings claim without provider-measured matched tasks.",
        gate_requirements=("explicit opt-in", "local artifact receipt", "exact re-expand command"),
        runtime_status="available-explicit-flags",
        commands=(
            "context-guard-trim-output --digest markdown --artifact-receipt -- <command>",
            "context-guard-trim-output --digest json --artifact-receipt -- <command>",
        ),
        opt_in_flags=("--digest markdown|json", "--artifact-receipt"),
        config_effect=(
            "Registry enablement records project-local intent only; output trimming still runs only when the helper is "
            "invoked with --digest markdown|json plus --artifact-receipt."
        ),
        evidence_contract=(
            "Stores the exact sanitized full output as a local context-guard-artifact receipt and emits an exact "
            "re-expand command before omitted details are relied on."
        ),
    ),
    Experiment(
        id="protected-zone-policy",
        name="Protected-zone transform policy",
        summary="Metadata policy that denies semantic rewrites for code, diffs, identifiers, hashes, paths, and other exact evidence.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Policy metadata only; it does not prove provider cache or token savings.",
        gate_requirements=("explicit opt-in", "protected-zone detection", "exact retrieval fallback"),
        runtime_status="available-explicit-flags",
        commands=(
            "context-guard-compress --json --protected-policy",
            "context-guard cost compile --json",
            "context-guard-cost compile --json",
        ),
        opt_in_flags=("--protected-policy", "protected=true manifest sections for cost compile"),
        config_effect=(
            "Registry enablement records project-local intent only; protected-zone policy metadata still appears only "
            "when explicit helper flags or protected manifest sections are used."
        ),
        evidence_contract=(
            "Denies semantic/paraphrase rewrites for protected classes and requires structural transforms plus exact "
            "artifact retrieval guidance for protected evidence."
        ),
    ),
    Experiment(
        id="context-diff-compaction",
        name="Reviewable context-diff compaction",
        summary="Explicit receipt-backed runtime for caller-supplied compact diff replacements with stable exact handles.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Smaller local diffs are proxy evidence only; hosted savings require provider-measured matched tasks.",
        gate_requirements=("explicit opt-in", "human-reviewable diff", "local receipt", "exact re-expand handle"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan context-diff-compaction",
            "context-guard experiments emit context-diff-compaction --receipt-id <id> --reexpand-command <cmd>",
        ),
        opt_in_flags=(
            "plan context-diff-compaction",
            "emit context-diff-compaction",
            "--receipt-id",
            "--reexpand-command",
            "--replacement-text|--replacement-file",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; context-diff replacement emits only through the "
            "explicit emit command with exact retrieval metadata and caller-supplied compact text."
        ),
        evidence_contract=(
            "Emitted replacements require human-reviewable hunks, caller-supplied compact text, and exact local "
            "artifact content that matches the input diff plus re-expand metadata; smaller local diffs remain proxy "
            "evidence only."
        ),
    ),
    Experiment(
        id="visual-crop-ocr",
        name="Visual crop/OCR evidence pack",
        summary="Explicit local runtime for caller-supplied visual crop/OCR evidence packs.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Image/OCR byte reductions are proxy evidence until provider image/text token fields are measured.",
        gate_requirements=("explicit opt-in", "original evidence preserved", "confidence/error notes", "missed-context guardrail"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan visual-crop-ocr",
            "context-guard experiments emit visual-crop-ocr",
        ),
        opt_in_flags=(
            "plan visual-crop-ocr",
            "emit visual-crop-ocr",
            "--full-evidence-receipt",
            "--crop-bounds",
            "--image-size",
            "--ocr-text|--ocr-text-file",
            "--ocr-confidence",
            "--ocr-error-note",
            "--missed-context-note",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; visual crop/OCR evidence packs emit only through "
            "the explicit emit command and do not run OCR, crop images, call providers, write files, or change stable behavior."
        ),
        evidence_contract=(
            "Emitted evidence packs require the full visual evidence receipt plus caller-supplied crop/OCR evidence, "
            "OCR confidence/error notes when OCR is present, and missed-context guardrails before human review."
        ),
    ),
    Experiment(
        id="image-context-pack",
        name="Pxpipe-inspired image context pack planning gate",
        summary=(
            "Plan-only evaluation gate for pxpipe-inspired image/context packing without rendering images, "
            "emitting visual artifacts, or changing runtime behavior."
        ),
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary=(
            "Image/request byte reductions are proxy evidence only; hosted token/cost savings require "
            "provider-measured matched successful tasks."
        ),
        gate_requirements=(
            "explicit opt-in",
            "verified exact text artifact fallback before omitted text is used",
            "protected-zone denial",
            "provider/model measurement boundary",
            "missed-context guardrails",
            "relation to visual-crop-ocr",
        ),
        runtime_status="available-plan-only",
        commands=("context-guard experiments plan image-context-pack",),
        opt_in_flags=(
            "plan image-context-pack",
            "--exact-text-fallback-receipt",
            "--reexpand-command",
            "--provider-boundary-ack",
            "--protected-zone-policy deny",
            "--missed-context-note",
            "--image-size",
            "--packed-image-size",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; image-context-pack exposes only a deterministic "
            "plan command. It does not add an emit/record/serve runtime, render images, run OCR, call models, proxy "
            "traffic, write binary artifacts, or duplicate the caller-supplied visual-crop-ocr evidence-pack emitter."
        ),
        evidence_contract=(
            "The planner requires acknowledgements for explicit evaluation intent, verified exact text artifact fallback, "
            "protected-zone denial, provider/model measured matched-task boundaries, missed-context review, and the fact that "
            "visual-crop-ocr is the existing caller-supplied visual evidence-pack surface, not a verified "
            "exact binary/image fallback."
        ),
    ),

    Experiment(
        id="semantic-checkpoint",
        name="Semantic checkpoint planning gate",
        summary=(
            "Plan-only evaluation gate for semantic checkpoint metadata and provenance readiness without "
            "emitting replacement context or changing runtime behavior."
        ),
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary=(
            "Semantic checkpoint metadata is dry-run planning evidence only; it cannot replace raw context or "
            "claim hosted token/cost savings without future provider-measured matched successful tasks."
        ),
        gate_requirements=(
            "explicit planning goal",
            "verified exact context fallback before checkpoint metadata is used",
            "provider/model measurement boundary",
            "protected-zone denial",
            "missed-context guardrails",
            "provenance review acknowledgement",
        ),
        runtime_status="available-plan-only",
        commands=("context-guard experiments plan semantic-checkpoint",),
        opt_in_flags=(
            "plan semantic-checkpoint",
            "--goal",
            "--constraint",
            "--decision",
            "--open-task",
            "--evidence-handle",
            "--missing-provenance-note",
            "--unresolved-question",
            "--exact-context-fallback-receipt",
            "--reexpand-command",
            "--provider-boundary-ack",
            "--protected-zone-policy deny",
            "--missed-context-note",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; semantic-checkpoint exposes only a deterministic "
            "plan command. It does not add an emit/record/serve runtime, call models/providers, proxy traffic, write "
            "files, edit prompts/transcripts, replace context, or emit checkpoint candidates."
        ),
        evidence_contract=(
            "The planner requires a goal, exact context artifact fallback, protected-zone denial, provider/model "
            "measured matched-task boundary, missed-context notes, and provenance review notes before checkpoint metadata "
            "is ready for plan review; raw context remains authoritative."
        ),
    ),
    Experiment(
        id="proof-carrying-context",
        name="Proof-carrying context metadata planning gate",
        summary=(
            "Plan-only proof-envelope metadata syntax and consistency readiness without reading source content, "
            "verifying receipts, or emitting compact context."
        ),
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary=(
            "Proof-envelope metadata readiness is not verified proof or hosted savings evidence; actual receipt, "
            "content, range, protected-zone, and rehydration checks require a separately approved consumer."
        ),
        gate_requirements=(
            "at least one bounded inline proof-unit JSON object",
            "caller-declared protected-zone denial",
            "provider/model measurement boundary acknowledgement",
            "syntax-only proof metadata and exact rehydration binding",
        ),
        runtime_status="available-plan-only",
        commands=("context-guard experiments plan proof-carrying-context",),
        opt_in_flags=(
            "plan proof-carrying-context",
            "--proof-unit-json",
            "--provider-boundary-ack",
            "--protected-zone-policy deny",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; proof-carrying-context exposes one deterministic "
            "plan command. It does not add an emit/record/serve runtime, read source/artifact/config/stdin content, "
            "execute rehydration, write files, edit prompts/transcripts, generate compact context, or replace context."
        ),
        evidence_contract=(
            "The planner validates bounded inline proof-envelope metadata syntax and defined cross-unit consistency "
            "only. Protected-zone compliance, range bounds, receipt storage, content hashes, timestamp freshness, "
            "and rehydration remain explicitly unchecked."
        ),
    ),
    Experiment(
        id="semantic-gc",
        name="Semantic graph garbage-collection planning gate",
        summary=(
            "Plan-only caller-declared mark-and-sweep classification with strict graph-integrity suppression "
            "and recovery-evidence gates for human review."
        ),
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary=(
            "Unreachable graph nodes are plan-review candidates, not proof of irrelevance or authorization to omit; "
            "the planner does not read content, verify provenance, execute fallback, or call providers."
        ),
        gate_requirements=(
            "complete unambiguous caller-declared graph",
            "deny-only protected-zone declaration",
            "candidate recovery evidence and missed-context note",
            "provider-boundary acknowledgement for every complete graph; "
            "human-review acknowledgement when unprotected sweep candidates exist",
        ),
        runtime_status="available-plan-only",
        commands=("context-guard experiments plan semantic-gc",),
        opt_in_flags=(
            "plan semantic-gc", "--context-unit-json", "--provider-boundary-ack",
            "--human-review-ack", "--protected-zone-policy deny",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; semantic-gc exposes one deterministic plan command. "
            "It does not add an emit/record/serve/apply/delete/omit runtime, read context or artifacts, write files, "
            "call models/providers/network, execute fallback, replace context, or authorize omission."
        ),
        evidence_contract=(
            "The complete caller-declared graph must pass strict structural validation before iterative reachability. "
            "Unprotected unreachable candidates require sanitized provenance, content hash, exact fallback, and an "
            "untrusted missed-context note plus human-review acknowledgement before the plan is ready for review. "
            "A complete graph with no unprotected sweep candidates does not require that acknowledgement. "
            "Ready plans exit 0; blocked plans still emit their envelope and exit 2."
        ),
    ),
    Experiment(
        id="learned-compression",
        name="Learned/synthetic compression candidate gate",
        summary="Explicit local runtime for caller-supplied compact prose candidates with verified exact fallback.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Semantic compression cannot claim savings or correctness without matched-task quality and provider token evidence.",
        gate_requirements=("explicit opt-in", "sanitized unprotected prose only", "protected-zone denial", "exact fallback or receipt"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan learned-compression",
            "context-guard experiments emit learned-compression --exact-fallback-receipt <id> --reexpand-command <cmd>",
        ),
        opt_in_flags=(
            "plan learned-compression",
            "emit learned-compression",
            "--sanitized",
            "--trusted-source",
            "--exact-fallback-receipt",
            "--reexpand-command",
            "--replacement-text|--replacement-file",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; learned-compression candidates emit only through "
            "the explicit emit command and do not run learned compressors, embeddings, rerankers, model calls, subprocesses, or external services."
        ),
        evidence_contract=(
            "Emitted candidates require caller-asserted sanitized trusted prose, verified exact local fallback content, "
            "a smaller caller-supplied prose candidate, and denial of protected or prompt-like signals."
        ),
    ),
    Experiment(
        id="self-hosted-metrics-ledger",
        name="Self-hosted metrics ledger",
        summary="Explicit local ledger runtime for self-hosted/local metrics sidecars kept separate from hosted API claims.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Self-hosted memory/latency metrics must stay separate from hosted API token/cost claims.",
        gate_requirements=("explicit opt-in", "separate ledger fields", "shifted-cost accounting"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan self-hosted-metrics-ledger",
            "context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl <path>",
        ),
        opt_in_flags=(
            "plan self-hosted-metrics-ledger",
            "record self-hosted-metrics-ledger",
            "--ledger-jsonl",
            "--input",
            "--latency-ms",
            "--peak-memory-mb",
            "--quality-score",
            "--energy-wh",
            "--local-cost-usd",
            "--tokens-per-second",
            "--model-server",
            "--optimization",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; self-hosted metrics still write a ledger only "
            "when the explicit record command is invoked with --ledger-jsonl."
        ),
        evidence_contract=(
            "The explicit record command writes context-guard-bench JSONL ledger sidecars; self-hosted metrics "
            "remain separate from hosted API token/cost savings."
        ),
    ),
    Experiment(
        id="local-proxy",
        name="Local proxy runtime gate",
        summary="Explicit local gate-record runtime for localhost-only proxy experiments with no hidden forwarding or API-key persistence.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Proxy metrics are diagnostic only; no hosted savings claim without provider-measured evidence.",
        gate_requirements=("explicit opt-in", "localhost-only default", "no API-key persistence", "no hidden external forwarding"),
        runtime_status="available-explicit-runtime",
        commands=(
            "context-guard experiments plan local-proxy",
            "context-guard experiments plan local-proxy-external-forwarding",
            "context-guard experiments record local-proxy-runtime-gate --ledger-jsonl <path>",
            "context-guard experiments serve local-proxy --bind-host 127.0.0.1 --bind-port <port> --target-host 127.0.0.1 --target-port <port> --runtime-gate-ack --forwarding-gate-ack --once --ready-file <path>",
            "context-guard experiments serve local-proxy --ready-file <ready-file> --diagnostic-ledger-jsonl <path> ...",
        ),
        opt_in_flags=(
            "plan local-proxy",
            "plan local-proxy-external-forwarding",
            "record local-proxy-runtime-gate",
            "serve local-proxy",
            "--bind-host",
            "--bind-port",
            "--target-host",
            "--target-port",
            "--upstream-url",
            "--ledger-jsonl",
            "--runtime-gate-ack",
            "--forwarding-gate-ack",
            "--once",
            "--max-request-bytes",
            "--max-response-bytes",
            "--diagnostic-ledger-jsonl",
            "--ready-file",
            "--external-forwarding-intent",
            "--external-forwarding-design-ack",
            "--allow-host",
            "--allow-scheme",
            "--threat-model-note",
            "--credential-redaction-policy",
            "--provider-evidence-boundary",
            "--persist-api-key",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; local proxy record/serve runtimes run only through "
            "explicit commands. Serve binds and forwards only literal loopback addresses, blocks credential material, "
            "and never persists API keys or calls non-local services; external-forwarding planning is design-only."
        ),
        evidence_contract=(
            "Gate rows require localhost-only bind/target metadata and explicit runtime gate acknowledgement. Serve "
            "evidence requires loopback-only bind/target IPs, a private ready-file nonce handoff, explicit forwarding "
            "acknowledgement, no credential forwarding or persistence, bounded bytes/timeouts, and optional diagnostic "
            "ledger rows that remain shifted-cost evidence only. External-forwarding design plans require threat model "
            "notes, explicit allowlists, credential redaction policy, and provider-evidence boundaries before any future "
            "runtime."
        ),
    ),
)

REGISTRY = {experiment.id: experiment for experiment in EXPERIMENTS}


class RegistryError(RuntimeError):
    pass


def fail(message: str, code: int = 2) -> NoReturn:
    print(f"{TOOL_NAME}: {message}", file=sys.stderr)
    raise SystemExit(code)


def os_error_detail(exc: OSError) -> str:
    detail = exc.strerror or exc.__class__.__name__
    if exc.errno is not None:
        return f"{detail} (errno {exc.errno})"
    return detail


def _no_follow_flag(*, label: str) -> int:
    if not NO_FOLLOW_SUPPORTED:
        raise RegistryError(f"{label} requires O_NOFOLLOW support")
    return os.O_NOFOLLOW


def _directory_open_flags(*, follow_final: bool = False, label: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_final:
        flags |= _no_follow_flag(label=label)
    return flags


def _file_open_flags(*, label: str, write: bool = False) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC if write else os.O_RDONLY
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _temp_file_open_flags(*, label: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _append_file_open_flags(*, label: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= _no_follow_flag(label=label)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    return flags


def _leaf_name(path: Path, *, label: str) -> str:
    name = path.name
    if name in {"", ".", ".."}:
        raise RegistryError(f"{label} must name a regular file")
    return name


def _normalized_link_target(anchor: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if target.is_absolute():
        return Path(os.path.normpath(str(target)))
    return Path(os.path.normpath(str(anchor / target)))


def normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    if not path.is_absolute():
        return path
    parts = path.parts
    if len(parts) < 2:
        return path
    first = parts[1]
    expected = ALLOWED_FIRST_COMPONENT_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if link.is_symlink() and _normalized_link_target(Path(path.anchor), os.readlink(link)) == expected:
            return expected.joinpath(*parts[2:])
    except OSError:
        return path
    return path


def normalize_local_path(path: Path) -> Path:
    path = path.expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(path))))


def normalize_project_path(root: Path, candidate: Path, *, label: str) -> Path:
    candidate = candidate.expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    normalized = normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(candidate))))
    try:
        normalized.relative_to(root)
    except ValueError as exc:
        raise RegistryError(f"{label} must stay inside project root: {normalized}") from exc
    return normalized


def open_directory_no_follow(path: Path, *, label: str, create: bool = False, missing_ok: bool = False) -> int | None:
    path = normalize_allowed_first_absolute_symlink(path)
    if not DIR_FD_OPEN_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd open support")
    if create and not DIR_FD_MKDIR_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd mkdir support")
    flags = _directory_open_flags(label=label)
    if path.is_absolute():
        anchor = path.anchor or os.sep
        parts = path.parts[1:]
        try:
            current_fd = os.open(anchor, _directory_open_flags(follow_final=True, label=label))
        except OSError as exc:
            raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    else:
        parts = path.parts
        try:
            current_fd = os.open(".", flags)
        except OSError as exc:
            raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise RegistryError(f"{label} must not contain parent traversal")
            next_fd = -1
            try:
                next_fd = os.open(part, flags, dir_fd=current_fd)
            except FileNotFoundError:
                if missing_ok:
                    os.close(current_fd)
                    current_fd = -1
                    return None
                if not create:
                    raise RegistryError(f"could not inspect {label}: missing directory component") from None
                try:
                    os.mkdir(part, mode=0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise RegistryError(f"could not create {label}: {os_error_detail(exc)}") from exc
                try:
                    next_fd = os.open(part, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
            except OSError as exc:
                raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise RegistryError(f"{label} must not traverse non-directory components")
            except Exception:
                if next_fd >= 0:
                    try:
                        os.close(next_fd)
                    except OSError:
                        pass
                raise
            try:
                os.close(current_fd)
            except OSError:
                pass
            current_fd = next_fd
        owned_fd = current_fd
        current_fd = -1
        return owned_fd
    finally:
        if current_fd >= 0:
            try:
                os.close(current_fd)
            except OSError:
                pass


def _precheck_regular_leaf(parent_fd: int, leaf_name: str, *, label: str, missing_ok: bool = False) -> bool:
    if not DIR_FD_STAT_NOFOLLOW_SUPPORTED:
        raise RegistryError(f"{label} requires dir_fd stat support")
    try:
        st = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return False
        raise RegistryError(f"could not inspect {label}: missing file") from None
    except OSError as exc:
        raise RegistryError(f"could not inspect {label}: {os_error_detail(exc)}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise RegistryError(f"{label} must be a regular file")
    return True


def read_bounded_regular_file(path: Path, *, max_bytes: int, label: str, missing_ok: bool = False) -> tuple[bytes, bool] | None:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", missing_ok=missing_ok)
    if parent_fd is None:
        return None
    fd = -1
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=missing_ok)
        if not exists:
            return None
        fd = os.open(leaf, _file_open_flags(label=label), dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        truncated = len(raw) > max_bytes
        return raw[:max_bytes], truncated
    except OSError as exc:
        raise RegistryError(f"could not read {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def write_regular_file_no_follow(path: Path, data: bytes, *, label: str) -> None:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", create=True)
    if parent_fd is None:  # pragma: no cover - create=True never returns None.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    temp_leaf: str | None = None
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        mode = 0o644
        if exists:
            try:
                mode = stat.S_IMODE(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False).st_mode) or 0o644
            except OSError:
                mode = 0o644
        for _attempt in range(20):
            candidate = _leaf_name(Path(f".{leaf}.{os.getpid()}.{secrets.token_hex(8)}.tmp"), label=f"{label} temp")
            try:
                fd = os.open(candidate, _temp_file_open_flags(label=f"{label} temp"), mode, dir_fd=parent_fd)
                temp_leaf = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temp_leaf is None:
            raise RegistryError(f"could not create temporary {label}")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} temp must be a regular file")
        write_all_fd(fd, data)
        try:
            os.fsync(fd)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        fd = -1
        os.replace(temp_leaf, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temp_leaf = None
    except OSError as exc:
        raise RegistryError(f"could not write {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_leaf is not None:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def _reject_parent_traversal(path: Path, *, label: str) -> None:
    if any(part == ".." for part in path.parts):
        raise RegistryError(f"{label} must not contain parent traversal")


def write_regular_file_no_follow_exclusive(path: Path, data: bytes, *, label: str, mode: int = 0o600) -> None:
    _reject_parent_traversal(path, label=label)
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent")
    if parent_fd is None:  # pragma: no cover - missing_ok is not enabled.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    created = False
    success = False
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        if exists:
            raise RegistryError(f"{label} must not already exist")
        flags = _temp_file_open_flags(label=label)
        fd = os.open(leaf, flags, mode, dir_fd=parent_fd)
        created = True
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} must be a regular file")
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
        write_all_fd(fd, data)
        try:
            os.fsync(fd)
        except OSError:
            pass
        success = True
    except FileExistsError as exc:
        raise RegistryError(f"{label} must not already exist") from exc
    except OSError as exc:
        raise RegistryError(f"could not write {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if created and not success:
            try:
                os.unlink(_leaf_name(path, label=label), dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def append_jsonl_no_follow(path: Path, payload: dict[str, Any], *, label: str) -> int:
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", create=True)
    if parent_fd is None:  # pragma: no cover - create=True never returns None.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    try:
        leaf = _leaf_name(path, label=label)
        _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        fd = os.open(leaf, _append_file_open_flags(label=label), 0o600, dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} must be a regular file")
        data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        write_all_fd(fd, data)
        try:
            os.fsync(fd)
        except OSError:
            pass
        return len(data)
    except OSError as exc:
        raise RegistryError(f"could not append {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.fsync(parent_fd)
        except OSError:
            pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def preflight_append_jsonl_no_follow(path: Path, *, label: str) -> None:
    """Validate that a JSONL append target is no-follow appendable before side effects."""
    path = normalize_local_path(path)
    parent_fd = open_directory_no_follow(path.parent, label=f"{label} parent", create=True)
    if parent_fd is None:  # pragma: no cover - create=True never returns None.
        raise RegistryError(f"could not inspect {label} parent")
    fd = -1
    temp_leaf: str | None = None
    try:
        leaf = _leaf_name(path, label=label)
        exists = _precheck_regular_leaf(parent_fd, leaf, label=label, missing_ok=True)
        if exists:
            fd = os.open(leaf, _append_file_open_flags(label=label), 0o600, dir_fd=parent_fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RegistryError(f"{label} must be a regular file")
            return
        for _attempt in range(20):
            candidate = _leaf_name(Path(f".{leaf}.{os.getpid()}.{secrets.token_hex(8)}.preflight"), label=f"{label} preflight")
            try:
                fd = os.open(candidate, _temp_file_open_flags(label=f"{label} preflight"), 0o600, dir_fd=parent_fd)
                temp_leaf = candidate
                break
            except FileExistsError:
                continue
        if fd < 0 or temp_leaf is None:
            raise RegistryError(f"could not create temporary {label} preflight")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RegistryError(f"{label} preflight temp must be a regular file")
    except OSError as exc:
        raise RegistryError(f"could not append {label}: {os_error_detail(exc)}") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_leaf is not None:
            try:
                os.unlink(temp_leaf, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def resolve_root(raw_root: str | None) -> Path:
    root = Path(raw_root) if raw_root else Path.cwd()
    try:
        return root.expanduser().resolve()
    except OSError as exc:
        raise RegistryError(f"could not resolve root: {root}: {exc}") from exc


def resolve_config_path(root: Path, raw_config: str | None) -> Path:
    if raw_config:
        candidate = Path(raw_config)
    else:
        candidate = DEFAULT_CONFIG
    return normalize_project_path(root, candidate, label="config path")


def load_config(path: Path) -> dict[str, Any]:
    loaded = read_bounded_regular_file(path, max_bytes=MAX_CONFIG_BYTES, label="config", missing_ok=True)
    if loaded is None:
        return {"schema_version": CONFIG_SCHEMA_VERSION, "enabled": []}
    raw, truncated = loaded
    if truncated:
        raise RegistryError("config exceeded max bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"could not decode config UTF-8: {path}: {exc.reason}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse config JSON: {path}: {exc.msg}") from exc
    except OSError as exc:
        raise RegistryError(f"could not read config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RegistryError(f"config must be a JSON object: {path}")
    schema = data.get("schema_version")
    if schema not in (None, CONFIG_SCHEMA_VERSION):
        raise RegistryError(f"unsupported config schema_version: {schema!r}")
    enabled = data.get("enabled", [])
    if not isinstance(enabled, list) or not all(isinstance(item, str) for item in enabled):
        raise RegistryError("config enabled must be a list of experiment ids")
    return {"schema_version": CONFIG_SCHEMA_VERSION, "enabled": sorted(set(enabled))}


def write_config(path: Path, enabled: set[str]) -> dict[str, Any]:
    data = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "enabled": sorted(enabled),
    }
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_regular_file_no_follow(path, payload, label="config")
    return data


def configured_enabled_set(config: dict[str, Any]) -> set[str]:
    return set(config.get("enabled", []))


def enabled_set(config: dict[str, Any]) -> set[str]:
    return {item for item in configured_enabled_set(config) if item in REGISTRY}


def unknown_enabled(config: dict[str, Any]) -> list[str]:
    return sorted(item for item in set(config.get("enabled", [])) if item not in REGISTRY)


def registry_payload(*, config_path: Path, config: dict[str, Any], root: Path) -> dict[str, Any]:
    enabled = enabled_set(config)
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "root": str(root),
        "config_path": str(config_path),
        "default_off": True,
        "note": "Experiments are opt-in metadata gates; enabling an experiment does not activate stable runtime behavior by itself.",
        "unknown_enabled": unknown_enabled(config),
        "experiments": [experiment.to_json(enabled=experiment.id in enabled) for experiment in EXPERIMENTS],
    }


def emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def emit_human(payload: dict[str, Any], *, include_details: bool = False) -> None:
    print("ContextGuard experiments (default off; explicit opt-in required)")
    print(f"Config: {payload['config_path']}")
    print("Enabling an experiment records project-local intent only; helpers still require explicit experimental use.")
    for experiment in payload["experiments"]:
        state = "enabled" if experiment["enabled"] else "disabled"
        print(f"- {experiment['id']}: {state} [{experiment['stability']}, risk={experiment['risk_level']}]")
        if include_details:
            print(f"  {experiment['summary']}")
            print(f"  Runtime: {experiment['runtime_status']}")
            if experiment["commands"]:
                print("  Commands: " + "; ".join(experiment["commands"]))
            if experiment["opt_in_flags"]:
                print("  Opt-in flags: " + ", ".join(experiment["opt_in_flags"]))
            print(f"  Config effect: {experiment['config_effect']}")
            print(f"  Evidence contract: {experiment['evidence_contract']}")
            print(f"  Claim boundary: {experiment['claim_boundary']}")
    if payload["unknown_enabled"]:
        print("Unknown enabled ids in config: " + ", ".join(payload["unknown_enabled"]))


def require_known(experiment_id: str) -> Experiment:
    try:
        return REGISTRY[experiment_id]
    except KeyError:
        choices = ", ".join(sorted(REGISTRY))
        fail(f"unknown experiment id {experiment_id!r}; known ids: {choices}")


def command_list(args: argparse.Namespace) -> int:
    root, config_path, config = load_args_context(args)
    payload = registry_payload(config_path=config_path, config=config, root=root)
    if args.json:
        emit_json(payload)
    else:
        emit_human(payload, include_details=True)
    return 0


def command_status(args: argparse.Namespace) -> int:
    root, config_path, config = load_args_context(args)
    payload = registry_payload(config_path=config_path, config=config, root=root)
    if args.json:
        emit_json(payload)
    else:
        emit_human(payload, include_details=False)
    return 0


def command_enable(args: argparse.Namespace) -> int:
    require_known(args.experiment_id)
    root, config_path, config = load_args_context(args)
    enabled = configured_enabled_set(config)
    changed = args.experiment_id not in enabled
    enabled.add(args.experiment_id)
    written = write_config(config_path, enabled)
    payload = registry_payload(config_path=config_path, config=written, root=root)
    payload["changed"] = changed
    payload["experiment_id"] = args.experiment_id
    if args.json:
        emit_json(payload)
    else:
        print(f"enabled {args.experiment_id} in {config_path}")
    return 0


def command_disable(args: argparse.Namespace) -> int:
    require_known(args.experiment_id)
    root, config_path, config = load_args_context(args)
    enabled = configured_enabled_set(config)
    changed = args.experiment_id in enabled
    enabled.discard(args.experiment_id)
    written = write_config(config_path, enabled)
    payload = registry_payload(config_path=config_path, config=written, root=root)
    payload["changed"] = changed
    payload["experiment_id"] = args.experiment_id
    if args.json:
        emit_json(payload)
    else:
        print(f"disabled {args.experiment_id} in {config_path}")
    return 0



DIFF_GIT_RE = re.compile(r"^diff --git (?P<old>\S+) (?P<new>\S+)$")
HUNK_RE = re.compile(r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_count>\d+))?\s+\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))?\s+@@(?P<section>.*)$")
CONTEXT_DIFF_ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")


def read_bounded_input(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    source_label = args.source_label
    if args.input:
        path = Path(args.input)
        source_label = source_label or str(path)
        loaded = read_bounded_regular_file(path, max_bytes=MAX_CONTEXT_DIFF_INPUT_BYTES, label="input")
        assert loaded is not None
        raw, truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_CONTEXT_DIFF_INPUT_BYTES + 1)
        truncated = len(raw) > MAX_CONTEXT_DIFF_INPUT_BYTES
        raw = raw[:MAX_CONTEXT_DIFF_INPUT_BYTES]
    if not raw:
        raise RegistryError("context-diff-compaction plan requires diff input on stdin or --input")
    text = raw.decode("utf-8", errors="replace")
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": truncated,
        "max_bytes": MAX_CONTEXT_DIFF_INPUT_BYTES,
    }
    return text, metadata


def strip_diff_prefix(path: str) -> str:
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def summarize_diff(text: str, *, max_files: int = 50, max_hunks: int = 200) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_hunk: dict[str, Any] | None = None
    total_hunks = 0
    summarized_hunks = 0
    lines = text.splitlines()
    diff_header_count = 0
    for line_number, line in enumerate(lines, start=1):
        match = DIFF_GIT_RE.match(line)
        if match:
            diff_header_count += 1
            current_hunk = None
            if len(files) >= max_files:
                current = None
                continue
            current = {
                "old_path": strip_diff_prefix(match.group("old")),
                "new_path": strip_diff_prefix(match.group("new")),
                "diff_header_line": line_number,
                "hunks": [],
            }
            files.append(current)
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            total_hunks += 1
            if current is None:
                if len(files) >= max_files:
                    current_hunk = None
                    continue
                current = {"old_path": None, "new_path": None, "diff_header_line": None, "hunks": []}
                files.append(current)
            if len(current["hunks"]) < max_hunks:
                current_hunk = {
                    "line": line_number,
                    "old_start": int(hunk.group("old_start")),
                    "old_count": int(hunk.group("old_count") or "1"),
                    "new_start": int(hunk.group("new_start")),
                    "new_count": int(hunk.group("new_count") or "1"),
                    "section": hunk.group("section").strip()[:120],
                    "added_lines": 0,
                    "removed_lines": 0,
                    "context_lines": 0,
                    "body_lines": 0,
                    "reviewable": False,
                }
                current["hunks"].append(current_hunk)
                summarized_hunks += 1
            else:
                current_hunk = None
            continue
        if current_hunk is not None:
            changed = False
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk["added_lines"] += 1
                changed = True
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk["removed_lines"] += 1
                changed = True
            elif line.startswith(" "):
                current_hunk["context_lines"] += 1
            else:
                continue
            current_hunk["body_lines"] += 1
    reviewable_hunks = 0
    malformed_hunks = 0
    for file_summary in files:
        for hunk_summary in file_summary["hunks"]:
            old_body_lines = hunk_summary["removed_lines"] + hunk_summary["context_lines"]
            new_body_lines = hunk_summary["added_lines"] + hunk_summary["context_lines"]
            has_changes = bool(hunk_summary["added_lines"] or hunk_summary["removed_lines"])
            well_formed = (
                old_body_lines == hunk_summary["old_count"]
                and new_body_lines == hunk_summary["new_count"]
            )
            hunk_summary["old_body_lines"] = old_body_lines
            hunk_summary["new_body_lines"] = new_body_lines
            hunk_summary["has_changes"] = has_changes
            hunk_summary["well_formed"] = well_formed
            hunk_summary["reviewable"] = bool(has_changes and well_formed)
            if hunk_summary["reviewable"]:
                reviewable_hunks += 1
            elif not well_formed:
                malformed_hunks += 1
    return {
        "file_count": len(files),
        "hunk_count": total_hunks,
        "summarized_hunk_count": summarized_hunks,
        "reviewable_hunk_count": reviewable_hunks,
        "malformed_hunk_count": malformed_hunks,
        "truncated_files": max(0, diff_header_count - len(files)),
        "truncated_hunks": max(0, total_hunks - summarized_hunks),
        "files": files,
    }


def valid_context_diff_reexpand_command(receipt_id: str | None, command: str | None) -> tuple[bool, str | None]:
    if not receipt_id or not command:
        return False, "missing_exact_receipt_or_reexpand_command"
    if not CONTEXT_DIFF_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command"
    if any(token in command for token in (";", "|", "&", ">", "<", "`", "$", "\n", "\r")):
        return False, "invalid_reexpand_command"
    try:
        argv = shlex.split(command)
    except ValueError:
        return False, "invalid_reexpand_command"
    if argv == ["context-guard-artifact", "get", receipt_id, "--full"]:
        return True, None
    if argv == ["context-guard", "artifact", "get", receipt_id, "--full"]:
        return True, None
    return False, "invalid_reexpand_command"


def context_diff_artifact_read_dirs() -> list[Path]:
    return [DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR, LEGACY_CONTEXT_DIFF_ARTIFACT_DIR]


def context_diff_artifact_paths(directory: Path, receipt_id: str) -> tuple[Path, Path]:
    return directory / f"{receipt_id}.txt", directory / f"{receipt_id}.json"


def verify_context_diff_artifact(
    receipt_id: str | None,
    *,
    expected_sha256: str,
    expected_bytes: int,
) -> tuple[bool, str | None, dict[str, Any]]:
    if not receipt_id or not CONTEXT_DIFF_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command", {"checked": False, "read_directories": []}
    read_dirs = context_diff_artifact_read_dirs()
    details: dict[str, Any] = {
        "checked": True,
        "read_directories": [str(path) for path in read_dirs],
        "matched_directory": None,
        "content_sha256": None,
        "content_bytes": None,
    }
    for directory in read_dirs:
        content_path, meta_path = context_diff_artifact_paths(directory, receipt_id)
        meta_loaded = read_bounded_regular_file(
            meta_path,
            max_bytes=MAX_CONTEXT_DIFF_ARTIFACT_METADATA_BYTES,
            label="context-diff artifact metadata",
            missing_ok=True,
        )
        content_loaded = read_bounded_regular_file(
            content_path,
            max_bytes=max(MAX_CONTEXT_DIFF_INPUT_BYTES, expected_bytes),
            label="context-diff artifact content",
            missing_ok=True,
        )
        if meta_loaded is None and content_loaded is None:
            continue
        if meta_loaded is None or content_loaded is None:
            return False, "artifact_receipt_invalid", details
        meta_raw, meta_truncated = meta_loaded
        content_raw, content_truncated = content_loaded
        if meta_truncated or content_truncated:
            return False, "artifact_receipt_invalid", details
        try:
            metadata = json.loads(meta_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "artifact_receipt_invalid", details
        if not isinstance(metadata, dict) or metadata.get("artifact_id") != receipt_id:
            return False, "artifact_receipt_invalid", details
        stored = metadata.get("stored_output")
        stored_sha = stored.get("sha256") if isinstance(stored, dict) else None
        stored_bytes = stored.get("bytes") if isinstance(stored, dict) else None
        actual_sha = hashlib.sha256(content_raw).hexdigest()
        actual_bytes = len(content_raw)
        details.update({
            "matched_directory": str(directory),
            "content_sha256": actual_sha,
            "content_bytes": actual_bytes,
        })
        if stored_sha != actual_sha or stored_bytes != actual_bytes:
            return False, "artifact_receipt_invalid", details
        if actual_sha != expected_sha256 or actual_bytes != expected_bytes:
            return False, "artifact_content_mismatch", details
        return True, None, details
    return False, "artifact_receipt_not_found", details


def read_context_diff_replacement(args: argparse.Namespace) -> tuple[str | None, dict[str, Any]]:
    if args.replacement_text is not None and args.replacement_file:
        raise RegistryError("context-diff-compaction emit accepts only one of --replacement-text or --replacement-file")
    if args.replacement_text is not None:
        text = str(args.replacement_text)
        raw = text.encode("utf-8")
        truncated = len(raw) > MAX_CONTEXT_DIFF_REPLACEMENT_BYTES
        raw = raw[:MAX_CONTEXT_DIFF_REPLACEMENT_BYTES]
        text = raw.decode("utf-8", errors="replace")
        source_label = "inline"
    elif args.replacement_file:
        path = Path(args.replacement_file)
        loaded = read_bounded_regular_file(
            path,
            max_bytes=MAX_CONTEXT_DIFF_REPLACEMENT_BYTES,
            label="context-diff replacement",
        )
        assert loaded is not None
        raw, truncated = loaded
        text = raw.decode("utf-8", errors="replace")
        source_label = str(path)
    else:
        text = None
        raw = b""
        truncated = False
        source_label = None
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()) if text is not None else 0,
        "sha256": hashlib.sha256(raw).hexdigest() if text is not None else None,
        "truncated": truncated,
        "max_bytes": MAX_CONTEXT_DIFF_REPLACEMENT_BYTES,
    }
    return text, metadata


def context_diff_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    text, input_meta = read_bounded_input(args)
    summary = summarize_diff(text)
    receipt_id = args.receipt_id.strip() if args.receipt_id else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    has_exact_handle = bool(receipt_id and reexpand_command)
    readiness_blockers: list[str] = []
    if not has_exact_handle:
        readiness_blockers.append("missing_exact_receipt_or_reexpand_command")
    if input_meta["truncated"]:
        readiness_blockers.append("input_truncated")
    if summary.get("truncated_files", 0) or summary.get("truncated_hunks", 0):
        readiness_blockers.append("diff_summary_truncated")
    if summary.get("malformed_hunk_count", 0):
        readiness_blockers.append("malformed_diff_hunks")
    if summary["file_count"] == 0 or summary.get("reviewable_hunk_count", 0) == 0:
        readiness_blockers.append("no_reviewable_diff_hunks")
    status = (
        "ready_for_human_review"
        if not readiness_blockers
        else "blocked_until_reviewable_diff"
        if has_exact_handle
        else "blocked_until_exact_receipt"
    )
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "context-diff-compaction",
        "mode": "dry_run",
        "status": status,
        "input": input_meta,
        "transform_policy": {
            "automatic_compaction": False,
            "lossy_replacement_allowed": False,
            "semantic_rewrite_allowed": False,
            "human_review_required": True,
            "stable_runtime_behavior_changed": False,
        },
        "exact_retrieval": {
            "required": True,
            "available": has_exact_handle,
            "artifact_id": receipt_id,
            "cli": reexpand_command,
            "verified": False,
            "note": "Dry-run planning records user-supplied handles for human review only; it does not verify local receipt storage.",
        },
        "review_plan": {
            "summary": summary,
            "readiness_blockers": readiness_blockers,
            "bounded_loss_disclosure": (
                "No compacted replacement was produced. Any future lossy replacement must keep this diff reviewable "
                "and provide exact receipt/re-expand handles before use."
            ),
            "next_steps": [
                "Store exact original evidence with context-guard-artifact or another local receipt before compacting.",
                "Review file and hunk summaries against the original diff.",
                "Do not claim hosted token/cost savings from this dry-run plan.",
            ],
        },
        "claim_boundary": "Dry-run local planning only; no hosted API token/cost savings claim without provider-measured matched successful tasks.",
        "compacted_replacement": None,
    }


def command_plan_context_diff_compaction(args: argparse.Namespace) -> int:
    payload = context_diff_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard context-diff compaction plan (dry-run only)")
        print("No compaction was performed and no replacement text was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Input: {payload['input']['source_label']} lines={payload['input']['lines']} sha256={payload['input']['sha256']}")
        print(
            f"Review summary: files={payload['review_plan']['summary']['file_count']} "
            f"hunks={payload['review_plan']['summary']['hunk_count']}"
        )
        if not payload["exact_retrieval"]["available"]:
            print("Exact receipt/re-expand command required before any lossy replacement can be reviewed.")
        else:
            print("Exact retrieval handle supplied for human review only; verified=false.")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def context_diff_emit_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = context_diff_plan_payload(args)
    receipt_id = args.receipt_id.strip() if args.receipt_id else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, reexpand_blocker = valid_context_diff_reexpand_command(receipt_id, reexpand_command)
    replacement_text, replacement_meta = read_context_diff_replacement(args)
    artifact_verified = False
    artifact_blocker = None
    artifact_verification: dict[str, Any] = {"checked": False, "read_directories": []}
    if reexpand_valid:
        artifact_verified, artifact_blocker, artifact_verification = verify_context_diff_artifact(
            receipt_id,
            expected_sha256=payload["input"]["sha256"],
            expected_bytes=payload["input"]["bytes"],
        )

    blockers = list(payload["review_plan"]["readiness_blockers"])
    if reexpand_blocker:
        blockers.append(reexpand_blocker)
    if artifact_blocker:
        blockers.append(artifact_blocker)
    if replacement_text is None or not replacement_text.strip():
        blockers.append("missing_compacted_replacement")
    if replacement_meta["truncated"]:
        blockers.append("replacement_truncated")
    if (
        replacement_text is not None
        and not replacement_meta["truncated"]
        and replacement_meta["bytes"] >= payload["input"]["bytes"]
    ):
        blockers.append("replacement_not_smaller_than_input")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    replacement_record = None
    if ready and replacement_text is not None:
        replacement_record = {
            "text": replacement_text,
            "bytes": replacement_meta["bytes"],
            "lines": replacement_meta["lines"],
            "sha256": replacement_meta["sha256"],
            "source_label": replacement_meta["source_label"],
        }

    payload["mode"] = "emit"
    payload["status"] = "replacement_emitted" if ready else "blocked_until_emit_ready"
    payload["transform_policy"] = {
        "automatic_compaction": False,
        "lossy_replacement_allowed": ready,
        "semantic_rewrite_allowed": False,
        "caller_supplied_replacement_required": True,
        "human_review_required": True,
        "stable_runtime_behavior_changed": False,
    }
    payload["exact_retrieval"] = {
        "required": True,
        "available": bool(receipt_id and reexpand_command and reexpand_valid and artifact_verified),
        "artifact_id": receipt_id,
        "cli": reexpand_command,
        "verified": artifact_verified,
        "valid_command_shape": reexpand_valid,
        "verification": artifact_verification,
        "note": "Emit mode validates exact local artifact command shape and verifies local artifact content matches the input diff.",
    }
    payload["replacement"] = replacement_meta
    payload["review_plan"]["readiness_blockers"] = blockers
    payload["review_plan"]["bounded_loss_disclosure"] = (
        "Compacted replacement is caller supplied and lossy; use exact_retrieval.cli to recover the original diff "
        "before relying on omitted details."
    )
    payload["review_plan"]["next_steps"] = [
        "Human-review the compacted replacement against the original diff before use.",
        "Use exact_retrieval.cli to recover the original diff whenever omitted details matter.",
        "Treat bytes_before/bytes_after as local proxy evidence only; do not claim hosted token/cost savings.",
    ]
    payload["claim_boundary"] = (
        "Explicit local context-diff replacement emission only; smaller local diffs are proxy evidence and are not "
        "hosted API token or cost savings evidence."
    )
    bytes_after = replacement_meta["bytes"] if replacement_text is not None else 0
    payload["compaction_evidence"] = {
        "bytes_before": payload["input"]["bytes"],
        "bytes_after": bytes_after,
        "byte_reduction": max(0, payload["input"]["bytes"] - bytes_after),
        "byte_reduction_proxy_only": True,
        "hosted_api_token_savings_claim_allowed": False,
        "hosted_api_cost_savings_claim_allowed": False,
    }
    payload["compacted_replacement"] = replacement_record
    return payload


def command_emit_context_diff_compaction(args: argparse.Namespace) -> int:
    payload = context_diff_emit_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "replacement_emitted":
            print("ContextGuard context-diff compact replacement emitted")
            print(
                f"Replacement: bytes={payload['replacement']['bytes']} "
                f"sha256={payload['replacement']['sha256']}"
            )
            print(f"Exact re-expand: {payload['exact_retrieval']['cli']}")
        else:
            print("ContextGuard context-diff compact replacement blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "replacement_emitted" else 1


def clean_values(values: list[str] | None) -> list[str]:
    return [value.strip() for value in values or [] if value.strip()]


def parse_int_tuple(raw: str | None, *, count: int) -> tuple[int, ...] | None:
    if raw is None or not raw.strip():
        return None
    parts = [part.strip() for part in raw.split(",")]
    if len(parts) != count:
        return None
    try:
        return tuple(int(part, 10) for part in parts)
    except ValueError:
        return None


def crop_payload(bounds: tuple[int, ...] | None, image_size: tuple[int, ...] | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    bounds_payload = None
    image_payload = None
    if bounds is not None:
        x, y, width, height = bounds
        bounds_payload = {"x": x, "y": y, "width": width, "height": height}
    if image_size is not None:
        width, height = image_size
        image_payload = {"width": width, "height": height}
    return bounds_payload, image_payload


def valid_crop_geometry(bounds: tuple[int, ...] | None, image_size: tuple[int, ...] | None) -> tuple[bool, bool]:
    if bounds is None or image_size is None:
        return False, False
    x, y, crop_width, crop_height = bounds
    image_width, image_height = image_size
    if x < 0 or y < 0 or crop_width <= 0 or crop_height <= 0 or image_width <= 0 or image_height <= 0:
        return False, False
    if x + crop_width > image_width or y + crop_height > image_height:
        return True, True
    return True, False


def parse_confidence(raw: str | None) -> tuple[float | None, str | None]:
    if raw is None or not raw.strip():
        return None, "missing"
    try:
        value = float(raw)
    except ValueError:
        return None, "invalid"
    if not (0.0 <= value <= 1.0):
        return None, "invalid"
    return value, None


def read_visual_ocr_text(args: argparse.Namespace) -> dict[str, Any]:
    if args.ocr_text is not None and args.ocr_text_file is not None:
        raise RegistryError("--ocr-text and --ocr-text-file are mutually exclusive")
    if args.ocr_text_file is not None:
        path = Path(args.ocr_text_file)
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else path.name
        loaded = read_bounded_regular_file(path, max_bytes=MAX_VISUAL_OCR_TEXT_BYTES, label="OCR text file")
        assert loaded is not None
        raw, truncated = loaded
        source_type = "file"
    elif args.ocr_text is not None:
        raw = args.ocr_text.encode("utf-8")
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else "inline"
        source_type = "inline"
        truncated = len(raw) > MAX_VISUAL_OCR_TEXT_BYTES
        raw = raw[:MAX_VISUAL_OCR_TEXT_BYTES]
    else:
        raw = b""
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else None
        source_type = None
        truncated = False
    try:
        text = raw.decode("utf-8")
        valid_encoding = True
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        valid_encoding = False
    return {
        "source_type": source_type,
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "truncated": truncated,
        "max_bytes": MAX_VISUAL_OCR_TEXT_BYTES,
        "valid_utf8": valid_encoding,
        "text": text,
        "text_preview": text,
        "has_text": bool(text.strip()),
    }


def visual_crop_ocr_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    full_receipt = args.full_evidence_receipt.strip() if args.full_evidence_receipt else None
    full_label = args.full_evidence_label.strip() if args.full_evidence_label else None
    missed_context_notes = clean_values(args.missed_context_note)
    ocr_error_notes = clean_values(args.ocr_error_note)
    crop_label = args.crop_label.strip() if args.crop_label else None

    bounds = parse_int_tuple(args.crop_bounds, count=4)
    image_size = parse_int_tuple(args.image_size, count=2)
    bounds_payload, image_payload = crop_payload(bounds, image_size)
    crop_fields_present = any(value is not None and str(value).strip() for value in (args.crop_label, args.crop_bounds, args.image_size))
    crop_geometry_valid, crop_exceeds = valid_crop_geometry(bounds, image_size)
    crop_complete = bool(crop_label and crop_geometry_valid and not crop_exceeds)

    ocr_text = read_visual_ocr_text(args)
    confidence, confidence_error = parse_confidence(args.ocr_confidence)
    ocr_fields_present = any(
        [
            args.ocr_text is not None,
            args.ocr_text_file is not None,
            args.ocr_confidence is not None,
            bool(ocr_error_notes),
        ]
    )
    ocr_complete = bool(
        ocr_text["has_text"]
        and ocr_text["valid_utf8"]
        and not ocr_text["truncated"]
        and confidence_error is None
        and ocr_error_notes
    )

    blockers: list[str] = []
    if not full_receipt:
        blockers.append("missing_full_evidence_receipt")
    if not missed_context_notes:
        blockers.append("missing_missed_context_note")
    if not crop_complete and not ocr_complete:
        blockers.append("missing_derived_evidence")

    if crop_fields_present and (not crop_label or not crop_geometry_valid):
        blockers.append("invalid_crop_bounds")
    elif crop_fields_present and crop_exceeds:
        blockers.append("crop_exceeds_image_bounds")

    if ocr_fields_present:
        if confidence_error == "missing":
            blockers.append("missing_ocr_confidence")
        elif confidence_error == "invalid":
            blockers.append("invalid_ocr_confidence")
        if not ocr_error_notes:
            blockers.append("missing_ocr_error_note")
        if not ocr_text["has_text"]:
            blockers.append("missing_ocr_text")
        if not ocr_text["valid_utf8"]:
            blockers.append("invalid_ocr_text_encoding")
        if ocr_text["truncated"]:
            blockers.append("ocr_text_truncated")

    # Preserve stable ordering while avoiding duplicates when incomplete derived
    # evidence also contributed path-specific blockers.
    blockers = list(dict.fromkeys(blockers))
    status = "ready_for_human_review" if not blockers else "blocked_until_visual_evidence"

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "visual-crop-ocr",
        "mode": "dry_run",
        "status": status,
        "external_services": {
            "called": False,
            "ocr_service": None,
            "image_service": None,
            "network": False,
        },
        "full_visual_evidence": {
            "required": True,
            "available": bool(full_receipt),
            "receipt_id": full_receipt,
            "label": full_label,
            "verified": False,
            "note": "G004 records user-supplied full visual evidence handles only; it does not verify receipt storage.",
        },
        "derived_evidence": {
            "crop": {
                "available": crop_complete,
                "label": crop_label,
                "bounds": bounds_payload,
                "image_size": image_payload,
                "source": "user_supplied_metadata" if crop_fields_present else None,
            },
            "ocr": {
                "available": ocr_complete,
                "source_type": ocr_text["source_type"],
                "source_label": ocr_text["source_label"],
                "text_preview": ocr_text["text_preview"] if ocr_text["has_text"] else None,
                "metadata": {
                    "bytes": ocr_text["bytes"],
                    "lines": ocr_text["lines"],
                    "sha256": ocr_text["sha256"],
                    "truncated": ocr_text["truncated"],
                    "max_bytes": ocr_text["max_bytes"],
                    "valid_utf8": ocr_text["valid_utf8"],
                },
                "confidence": confidence,
                "error_notes": ocr_error_notes,
            },
        },
        "guardrails": {
            "original_evidence_required": True,
            "full_visual_evidence_must_remain_available": True,
            "external_ocr_service_allowed": False,
            "external_image_service_allowed": False,
            "human_review_required": True,
            "missed_context_review_required": True,
            "confidence_error_notes_required_for_ocr": True,
            "stable_runtime_behavior_changed": False,
            "candidate_replacement_allowed": False,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "missed_context_notes": missed_context_notes,
            "next_steps": [
                "Keep full visual evidence retrievable before relying on cropped or OCR-derived evidence.",
                "Review crop bounds and OCR text against the original evidence for missed context.",
                "Do not claim hosted image/text token or cost savings from this dry-run plan.",
            ],
        },
        "claim_boundary": (
            "Dry-run visual/OCR fixture planning only; no hosted visual/text token or cost savings claim without "
            "provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_visual_crop_ocr(args: argparse.Namespace) -> int:
    payload = visual_crop_ocr_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard visual crop/OCR plan (dry-run only)")
        print("No external OCR/image service was called and no replacement evidence was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Full evidence available: {payload['full_visual_evidence']['available']} verified=false")
        print(
            "Derived evidence: "
            f"crop={payload['derived_evidence']['crop']['available']} "
            f"ocr={payload['derived_evidence']['ocr']['available']}"
        )
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def image_context_pack_size_payload(raw: str | None) -> tuple[dict[str, Any] | None, bool]:
    size = parse_int_tuple(raw, count=2)
    if raw is None or not str(raw).strip():
        return None, True
    if size is None:
        return None, False
    width, height = size
    if width <= 0 or height <= 0:
        return {"width": width, "height": height}, False
    return {"width": width, "height": height}, True


def image_context_pack_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    receipt_id = args.exact_text_fallback_receipt.strip() if args.exact_text_fallback_receipt else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, fallback_blocker = valid_learned_reexpand_command(receipt_id, reexpand_command)
    fallback_blocker_map = {
        "missing_exact_fallback": "missing_exact_text_fallback",
        "invalid_reexpand_command": "invalid_exact_text_reexpand_command",
    }
    source_size, source_size_valid = image_context_pack_size_payload(args.image_size)
    packed_size, packed_size_valid = image_context_pack_size_payload(args.packed_image_size)
    missed_context_notes = clean_values(args.missed_context_note)
    protected_policy = (args.protected_zone_policy or "deny").strip().lower()

    blockers: list[str] = []
    if fallback_blocker:
        blockers.append(fallback_blocker_map.get(fallback_blocker, fallback_blocker))
    if not args.provider_boundary_ack:
        blockers.append("missing_provider_measurement_boundary")
    if not missed_context_notes:
        blockers.append("missing_missed_context_note")
    if protected_policy != "deny":
        blockers.append("protected_zone_denial_required")
    if not source_size_valid:
        blockers.append("invalid_image_size")
    if not packed_size_valid:
        blockers.append("invalid_packed_image_size")
    blockers = list(dict.fromkeys(blockers))

    source_area = source_size["width"] * source_size["height"] if source_size and source_size_valid else None
    packed_area = packed_size["width"] * packed_size["height"] if packed_size and packed_size_valid else None
    area_delta = source_area - packed_area if source_area is not None and packed_area is not None else None
    ready = not blockers

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "plan_schema_version": IMAGE_CONTEXT_PACK_PLAN_SCHEMA_VERSION,
        "experiment_id": "image-context-pack",
        "mode": "dry_run",
        "status": "ready_for_plan_review" if ready else "blocked_until_image_context_pack_gate_ready",
        "plan_only": {
            "command_advertised": True,
            "emit_command_available": False,
            "record_command_available": False,
            "serve_command_available": False,
            "runtime_behavior_changed": False,
            "replacement_or_visual_evidence_emitted": False,
        },
        "external_services": {
            "called": False,
            "network": False,
            "model_calls": False,
            "ocr_service": None,
            "image_service": None,
            "proxy_forwarding": False,
        },
        "runtime_side_effects": {
            "files_written": False,
            "image_rendering": False,
            "ocr_execution": False,
            "image_parsing": False,
            "binary_artifacts_written": False,
            "proxy_forwarding": False,
            "stable_runtime_behavior_changed": False,
        },
        "text_fallback": {
            "required": True,
            "available": bool(reexpand_valid),
            "receipt_id": receipt_id,
            "reexpand_command": reexpand_command,
            "verified": False,
            "must_be_verified_before_omitted_text_is_used": True,
            "note": (
                "This dry-run validates only local receipt/re-expand shape. A future runtime must verify exact "
                "text artifact content before relying on omitted exact text."
            ),
        },
        "protected_zones": {
            "policy": protected_policy,
            "override_allowed": False,
            "denied_classes": [
                "code",
                "diffs",
                "identifiers",
                "hashes",
                "paths",
                "numeric_constants",
                "json_keys",
                "stack_frames",
                "secrets",
                "prompt_like_instructions",
            ],
        },
        "image_pack_plan": {
            "source_label": sanitize_self_hosted_text(args.source_label) if args.source_label else "manual-plan",
            "source_image_size": source_size,
            "packed_image_size": packed_size,
            "source_area": source_area,
            "packed_area": packed_area,
            "area_delta": area_delta,
            "area_reduction_is_proxy_only": area_delta is not None,
            "image_or_request_byte_reductions_are_proxy_evidence_only": True,
        },
        "measurement_boundary": {
            "provider_boundary_acknowledged": bool(args.provider_boundary_ack),
            "provider_boundary_policy": IMAGE_CONTEXT_PACK_PROVIDER_BOUNDARY,
            "provider_measured_matched_tasks_required_for_hosted_claims": True,
            "provider_model_specific": True,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
        },
        "relation_to_visual_crop_ocr": {
            "visual_crop_ocr_is_existing_surface": True,
            "visual_crop_ocr_remains_caller_supplied_visual_evidence_pack": True,
            "image_context_pack_is_planning_gate_not_duplicate_emitter": True,
            "verified_exact_binary_or_image_fallback_claimed": False,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "missed_context_notes": missed_context_notes,
            "next_steps": [
                "Keep exact text artifact fallback verified before any future image/context packing omits source text.",
                "Deny protected evidence zones before any future lossy visual packing is considered.",
                "Measure provider/model token and cost fields on matched successful tasks before any hosted savings claim.",
                "Use visual-crop-ocr only for caller-supplied visual evidence packs; this gate emits no images or evidence.",
            ],
        },
        "claim_boundary": (
            "Dry-run image-context-pack planning only; image/request byte reductions are proxy evidence and no hosted "
            "token/cost savings claim is allowed without provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_image_context_pack(args: argparse.Namespace) -> int:
    payload = image_context_pack_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard image-context-pack plan (dry-run only)")
        print("No image rendering, OCR/image service, model call, proxy forwarding, binary artifact, or replacement was emitted.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def semantic_checkpoint_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    goal = args.goal.strip() if args.goal else None
    receipt_id = args.exact_context_fallback_receipt.strip() if args.exact_context_fallback_receipt else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, fallback_blocker = valid_learned_reexpand_command(receipt_id, reexpand_command)
    fallback_blocker_map = {
        "missing_exact_fallback": "missing_exact_context_fallback",
        "invalid_reexpand_command": "invalid_exact_context_reexpand_command",
    }
    protected_policy = (args.protected_zone_policy or "deny").strip().lower()
    missed_context_notes = clean_values(args.missed_context_note)
    missing_provenance_notes = clean_values(args.missing_provenance_note)

    blockers: list[str] = []
    if not goal:
        blockers.append("missing_goal")
    if fallback_blocker:
        blockers.append(fallback_blocker_map.get(fallback_blocker, fallback_blocker))
    if not args.provider_boundary_ack:
        blockers.append("missing_provider_measurement_boundary")
    if protected_policy != "deny":
        blockers.append("protected_zone_denial_required")
    if not missed_context_notes:
        blockers.append("missing_missed_context_note")
    if not missing_provenance_notes:
        blockers.append("missing_provenance_review")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "plan_schema_version": SEMANTIC_CHECKPOINT_PLAN_SCHEMA_VERSION,
        "experiment_id": "semantic-checkpoint",
        "mode": "dry_run",
        "status": "ready_for_plan_review" if ready else "blocked_until_semantic_checkpoint_gate_ready",
        "plan_only": {
            "command_advertised": True,
            "emit_command_available": False,
            "record_command_available": False,
            "serve_command_available": False,
            "runtime_behavior_changed": False,
            "replacement_context_emitted": False,
        },
        "external_services": {
            "called": False,
            "network": False,
            "model_calls": False,
            "provider_calls": False,
            "proxy_forwarding": False,
        },
        "runtime_side_effects": {
            "files_written": False,
            "transcript_edited": False,
            "prompt_edited": False,
            "context_replaced": False,
            "stable_runtime_behavior_changed": False,
        },
        "checkpoint_metadata": {
            "goal": goal,
            "constraints": clean_values(args.constraint),
            "decisions": clean_values(args.decision),
            "open_tasks": clean_values(args.open_task),
            "evidence_provenance_handles": clean_values(args.evidence_handle),
            "unresolved_questions": clean_values(args.unresolved_question),
        },
        "exact_context_fallback": {
            "required": True,
            "available": bool(reexpand_valid),
            "receipt_id": receipt_id,
            "reexpand_command": reexpand_command,
            "verified": False,
            "must_be_verified_before_checkpoint_metadata_is_used": True,
            "allowed_reexpand_shapes": [
                "context-guard-artifact get RECEIPT --full",
                "context-guard artifact get RECEIPT --full",
            ],
        },
        "protected_zones": {
            "policy": protected_policy,
            "override_allowed": False,
            "denied_classes": [
                "code",
                "diffs",
                "identifiers",
                "hashes",
                "paths",
                "numeric_constants",
                "json_keys",
                "stack_frames",
                "secrets",
                "prompt_like_instructions",
            ],
        },
        "measurement_boundary": {
            "provider_boundary_acknowledged": bool(args.provider_boundary_ack),
            "provider_boundary_policy": IMAGE_CONTEXT_PACK_PROVIDER_BOUNDARY,
            "provider_measured_matched_tasks_required_for_hosted_claims": True,
            "provider_model_specific": True,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
        },
        "provenance_review": {
            "required": True,
            "reviewed": bool(missing_provenance_notes),
            "missing_provenance_notes": missing_provenance_notes,
            "missing_provenance_warnings": [] if missing_provenance_notes else ["missing_provenance_review"],
            "checkpoint_cannot_replace_raw_context_without_complete_provenance": True,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "missed_context_notes": missed_context_notes,
            "next_steps": [
                "Keep exact raw context fallback verified before checkpoint metadata is used.",
                "Deny protected evidence zones before any semantic checkpoint summary is considered.",
                "Keep provenance handles and missing-provenance review notes attached to checkpoint metadata.",
                "Measure provider/model token and cost fields on matched successful tasks before any hosted savings claim.",
            ],
        },
        "claim_boundary": (
            "Dry-run semantic-checkpoint planning only; checkpoint metadata is not replacement context and no hosted "
            "token/cost savings claim is allowed without provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_semantic_checkpoint(args: argparse.Namespace) -> int:
    payload = semantic_checkpoint_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard semantic-checkpoint plan (dry-run only)")
        print("No files, prompts, transcripts, model/provider calls, proxy forwarding, or replacement context were emitted.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


_PROOF_NONFINITE_SENTINEL = object()


def ordered_proof_taxonomy(values: list[str] | set[str], order: tuple[str, ...]) -> list[str]:
    selected = set(values)
    return [value for value in order if value in selected]


def empty_proof_unit_row(unit_index: int, issue: str) -> dict[str, Any]:
    return {
        "captured_at": None,
        "content_hash": {
            "algorithm": "sha256",
            "content_verified": False,
            "syntax_valid": False,
            "value": None,
        },
        "receipt": {
            "id": None,
            "storage_checked": False,
            "syntax_valid": False,
        },
        "rehydration": {
            "command": None,
            "executed": False,
            "receipt_bound": False,
            "syntax_valid": False,
        },
        "safe_range": None,
        "source_label": None,
        "syntax_and_consistency_valid": False,
        "transform_policy": None,
        "unit_index": unit_index,
        "validation_issues": [issue],
        "warnings": [],
    }


def decode_proof_unit_json(raw: Any, unit_index: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(raw, str):
        return None, empty_proof_unit_row(unit_index, "invalid_proof_unit_json")
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        return None, empty_proof_unit_row(unit_index, "invalid_proof_unit_unicode")
    if len(encoded) > PROOF_CARRYING_CONTEXT_UNIT_JSON_BYTE_CAP:
        return None, empty_proof_unit_row(unit_index, "proof_unit_json_too_large")

    duplicate_keys = False

    def proof_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate_keys
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicate_keys = True
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=proof_object_pairs_hook,
            parse_constant=lambda _value: _PROOF_NONFINITE_SENTINEL,
        )
    except RecursionError:
        return None, empty_proof_unit_row(unit_index, "proof_unit_json_nesting_too_deep")
    except (json.JSONDecodeError, ValueError, TypeError):
        return None, empty_proof_unit_row(unit_index, "invalid_proof_unit_json")

    depth_exceeded = False
    decoded_unicode_invalid = False
    nonfinite_number = False
    stack: list[tuple[Any, int]] = [(decoded, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > PROOF_UNIT_JSON_MAX_DEPTH:
            depth_exceeded = True
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                decoded_unicode_invalid = True
        elif value is _PROOF_NONFINITE_SENTINEL:
            nonfinite_number = True
        elif type(value) is float and not math.isfinite(value):
            nonfinite_number = True

        if depth > PROOF_UNIT_JSON_MAX_DEPTH:
            continue
        if isinstance(value, dict):
            next_depth = depth + 1
            for key, child in value.items():
                stack.append((key, next_depth))
                stack.append((child, next_depth))
        elif isinstance(value, list):
            next_depth = depth + 1
            for child in value:
                stack.append((child, next_depth))

    if duplicate_keys:
        return None, empty_proof_unit_row(unit_index, "duplicate_proof_unit_keys")
    if depth_exceeded:
        return None, empty_proof_unit_row(unit_index, "proof_unit_json_nesting_too_deep")
    if nonfinite_number:
        return None, empty_proof_unit_row(unit_index, "nonfinite_proof_unit_number")
    if decoded_unicode_invalid:
        return None, empty_proof_unit_row(unit_index, "invalid_proof_unit_unicode")
    if not isinstance(decoded, dict):
        return None, empty_proof_unit_row(unit_index, "proof_unit_not_object")
    return decoded, None


def normalize_required_proof_string(
    obj: dict[str, Any],
    field: str,
    missing_issue: str,
    invalid_issue: str,
    validator: Any,
    issues: list[str],
) -> str | None:
    raw = obj.get(field)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        issues.append(missing_issue)
        return None
    if not isinstance(raw, str):
        issues.append(invalid_issue)
        return None
    value = raw.strip()
    if not validator(value):
        issues.append(invalid_issue)
        return None
    return value


def valid_proof_timestamp(value: str) -> bool:
    if PROOF_CAPTURED_AT_RE.fullmatch(value) is None:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def normalize_proof_safe_range(
    obj: dict[str, Any],
    issues: list[str],
) -> tuple[dict[str, Any] | None, bool, bool]:
    if "safe_range" not in obj or obj.get("safe_range") is None:
        return None, False, False
    raw = obj.get("safe_range")
    if not isinstance(raw, dict) or set(raw) != {"kind", "start", "end"}:
        issues.append("invalid_safe_range")
        return None, True, True
    kind = raw.get("kind")
    start = raw.get("start")
    end = raw.get("end")
    if type(start) is not int or type(end) is not int:
        issues.append("invalid_safe_range")
        return None, True, True
    if kind == "lines":
        valid = 1 <= start <= end <= JSON_SAFE_INTEGER_MAX
        coordinate_system = "one_based_inclusive"
    elif kind == "bytes":
        valid = 0 <= start < end <= JSON_SAFE_INTEGER_MAX
        coordinate_system = "zero_based_half_open"
    else:
        valid = False
        coordinate_system = ""
    if not valid:
        issues.append("invalid_safe_range")
        return None, True, True
    return {
        "coordinate_system": coordinate_system,
        "end": end,
        "kind": kind,
        "start": start,
    }, True, False


def parse_proof_rehydrate_command(command: str) -> tuple[bool, str | None]:
    if any(character in command for character in ";|&><`$\\\n\r"):
        return False, None
    try:
        argv = shlex.split(command)
    except ValueError:
        return False, None
    receipt: str | None = None
    if len(argv) == 4 and argv[0:2] == ["context-guard-artifact", "get"] and argv[3] == "--full":
        receipt = argv[2]
    elif len(argv) == 5 and argv[0:3] == ["context-guard", "artifact", "get"] and argv[4] == "--full":
        receipt = argv[3]
    if receipt is None or PROOF_RECEIPT_ID_RE.fullmatch(receipt) is None:
        return False, None
    return True, receipt


def normalize_proof_unit(obj: dict[str, Any], unit_index: int) -> tuple[dict[str, Any], str | None, str | None]:
    issues: list[str] = []
    if set(obj) - PROOF_UNIT_ALLOWED_FIELDS:
        issues.append("unknown_proof_unit_fields")

    source_label = normalize_required_proof_string(
        obj,
        "source_label",
        "missing_source_label",
        "invalid_source_label",
        lambda value: PROOF_SOURCE_LABEL_RE.fullmatch(value) is not None,
        issues,
    )
    receipt_id = normalize_required_proof_string(
        obj,
        "receipt_id",
        "missing_receipt",
        "invalid_receipt",
        lambda value: PROOF_RECEIPT_ID_RE.fullmatch(value) is not None,
        issues,
    )
    content_sha256 = normalize_required_proof_string(
        obj,
        "content_sha256",
        "missing_content_sha256",
        "invalid_content_sha256",
        lambda value: PROOF_CONTENT_SHA256_RE.fullmatch(value) is not None,
        issues,
    )
    captured_at = normalize_required_proof_string(
        obj,
        "captured_at",
        "missing_timestamp",
        "invalid_timestamp",
        valid_proof_timestamp,
        issues,
    )
    raw_transform_policy = obj.get("transform_policy")
    transform_policy: str | None = None
    if raw_transform_policy is None or (
        isinstance(raw_transform_policy, str) and not raw_transform_policy.strip()
    ):
        issues.append("missing_transform_policy")
    elif not isinstance(raw_transform_policy, str) or raw_transform_policy not in {
        "identity",
        "safe_range_extract",
    }:
        issues.append("invalid_transform_policy")
    else:
        transform_policy = raw_transform_policy
    safe_range, safe_range_supplied, safe_range_invalid = normalize_proof_safe_range(obj, issues)
    if transform_policy == "safe_range_extract" and not safe_range_supplied and not safe_range_invalid:
        issues.append("missing_safe_range_for_transform_policy")

    raw_command = obj.get("rehydrate_command")
    command_value: str | None = None
    command_syntax_valid = False
    command_receipt: str | None = None
    if raw_command is None or (isinstance(raw_command, str) and not raw_command.strip()):
        issues.append("missing_rehydrate_command")
    elif not isinstance(raw_command, str):
        issues.append("invalid_rehydrate_command")
    else:
        command_syntax_valid, command_receipt = parse_proof_rehydrate_command(raw_command)
        if not command_syntax_valid:
            issues.append("invalid_rehydrate_command")

    receipt_bound = bool(
        command_syntax_valid
        and receipt_id is not None
        and command_receipt == receipt_id
    )
    if command_syntax_valid and receipt_id is not None and command_receipt != receipt_id:
        issues.append("rehydrate_receipt_mismatch")
    if receipt_bound and isinstance(raw_command, str):
        command_value = raw_command.strip()

    ordered_issues = ordered_proof_taxonomy(issues, PROOF_READINESS_BLOCKER_ORDER)
    row = {
        "captured_at": captured_at,
        "content_hash": {
            "algorithm": "sha256",
            "content_verified": False,
            "syntax_valid": content_sha256 is not None,
            "value": content_sha256,
        },
        "receipt": {
            "id": receipt_id,
            "storage_checked": False,
            "syntax_valid": receipt_id is not None,
        },
        "rehydration": {
            "command": command_value,
            "executed": False,
            "receipt_bound": receipt_bound,
            "syntax_valid": command_syntax_valid,
        },
        "safe_range": safe_range,
        "source_label": source_label,
        "syntax_and_consistency_valid": not ordered_issues,
        "transform_policy": transform_policy,
        "unit_index": unit_index,
        "validation_issues": ordered_issues,
        "warnings": [],
    }
    return row, receipt_id, content_sha256


def proof_duplicate_key(row: dict[str, Any]) -> tuple[Any, ...]:
    safe_range = row["safe_range"]
    normalized_range = None if safe_range is None else (
        safe_range["kind"],
        safe_range["start"],
        safe_range["end"],
    )
    return (
        row["source_label"],
        row["receipt"]["id"],
        row["content_hash"]["value"],
        normalized_range,
        row["captured_at"],
        row["transform_policy"],
        row["rehydration"]["command"],
    )


def proof_verification_scope() -> dict[str, Any]:
    return {
        "content_hash_verified": False,
        "cross_field_consistency_checked": True,
        "cross_unit_receipt_hash_consistency_checked": True,
        "decoded_number_finiteness_checked": True,
        "decoded_unicode_checked": True,
        "duplicate_json_keys_checked": True,
        "field_syntax_checked": True,
        "json_depth_checked": True,
        "json_syntax_checked": True,
        "protected_zone_compliance_checked": False,
        "receipt_content_read": False,
        "receipt_storage_checked": False,
        "rehydration_executed": False,
        "safe_range_bounds_checked": False,
        "semantics": "validator_capability_invariant",
        "source_content_read": False,
    }


def proof_carrying_context_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    raw_units = args.proof_unit_json or []
    supplied_count = len(raw_units)
    detailed_count = min(supplied_count, PROOF_CARRYING_CONTEXT_DETAILED_UNIT_CAP)
    overflow_count = max(supplied_count - PROOF_CARRYING_CONTEXT_DETAILED_UNIT_CAP, 0)
    detailed_raw_units = raw_units[:PROOF_CARRYING_CONTEXT_DETAILED_UNIT_CAP]

    rows: list[dict[str, Any]] = []
    conflict_inputs: list[tuple[str | None, str | None]] = []
    for unit_index, raw in enumerate(detailed_raw_units):
        decoded, terminal_row = decode_proof_unit_json(raw, unit_index)
        if terminal_row is not None:
            rows.append(terminal_row)
            conflict_inputs.append((None, None))
            continue
        assert decoded is not None
        row, receipt_id, content_sha256 = normalize_proof_unit(decoded, unit_index)
        rows.append(row)
        conflict_inputs.append((receipt_id, content_sha256))

    hashes_by_receipt: dict[str, set[str]] = {}
    for receipt_id, content_sha256 in conflict_inputs:
        if receipt_id is not None and content_sha256 is not None:
            hashes_by_receipt.setdefault(receipt_id, set()).add(content_sha256)
    conflicted_receipts = {
        receipt_id for receipt_id, hashes in hashes_by_receipt.items() if len(hashes) > 1
    }
    for row, (receipt_id, _content_sha256) in zip(rows, conflict_inputs):
        if receipt_id in conflicted_receipts:
            row["validation_issues"] = ordered_proof_taxonomy(
                [*row["validation_issues"], "receipt_hash_conflict"],
                PROOF_READINESS_BLOCKER_ORDER,
            )

    duplicate_groups: dict[tuple[Any, ...], list[int]] = {}
    for row in rows:
        if not row["validation_issues"]:
            duplicate_groups.setdefault(proof_duplicate_key(row), []).append(row["unit_index"])
    duplicate_indexes = {
        unit_index
        for indexes in duplicate_groups.values()
        if len(indexes) > 1
        for unit_index in indexes
    }

    valid_count = 0
    for row in rows:
        row_valid = not row["validation_issues"]
        row["syntax_and_consistency_valid"] = row_valid
        if not row_valid:
            row["warnings"] = []
            continue
        valid_count += 1
        warnings = list(PROOF_WARNING_ORDER[:6])
        if row["safe_range"] is None:
            warnings.append("safe_range_omitted")
        if row["unit_index"] in duplicate_indexes:
            warnings.append("duplicate_proof_unit")
        row["warnings"] = ordered_proof_taxonomy(warnings, PROOF_WARNING_ORDER)

    protected_policy = (args.protected_zone_policy or "deny").strip().lower()
    blockers: list[str] = []
    if supplied_count == 0:
        blockers.append("missing_proof_unit")
    if overflow_count:
        blockers.append("too_many_proof_units")
    for row in rows:
        blockers.extend(row["validation_issues"])
    if protected_policy != "deny":
        blockers.append("protected_zone_denial_required")
    if not args.provider_boundary_ack:
        blockers.append("missing_provider_measurement_boundary")
    blockers = ordered_proof_taxonomy(blockers, PROOF_READINESS_BLOCKER_ORDER)

    top_warnings = list(PROOF_WARNING_ORDER[:2])
    for row in rows:
        top_warnings.extend(row["warnings"])
    top_warnings = ordered_proof_taxonomy(top_warnings, PROOF_WARNING_ORDER)
    ready = not blockers

    return {
        "candidate_replacement": None,
        "claim_boundary": (
            "Dry-run proof-carrying-context metadata validation only; protected-zone compliance, safe-range bounds, "
            "receipt storage, source content, SHA-256, timestamp freshness, and rehydration were not checked, no "
            "context was generated or replaced, and no hosted token/cost savings claim is allowed without "
            "provider-measured matched successful tasks."
        ),
        "experiment_id": "proof-carrying-context",
        "external_services": {
            "called": False,
            "dns_lookup": False,
            "model_calls": False,
            "network": False,
            "provider_calls": False,
            "proxy_forwarding": False,
        },
        "measurement_boundary": {
            "hosted_api_cost_savings_claim_allowed": False,
            "hosted_api_token_savings_claim_allowed": False,
            "local_metadata_readiness_is_not_hosted_savings_evidence": True,
            "provider_boundary_acknowledged": bool(args.provider_boundary_ack),
            "provider_boundary_policy": IMAGE_CONTEXT_PACK_PROVIDER_BOUNDARY,
            "provider_measured_matched_successful_tasks_required_for_hosted_claims": True,
            "provider_model_specific": True,
        },
        "mode": "dry_run",
        "plan_only": {
            "command_advertised": True,
            "compact_context_generated": False,
            "emit_command_available": False,
            "evaluation_only": True,
            "record_command_available": False,
            "replacement_context_emitted": False,
            "runtime_behavior_changed": False,
            "serve_command_available": False,
        },
        "plan_schema_version": PROOF_CARRYING_CONTEXT_PLAN_SCHEMA_VERSION,
        "proof_contract": {
            "detailed_unit_cap": PROOF_CARRYING_CONTEXT_DETAILED_UNIT_CAP,
            "hash_policy": {
                "algorithm": "sha256",
                "content_read": False,
                "content_verified": False,
                "input_format": "64_lowercase_hex",
            },
            "optional_input_fields": ["safe_range"],
            "overflow_policy": {
                "detailed_rows_emitted": False,
                "overflow_values_echoed": False,
                "overflow_values_encoded": False,
                "overflow_values_parsed": False,
            },
            "proof_unit_input_flag": "--proof-unit-json",
            "proof_unit_input_repeatable": True,
            "rehydration_policy": {
                "allowed_command_shapes": [
                    "context-guard-artifact get RECEIPT --full",
                    "context-guard artifact get RECEIPT --full",
                ],
                "command_executed": False,
                "receipt_bound_command_required": True,
                "receipt_storage_checked": False,
            },
            "required_input_fields": [
                "source_label",
                "receipt_id",
                "content_sha256",
                "captured_at",
                "transform_policy",
                "rehydrate_command",
            ],
            "safe_range_policy": {
                "bounds_checked": False,
                "byte_coordinate_system": "zero_based_half_open",
                "json_safe_integer_max": JSON_SAFE_INTEGER_MAX,
                "kinds": ["lines", "bytes"],
                "line_coordinate_system": "one_based_inclusive",
                "required_by_default": False,
                "semantic_safety_checked": False,
            },
            "source_label_policy": {
                "max_characters": 120,
                "profile": "ascii-identifier-v1",
                "raw_content_allowed": False,
                "regex": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,119}$",
                "safety_checked": False,
                "secrecy_checked": False,
            },
            "strict_json_policy": {
                "decoded_unicode_must_encode_utf8": True,
                "depth_root": 0,
                "duplicate_keys_allowed": False,
                "float_finiteness_check": "math.isfinite",
                "max_depth": PROOF_UNIT_JSON_MAX_DEPTH,
                "non_finite_numbers_allowed": False,
                "post_decode_walk": "iterative_container_keys_and_values",
                "raw_unicode_must_encode_utf8": True,
                "root_must_be_object": True,
            },
            "timestamp_policy": {
                "caller_supplied_only": True,
                "current_time_generated": False,
                "freshness_checked": False,
                "input_format": "YYYY-MM-DDTHH:MM:SSZ",
                "required": True,
            },
            "transform_policy": {
                "allowed": ["identity", "safe_range_extract"],
                "automatic_deletion_allowed": False,
                "lossy_transform_allowed": False,
                "semantic_rewrite_allowed": False,
            },
            "unit_json_byte_cap": PROOF_CARRYING_CONTEXT_UNIT_JSON_BYTE_CAP,
            "verification_scope": proof_verification_scope(),
        },
        "proof_unit_schema_version": PROOF_CARRYING_CONTEXT_UNIT_SCHEMA_VERSION,
        "proof_units": rows,
        "protected_zones": {
            "compliance_checked": False,
            "content_inspected": False,
            "declared_policy": protected_policy,
            "declared_policy_only": True,
            "denied_classes": [
                "code",
                "diffs",
                "identifiers",
                "hashes",
                "paths",
                "numeric_constants",
                "json_keys",
                "stack_frames",
                "secrets",
                "prompt_like_instructions",
            ],
            "override_allowed": False,
            "prompt_like_instruction_compliance_checked": False,
            "semantic_transform_permitted_by_gate": False,
        },
        "review_plan": {
            "detailed_proof_unit_count": detailed_count,
            "invalid_detailed_proof_unit_count": detailed_count - valid_count,
            "next_steps": [
                "Treat this result as proof-envelope metadata syntax and consistency review only.",
                "Verify protected-zone compliance, range bounds, receipt storage, source content, SHA-256, and rehydration only in a separately approved future consumer/runtime.",
                "Keep protected evidence and prompt-like instructions out of transformation paths.",
                "Measure provider/model token and cost fields on matched successful tasks before any hosted savings claim.",
            ],
            "overflow_proof_unit_count": overflow_count,
            "readiness_blocker_order": list(PROOF_READINESS_BLOCKER_ORDER),
            "readiness_blockers": blockers,
            "supplied_proof_unit_count": supplied_count,
            "valid_detailed_proof_unit_count": valid_count,
            "warning_order": list(PROOF_WARNING_ORDER),
            "warnings": top_warnings,
        },
        "runtime_side_effects": {
            "artifact_files_read": False,
            "config_files_read": False,
            "current_time_generated": False,
            "files_written": False,
            "prompt_edited": False,
            "rehydrate_command_executed": False,
            "source_files_read": False,
            "stable_runtime_behavior_changed": False,
            "stdin_content_read": False,
            "subprocesses_executed": False,
            "transcript_edited": False,
        },
        "schema_version": CONFIG_SCHEMA_VERSION,
        "status": (
            "ready_for_plan_review"
            if ready
            else "blocked_until_proof_carrying_context_gate_ready"
        ),
        "tool": TOOL_NAME,
    }


def command_plan_proof_carrying_context(args: argparse.Namespace) -> int:
    payload = proof_carrying_context_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard proof-carrying-context plan (dry-run metadata readiness only)")
        print("No source/artifact/config/stdin content was read; no verification, context generation, replacement, network, subprocess, or file write occurred.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(f"Warnings: {', '.join(payload['review_plan']['warnings'])}")
        print(payload["claim_boundary"])
    return 0


_SEMANTIC_GC_NONFINITE_SENTINEL = object()


def ordered_semantic_gc_taxonomy(values: list[str] | set[str], order: tuple[str, ...]) -> list[str]:
    selected = set(values)
    return [value for value in order if value in selected]


def semantic_gc_validation_row(index: int, issue: str | None = None) -> dict[str, Any]:
    return {
        "candidate_safety_applicable": None,
        "candidate_safety_issues": [],
        "input_index": index,
        "structural_issues": [issue] if issue else [],
        "unit_id": None,
    }


def decode_semantic_gc_unit(raw: Any, index: int) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    row = semantic_gc_validation_row(index)
    if not isinstance(raw, str):
        row["structural_issues"] = ["invalid_context_unit_json"]
        return None, row
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        row["structural_issues"] = ["invalid_unicode_scalar"]
        return None, row
    if len(encoded) > SEMANTIC_GC_UNIT_JSON_BYTE_CAP:
        row["structural_issues"] = ["invalid_context_unit_json"]
        return None, row

    duplicate_key = False

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicate_key
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicate_key = True
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=pairs_hook,
            parse_constant=lambda _value: _SEMANTIC_GC_NONFINITE_SENTINEL,
        )
    except RecursionError:
        row["structural_issues"] = ["decoder_recursion_limit"]
        return None, row
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError):
        row["structural_issues"] = ["invalid_context_unit_json"]
        return None, row

    depth_exceeded = False
    nonfinite = False
    invalid_unicode = False
    stack: list[tuple[Any, int]] = [(decoded, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > SEMANTIC_GC_JSON_MAX_DEPTH:
            depth_exceeded = True
            continue
        if isinstance(value, str):
            try:
                value.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                invalid_unicode = True
        elif value is _SEMANTIC_GC_NONFINITE_SENTINEL or (type(value) is float and not math.isfinite(value)):
            nonfinite = True
        if isinstance(value, dict):
            for key, child in value.items():
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            for child in value:
                stack.append((child, depth + 1))

    issue = None
    if duplicate_key:
        issue = "duplicate_json_key"
    elif depth_exceeded:
        issue = "context_unit_depth_exceeded"
    elif nonfinite:
        issue = "nonfinite_json_number"
    elif invalid_unicode:
        issue = "invalid_unicode_scalar"
    elif not isinstance(decoded, dict):
        issue = "invalid_context_unit_json"
    if issue:
        row["structural_issues"] = [issue]
        return None, row
    return decoded, row


def normalize_semantic_gc_structure(obj: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    issues: list[str] = []
    if obj.get("schema") != SEMANTIC_GC_UNIT_SCHEMA_VERSION:
        issues.append("invalid_context_unit_schema")
    if set(obj) - SEMANTIC_GC_ALLOWED_FIELDS:
        issues.append("unknown_context_unit_field")

    raw_id = obj.get("unit_id")
    unit_id = raw_id if isinstance(raw_id, str) and SEMANTIC_GC_UNIT_ID_RE.fullmatch(raw_id) else None
    if raw_id is None or raw_id == "":
        issues.append("missing_unit_id")
    elif unit_id is None:
        issues.append("invalid_unit_id")
    row["unit_id"] = unit_id

    raw_references = obj.get("references")
    references: list[str] = []
    reference_targets: list[str] = []
    if not isinstance(raw_references, list) or len(raw_references) > 64:
        issues.append("invalid_references")
    else:
        seen: set[str] = set()
        reference_issue = False
        for reference in raw_references:
            if not isinstance(reference, str) or SEMANTIC_GC_UNIT_ID_RE.fullmatch(reference) is None:
                issues.append("invalid_references")
                reference_issue = True
                continue
            if reference in seen:
                issues.append("duplicate_reference")
                reference_issue = True
                continue
            references.append(reference)
            reference_targets.append(reference)
            seen.add(reference)
        if reference_issue:
            references = []

    is_root = obj.get("is_root")
    if type(is_root) is not bool:
        issues.append("invalid_root_flag")
        is_root = None
    protected = obj.get("protected_zone")
    if type(protected) is not bool:
        issues.append("invalid_protected_zone_flag")
        protected = None
    row["structural_issues"] = ordered_semantic_gc_taxonomy(issues, SEMANTIC_GC_BLOCKER_ORDER)
    return {
        "object": obj,
        "row": row,
        "unit_id": unit_id,
        "references": references,
        "reference_targets": reference_targets,
        "is_root": is_root,
        "protected_zone": protected,
    }


def valid_semantic_gc_note(value: Any) -> bool:
    if not isinstance(value, str) or not (1 <= len(value) <= 512) or value != value.strip():
        return False
    return not any(unicodedata.category(char) in {"Cc", "Cf", "Zl", "Zp"} for char in value)


def normalize_semantic_gc_candidate(unit: dict[str, Any]) -> tuple[dict[str, Any], list[str], str | None, str | None]:
    obj = unit["object"]
    issues: list[str] = []
    raw_hash = obj.get("content_sha256")
    content_hash = raw_hash if isinstance(raw_hash, str) and SEMANTIC_GC_CONTENT_SHA256_RE.fullmatch(raw_hash) else None
    if content_hash is None:
        issues.append("invalid_content_sha256")

    raw_provenance = obj.get("provenance")
    source_label = None
    receipt_id = None
    if raw_provenance is None:
        issues.append("missing_provenance")
    elif not isinstance(raw_provenance, dict) or set(raw_provenance) != {"source_label", "receipt_id"}:
        issues.append("invalid_provenance")
    else:
        raw_label = raw_provenance.get("source_label")
        if (
            isinstance(raw_label, str)
            and raw_label == raw_label.strip()
            and SEMANTIC_GC_SOURCE_LABEL_RE.fullmatch(raw_label) is not None
        ):
            source_label = raw_label
        else:
            issues.append("invalid_source_label")
        raw_receipt = raw_provenance.get("receipt_id")
        if isinstance(raw_receipt, str) and SEMANTIC_GC_RECEIPT_ID_RE.fullmatch(raw_receipt):
            receipt_id = raw_receipt
        else:
            issues.append("invalid_receipt_id")

    raw_note = obj.get("missed_context_note")
    note = raw_note if valid_semantic_gc_note(raw_note) else None
    if raw_note is None or raw_note == "":
        issues.append("missing_missed_context_note")
    elif note is None:
        issues.append("invalid_missed_context_note")

    raw_fallback = obj.get("exact_fallback_command")
    fallback = None
    if raw_fallback is None or raw_fallback == "":
        issues.append("missing_exact_fallback")
    elif not isinstance(raw_fallback, str):
        issues.append("invalid_exact_fallback")
    else:
        forbidden = (';', '|', '&', '>', '<', '`', '$', '\\', '\n', '\r', '"', "'")
        if any(token in raw_fallback for token in forbidden) or raw_fallback != raw_fallback.strip():
            issues.append("invalid_exact_fallback")
        else:
            parts = raw_fallback.split(" ")
            if len(parts) != 4 or parts[0] != "context-guard-artifact" or parts[1] != "get" or parts[3] != "--full":
                issues.append("invalid_exact_fallback")
            elif SEMANTIC_GC_RECEIPT_ID_RE.fullmatch(parts[2]) is None:
                issues.append("invalid_exact_fallback")
            elif receipt_id is not None and parts[2] != receipt_id:
                issues.append("fallback_receipt_mismatch")
            elif receipt_id is None:
                issues.append("invalid_exact_fallback")
            else:
                fallback = raw_fallback

    issues = ordered_semantic_gc_taxonomy(issues, SEMANTIC_GC_BLOCKER_ORDER)
    return ({
        "candidate_replacement": None,
        "candidate_safety_issues": issues,
        "content_sha256": content_hash,
        "exact_fallback_command": fallback,
        "human_review_required": True,
        "missed_context_note": note,
        "protected_zone": False,
        "provenance": {"receipt_id": receipt_id, "source_label": source_label},
        "reason": "unreachable_from_declared_roots",
        "unit_id": unit["unit_id"],
    }, issues, content_hash, receipt_id)


def semantic_gc_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    raw_units = args.context_unit_json or []
    total_count = len(raw_units)
    detailed_count = min(total_count, SEMANTIC_GC_DETAILED_UNIT_CAP)
    overflow_count = max(total_count - SEMANTIC_GC_DETAILED_UNIT_CAP, 0)
    units: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    decoded_count = 0
    for index, raw in enumerate(raw_units[:SEMANTIC_GC_DETAILED_UNIT_CAP]):
        decoded, row = decode_semantic_gc_unit(raw, index)
        rows.append(row)
        if decoded is None:
            continue
        decoded_count += 1
        units.append(normalize_semantic_gc_structure(decoded, row))

    by_id: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        if unit["unit_id"] is not None:
            by_id.setdefault(unit["unit_id"], []).append(unit)
    duplicate_ids = {unit_id for unit_id, matches in by_id.items() if len(matches) > 1}
    for unit in units:
        structural = list(unit["row"]["structural_issues"])
        if unit["unit_id"] in duplicate_ids:
            structural.append("duplicate_unit_id")
        if any(reference not in by_id for reference in unit["reference_targets"]):
            structural.append("unknown_reference")
        if any(reference in duplicate_ids for reference in unit["reference_targets"]):
            structural.append("ambiguous_reference")
        unit["row"]["structural_issues"] = ordered_semantic_gc_taxonomy(structural, SEMANTIC_GC_BLOCKER_ORDER)

    declared_roots = sorted(
        unit_id for unit_id, matches in by_id.items()
        if unit_id not in duplicate_ids and len(matches) == 1 and matches[0]["is_root"] is True
    )
    structural_blockers: list[str] = []
    if total_count == 0:
        structural_blockers.append("no_context_units")
    if overflow_count:
        structural_blockers.append("unit_limit_exceeded")
    for row in rows:
        structural_blockers.extend(row["structural_issues"])
    if not declared_roots:
        structural_blockers.append("no_declared_root")
    graph_complete = not structural_blockers

    marked_ids: list[str] = []
    candidates: list[dict[str, Any]] = []
    unreachable_count = 0
    protected_unreachable_count = 0
    safety_valid_count = 0
    safety_invalid_count = 0
    safety_blockers: list[str] = []
    candidate_hashes: list[str] = []
    candidate_receipts: list[str] = []
    if graph_complete:
        marked: set[str] = set()
        pending = list(declared_roots)
        while pending:
            unit_id = pending.pop()
            if unit_id in marked:
                continue
            marked.add(unit_id)
            pending.extend(by_id[unit_id][0]["references"])
        marked_ids = sorted(marked)
        for unit in units:
            unit_id = unit["unit_id"]
            assert unit_id is not None
            row = unit["row"]
            if unit_id in marked:
                row["candidate_safety_applicable"] = False
                continue
            unreachable_count += 1
            if unit["protected_zone"] is True:
                protected_unreachable_count += 1
                row["candidate_safety_applicable"] = False
                continue
            row["candidate_safety_applicable"] = True
            candidate, issues, content_hash, receipt_id = normalize_semantic_gc_candidate(unit)
            row["candidate_safety_issues"] = issues
            candidates.append(candidate)
            safety_blockers.extend(issues)
            if issues:
                safety_invalid_count += 1
            else:
                safety_valid_count += 1
            if content_hash is not None:
                candidate_hashes.append(content_hash)
            if receipt_id is not None:
                candidate_receipts.append(receipt_id)
        candidates.sort(key=lambda item: item["unit_id"])

    blockers = list(structural_blockers)
    if not graph_complete:
        blockers.append("graph_evaluation_suppressed")
    protected_policy = "deny" if getattr(args, "protected_zone_policy", None) == "deny" else None
    if protected_policy is None:
        blockers.append("protected_zone_policy_required")
    blockers.extend(safety_blockers)
    if graph_complete and not args.provider_boundary_ack:
        blockers.append("provider_boundary_ack_required")
    if graph_complete and candidates and not args.human_review_ack:
        blockers.append("human_review_ack_required")
    blockers = ordered_semantic_gc_taxonomy(blockers, SEMANTIC_GC_BLOCKER_ORDER)

    warnings = list(SEMANTIC_GC_WARNING_ORDER[:6])
    if candidates:
        warnings.extend(("human_review_still_required", "accepted_notes_are_untrusted"))
    if len(candidate_hashes) != len(set(candidate_hashes)):
        warnings.append("duplicate_content_sha256")
    if len(candidate_receipts) != len(set(candidate_receipts)):
        warnings.append("duplicate_receipt_id")
    if protected_unreachable_count:
        warnings.append("protected_unreachable_excluded")
    if graph_complete and not candidates:
        warnings.append("no_sweep_candidates")
    warnings = ordered_semantic_gc_taxonomy(warnings, SEMANTIC_GC_WARNING_ORDER)

    verification_scope = {
        "artifact_content_read": False,
        "context_content_read": False,
        "deletion_or_omission_performed": False,
        "exact_fallback_executed": False,
        "files_written": False,
        "model_or_provider_called": False,
        "network_called": False,
        "provenance_verified_externally": False,
        "subprocess_started": False,
    }
    return {
        "blockers": blockers,
        "candidate_count": len(candidates),
        "candidate_replacement": None,
        "candidate_safety_invalid_count": safety_invalid_count,
        "candidate_safety_valid_count": safety_valid_count,
        "candidates": candidates,
        "declared_root_count": len(declared_roots),
        "declared_root_ids": declared_roots,
        "decoded_unit_count": decoded_count,
        "detailed_unit_count": detailed_count,
        "effective_protected_zone_policy": "deny",
        "experiment": "semantic-gc",
        "graph_evaluation_performed": graph_complete,
        "graph_integrity_complete": graph_complete,
        "human_review_acknowledged": bool(args.human_review_ack),
        "human_review_performed": False,
        "marked_unit_count": len(marked_ids),
        "marked_unit_ids": marked_ids,
        "omission_authorized": False,
        "overflow_unit_count": overflow_count,
        "plan_only": True,
        "process_exit_contract": SEMANTIC_GC_PROCESS_EXIT_CONTRACT,
        "protected_unreachable_count": protected_unreachable_count,
        "protected_zone_policy": protected_policy,
        "provider_boundary_acknowledged": bool(args.provider_boundary_ack),
        "runtime_action_allowed": False,
        "schema": SEMANTIC_GC_PLAN_SCHEMA_VERSION,
        "status": "ready_for_plan_review" if not blockers else "blocked",
        "structurally_valid_unit_count": sum(not row["structural_issues"] for row in rows),
        "total_unit_count": total_count,
        "unit_validation": rows,
        "unreachable_unit_count": unreachable_count,
        "verification_scope": verification_scope,
        "warnings": warnings,
    }


def command_plan_semantic_gc(args: argparse.Namespace) -> int:
    payload = semantic_gc_plan_payload(args)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    else:
        print("ContextGuard semantic-gc plan")
        print(f"Status: {payload['status']}")
        print(f"Graph complete: {payload['graph_integrity_complete']}; candidates: {payload['candidate_count']}")
        if payload["blockers"]:
            print(f"Blockers: {', '.join(payload['blockers'])}")
        print(f"Exit contract: {payload['process_exit_contract']}.")
        print("semantic-gc is plan-only; no context was deleted, omitted, read, replaced, or authorized for runtime action.")
    return 0 if payload["status"] == "ready_for_plan_review" else 2


def visual_crop_ocr_evidence_pack_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = visual_crop_ocr_plan_payload(args)
    blockers = list(payload["review_plan"]["readiness_blockers"])
    ready = not blockers
    crop = payload["derived_evidence"]["crop"]
    ocr = payload["derived_evidence"]["ocr"]

    image_area = None
    crop_area = None
    if crop["bounds"] is not None and crop["image_size"] is not None:
        image_area = crop["image_size"]["width"] * crop["image_size"]["height"]
        crop_area = crop["bounds"]["width"] * crop["bounds"]["height"]

    payload["mode"] = "emit"
    payload["status"] = "evidence_pack_emitted" if ready else "blocked_until_visual_evidence_pack_ready"
    payload["guardrails"] = dict(payload["guardrails"])
    payload["guardrails"].update({
        "candidate_replacement_allowed": False,
        "evidence_pack_allowed": ready,
        "runtime_writes_files": False,
        "external_services_called": False,
    })
    payload["claim_boundary"] = (
        "Explicit local visual crop/OCR evidence-pack emission only; image area and OCR byte reductions are proxy "
        "evidence and are not hosted API token or cost savings evidence."
    )
    payload["reduction_evidence"] = {
        "image_area_before": image_area,
        "crop_area_after": crop_area if crop["available"] else None,
        "crop_area_reduction": (image_area - crop_area) if crop["available"] and image_area is not None and crop_area is not None else None,
        "ocr_text_bytes": ocr["metadata"]["bytes"] if ocr["available"] else None,
        "proxy_only": True,
        "hosted_api_token_savings_claim_allowed": False,
        "hosted_api_cost_savings_claim_allowed": False,
    }
    payload["review_plan"]["next_steps"] = [
        "Human-review crop/OCR evidence against the full visual evidence receipt before using it as a substitute.",
        "Read missed-context notes before relying on omitted visual regions.",
        "Treat image area/OCR byte reductions as local proxy evidence only; do not claim hosted token/cost savings.",
    ]
    if ready:
        payload["evidence_pack"] = {
            "schema_version": "contextguard.visual-evidence-pack.v1",
            "full_visual_evidence": payload["full_visual_evidence"],
            "crop_evidence": crop if crop["available"] else None,
            "ocr_evidence": (
                {
                    "source_type": ocr["source_type"],
                    "source_label": ocr["source_label"],
                    "text": ocr["text_preview"],
                    "metadata": ocr["metadata"],
                    "confidence": ocr["confidence"],
                    "error_notes": ocr["error_notes"],
                }
                if ocr["available"]
                else None
            ),
            "missed_context_notes": payload["review_plan"]["missed_context_notes"],
            "guardrails": payload["guardrails"],
            "reduction_evidence": payload["reduction_evidence"],
            "claim_boundary": payload["claim_boundary"],
        }
    return payload


def command_emit_visual_crop_ocr(args: argparse.Namespace) -> int:
    payload = visual_crop_ocr_evidence_pack_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "evidence_pack_emitted":
            print("ContextGuard visual crop/OCR evidence pack emitted")
            print(f"Full evidence receipt: {payload['full_visual_evidence']['receipt_id']}")
            print(
                "Derived evidence: "
                f"crop={payload['derived_evidence']['crop']['available']} "
                f"ocr={payload['derived_evidence']['ocr']['available']}"
            )
        else:
            print("ContextGuard visual crop/OCR evidence pack blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "evidence_pack_emitted" else 1


SECRET_LABEL_KEY_RE = (
    r"[A-Za-z0-9_.-]*(?:"
    r"api[-_]?key|apikey|token|secret|password|passwd|pwd|client[-_]?secret|"
    r"auth|authorization|bearer|basic|pass|credential|credentials|signature|sig|"
    r"x[-_]?amz[-_]?[a-z0-9_.-]*|aws[a-z0-9_.-]*|(?:aws[-_]?)?access[-_]?key(?:[-_]?id)?|"
    r"private[-_]?key|privatekey|pgp[-_]?private[-_]?key|pgpprivatekey|ssh[-_]?key|sshkey"
    r")[A-Za-z0-9_.-]*"
)
SECRET_LABEL_VALUE_RE = r"(?:'[^']*'|\"[^\"]*\"|[^\s,}&#;]+)"
SECRET_LABEL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic|AWS|AWS4-HMAC-SHA256)\s+[^\s,}\]]+(?:\s+[A-Za-z0-9_-]+=[^\s,}\]]+)*"), "Authorization: [REDACTED]"),
    (re.compile(r"(?i)\b(?:Bearer|Basic)\s*(?:[:=]\s*)?[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\b(?:AWS|AWS4-HMAC-SHA256)\s+[A-Za-z0-9,=:/+._~%-]+"), "[REDACTED]"),
    (re.compile(rf"(?i)([?&#;]({SECRET_LABEL_KEY_RE})=)[^\s?&#;]+"), r"\1[REDACTED]"),
    (
        re.compile(rf"(?i)(^|[\s{{,?&#;])([\"']?(?:{SECRET_LABEL_KEY_RE})[\"']?\s*[:=]\s*){SECRET_LABEL_VALUE_RE}"),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(rf"(?i)(^|[\s\"'])(--(?:{SECRET_LABEL_KEY_RE})(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?i)(^|[\s\"'])((?:-u|--user)(?:\s+|=))(?:'[^']*'|\"[^\"]*\"|[^\s\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(rf"(?i)(^|[/\\\s{{,?&#;\[\(<])({SECRET_LABEL_KEY_RE}(?:[:=][^\s,}}&#;\]\)\\/]*)?)"), r"\1[REDACTED]"),
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


def sanitize_self_hosted_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in text)
    text = " ".join(text.split())
    for pattern, replacement in SECRET_LABEL_PATTERNS:
        text = pattern.sub(replacement, text)
    text = re.sub(r"\[REDACTED\]\]+", "[REDACTED]", text)
    text = re.sub(r"(?:\[REDACTED\]\s*){2,}", "[REDACTED]", text)
    if len(text) > MAX_SELF_HOSTED_LABEL_CHARS:
        text = text[: MAX_SELF_HOSTED_LABEL_CHARS - 12].rstrip() + "…[truncated]"
    return text


def sanitize_self_hosted_label(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = sanitize_self_hosted_text(value)
    if not text:
        return None
    return text


def sanitize_self_hosted_ignored_key(value: Any) -> str:
    if not isinstance(value, str):
        return "non_string_key"
    text = sanitize_self_hosted_text(value)
    if not text:
        return "empty_key"
    if "[REDACTED]" in text:
        return "redacted_key"
    return text


def normalize_self_hosted_metric(value: Any, *, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        return None
    return number


SELF_HOSTED_METRIC_LIMITS: dict[str, float] = {
    "latency_ms": MAX_SELF_HOSTED_LATENCY_MS,
    "peak_memory_mb": MAX_SELF_HOSTED_MEMORY_MB,
    "quality_score": 1.0,
    "energy_wh": MAX_SELF_HOSTED_ENERGY_WH,
    "local_cost_usd": MAX_SELF_HOSTED_LOCAL_COST_USD,
    "tokens_per_second": MAX_SELF_HOSTED_TOKENS_PER_SECOND,
}
SELF_HOSTED_LABEL_KEYS = ("model_server", "optimization", "quality_metric", "hardware", "runtime", "dataset")


def normalize_self_hosted_metrics(raw: Any, *, source: str) -> tuple[dict[str, Any] | None, list[str], list[str]]:
    invalid_keys: list[str] = []
    ignored_keys: list[str] = []
    if not isinstance(raw, dict):
        return None, ["self_hosted_metrics_not_object"], ignored_keys
    metrics: dict[str, float] = {}
    labels: dict[str, str] = {}
    availability = {key: False for key in SELF_HOSTED_METRIC_LIMITS}
    for key, value in raw.items():
        if key in SELF_HOSTED_METRIC_LIMITS:
            metric = normalize_self_hosted_metric(value, maximum=SELF_HOSTED_METRIC_LIMITS[key])
            if metric is None:
                invalid_keys.append(key)
            else:
                metrics[key] = metric
                availability[key] = True
        elif key in SELF_HOSTED_LABEL_KEYS:
            label = sanitize_self_hosted_label(value)
            if label is not None:
                labels[key] = label
            elif value is not None:
                invalid_keys.append(key)
        else:
            ignored_keys.append(sanitize_self_hosted_ignored_key(key))
    if not metrics:
        return None, invalid_keys, ignored_keys
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
                "Self-hosted local/model-server latency, memory, quality, energy, and local cost metrics "
                "are not hosted API token or cost telemetry."
            ),
        },
    }, invalid_keys, ignored_keys


def cli_self_hosted_metrics(args: argparse.Namespace) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    for arg_name, metric_name in (
        ("latency_ms", "latency_ms"),
        ("peak_memory_mb", "peak_memory_mb"),
        ("quality_score", "quality_score"),
        ("energy_wh", "energy_wh"),
        ("local_cost_usd", "local_cost_usd"),
        ("tokens_per_second", "tokens_per_second"),
    ):
        value = getattr(args, arg_name)
        if value is not None:
            raw[metric_name] = value
    for arg_name in SELF_HOSTED_LABEL_KEYS:
        value = getattr(args, arg_name)
        if value is not None:
            raw[arg_name] = value
    return raw


def reject_non_finite_json_constant(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON value {value}")


def has_non_finite_json_number(value: Any) -> bool:
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while stack:
        item, depth = stack.pop()
        visited += 1
        if depth > MAX_SELF_HOSTED_JSON_DEPTH or visited > MAX_SELF_HOSTED_JSON_NODES:
            return True
        if isinstance(item, bool):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                return True
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
    return False


def read_self_hosted_payload(args: argparse.Namespace) -> tuple[Any, dict[str, Any]]:
    source_label = sanitize_self_hosted_text(args.source_label) if args.source_label else None
    if args.input:
        path = Path(args.input)
        source_label = source_label or sanitize_self_hosted_text(path)
        try:
            loaded = read_bounded_regular_file(path, max_bytes=MAX_SELF_HOSTED_METRICS_INPUT_BYTES, label=f"self-hosted metrics input: {source_label}")
        except RegistryError as exc:
            raise RegistryError(f"could not read self-hosted metrics input: {source_label}: {exc}") from exc
        assert loaded is not None
        raw, loaded_truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_SELF_HOSTED_METRICS_INPUT_BYTES + 1)
        loaded_truncated = len(raw) > MAX_SELF_HOSTED_METRICS_INPUT_BYTES
        raw = raw[:MAX_SELF_HOSTED_METRICS_INPUT_BYTES]
    if loaded_truncated:
        return None, {
            "source_label": source_label,
            "bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": True,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": None,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    if not raw.strip():
        return None, {
            "source_label": source_label,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": None,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    text = raw.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text, parse_constant=reject_non_finite_json_constant)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse self-hosted metrics JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise RegistryError(f"could not parse self-hosted metrics JSON: {exc}") from exc
    except RecursionError as exc:
        raise RegistryError("could not parse self-hosted metrics JSON: nesting too deep") from exc
    if has_non_finite_json_number(payload):
        raise RegistryError("could not parse self-hosted metrics JSON: non-finite JSON number")
    return payload, {
        "source_label": source_label,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": False,
        "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
        "envelope_source": None,
        "invalid_metric_keys": [],
        "ignored_keys": [],
    }


def select_self_hosted_envelope(payload: Any) -> tuple[Any, str | None, list[str]]:
    if not isinstance(payload, dict):
        return None, None, ["input_not_object"]
    ignored: list[str] = []
    if SELF_HOSTED_METRICS_KEY in payload:
        return payload.get(SELF_HOSTED_METRICS_KEY), f"explicit_provider_payload.{SELF_HOSTED_METRICS_KEY}", ignored
    metrics = payload.get("metrics")
    if isinstance(metrics, dict) and SELF_HOSTED_METRICS_KEY in metrics:
        return metrics.get(SELF_HOSTED_METRICS_KEY), f"explicit_provider_payload.metrics.{SELF_HOSTED_METRICS_KEY}", ignored
    if any(isinstance(key, str) and key.startswith("self_hosted_") for key in payload):
        ignored.append("incidental_self_hosted_keys")
    return None, None, ignored


def parse_optional_success(value: str | None) -> bool | None:
    if value is None or value == "unknown":
        return None
    return value == "true"


def self_hosted_metrics_ledger_row(
    sidecar: dict[str, Any],
    *,
    task_id: str = "self-hosted-metrics-manual",
    variant: str = "self-hosted-metrics-ledger",
    success: bool | None = None,
    notes: str = "explicit self-hosted metrics record; no hosted API savings claim",
    claude_version: str = "manual",
    wall_time_seconds: float = 0.0,
) -> dict[str, Any]:
    return {
        "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claude_version": sanitize_self_hosted_text(claude_version) or "manual",
        "task_id": sanitize_self_hosted_text(task_id) or "self-hosted-metrics-manual",
        "variant": sanitize_self_hosted_text(variant) or "self-hosted-metrics-ledger",
        "transform_id": "self-hosted-metrics-ledger",
        "success": success,
        "primary_tokens_measured": False,
        "primary_tokens": 0,
        "primary_cost_measured": False,
        "primary_cost_usd": 0.0,
        "provider_cached_tokens": None,
        "provider_cached_tokens_measured": False,
        "wall_time_seconds": wall_time_seconds,
        "external_tokens_measured": False,
        "external_tokens": 0,
        "external_cost_measured": False,
        "external_cost_usd": 0.0,
        "total_cost_with_shift_usd": None,
        "artifacts_used": 0,
        "bytes_before": 0,
        "bytes_after": 0,
        "hook_triggers": 0,
        "turns": 0,
        "notes": sanitize_self_hosted_text(notes)
        or "explicit self-hosted metrics record; no hosted API savings claim",
        "measurement_availability": {
            "primary_tokens": False,
            "primary_cost": False,
            "external_tokens": False,
            "external_cost": False,
            "shifted_cost": False,
            "provider_cache": False,
            "byte_metrics": False,
            "wall_time": False,
            "self_hosted_metrics": True,
        },
        "self_hosted_metrics": sidecar,
        "proxy_metrics": {
            "byte_metrics_observed": False,
            "token_proxy": "chars_div_4",
            "bytes_per_token": TOKEN_PROXY_BYTES_PER_TOKEN,
            "claim_boundary": "proxy_only_not_hosted_token_savings",
        },
    }


def self_hosted_metrics_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    cli_metrics = cli_self_hosted_metrics(args)
    if cli_metrics:
        raw_metrics = cli_metrics
        source = "cli_flags"
        ignored_envelope_keys = []
        input_meta = {
            "source_label": sanitize_self_hosted_text(args.source_label) if args.source_label else "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": source,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    elif args.input or not sys.stdin.isatty():
        raw_payload, input_meta = read_self_hosted_payload(args)
        raw_metrics, source, ignored_envelope_keys = select_self_hosted_envelope(raw_payload)
    else:
        raw_metrics = {}
        source = None
        ignored_envelope_keys = []
        input_meta = {
            "source_label": sanitize_self_hosted_text(args.source_label) if args.source_label else "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "max_bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "envelope_source": source,
            "invalid_metric_keys": [],
            "ignored_keys": [],
        }
    if input_meta["truncated"]:
        sidecar = None
        invalid_keys: list[str] = []
        ignored_keys = ignored_envelope_keys
    elif raw_metrics is None:
        sidecar = None
        invalid_keys = []
        ignored_keys = ignored_envelope_keys
    else:
        sidecar, invalid_keys, ignored_keys = normalize_self_hosted_metrics(raw_metrics, source=source or "missing_explicit_envelope")
    input_meta["envelope_source"] = source
    input_meta["invalid_metric_keys"] = sorted(set(invalid_keys))
    input_meta["ignored_keys"] = sorted(set(ignored_keys + ignored_envelope_keys))
    blockers: list[str] = []
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if source is None:
        blockers.append("missing_explicit_self_hosted_metrics_envelope")
    if sidecar is None:
        blockers.append("missing_self_hosted_metrics")
    if invalid_keys:
        blockers.append("invalid_self_hosted_metrics")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    ledger_preview = None
    if sidecar is not None:
        ledger_preview = self_hosted_metrics_ledger_row(
            sidecar,
            task_id="self-hosted-metrics-dry-run",
            notes="dry-run preview; no ledger file written",
            claude_version="dry-run",
        )
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "self-hosted-metrics-ledger",
        "mode": "dry_run",
        "status": "ready_for_ledger_review" if ready else "blocked_until_metrics",
        "input": input_meta,
        "policy": {
            "default_off": True,
            "ledger_write_performed": False,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
            "stable_runtime_behavior_changed": False,
        },
        "self_hosted_metrics": sidecar,
        "ledger_preview": ledger_preview,
        "review_plan": {
            "readiness_blockers": blockers,
            "next_steps": [
                "Record real run evidence with context-guard-bench --ledger-jsonl when benchmark data exists.",
                "Keep self-hosted local metrics out of hosted API token/cost savings claims.",
                "Use provider-measured matched successful tasks for hosted API savings claims.",
            ],
        },
        "claim_boundary": (
            "Dry-run self-hosted metrics ledger preview only; local/model-server metrics are diagnostic sidecars "
            "and are not hosted API token or cost savings evidence."
        ),
    }


def command_plan_self_hosted_metrics_ledger(args: argparse.Namespace) -> int:
    payload = self_hosted_metrics_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard self-hosted metrics ledger preview (dry-run only)")
        print("No ledger file was written and no hosted API token/cost savings claim is allowed from these metrics.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def self_hosted_metrics_record_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = self_hosted_metrics_plan_payload(args)
    payload["mode"] = "record"
    payload["claim_boundary"] = (
        "Explicit local self-hosted metrics ledger record only; local/model-server metrics are diagnostic sidecars "
        "and are not hosted API token or cost savings evidence."
    )
    payload["policy"]["ledger_write_performed"] = False
    payload["policy"]["stable_runtime_behavior_changed"] = False
    payload["ledger_record"] = None
    payload["ledger_jsonl"] = {
        "path": sanitize_self_hosted_text(args.ledger_jsonl),
        "write_performed": False,
        "bytes_written": 0,
    }
    if payload["self_hosted_metrics"] is None or payload["review_plan"]["readiness_blockers"]:
        payload["status"] = "blocked_until_metrics"
        return payload

    row = self_hosted_metrics_ledger_row(
        payload["self_hosted_metrics"],
        task_id=args.task_id,
        variant=args.variant,
        success=parse_optional_success(args.success),
        notes=args.notes,
        claude_version="manual",
    )
    bytes_written = append_jsonl_no_follow(Path(args.ledger_jsonl), row, label="self-hosted metrics ledger")
    payload["status"] = "recorded"
    payload["ledger_preview"] = row
    payload["ledger_record"] = row
    payload["policy"]["ledger_write_performed"] = True
    payload["ledger_jsonl"]["write_performed"] = True
    payload["ledger_jsonl"]["bytes_written"] = bytes_written
    payload["review_plan"]["next_steps"] = [
        "Use this JSONL row only as self-hosted/local diagnostic evidence.",
        "Keep hosted API token/cost savings claims behind provider-measured matched successful tasks.",
        "Compare this sidecar with benchmark rows only through explicit shifted-cost accounting.",
    ]
    return payload


def command_record_self_hosted_metrics_ledger(args: argparse.Namespace) -> int:
    payload = self_hosted_metrics_record_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "recorded":
            print("ContextGuard self-hosted metrics ledger record written")
            print(f"Ledger: {payload['ledger_jsonl']['path']} bytes={payload['ledger_jsonl']['bytes_written']}")
        else:
            print("ContextGuard self-hosted metrics ledger record blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def sanitize_local_proxy_value(value: Any) -> str:
    return sanitize_self_hosted_text(value)


def local_proxy_secret_like(value: Any) -> bool:
    if value is None:
        return False
    return "[REDACTED]" in sanitize_local_proxy_value(value)


def local_proxy_bytes_secret_like(value: bytes) -> bool:
    return local_proxy_secret_like(value.decode("utf-8", errors="replace"))


def local_proxy_request_target_meta(value: Any) -> dict[str, Any]:
    text = "" if value is None else str(value)
    raw = text.encode("utf-8", errors="replace")
    return {
        "request_target_sha256": hashlib.sha256(raw).hexdigest(),
        "request_target_bytes": len(raw),
    }


def normalize_external_allow_host(value: Any) -> tuple[str, list[str]]:
    raw = "" if value is None else str(value).strip()
    sanitized = sanitize_local_proxy_value(raw)
    blockers: list[str] = []
    host = raw.strip().strip("[]").lower().rstrip(".")
    if not host:
        return sanitized, ["invalid_external_allow_host"]
    if "[REDACTED]" in sanitized:
        blockers.append("secret_like_external_forwarding_design_metadata")
    if any(ch in host for ch in ("*", "/", "\\", "@", ":", " ")) or len(host) > 253:
        blockers.append("invalid_external_allow_host")
    elif is_localhost_host(host):
        blockers.append("localhost_external_allow_host_not_allowed")
    else:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split(".")
            label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
            if len(labels) < 2 or any(not label_re.fullmatch(label) for label in labels):
                blockers.append("invalid_external_allow_host")
        else:
            if not ip.is_global:
                blockers.append("non_global_external_allow_host_not_allowed")
    return sanitized, blockers


def local_proxy_external_forwarding_design_payload(args: argparse.Namespace) -> dict[str, Any]:
    intent = bool(args.external_forwarding_intent)
    design_ack = bool(args.external_forwarding_design_ack)
    raw_hosts = args.allow_host or []
    raw_schemes = args.allow_scheme or []
    raw_notes = args.threat_model_note or []
    redaction_policy = sanitize_local_proxy_value(args.credential_redaction_policy)
    provider_boundary = sanitize_local_proxy_value(args.provider_evidence_boundary)

    blockers: list[str] = []
    if not intent:
        blockers.append("missing_external_forwarding_intent")
    if not design_ack:
        blockers.append("missing_external_forwarding_design_ack")

    hosts: list[str] = []
    if not raw_hosts:
        blockers.append("missing_external_allow_host")
    for raw_host in raw_hosts:
        host, host_blockers = normalize_external_allow_host(raw_host)
        if host:
            hosts.append(host)
        blockers.extend(host_blockers)
    hosts = sorted(set(hosts))

    schemes = sorted(set(sanitize_local_proxy_value(str(value).strip().lower()) for value in raw_schemes if str(value).strip()))
    if not schemes:
        blockers.append("missing_external_allow_scheme")
    for scheme in schemes:
        if "[REDACTED]" in scheme:
            blockers.append("secret_like_external_forwarding_design_metadata")
        elif scheme not in LOCAL_PROXY_EXTERNAL_ALLOWED_SCHEMES:
            blockers.append("https_only_external_allow_scheme_required")

    threat_model_notes = [sanitize_local_proxy_value(note) for note in clean_values(raw_notes)]
    if not threat_model_notes:
        blockers.append("missing_threat_model_note")
    if any(local_proxy_secret_like(note) for note in raw_notes):
        blockers.append("secret_like_external_forwarding_design_metadata")

    if not redaction_policy:
        blockers.append("missing_credential_redaction_policy")
    elif redaction_policy != LOCAL_PROXY_EXTERNAL_CREDENTIAL_REDACTION_POLICY:
        blockers.append("unsupported_credential_redaction_policy")
    if not provider_boundary:
        blockers.append("missing_provider_evidence_boundary")
    elif provider_boundary != LOCAL_PROXY_EXTERNAL_PROVIDER_EVIDENCE_BOUNDARY:
        blockers.append("unsupported_provider_evidence_boundary")
    if local_proxy_secret_like(redaction_policy) or local_proxy_secret_like(provider_boundary):
        blockers.append("secret_like_external_forwarding_design_metadata")

    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    return {
        "tool": TOOL_NAME,
        "schema_version": LOCAL_PROXY_EXTERNAL_DESIGN_SCHEMA_VERSION,
        "experiment_id": "local-proxy",
        "mode": "external_forwarding_design",
        "status": "ready_for_external_forwarding_design_review" if ready else "blocked_until_external_forwarding_design_constraints",
        "policy": {
            "default_off": True,
            "design_only": True,
            "external_forwarding_runtime_implemented": False,
            "external_forwarding_allowed": False,
            "hidden_external_forwarding": False,
            "api_key_persistence_allowed": False,
            "credential_material_forwarded": False,
            "stable_runtime_behavior_changed": False,
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
        },
        "network_actions": {
            "listener_started": False,
            "outbound_forwarding_attempted": False,
            "dns_lookup_attempted": False,
            "external_services_called": False,
        },
        "external_forwarding_design": {
            "intent_acknowledged": intent,
            "design_acknowledged": design_ack,
            "allowlist_required": True,
            "allowlist": {
                "hosts": hosts,
                "schemes": schemes,
                "wildcards_allowed": False,
                "localhost_allowed": False,
                "non_global_ip_allowed": False,
            },
            "credential_redaction": {
                "policy": redaction_policy,
                "required_policy": LOCAL_PROXY_EXTERNAL_CREDENTIAL_REDACTION_POLICY,
                "blocked_header_names": sorted(LOCAL_PROXY_SENSITIVE_HEADER_NAMES),
                "raw_headers_persisted": False,
                "request_bodies_persisted": False,
                "response_bodies_persisted": False,
            },
            "threat_model": {
                "required": True,
                "notes": threat_model_notes,
                "future_review_required": True,
            },
            "provider_evidence_boundary": {
                "policy": provider_boundary,
                "required_policy": LOCAL_PROXY_EXTERNAL_PROVIDER_EVIDENCE_BOUNDARY,
                "diagnostic_only": True,
                "provider_measured_matched_tasks_required_for_hosted_claims": True,
                "hosted_api_token_savings_claim_allowed": False,
                "hosted_api_cost_savings_claim_allowed": False,
            },
            "future_runtime_requirements": [
                "separate future runtime gate and review",
                "explicit host/scheme allowlist enforcement before any network connection",
                "credential-bearing requests blocked or stripped before forwarding",
                "no CONNECT/TLS interception without a separate reviewed gate",
                "diagnostic shifted-cost accounting only unless provider-measured matched-task evidence exists",
            ],
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "next_steps": [
                "Treat this as design evidence only; do not forward external traffic from this command.",
                "Keep existing local-proxy serve runtime literal-loopback-only.",
                "Require a separate future runtime gate before any external forwarding implementation.",
            ],
        },
        "claim_boundary": (
            "Dry-run external forwarding design gate only; no listener, DNS lookup, external service call, credential "
            "persistence, traffic forwarding, or hosted API token/cost savings claim is performed."
        ),
    }


def command_plan_local_proxy_external_forwarding(args: argparse.Namespace) -> int:
    payload = local_proxy_external_forwarding_design_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard local proxy external-forwarding design gate (dry-run only)")
        print("No listener was started, no traffic was forwarded, no DNS lookup was performed, and no API key was persisted.")
        print(f"Status: {payload['status']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def is_localhost_host(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    host = value.strip().strip("[]").lower().rstrip(".")
    if host in LOCAL_PROXY_LOCALHOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_loopback_ip_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    host = value.strip().strip("[]").lower().rstrip(".")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_local_proxy_host(value: Any, *, default: str) -> tuple[str, bool, bool]:
    if value is None or str(value).strip() == "":
        host = default
    else:
        host = str(value).strip().strip("[]")
    sanitized = sanitize_local_proxy_value(host)
    return sanitized, is_localhost_host(host), "[REDACTED]" in sanitized


def normalize_local_proxy_port(value: Any, *, default: int) -> tuple[int, bool]:
    if value is None or value == "":
        return default, True
    if isinstance(value, bool):
        return default, False
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default, False
    return port, 0 <= port <= 65535


def normalize_local_proxy_int_limit(value: Any, *, default: int, maximum: int) -> tuple[int, bool]:
    if value is None or value == "":
        return default, True
    if isinstance(value, bool):
        return default, False
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default, False
    return parsed, 1 <= parsed <= maximum


def normalize_local_proxy_timeout(value: Any) -> tuple[float, bool]:
    if value is None or value == "":
        return LOCAL_PROXY_DEFAULT_TIMEOUT_SECONDS, True
    if isinstance(value, bool):
        return LOCAL_PROXY_DEFAULT_TIMEOUT_SECONDS, False
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return LOCAL_PROXY_DEFAULT_TIMEOUT_SECONDS, False
    return parsed, 0.1 <= parsed <= LOCAL_PROXY_MAX_TIMEOUT_SECONDS


def read_local_proxy_payload(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    if not args.input:
        return {}, {
            "source_label": "cli_flags",
            "bytes": 0,
            "sha256": None,
            "truncated": False,
            "ignored_keys": [],
        }
    path = Path(args.input)
    safe_path = sanitize_local_proxy_value(path)
    try:
        loaded = read_bounded_regular_file(path, max_bytes=MAX_SELF_HOSTED_METRICS_INPUT_BYTES, label=f"local-proxy input: {safe_path}")
    except RegistryError as exc:
        raise RegistryError(f"could not read local-proxy input: {safe_path}: {exc}") from exc
    assert loaded is not None
    raw, loaded_truncated = loaded
    if loaded_truncated:
        return {}, {
            "source_label": safe_path,
            "bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": True,
            "ignored_keys": [],
        }
    if not raw.strip():
        return {}, {
            "source_label": safe_path,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "ignored_keys": [],
        }
    text = raw.decode("utf-8", errors="replace")
    try:
        payload = json.loads(text, parse_constant=reject_non_finite_json_constant)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"could not parse local-proxy JSON: {exc.msg}") from exc
    except ValueError as exc:
        raise RegistryError(f"could not parse local-proxy JSON: {exc}") from exc
    except RecursionError as exc:
        raise RegistryError("could not parse local-proxy JSON: nesting too deep") from exc
    if has_non_finite_json_number(payload):
        raise RegistryError("could not parse local-proxy JSON: non-finite JSON number")
    if not isinstance(payload, dict):
        return {}, {
            "source_label": safe_path,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": False,
            "ignored_keys": ["input_not_object"],
        }
    envelope = payload.get("local_proxy", payload)
    ignored = []
    if not isinstance(envelope, dict):
        envelope = {}
        ignored.append("local_proxy_not_object")
    allowed = {
        "bind_host",
        "bind_port",
        "target_host",
        "target_port",
        "upstream_url",
        "ledger_jsonl",
        "proxy_label",
        "api_key",
        "authorization_header",
        "persist_api_key",
        "external_forwarding_intent",
        "runtime_gate_ack",
        "forwarding_gate_ack",
        "once",
        "max_request_bytes",
        "max_response_bytes",
        "timeout_seconds",
        "diagnostic_ledger_jsonl",
        "response_sandbox",
        "response_artifact_dir",
        "show_artifact_paths",
    }
    ignored.extend(sanitize_self_hosted_ignored_key(key) for key in envelope if key not in allowed)
    return dict(envelope), {
        "source_label": safe_path,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": False,
        "ignored_keys": sorted(set(ignored)),
    }


def coalesce_local_proxy_value(args: argparse.Namespace, payload: dict[str, Any], attr: str, key: str) -> Any:
    value = getattr(args, attr, None)
    return value if value is not None else payload.get(key)


def parse_local_proxy_json_bool(value: Any) -> tuple[bool, bool]:
    if value is None:
        return False, True
    if isinstance(value, bool):
        return value, True
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in LOCAL_PROXY_TRUE_VALUES:
            return True, True
        if normalized in LOCAL_PROXY_FALSE_VALUES:
            return False, True
        return False, False
    if isinstance(value, int) and not isinstance(value, bool):
        if value == 1:
            return True, True
        if value == 0:
            return False, True
    return False, False


def coalesce_local_proxy_bool(args: argparse.Namespace, payload: dict[str, Any], attr: str, key: str) -> tuple[bool, bool]:
    if getattr(args, attr, False):
        return True, True
    return parse_local_proxy_json_bool(payload.get(key))


def local_proxy_plan_payload(
    args: argparse.Namespace,
    input_payload: dict[str, Any] | None = None,
    input_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if input_payload is None or input_meta is None:
        input_payload, input_meta = read_local_proxy_payload(args)
    bind_host_raw = coalesce_local_proxy_value(args, input_payload, "bind_host", "bind_host")
    bind_port_raw = coalesce_local_proxy_value(args, input_payload, "bind_port", "bind_port")
    target_host_raw = coalesce_local_proxy_value(args, input_payload, "target_host", "target_host")
    target_port_raw = coalesce_local_proxy_value(args, input_payload, "target_port", "target_port")
    upstream_url_raw = coalesce_local_proxy_value(args, input_payload, "upstream_url", "upstream_url")
    ledger_jsonl_raw = coalesce_local_proxy_value(args, input_payload, "ledger_jsonl", "ledger_jsonl")
    proxy_label_raw = coalesce_local_proxy_value(args, input_payload, "proxy_label", "proxy_label")
    api_key_raw = coalesce_local_proxy_value(args, input_payload, "api_key", "api_key")
    authorization_raw = coalesce_local_proxy_value(args, input_payload, "authorization_header", "authorization_header")
    persist_api_key, persist_api_key_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "persist_api_key",
        "persist_api_key",
    )
    external_forwarding_intent, external_forwarding_intent_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "external_forwarding_intent",
        "external_forwarding_intent",
    )
    runtime_gate_ack, runtime_gate_ack_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "runtime_gate_ack",
        "runtime_gate_ack",
    )

    upstream_url = sanitize_local_proxy_value(upstream_url_raw) if upstream_url_raw else None
    upstream_host = None
    upstream_url_valid = True
    upstream_localhost = True
    upstream_secret_like = False
    if upstream_url_raw:
        upstream_secret_like = local_proxy_secret_like(upstream_url_raw)
        try:
            parsed = urlparse(str(upstream_url_raw))
            upstream_host = parsed.hostname
        except ValueError:
            upstream_url_valid = False
            upstream_host = None
        else:
            if upstream_host:
                upstream_localhost = is_localhost_host(upstream_host)
            else:
                upstream_url_valid = False
                upstream_localhost = False
            try:
                upstream_port = parsed.port
            except ValueError:
                upstream_url_valid = False
                upstream_port = None
            if upstream_port is not None and target_port_raw is None:
                target_port_raw = upstream_port
        if upstream_host and target_host_raw is None:
            target_host_raw = upstream_host

    bind_host, bind_localhost, bind_secret_like = normalize_local_proxy_host(
        bind_host_raw,
        default=LOCAL_PROXY_DEFAULT_BIND_HOST,
    )
    target_host, target_localhost, target_secret_like = normalize_local_proxy_host(
        target_host_raw,
        default=LOCAL_PROXY_DEFAULT_TARGET_HOST,
    )
    bind_port, bind_port_valid = normalize_local_proxy_port(bind_port_raw, default=LOCAL_PROXY_DEFAULT_BIND_PORT)
    target_port, target_port_valid = normalize_local_proxy_port(target_port_raw, default=LOCAL_PROXY_DEFAULT_TARGET_PORT)
    ledger_jsonl = sanitize_local_proxy_value(ledger_jsonl_raw) if ledger_jsonl_raw else None
    proxy_label = sanitize_local_proxy_value(proxy_label_raw) if proxy_label_raw else "local-proxy-dry-run"
    api_key_provided = api_key_raw is not None and str(api_key_raw).strip() != ""
    authorization_header_provided = authorization_raw is not None and str(authorization_raw).strip() != ""
    secret_like_fields: list[str] = []
    for field, raw in (
        ("bind_host", bind_host_raw),
        ("bind_port", bind_port_raw),
        ("target_host", target_host_raw),
        ("target_port", target_port_raw),
        ("upstream_url", upstream_url_raw),
        ("ledger_jsonl", ledger_jsonl_raw),
        ("proxy_label", proxy_label_raw),
        ("api_key", api_key_raw),
        ("authorization_header", authorization_raw),
    ):
        if raw is not None and local_proxy_secret_like(raw):
            secret_like_fields.append(field)
    if bind_secret_like and "bind_host" not in secret_like_fields:
        secret_like_fields.append("bind_host")
    if target_secret_like and "target_host" not in secret_like_fields:
        secret_like_fields.append("target_host")
    if upstream_secret_like and "upstream_url" not in secret_like_fields:
        secret_like_fields.append("upstream_url")

    blockers: list[str] = []
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if not persist_api_key_valid:
        blockers.append("invalid_persist_api_key")
    if not external_forwarding_intent_valid:
        blockers.append("invalid_external_forwarding_intent")
    if not runtime_gate_ack_valid:
        blockers.append("invalid_runtime_gate_ack")
    if not bind_port_valid:
        blockers.append("invalid_bind_port")
    if not target_port_valid:
        blockers.append("invalid_target_port")
    if upstream_url_raw and not upstream_url_valid:
        blockers.append("invalid_upstream_url")
    if not bind_localhost:
        blockers.append("non_localhost_bind_host")
    if not target_localhost:
        blockers.append("non_localhost_target_host")
    if upstream_url_raw and not upstream_localhost:
        blockers.append("non_localhost_upstream_url")
    if api_key_provided or authorization_header_provided:
        blockers.append("api_key_material_provided")
    if persist_api_key:
        blockers.append("api_key_persistence_requested")
    if external_forwarding_intent:
        blockers.append("external_forwarding_intent_not_allowed")
        if not runtime_gate_ack:
            blockers.append("missing_runtime_gate_ack")
    if secret_like_fields:
        blockers.append("secret_like_proxy_metadata")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "local-proxy",
        "mode": "dry_run",
        "status": "ready_for_runtime_review" if ready else "blocked_until_local_proxy_constraints",
        "input": input_meta,
        "policy": {
            "default_off": True,
            "dry_run_only": True,
            "localhost_only": True,
            "runtime_gate_required_before_forwarding": True,
            "runtime_gate_acknowledged": runtime_gate_ack,
            "stable_runtime_behavior_changed": False,
        },
        "bind": {
            "host": bind_host,
            "port": bind_port,
            "localhost_only": bind_localhost,
        },
        "target": {
            "host": target_host,
            "port": target_port,
            "upstream_url": upstream_url,
            "localhost_only": target_localhost,
        },
        "network_actions": {
            "listener_started": False,
            "outbound_forwarding_attempted": False,
            "dns_lookup_attempted": False,
            "external_services_called": False,
        },
        "api_key_persistence": {
            "api_key_material_provided": api_key_provided,
            "authorization_header_provided": authorization_header_provided,
            "requested": persist_api_key,
            "performed": False,
            "allowed_by_default": False,
        },
        "ledger_preview": {
            "schema_version": LOCAL_PROXY_SCHEMA_VERSION,
            "ledger_jsonl": ledger_jsonl,
            "ledger_write_performed": False,
            "proxy_label": proxy_label,
            "claim_boundary": "local_proxy_advisory_only_not_hosted_token_or_cost_savings",
        },
        "forwarding": {
            "external_forwarding_intent": external_forwarding_intent,
            "hidden_external_forwarding": False,
            "runtime_gate_acknowledged": runtime_gate_ack,
            "future_runtime_gate_required": True,
        },
        "redaction": {
            "secret_like_fields": sorted(set(secret_like_fields)),
            "raw_api_key_output": False,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "next_steps": [
                "Keep any real proxy runtime behind a separate future runtime gate.",
                "Use localhost-only bind and target defaults for advisory review.",
                "Do not persist API keys or forward externally from this dry-run planner.",
            ],
        },
        "claim_boundary": (
            "Dry-run local proxy advisory preview only; no listener, forwarding, API-key persistence, ledger write, "
            "or hosted API token/cost savings claim is performed."
        ),
    }


def command_plan_local_proxy(args: argparse.Namespace) -> int:
    payload = local_proxy_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard local proxy plan (dry-run only)")
        print("No listener was started, no traffic was forwarded, no API key was persisted, and no ledger was written.")
        print(f"Status: {payload['status']}")
        print(f"Bind: {payload['bind']['host']}:{payload['bind']['port']} localhost_only={payload['bind']['localhost_only']}")
        print(
            f"Target: {payload['target']['host']}:{payload['target']['port']} "
            f"localhost_only={payload['target']['localhost_only']}"
        )
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def local_proxy_gate_row(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": LOCAL_PROXY_GATE_SCHEMA_VERSION,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "experiment_id": "local-proxy",
        "proxy_label": payload["ledger_preview"]["proxy_label"],
        "bind": payload["bind"],
        "target": payload["target"],
        "policy": {
            "localhost_only": True,
            "runtime_gate_acknowledged": payload["policy"]["runtime_gate_acknowledged"],
            "listener_started": False,
            "traffic_forwarded": False,
            "dns_lookup_attempted": False,
            "api_key_persisted": False,
            "hidden_external_forwarding": False,
        },
        "network_actions": payload["network_actions"],
        "api_key_persistence": payload["api_key_persistence"],
        "forwarding": payload["forwarding"],
        "claim_boundary": {
            "id": "local_proxy_runtime_gate_not_hosted_savings",
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
            "requires_provider_measured_matched_tasks_for_hosted_claims": True,
            "reason": "This row records a local proxy runtime gate only; it starts no listener and forwards no traffic.",
        },
        "shifted_cost_accounting_required": True,
    }


def local_proxy_record_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = local_proxy_plan_payload(args)
    payload["mode"] = "record"
    payload["claim_boundary"] = (
        "Explicit local proxy runtime-gate record only; no listener, forwarding, DNS lookup, API-key persistence, "
        "external service call, or hosted API token/cost savings claim is performed."
    )
    payload["policy"] = dict(payload["policy"])
    payload["policy"].update({
        "dry_run_only": False,
        "runtime_gate_record_only": True,
        "runtime_gate_recorded": False,
        "listener_started": False,
        "traffic_forwarded": False,
        "stable_runtime_behavior_changed": False,
    })
    payload["ledger_record"] = None
    payload["ledger_jsonl"] = {
        "path": sanitize_local_proxy_value(args.ledger_jsonl),
        "write_performed": False,
        "bytes_written": 0,
    }
    blockers = list(payload["review_plan"]["readiness_blockers"])
    if not payload["policy"]["runtime_gate_acknowledged"]:
        blockers.append("missing_runtime_gate_ack")
    blockers = list(dict.fromkeys(blockers))
    payload["review_plan"]["readiness_blockers"] = blockers
    payload["ledger_preview"]["schema_version"] = LOCAL_PROXY_GATE_SCHEMA_VERSION
    payload["ledger_preview"]["ledger_jsonl"] = sanitize_local_proxy_value(args.ledger_jsonl)
    payload["ledger_preview"]["ledger_write_performed"] = False
    if blockers:
        payload["status"] = "blocked_until_local_proxy_gate_ready"
        return payload

    row = local_proxy_gate_row(payload)
    bytes_written = append_jsonl_no_follow(Path(args.ledger_jsonl), row, label="local proxy runtime gate ledger")
    payload["status"] = "recorded"
    payload["ledger_preview"] = row
    payload["ledger_record"] = row
    payload["ledger_jsonl"]["write_performed"] = True
    payload["ledger_jsonl"]["bytes_written"] = bytes_written
    payload["policy"]["runtime_gate_recorded"] = True
    payload["review_plan"]["next_steps"] = [
        "Use this JSONL row only as a local proxy runtime-gate record.",
        "Keep any actual proxy listener or forwarding implementation behind a separate reviewed runtime.",
        "Do not persist API keys or claim hosted token/cost savings from this gate record.",
    ]
    return payload


def command_record_local_proxy_runtime_gate(args: argparse.Namespace) -> int:
    payload = local_proxy_record_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "recorded":
            print("ContextGuard local proxy runtime-gate record written")
            print(f"Ledger: {payload['ledger_jsonl']['path']} bytes={payload['ledger_jsonl']['bytes_written']}")
        else:
            print("ContextGuard local proxy runtime-gate record blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "recorded" else 1


def local_proxy_forward_payload(args: argparse.Namespace) -> dict[str, Any]:
    input_payload, input_meta = read_local_proxy_payload(args)
    payload = local_proxy_plan_payload(args, input_payload=input_payload, input_meta=input_meta)
    forwarding_gate_ack, forwarding_gate_ack_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "forwarding_gate_ack",
        "forwarding_gate_ack",
    )
    once, once_valid = coalesce_local_proxy_bool(args, input_payload, "once", "once")
    max_request_bytes, max_request_valid = normalize_local_proxy_int_limit(
        coalesce_local_proxy_value(args, input_payload, "max_request_bytes", "max_request_bytes"),
        default=LOCAL_PROXY_DEFAULT_MAX_REQUEST_BYTES,
        maximum=LOCAL_PROXY_MAX_FORWARD_BYTES,
    )
    max_response_bytes, max_response_valid = normalize_local_proxy_int_limit(
        coalesce_local_proxy_value(args, input_payload, "max_response_bytes", "max_response_bytes"),
        default=LOCAL_PROXY_DEFAULT_MAX_RESPONSE_BYTES,
        maximum=LOCAL_PROXY_MAX_FORWARD_BYTES,
    )
    timeout_seconds, timeout_valid = normalize_local_proxy_timeout(
        coalesce_local_proxy_value(args, input_payload, "timeout_seconds", "timeout_seconds")
    )
    diagnostic_ledger_raw = coalesce_local_proxy_value(
        args,
        input_payload,
        "diagnostic_ledger_jsonl",
        "diagnostic_ledger_jsonl",
    )
    response_sandbox, response_sandbox_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "response_sandbox",
        "response_sandbox",
    )
    show_artifact_paths, show_artifact_paths_valid = coalesce_local_proxy_bool(
        args,
        input_payload,
        "show_artifact_paths",
        "show_artifact_paths",
    )
    response_artifact_dir_raw = coalesce_local_proxy_value(
        args,
        input_payload,
        "response_artifact_dir",
        "response_artifact_dir",
    ) or str(DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR)
    diagnostic_ledger_path = sanitize_local_proxy_value(diagnostic_ledger_raw) if diagnostic_ledger_raw else None
    diagnostic_ledger_write_path = str(diagnostic_ledger_raw) if diagnostic_ledger_raw else None
    response_artifact_dir = sanitize_local_proxy_value(response_artifact_dir_raw)
    response_artifact_write_dir = str(response_artifact_dir_raw)
    bind_host = payload["bind"]["host"]
    target_host = payload["target"]["host"]
    bind_ip_literal = is_loopback_ip_literal(bind_host)
    target_ip_literal = is_loopback_ip_literal(target_host)
    upstream_url = payload["target"].get("upstream_url")
    upstream_scheme = ""
    if upstream_url:
        try:
            upstream_scheme = urlparse(str(upstream_url)).scheme.lower()
        except ValueError:
            upstream_scheme = "invalid"

    payload["mode"] = "serve"
    payload["schema_version"] = LOCAL_PROXY_FORWARD_SCHEMA_VERSION
    payload["claim_boundary"] = (
        "Explicit local proxy forwarding MVP only; binds and forwards literal loopback IPs, blocks credential "
        "material, persists no API keys, performs no DNS lookup, calls no external services, and makes no hosted "
        "API token/cost savings claim."
    )
    payload["policy"] = dict(payload["policy"])
    payload["policy"].update({
        "dry_run_only": False,
        "forwarding_runtime": True,
        "forwarding_gate_acknowledged": forwarding_gate_ack,
        "once_required": True,
        "once": once,
        "literal_loopback_ip_only": True,
        "listener_started": False,
        "traffic_forwarded": False,
        "stable_runtime_behavior_changed": False,
        "response_sandbox_enabled": response_sandbox,
    })
    payload["forwarding"] = dict(payload["forwarding"])
    payload["forwarding"].update({
        "actual_local_forwarding_runtime": True,
        "forwarding_gate_acknowledged": forwarding_gate_ack,
        "external_forwarding_allowed": False,
        "connect_tunneling_allowed": False,
        "https_mitm_allowed": False,
    })
    payload["runtime_limits"] = {
        "once": once,
        "max_request_bytes": max_request_bytes,
        "max_response_bytes": max_response_bytes,
        "timeout_seconds": timeout_seconds,
    }
    payload["diagnostic_ledger"] = {
        "schema_version": LOCAL_PROXY_DIAGNOSTIC_SCHEMA_VERSION,
        "path": diagnostic_ledger_path,
        "path_sha256": hashlib.sha256(str(diagnostic_ledger_raw).encode("utf-8", errors="replace")).hexdigest() if diagnostic_ledger_raw else None,
        "write_requested": bool(diagnostic_ledger_raw),
        "write_performed": False,
        "bytes_written": 0,
        "reason": None if diagnostic_ledger_raw else "not_requested",
    }
    payload["response_sandbox"] = {
        "schema_version": LOCAL_PROXY_RESPONSE_SANDBOX_SCHEMA_VERSION,
        "enabled": response_sandbox,
        "artifact_dir": response_artifact_dir,
        "artifact_dir_sha256": hashlib.sha256(response_artifact_write_dir.encode("utf-8", errors="replace")).hexdigest(),
        "show_artifact_paths": show_artifact_paths,
        "exact_rehydration_commands": (
            Path(response_artifact_write_dir).expanduser() == Path(DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR)
            or show_artifact_paths
        ),
        "text_policy": "utf8_text_only",
        "stored_scope": LOCAL_PROXY_RESPONSE_SANDBOX_SCOPE,
        "downstream_envelope_only": True,
        "performed": False,
        "artifact_id": None,
        "artifact_handle": None,
        "sanitized_text_sha256": None,
        "envelope_bytes": 0,
        "claim_boundary": {
            "local_only": True,
            "stored_content_is_sanitized_utf8_text": True,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
        },
    }
    payload["client_auth"] = {
        "required": True,
        "type": "nonce_header",
        "header": LOCAL_PROXY_NONCE_HEADER,
        "delivery": "ready_file",
        "ready_file_required": True,
        "nonce_in_public_output": False,
        "nonce_forwarded_upstream": False,
    }
    payload["_diagnostic_ledger_write_path"] = diagnostic_ledger_write_path
    payload["_response_artifact_dir_write_path"] = response_artifact_write_dir
    payload["_response_artifact_show_paths"] = show_artifact_paths
    payload["forward_result"] = None

    blockers = list(payload["review_plan"]["readiness_blockers"])
    if diagnostic_ledger_raw is not None and local_proxy_secret_like(diagnostic_ledger_raw):
        blockers.append("secret_like_diagnostic_ledger_path")
    if not payload["policy"]["runtime_gate_acknowledged"]:
        blockers.append("missing_runtime_gate_ack")
    if not forwarding_gate_ack_valid:
        blockers.append("invalid_forwarding_gate_ack")
    if not once_valid:
        blockers.append("invalid_once")
    if not forwarding_gate_ack:
        blockers.append("missing_forwarding_gate_ack")
    if not once:
        blockers.append("once_required_for_forwarding_mvp")
    if payload["bind"]["port"] <= 0:
        blockers.append("bind_port_required_for_listener")
    if payload["target"]["port"] <= 0:
        blockers.append("target_port_required_for_forwarding")
    if not bind_ip_literal:
        blockers.append("bind_host_must_be_loopback_ip_literal")
    if not target_ip_literal:
        blockers.append("target_host_must_be_loopback_ip_literal")
    if upstream_scheme and upstream_scheme != "http":
        blockers.append("unsupported_upstream_url_scheme")
    if not max_request_valid:
        blockers.append("invalid_max_request_bytes")
    if not max_response_valid:
        blockers.append("invalid_max_response_bytes")
    if not timeout_valid:
        blockers.append("invalid_timeout_seconds")
    if not response_sandbox_valid:
        blockers.append("invalid_response_sandbox")
    if not show_artifact_paths_valid:
        blockers.append("invalid_show_artifact_paths")
    blockers = list(dict.fromkeys(blockers))
    payload["review_plan"]["readiness_blockers"] = blockers
    payload["review_plan"]["next_steps"] = [
        "Use this MVP only for local loopback HTTP forwarding.",
        "Keep external forwarding, CONNECT tunneling, credential persistence, and hosted savings claims behind later gates.",
        "Use --once plus byte/time limits for bounded operation.",
    ]
    payload["status"] = "ready_to_serve" if not blockers else "blocked_until_local_proxy_forwarding_ready"
    return payload


def local_proxy_forward_diagnostic_row(payload: dict[str, Any]) -> dict[str, Any]:
    result = payload.get("forward_result") or {}
    return {
        "schema_version": LOCAL_PROXY_DIAGNOSTIC_SCHEMA_VERSION,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "experiment_id": "local-proxy",
        "mode": "serve",
        "proxy_label": payload["ledger_preview"]["proxy_label"],
        "bind": payload["bind"],
        "target": {
            "host": payload["target"]["host"],
            "port": payload["target"]["port"],
            "localhost_only": payload["target"]["localhost_only"],
        },
        "request": {
            "method": result.get("request_method"),
            "target_sha256": result.get("request_target_sha256"),
            "target_bytes": result.get("request_target_bytes", 0),
            "body_bytes": result.get("inbound_request_bytes", 0),
            "headers_persisted": False,
            "body_persisted": False,
            "credential_material_forwarded": False,
        },
        "response": {
            "upstream_status": result.get("upstream_status"),
            "upstream_response_bytes": result.get("upstream_response_bytes", 0),
            "body_persisted": False,
            "response_sandboxed": bool(result.get("response_sandboxed")),
            "artifact_id": result.get("response_artifact_id"),
            "artifact_handle": result.get("response_artifact_handle"),
            "sanitized_text_sha256": result.get("sanitized_text_sha256"),
        },
        "runtime_limits": payload["runtime_limits"],
        "network_actions": payload["network_actions"],
        "policy": {
            "localhost_only": True,
            "literal_loopback_ip_only": True,
            "forwarded": bool(result.get("forwarded")),
            "api_key_persisted": False,
            "hidden_external_forwarding": False,
            "external_services_called": False,
            "dns_lookup_attempted": False,
            "connect_tunneling_allowed": False,
            "https_mitm_allowed": False,
            "response_sandboxed": bool(result.get("response_sandboxed")),
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
        },
        "shifted_cost_accounting": {
            "required": True,
            "local_proxy_request": True,
            "diagnostic_only": True,
            "provider_measured_matched_tasks_required_for_hosted_claims": True,
        },
        "claim_boundary": {
            "id": "local_proxy_forward_diagnostic_not_hosted_savings",
            "reason": "This row records one explicit literal-loopback forwarded request as shifted-cost diagnostic evidence only.",
            "hosted_api_token_savings_claim_allowed": False,
            "hosted_api_cost_savings_claim_allowed": False,
        },
    }


def maybe_write_local_proxy_forward_diagnostic(payload: dict[str, Any]) -> None:
    ledger = payload.get("diagnostic_ledger")
    if not isinstance(ledger, dict) or not ledger.get("write_requested"):
        return
    if payload.get("status") != "served_once" or not (payload.get("forward_result") or {}).get("forwarded"):
        if ledger.get("reason") != "preflight_failed":
            ledger["reason"] = "not_forwarded"
        return
    row = local_proxy_forward_diagnostic_row(payload)
    write_path = payload.get("_diagnostic_ledger_write_path")
    if not write_path:
        ledger["reason"] = "not_requested"
        return
    bytes_written = append_jsonl_no_follow(Path(str(write_path)), row, label="local proxy forwarding diagnostic ledger")
    ledger["write_performed"] = True
    ledger["bytes_written"] = bytes_written
    ledger["reason"] = None
    ledger["row_preview"] = row


def local_proxy_has_sensitive_headers(headers: Any) -> list[str]:
    found: list[str] = []
    for name, value in headers.items():
        lower = str(name).lower()
        if lower == LOCAL_PROXY_NONCE_HEADER.lower():
            # The per-run proxy nonce is a local client-auth secret delivered only
            # through the 0600 ready file. It is validated before this check and is
            # never forwarded upstream; do not let random nonce bytes
            # probabilistically trip the generic secret-like header detector.
            continue
        if lower in LOCAL_PROXY_SENSITIVE_HEADER_NAMES:
            found.append(lower)
        elif local_proxy_secret_like(name):
            found.append("redacted_sensitive_header")
        elif local_proxy_secret_like(value):
            found.append(lower)
    return sorted(set(found))


def local_proxy_safe_forward_headers(headers: Any, *, target_host: str, target_port: int) -> dict[str, str]:
    return {
        "Host": f"{target_host}:{target_port}",
        "Connection": "close",
    }


def local_proxy_response_headers(headers: Any) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for name, value in headers.items():
        lower = str(name).lower()
        if lower in LOCAL_PROXY_SENSITIVE_HEADER_NAMES or lower in LOCAL_PROXY_HOP_BY_HOP_HEADERS:
            continue
        if lower not in {"content-type"}:
            continue
        if local_proxy_secret_like(name) or local_proxy_secret_like(value):
            continue
        result.append((str(name), str(value)))
    return result


_LOCAL_PROXY_ARTIFACT_MODULE: Any | None = None


def load_local_proxy_artifact_module() -> Any:
    """Load the artifact escrow helper from kit source or packaged plugin bin.

    The source tree exposes ``context_escrow.py`` while the packaged plugin ships
    the same implementation as an extensionless executable named
    ``context-guard-artifact``.  Load either without adding non-stdlib runtime
    dependencies to the experimental registry.
    """
    global _LOCAL_PROXY_ARTIFACT_MODULE
    if _LOCAL_PROXY_ARTIFACT_MODULE is not None:
        return _LOCAL_PROXY_ARTIFACT_MODULE
    try:
        import context_escrow as artifact_module  # type: ignore[import-not-found]
    except ImportError:
        current_dir = Path(__file__).resolve().parent
        candidates = [
            current_dir / "context_escrow.py",
            current_dir / "context-guard-artifact",
        ]
        for candidate in candidates:
            if not candidate.is_file():
                continue
            loader = importlib.machinery.SourceFileLoader("_context_guard_local_proxy_artifact", str(candidate))
            spec = importlib.util.spec_from_loader("_context_guard_local_proxy_artifact", loader)
            if spec is None:
                continue
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            _LOCAL_PROXY_ARTIFACT_MODULE = module
            return module
        raise RegistryError("could not load local artifact helper for response sandbox")
    _LOCAL_PROXY_ARTIFACT_MODULE = artifact_module
    return artifact_module


def local_proxy_response_text_policy(body: bytes, content_type: str) -> tuple[str | None, str | None, str]:
    """Return decoded UTF-8 text for response sandbox or a block reason.

    G003 intentionally defines exact rehydration as exact sanitized UTF-8 text
    retrieval, not original arbitrary HTTP bytes.
    """
    base_content_type = content_type.split(";", 1)[0].strip().lower()
    text_like = (
        not base_content_type
        or base_content_type.startswith("text/")
        or base_content_type in {
            "application/json",
            "application/javascript",
            "application/xml",
            "application/x-ndjson",
            "application/problem+json",
        }
        or base_content_type.endswith("+json")
        or base_content_type.endswith("+xml")
    )
    binary_like = (
        base_content_type.startswith("image/")
        or base_content_type.startswith("audio/")
        or base_content_type.startswith("video/")
        or base_content_type in {
            "application/octet-stream",
            "application/pdf",
            "application/zip",
            "application/gzip",
        }
    )
    if binary_like or not text_like:
        return None, "response_sandbox_text_required", base_content_type or "unknown"
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "response_sandbox_text_required", base_content_type or "unknown"
    if any((ord(ch) < 32 and ch not in "\n\r\t") or ord(ch) == 127 for ch in text):
        return None, "response_sandbox_text_required", base_content_type or "unknown"
    return text, None, base_content_type or "none"


def local_proxy_store_response_artifact(
    response_text: str,
    *,
    artifact_dir: str,
    show_artifact_paths: bool,
    upstream_status: int,
) -> dict[str, Any]:
    artifact = load_local_proxy_artifact_module()
    directory = artifact.normalize_allowed_first_absolute_symlink(Path(artifact_dir).expanduser())
    sanitized_text, redacted_lines = artifact.sanitize_text(response_text, show_paths=show_artifact_paths)
    content_bytes = len(sanitized_text.encode("utf-8", errors="replace"))
    content_sha = hashlib.sha256(sanitized_text.encode("utf-8", errors="replace")).hexdigest()
    command_preview = f"local-proxy response sandbox upstream_status={upstream_status}"
    id_basis = json.dumps(
        {
            "content_sha256": content_sha,
            "command_preview": command_preview,
            "scope": LOCAL_PROXY_RESPONSE_SANDBOX_SCOPE,
        },
        sort_keys=True,
    )
    artifact_id = hashlib.sha256(id_basis.encode("utf-8")).hexdigest()[:20]
    content_path, meta_path = artifact.artifact_paths(directory, artifact_id)
    total_lines = sanitized_text.count("\n") + (1 if sanitized_text and not sanitized_text.endswith("\n") else 0)
    content_type = artifact.classify_content_type(sanitized_text)
    strategy = artifact.recommended_strategy(content_type)
    metadata: dict[str, Any] = {
        "artifact_id": artifact_id,
        "created_at": int(time.time()),
        "command_preview": command_preview,
        "content_type": content_type,
        "input": {
            "bytes_read": len(response_text.encode("utf-8", errors="replace")),
            "truncated": False,
            "max_bytes": LOCAL_PROXY_MAX_FORWARD_BYTES,
        },
        "stored_output": {
            "bytes": content_bytes,
            "lines": total_lines,
            "sha256": content_sha,
            "sanitized_text_sha256": content_sha,
            "content_file": content_path.name,
            "metadata_file": meta_path.name,
            "scope": LOCAL_PROXY_RESPONSE_SANDBOX_SCOPE,
        },
        "digest": artifact.build_digest(
            sanitized_text,
            artifact_id=artifact_id,
            redacted_lines=redacted_lines,
            raw_dir=artifact_dir,
            show_paths=show_artifact_paths,
        ),
        "retrieval": {
            "strategy": strategy,
            "deterministic": True,
            "hints": artifact.build_retrieval_hints(
                artifact_id,
                sanitized_text,
                content_type=content_type,
                strategy=strategy,
                total_lines=total_lines,
                raw_dir=artifact_dir,
                show_paths=show_artifact_paths,
            ),
        },
    }
    artifact.shrink_digest_for_metadata_cap(metadata)
    artifact.write_private_text(content_path, sanitized_text)
    artifact.write_private_text(meta_path, artifact.metadata_json_text(metadata))
    return artifact.receipt_for(metadata, raw_dir=artifact_dir, show_paths=show_artifact_paths)


def minimized_local_proxy_rehydration(receipt: dict[str, Any]) -> dict[str, Any]:
    sandbox = receipt.get("output_sandbox")
    rehydration = sandbox.get("rehydration") if isinstance(sandbox, dict) else None
    commands = rehydration.get("commands") if isinstance(rehydration, dict) else None
    kept_commands: list[dict[str, Any]] = []
    if isinstance(commands, list):
        for command in commands[:5]:
            if not isinstance(command, dict) or not isinstance(command.get("cli"), str):
                continue
            kept_commands.append({
                key: command[key]
                for key in ("type", "selector", "cli", "exact", "note")
                if key in command
            })
    return {
        "commands": kept_commands,
        "dir_argument": rehydration.get("dir_argument") if isinstance(rehydration, dict) else None,
        "exact_commands": rehydration.get("exact_commands") if isinstance(rehydration, dict) else None,
    }


def local_proxy_response_sandbox_envelope(
    *,
    receipt: dict[str, Any],
    upstream_status: int,
    upstream_response_bytes: int,
    content_type: str,
) -> dict[str, Any]:
    sandbox = receipt.get("output_sandbox")
    handle = sandbox.get("handle") if isinstance(sandbox, dict) else f"contextguard-artifact:{receipt.get('artifact_id')}"
    stored = receipt.get("stored_output")
    stored_output = stored if isinstance(stored, dict) else {}
    return {
        "schema_version": LOCAL_PROXY_RESPONSE_SANDBOX_SCHEMA_VERSION,
        "status": "response_sandboxed",
        "mode": "local_proxy_response_sandbox",
        "artifact_id": receipt.get("artifact_id"),
        "artifact_handle": handle,
        "upstream": {
            "status": upstream_status,
            "response_bytes": upstream_response_bytes,
            "content_type": content_type,
        },
        "stored_output": {
            "scope": LOCAL_PROXY_RESPONSE_SANDBOX_SCOPE,
            "bytes": stored_output.get("bytes"),
            "lines": stored_output.get("lines"),
            "sanitized_text_sha256": stored_output.get("sanitized_text_sha256") or stored_output.get("sha256"),
        },
        "rehydration": minimized_local_proxy_rehydration(receipt),
        "agent_guidance": [
            "Keep this compact local proxy response envelope in context instead of the full response body.",
            "Use rehydration.commands to retrieve exact sanitized UTF-8 response slices before relying on omitted details.",
        ],
        "claim_boundary": {
            "local_only": True,
            "stored_content_is_sanitized_utf8_text": True,
            "original_http_bytes_rehydration_available": False,
            "hosted_api_token_or_cost_savings_claim_allowed": False,
            "provider_measured_matched_tasks_required_for_hosted_claims": True,
        },
    }


def write_local_proxy_ready_file(path: str | None, *, bind_host: str, bind_port: int, auth_nonce: str) -> None:
    if not path:
        return
    ready_payload = {
        "schema_version": LOCAL_PROXY_READY_SCHEMA_VERSION,
        "experiment_id": "local-proxy",
        "mode": "serve",
        "status": "listener_ready",
        "diagnostic_only": True,
        "pid": os.getpid(),
        "bind": {
            "host": bind_host,
            "port": bind_port,
        },
        "client_auth": {
            "required": True,
            "type": "nonce_header",
            "header": LOCAL_PROXY_NONCE_HEADER,
            "nonce": auth_nonce,
            "forwarded_upstream": False,
            "public_output": False,
        },
    }
    data = json.dumps(ready_payload, sort_keys=True).encode("utf-8") + b"\n"
    write_regular_file_no_follow_exclusive(Path(path), data, label="local proxy ready file", mode=0o600)


def serve_local_proxy_once(payload: dict[str, Any], *, ready_file: str | None = None) -> dict[str, Any]:
    bind_host = payload["bind"]["host"]
    bind_port = int(payload["bind"]["port"])
    target_host = payload["target"]["host"]
    target_port = int(payload["target"]["port"])
    limits = payload["runtime_limits"]
    max_request_bytes = int(limits["max_request_bytes"])
    max_response_bytes = int(limits["max_response_bytes"])
    timeout_seconds = float(limits["timeout_seconds"])
    response_sandbox = payload.get("response_sandbox")
    response_sandbox_enabled = bool(response_sandbox.get("enabled")) if isinstance(response_sandbox, dict) else False
    response_artifact_dir = str(payload.get("_response_artifact_dir_write_path") or DEFAULT_CONTEXT_DIFF_ARTIFACT_DIR)
    response_show_artifact_paths = bool(payload.get("_response_artifact_show_paths"))
    auth_nonce = secrets.token_urlsafe(32)
    server_result: dict[str, Any] = {
        "served_once": False,
        "forwarded": False,
        "blocked_reason": None,
        "forward_attempted": False,
        "request_method": None,
        "request_target_sha256": None,
        "request_target_bytes": 0,
        "inbound_request_bytes": 0,
        "upstream_status": None,
        "upstream_response_bytes": 0,
        "downstream_status": None,
        "sensitive_headers_blocked": [],
        "listener_started": False,
        "ready_file_written": False,
        "client_auth_required": True,
        "client_auth_header": LOCAL_PROXY_NONCE_HEADER,
        "client_auth_delivered": False,
        "client_auth_nonce_forwarded": False,
        "auth_failures": 0,
        "response_sandbox_requested": response_sandbox_enabled,
        "response_sandboxed": False,
        "response_artifact_id": None,
        "response_artifact_handle": None,
        "response_envelope_bytes": 0,
        "sanitized_text_sha256": None,
        "response_text_policy": "utf8_text_only" if response_sandbox_enabled else None,
    }

    def finish_blocked(
        handler: BaseHTTPRequestHandler,
        status_code: int,
        reason: str,
        *,
        sensitive: list[str] | None = None,
        consume_once: bool = True,
    ) -> None:
        updates = {
            "forwarded": False,
            "blocked_reason": reason,
            "downstream_status": status_code,
            "sensitive_headers_blocked": sorted(set(sensitive or [])),
        }
        if consume_once:
            updates["served_once"] = True
        server_result.update(updates)
        body = json.dumps({"status": "blocked", "reason": reason}, sort_keys=True).encode("utf-8")
        handler.send_response(status_code)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    class LocalProxyHandler(BaseHTTPRequestHandler):
        server_version = "ContextGuardLocalProxy/0"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - BaseHTTPRequestHandler API.
            return

        def authorize_request(self) -> bool:
            values = self.headers.get_all(LOCAL_PROXY_NONCE_HEADER, [])
            if len(values) == 0:
                server_result["auth_failures"] = int(server_result.get("auth_failures", 0)) + 1
                finish_blocked(self, 403, "missing_proxy_nonce", consume_once=False)
                return False
            if len(values) != 1:
                server_result["auth_failures"] = int(server_result.get("auth_failures", 0)) + 1
                finish_blocked(self, 403, "duplicate_proxy_nonce", consume_once=False)
                return False
            candidate = str(values[0])
            if not secrets.compare_digest(candidate, auth_nonce):
                server_result["auth_failures"] = int(server_result.get("auth_failures", 0)) + 1
                finish_blocked(self, 403, "invalid_proxy_nonce", consume_once=False)
                return False
            return True

        def do_CONNECT(self) -> None:
            server_result["request_method"] = "CONNECT"
            server_result.update(local_proxy_request_target_meta(self.path))
            if not self.authorize_request():
                return
            finish_blocked(self, 405, "connect_tunneling_not_allowed")

        def do_HEAD(self) -> None:
            self.forward_request()

        def do_GET(self) -> None:
            self.forward_request()

        def do_POST(self) -> None:
            self.block_method()

        def do_PUT(self) -> None:
            self.block_method()

        def do_PATCH(self) -> None:
            self.block_method()

        def block_method(self) -> None:
            server_result["request_method"] = self.command
            server_result.update(local_proxy_request_target_meta(self.path))
            if not self.authorize_request():
                return
            finish_blocked(self, 405, "method_not_allowed")

        def do_DELETE(self) -> None:
            self.block_method()

        def do_OPTIONS(self) -> None:
            self.block_method()

        def do_TRACE(self) -> None:
            self.block_method()

        def forward_request(self) -> None:
            server_result["request_method"] = self.command
            server_result.update(local_proxy_request_target_meta(self.path))
            if not self.authorize_request():
                return
            if response_sandbox_enabled and self.command != "GET":
                finish_blocked(self, 405, "response_sandbox_get_only")
                return
            if local_proxy_secret_like(self.path):
                finish_blocked(self, 400, "secret_like_request_target")
                return
            parsed_target = urlparse(self.path)
            if parsed_target.scheme or parsed_target.netloc:
                finish_blocked(self, 400, "absolute_proxy_url_not_allowed")
                return
            if str(self.headers.get("Transfer-Encoding", "")).strip():
                finish_blocked(self, 400, "transfer_encoding_not_allowed")
                return
            sensitive_headers = local_proxy_has_sensitive_headers(self.headers)
            if sensitive_headers:
                finish_blocked(self, 403, "sensitive_request_headers_blocked", sensitive=sensitive_headers)
                return
            raw_length = self.headers.get("Content-Length")
            try:
                content_length = int(raw_length) if raw_length else 0
            except ValueError:
                finish_blocked(self, 400, "invalid_content_length")
                return
            if content_length < 0 or content_length > max_request_bytes:
                finish_blocked(self, 413, "request_body_exceeds_limit")
                return
            if content_length:
                finish_blocked(self, 400, "request_body_not_allowed_for_forwarding_mvp")
                return
            body = self.rfile.read(content_length) if content_length else b""
            server_result["inbound_request_bytes"] = len(body)
            path = self.path if self.path.startswith("/") else f"/{self.path}"
            conn = http.client.HTTPConnection(target_host, target_port, timeout=timeout_seconds)
            try:
                server_result["forward_attempted"] = True
                conn.request(
                    self.command,
                    path,
                    body=body,
                    headers=local_proxy_safe_forward_headers(self.headers, target_host=target_host, target_port=target_port),
                )
                response = conn.getresponse()
                response_body = response.read(max_response_bytes + 1)
                if len(response_body) > max_response_bytes:
                    finish_blocked(self, 502, "upstream_response_exceeds_limit")
                    return
                if local_proxy_bytes_secret_like(response_body):
                    finish_blocked(self, 502, "upstream_response_sensitive_content_blocked")
                    return
                if response_sandbox_enabled:
                    content_type = str(response.headers.get("Content-Type", ""))
                    response_text, blocked_reason, normalized_content_type = local_proxy_response_text_policy(response_body, content_type)
                    if response_text is None:
                        finish_blocked(self, 502, blocked_reason or "response_sandbox_text_required")
                        return
                    try:
                        receipt = local_proxy_store_response_artifact(
                            response_text,
                            artifact_dir=response_artifact_dir,
                            show_artifact_paths=response_show_artifact_paths,
                            upstream_status=int(response.status),
                        )
                        envelope = local_proxy_response_sandbox_envelope(
                            receipt=receipt,
                            upstream_status=int(response.status),
                            upstream_response_bytes=len(response_body),
                            content_type=normalized_content_type,
                        )
                        envelope_body = json.dumps(envelope, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
                    except (OSError, RuntimeError, ValueError, RegistryError, json.JSONDecodeError) as exc:
                        finish_blocked(self, 502, "response_sandbox_artifact_store_failed")
                        server_result["error"] = sanitize_local_proxy_value(str(exc))
                        return
                    self.send_response(response.status, response.reason)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(envelope_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(envelope_body)
                    stored = receipt.get("stored_output") if isinstance(receipt, dict) else {}
                    sandbox = receipt.get("output_sandbox") if isinstance(receipt, dict) else {}
                    server_result.update({
                        "response_sandboxed": True,
                        "response_artifact_id": receipt.get("artifact_id"),
                        "response_artifact_handle": sandbox.get("handle") if isinstance(sandbox, dict) else None,
                        "response_envelope_bytes": len(envelope_body),
                        "sanitized_text_sha256": stored.get("sanitized_text_sha256") or stored.get("sha256") if isinstance(stored, dict) else None,
                    })
                else:
                    self.send_response(response.status, response.reason)
                    for header_name, header_value in local_proxy_response_headers(response.headers):
                        self.send_header(header_name, header_value)
                    self.send_header("Content-Length", str(len(response_body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(response_body)
                server_result.update({
                    "served_once": True,
                    "forwarded": True,
                    "blocked_reason": None,
                    "upstream_status": response.status,
                    "upstream_response_bytes": len(response_body),
                    "downstream_status": response.status,
                })
            except (OSError, http.client.HTTPException, TimeoutError) as exc:
                finish_blocked(self, 502, "upstream_forward_error")
                server_result["error"] = sanitize_local_proxy_value(str(exc))
            finally:
                conn.close()

    address_family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    class LocalProxyHTTPServer(HTTPServer):
        def server_bind(self) -> None:
            TCPServer.server_bind(self)
            host, port = self.server_address[:2]
            self.server_name = str(host)
            self.server_port = int(port)

        def get_request(self) -> tuple[Any, Any]:
            request, client_address = super().get_request()
            request.settimeout(timeout_seconds)
            return request, client_address

    LocalProxyHTTPServer.address_family = address_family
    try:
        httpd = LocalProxyHTTPServer((bind_host, bind_port), LocalProxyHandler)
    except OSError as exc:
        raise RegistryError(f"could not start local proxy listener: {os_error_detail(exc)}") from exc
    httpd.timeout = timeout_seconds
    try:
        try:
            write_local_proxy_ready_file(ready_file, bind_host=bind_host, bind_port=bind_port, auth_nonce=auth_nonce)
            server_result["ready_file_written"] = bool(ready_file)
            server_result["client_auth_delivered"] = bool(ready_file)
            server_result["listener_started"] = True
        except RegistryError as exc:
            server_result.update({
                "served_once": False,
                "forwarded": False,
                "blocked_reason": "ready_file_write_failed",
                "downstream_status": None,
                "error": sanitize_local_proxy_value(str(exc)),
            })
            return server_result
        deadline = time.monotonic() + timeout_seconds
        while not server_result["served_once"]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            httpd.timeout = max(0.001, min(timeout_seconds, remaining))
            httpd.handle_request()
        if not server_result["served_once"] and not server_result.get("blocked_reason"):
            server_result.update({
                "blocked_reason": "timeout_waiting_for_request",
                "downstream_status": None,
            })
    finally:
        httpd.server_close()
    return server_result


def command_serve_local_proxy(args: argparse.Namespace) -> int:
    payload = local_proxy_forward_payload(args)
    diagnostic_ledger = payload.get("diagnostic_ledger") if isinstance(payload.get("diagnostic_ledger"), dict) else {}
    if payload["status"] == "ready_to_serve" and not args.ready_file:
        payload["status"] = "blocked_until_local_proxy_forwarding_ready"
        payload["review_plan"]["readiness_blockers"].append("missing_ready_file_for_proxy_nonce")
        diagnostic_ledger["reason"] = "not_forwarded" if diagnostic_ledger.get("write_requested") else diagnostic_ledger.get("reason")
    if payload["status"] == "ready_to_serve" and diagnostic_ledger.get("write_requested"):
        try:
            preflight_append_jsonl_no_follow(
                Path(str(payload.get("_diagnostic_ledger_write_path"))),
                label="local proxy forwarding diagnostic ledger",
            )
        except RegistryError as exc:
            payload["status"] = "blocked_until_local_proxy_forwarding_ready"
            payload["review_plan"]["readiness_blockers"].append("diagnostic_ledger_preflight_failed")
            diagnostic_ledger["reason"] = "preflight_failed"
            diagnostic_ledger["error"] = sanitize_local_proxy_value(str(exc))
    if payload["status"] == "ready_to_serve":
        result = serve_local_proxy_once(payload, ready_file=args.ready_file)
        payload["forward_result"] = result
        payload["network_actions"]["listener_started"] = bool(result.get("listener_started"))
        payload["network_actions"]["outbound_forwarding_attempted"] = bool(result["forward_attempted"])
        payload["network_actions"]["dns_lookup_attempted"] = False
        payload["network_actions"]["external_services_called"] = False
        payload["policy"]["listener_started"] = bool(result.get("listener_started"))
        payload["policy"]["traffic_forwarded"] = bool(result["forwarded"])
        if isinstance(payload.get("response_sandbox"), dict):
            payload["response_sandbox"]["performed"] = bool(result.get("response_sandboxed"))
            payload["response_sandbox"]["artifact_id"] = result.get("response_artifact_id")
            payload["response_sandbox"]["artifact_handle"] = result.get("response_artifact_handle")
            payload["response_sandbox"]["sanitized_text_sha256"] = result.get("sanitized_text_sha256")
            payload["response_sandbox"]["envelope_bytes"] = result.get("response_envelope_bytes", 0)
        if result["forwarded"]:
            payload["status"] = "served_once"
        elif result.get("blocked_reason") == "ready_file_write_failed":
            payload["status"] = "blocked_until_local_proxy_forwarding_ready"
            payload["review_plan"]["readiness_blockers"].append("ready_file_write_failed")
        else:
            payload["status"] = "blocked_request"
    maybe_write_local_proxy_forward_diagnostic(payload)
    payload.pop("_diagnostic_ledger_write_path", None)
    payload.pop("_response_artifact_dir_write_path", None)
    payload.pop("_response_artifact_show_paths", None)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "served_once":
            print("ContextGuard local proxy served one loopback request")
        else:
            print("ContextGuard local proxy serve blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
            if payload.get("forward_result") and payload["forward_result"].get("blocked_reason"):
                print(f"Request blocker: {payload['forward_result']['blocked_reason']}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "served_once" else 1


LEARNED_CODE_FENCE_RE = re.compile(r"(?m)^\s*(?:```|~~~)")
LEARNED_DIFF_RE = re.compile(r"(?m)^\s*(diff --git |@@\s+-|--- |\+\+\+ |[+-].*)")
LEARNED_IDENTIFIER_RE = re.compile(
    r"\b(?:"
    r"_*[A-Za-z]+_[A-Za-z0-9_]*"
    r"|_*[a-z]+[A-Z][A-Za-z0-9]*"
    r"|_*[A-Z][a-z]+[A-Z][A-Za-z0-9]*"
    r"|_*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r"|_*[A-Z][A-Z0-9_]{2,}"
    r")\b"
)
LEARNED_PATH_RE = re.compile(
    r"(?x)(?:"
    r"(?<![\w.-])/(?:[A-Za-z0-9._@%+=:-]+/)*[A-Za-z0-9._@%+=:-]+"
    r"|"
    r"\b[A-Za-z]:\\(?:[^\\\s:\"'<>|]+\\)*[^\\\s:\"'<>|]+"
    r"|"
    r"(?<![\w.-])(?:\.{1,2}/)+[A-Za-z0-9._@%+=:-]+(?:/[A-Za-z0-9._@%+=:-]+)*\b"
    r"|"
    r"\b(?:\.{1,2}/)?(?:[A-Za-z0-9._@%+=:-]+/)+[A-Za-z0-9._@%+=:-]+\b"
    r"|"
    r"\b[A-Za-z0-9._-]+\.(?:py|js|ts|tsx|jsx|go|rs|java|kt|swift|json|ya?ml|toml|md|txt|log|sh|bash|zsh|sql|html|css)\b"
    r")"
)
LEARNED_HASH_RE = re.compile(r"\b(?:sha256:[0-9a-fA-F]{32,64}|[0-9a-fA-F]{7,64})\b")
LEARNED_STACK_FRAME_RE = re.compile(
    r"(?m)^\s*(?:File\s+\"[^\"]+\",\s+line\s+\d+,\s+in\s+\S+|at\s+\S+.*\([^)]*:\d+(?::\d+)?\))"
)
LEARNED_JSON_KEY_RE = re.compile(r"""(?x)"(?:[^"\\]|\\.)*"\s*:|'(?:[^'\\]|\\.)*'\s*:""")
LEARNED_QUOTED_STRING_RE = re.compile(
    r'''(?x)"""(?:.|\n)*?"""|''' + r"""'''(?:.|\n)*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'"""
)
LEARNED_NUMERIC_CONSTANT_RE = re.compile(
    r"(?<![\w.])(?:[vV]?\d+(?:\.\d+)*|[-+]?0x[0-9A-Fa-f]+)(?![\w.])"
)
LEARNED_PROMPT_LIKE_RE = re.compile(
    r"(?imx)(?:"
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:above|earlier|previous|prior)\s+instructions?\b"
    r"|^\s*(?:system|developer|user|assistant)\s*:"
    r"|\b(?:system|developer|user|assistant)\s+instructions?\b"
    r"|\b(?:system|developer)\s+message\b"
    r"|\byou\s+are\s+(?:now\s+)?(?:chatgpt|a\s+\w+|\w+)\b"
    r"|\bact\s+as\b"
    r"|\bjailbreak\b"
    r"|\bdo\s+not\s+follow\b"
    r"|\boverride\s+instructions\b"
    r")"
)
LEARNED_URL_RE = re.compile(
    r"(?i)\b(?:https?://|(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?:/|\b)"
)
LEARNED_CODE_LIKE_RE = re.compile(
    r"(?mx)^\s*(?:"
    r"(?:from\s+\S+\s+import\s+\S+|import\s+\S+|def\s+[A-Za-z_]\w*\s*\(|class\s+[A-Za-z_]\w*\s*(?:\(|:)|"
    r"function\s+[A-Za-z_$][\w$]*\s*\(|(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=)"
    r"|(?:if|elif|else|for|while|try|except|finally|with)\b.*:"
    r"|(?:print|raise|return|yield|assert)\b(?:\s*\(|\s+\S+)"
    r"|[A-Za-z_][A-Za-z0-9_]*\s*(?:=|==|!=|<=|>=|\+=|-=|\*=|/=)\s*\S+"
    r"|.*[{};]\s*$"
    r"|(?:ls|cp|mv|rm|sudo|curl|wget|chmod|chown|git|npm|npx|pnpm|yarn|python3?|pip|node|bash|sh|zsh|cat|grep|sed|awk|make|cargo|pytest|tox|uv|ruff|mypy|pyright|docker|kubectl)(?:\s+(?:-\S+|\S+))*"
    r"|<[/!]?[A-Za-z][A-Za-z0-9-]*(?:\s+[^<>]*)?>"
    r")"
)
LEARNED_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")
LEARNED_NON_TEXT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufffd]")
LEARNED_WORD_RE = re.compile(r"\b[\w.-]+\b")
LEARNED_ARTIFACT_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")


def read_learned_input(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    source_label = args.source_label
    if args.input:
        path = Path(args.input)
        source_label = source_label or path.name
        loaded = read_bounded_regular_file(path, max_bytes=MAX_LEARNED_COMPRESSION_INPUT_BYTES, label="learned-compression input")
        assert loaded is not None
        raw, truncated = loaded
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_LEARNED_COMPRESSION_INPUT_BYTES + 1)
        truncated = len(raw) > MAX_LEARNED_COMPRESSION_INPUT_BYTES
        raw = raw[:MAX_LEARNED_COMPRESSION_INPUT_BYTES]
    text = raw.decode("utf-8", errors="replace")
    metadata = {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()),
        "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
        "truncated": truncated,
        "max_bytes": MAX_LEARNED_COMPRESSION_INPUT_BYTES,
    }
    return text, metadata


def learned_content_type(text: str, counts: dict[str, int]) -> str:
    stripped = text.strip()
    if not stripped:
        return "empty"
    if counts["non_text_input"]:
        return "non_text"
    if counts["protected_json_key"]:
        return "json"
    if counts["protected_diff"]:
        return "diff"
    if counts["protected_code_fence"] or counts["protected_code_like"] or counts["protected_identifier"] >= 3:
        return "code"
    return "prose"


def learned_signal_counts(text: str) -> dict[str, int]:
    words = LEARNED_WORD_RE.findall(text)
    numeric_count = len(LEARNED_NUMERIC_CONSTANT_RE.findall(text))
    code_like_count = len(LEARNED_CODE_LIKE_RE.findall(text)) + len(LEARNED_INLINE_CODE_RE.findall(text))
    numeric_density_high = 1 if words and numeric_count >= 3 and numeric_count / len(words) >= 0.20 else 0
    return {
        "protected_code_fence": len(LEARNED_CODE_FENCE_RE.findall(text)),
        "protected_diff": len(LEARNED_DIFF_RE.findall(text)),
        "protected_identifier": len(LEARNED_IDENTIFIER_RE.findall(text)),
        "protected_path": len(LEARNED_PATH_RE.findall(text)),
        "protected_hash": len(LEARNED_HASH_RE.findall(text)),
        "protected_stack_frame": len(LEARNED_STACK_FRAME_RE.findall(text)),
        "protected_json_key": len(LEARNED_JSON_KEY_RE.findall(text)),
        "protected_numeric_constant": numeric_count,
        "protected_quoted_string": len(LEARNED_QUOTED_STRING_RE.findall(text)),
        "prompt_like_instruction": len(LEARNED_PROMPT_LIKE_RE.findall(text)),
        "url_or_endpoint": len(LEARNED_URL_RE.findall(text)),
        "protected_code_like": code_like_count,
        "non_text_input": len(LEARNED_NON_TEXT_RE.findall(text)),
        "numeric_density_high": numeric_density_high,
    }


def valid_learned_reexpand_command(receipt_id: str | None, command: str | None) -> tuple[bool, str | None]:
    if not receipt_id or not command:
        return False, "missing_exact_fallback"
    if not LEARNED_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command"
    if any(token in command for token in (";", "|", "&", ">", "<", "`", "$", "\n", "\r")):
        return False, "invalid_reexpand_command"
    try:
        argv = shlex.split(command)
    except ValueError:
        return False, "invalid_reexpand_command"
    if len(argv) < 4:
        return False, "invalid_reexpand_command"
    if argv == ["context-guard-artifact", "get", receipt_id, "--full"]:
        return True, None
    if argv == ["context-guard", "artifact", "get", receipt_id, "--full"]:
        return True, None
    return False, "invalid_reexpand_command"


def verify_learned_fallback_artifact(
    receipt_id: str | None,
    *,
    expected_sha256: str,
    expected_bytes: int,
) -> tuple[bool, str | None, dict[str, Any]]:
    if not receipt_id or not LEARNED_ARTIFACT_ID_RE.fullmatch(receipt_id):
        return False, "invalid_reexpand_command", {"checked": False, "read_directories": []}
    read_dirs = context_diff_artifact_read_dirs()
    details: dict[str, Any] = {
        "checked": True,
        "read_directories": [str(path) for path in read_dirs],
        "matched_directory": None,
        "content_sha256": None,
        "content_bytes": None,
    }
    for directory in read_dirs:
        content_path, meta_path = context_diff_artifact_paths(directory, receipt_id)
        meta_loaded = read_bounded_regular_file(
            meta_path,
            max_bytes=MAX_LEARNED_COMPRESSION_ARTIFACT_METADATA_BYTES,
            label="learned-compression fallback metadata",
            missing_ok=True,
        )
        content_loaded = read_bounded_regular_file(
            content_path,
            max_bytes=max(MAX_LEARNED_COMPRESSION_INPUT_BYTES, expected_bytes),
            label="learned-compression fallback content",
            missing_ok=True,
        )
        if meta_loaded is None and content_loaded is None:
            continue
        if meta_loaded is None or content_loaded is None:
            return False, "fallback_receipt_invalid", details
        meta_raw, meta_truncated = meta_loaded
        content_raw, content_truncated = content_loaded
        if meta_truncated or content_truncated:
            return False, "fallback_receipt_invalid", details
        try:
            metadata = json.loads(meta_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return False, "fallback_receipt_invalid", details
        if not isinstance(metadata, dict) or metadata.get("artifact_id") != receipt_id:
            return False, "fallback_receipt_invalid", details
        stored = metadata.get("stored_output")
        stored_sha = stored.get("sha256") if isinstance(stored, dict) else None
        stored_bytes = stored.get("bytes") if isinstance(stored, dict) else None
        actual_sha = hashlib.sha256(content_raw).hexdigest()
        actual_bytes = len(content_raw)
        details.update({
            "matched_directory": str(directory),
            "content_sha256": actual_sha,
            "content_bytes": actual_bytes,
        })
        if stored_sha != actual_sha or stored_bytes != actual_bytes:
            return False, "fallback_receipt_invalid", details
        if actual_sha != expected_sha256 or actual_bytes != expected_bytes:
            return False, "fallback_content_mismatch", details
        return True, None, details
    return False, "fallback_receipt_not_found", details


def read_learned_candidate_replacement(args: argparse.Namespace) -> tuple[str | None, dict[str, Any]]:
    if args.replacement_text is not None and args.replacement_file:
        raise RegistryError("learned-compression emit accepts only one of --replacement-text or --replacement-file")
    if args.replacement_text is not None:
        text = str(args.replacement_text)
        raw = text.encode("utf-8")
        truncated = len(raw) > MAX_LEARNED_COMPRESSION_REPLACEMENT_BYTES
        raw = raw[:MAX_LEARNED_COMPRESSION_REPLACEMENT_BYTES]
        text = raw.decode("utf-8", errors="replace")
        source_label = "inline"
    elif args.replacement_file:
        path = Path(args.replacement_file)
        loaded = read_bounded_regular_file(
            path,
            max_bytes=MAX_LEARNED_COMPRESSION_REPLACEMENT_BYTES,
            label="learned-compression candidate replacement",
        )
        assert loaded is not None
        raw, truncated = loaded
        text = raw.decode("utf-8", errors="replace")
        source_label = path.name
    else:
        text = None
        raw = b""
        truncated = False
        source_label = None
    return text, {
        "source_label": source_label,
        "bytes": len(raw),
        "lines": len(text.splitlines()) if text is not None else 0,
        "sha256": hashlib.sha256(raw).hexdigest() if text is not None else None,
        "truncated": truncated,
        "max_bytes": MAX_LEARNED_COMPRESSION_REPLACEMENT_BYTES,
    }


def learned_compression_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    text, input_meta = read_learned_input(args)
    receipt_id = args.exact_fallback_receipt.strip() if args.exact_fallback_receipt else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, fallback_blocker = valid_learned_reexpand_command(receipt_id, reexpand_command)
    counts = learned_signal_counts(text)
    content_type = learned_content_type(text, counts)

    blockers: list[str] = []
    if not text.strip():
        blockers.append("missing_input")
    if input_meta["truncated"]:
        blockers.append("input_truncated")
    if not args.sanitized:
        blockers.append("missing_sanitized_assertion")
    if not args.trusted_source:
        blockers.append("untrusted_input")
    if fallback_blocker:
        blockers.append(fallback_blocker)
    if content_type != "prose" and text.strip():
        blockers.append("non_prose_input")
    for blocker, count in counts.items():
        if count:
            blockers.append(blocker)
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers
    return {
        "tool": TOOL_NAME,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "experiment_id": "learned-compression",
        "mode": "dry_run",
        "status": "ready_for_human_review" if ready else "blocked_until_safe_input",
        "input": input_meta,
        "policy": {
            "deny_by_default": True,
            "runtime_compression_allowed": False,
            "eligible_for_human_review": ready,
            "human_review_required": True,
            "stable_runtime_behavior_changed": False,
        },
        "sanitization": {
            "required": True,
            "caller_asserted": bool(args.sanitized),
            "verified": False,
        },
        "trust": {
            "required": True,
            "caller_asserted": bool(args.trusted_source),
            "verified": False,
        },
        "exact_fallback": {
            "required": True,
            "available": bool(receipt_id and reexpand_command and reexpand_valid),
            "receipt_id": receipt_id,
            "cli": reexpand_command,
            "verified": False,
        },
        "protected_signal_scan": {
            "content_type": content_type,
            "counts": counts,
        },
        "review_plan": {
            "readiness_blockers": blockers,
            "protected_signals": [name for name, count in counts.items() if count],
            "next_steps": [
                "Keep exact fallback receipt and re-expand command available before considering any future summary.",
                "Reject learned compression for protected, prompt-like, untrusted, or non-prose input.",
                "Do not claim hosted token/cost savings from this dry-run policy check.",
            ],
        },
        "claim_boundary": (
            "Dry-run learned-compression policy check only; no hosted token/cost savings claim without "
            "provider-measured matched successful tasks."
        ),
        "candidate_replacement": None,
    }


def command_plan_learned_compression(args: argparse.Namespace) -> int:
    payload = learned_compression_plan_payload(args)
    if args.json:
        emit_json(payload)
    else:
        print("ContextGuard learned/synthetic compression gate (dry-run only)")
        print("No learned compressor/model/provider was called and no replacement text was emitted.")
        print(f"Status: {payload['status']}")
        print(f"Input: {payload['input']['source_label']} lines={payload['input']['lines']} sha256={payload['input']['sha256']}")
        if payload["review_plan"]["readiness_blockers"]:
            print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0


def learned_compression_emit_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload = learned_compression_plan_payload(args)
    receipt_id = args.exact_fallback_receipt.strip() if args.exact_fallback_receipt else None
    reexpand_command = args.reexpand_command.strip() if args.reexpand_command else None
    reexpand_valid, _fallback_blocker = valid_learned_reexpand_command(receipt_id, reexpand_command)
    fallback_verified = False
    fallback_blocker = None
    fallback_verification: dict[str, Any] = {"checked": False, "read_directories": []}
    if reexpand_valid:
        fallback_verified, fallback_blocker, fallback_verification = verify_learned_fallback_artifact(
            receipt_id,
            expected_sha256=payload["input"]["sha256"],
            expected_bytes=payload["input"]["bytes"],
        )

    candidate_text, candidate_meta = read_learned_candidate_replacement(args)
    candidate_counts = learned_signal_counts(candidate_text or "")
    candidate_content_type = learned_content_type(candidate_text or "", candidate_counts)

    blockers = list(payload["review_plan"]["readiness_blockers"])
    if fallback_blocker:
        blockers.append(fallback_blocker)
    if candidate_text is None or not candidate_text.strip():
        blockers.append("missing_candidate_replacement")
    if candidate_meta["truncated"]:
        blockers.append("candidate_replacement_truncated")
    if (
        candidate_text is not None
        and not candidate_meta["truncated"]
        and candidate_meta["bytes"] >= payload["input"]["bytes"]
    ):
        blockers.append("candidate_not_smaller_than_input")
    if candidate_text is not None and candidate_text.strip() and candidate_content_type != "prose":
        blockers.append("candidate_non_prose_input")
    for blocker, count in candidate_counts.items():
        if count:
            blockers.append(f"candidate_{blocker}")
    blockers = list(dict.fromkeys(blockers))
    ready = not blockers

    payload["mode"] = "emit"
    payload["status"] = "candidate_emitted" if ready else "blocked_until_candidate_ready"
    payload["policy"] = dict(payload["policy"])
    payload["policy"].update({
        "runtime_compression_allowed": False,
        "caller_supplied_candidate_required": True,
        "caller_supplied_candidate_allowed": ready,
        "lossy_replacement_allowed": ready,
        "learned_compressor_called": False,
        "embedding_or_reranker_called": False,
        "model_call_allowed": False,
        "subprocess_allowed": False,
    })
    payload["exact_fallback"] = {
        "required": True,
        "available": bool(receipt_id and reexpand_command and reexpand_valid and fallback_verified),
        "receipt_id": receipt_id,
        "cli": reexpand_command,
        "verified": fallback_verified,
        "valid_command_shape": reexpand_valid,
        "verification": fallback_verification,
        "note": "Emit mode validates exact local fallback command shape and verifies local artifact content matches the input prose.",
    }
    payload["candidate_scan"] = {
        "content_type": candidate_content_type,
        "counts": candidate_counts,
        "protected_signals": [name for name, count in candidate_counts.items() if count],
    }
    payload["replacement"] = candidate_meta
    payload["review_plan"]["readiness_blockers"] = blockers
    payload["review_plan"]["protected_signals"] = [name for name, count in payload["protected_signal_scan"]["counts"].items() if count]
    payload["review_plan"]["candidate_protected_signals"] = [
        name for name, count in candidate_counts.items() if count
    ]
    payload["review_plan"]["next_steps"] = [
        "Human-review the caller-supplied candidate against the exact fallback before using it.",
        "Reject candidates that omit protected facts, prompt-like text, paths, code, diffs, identifiers, or numeric constants.",
        "Treat byte reduction as local proxy evidence only; do not claim hosted token/cost savings.",
    ]
    payload["claim_boundary"] = (
        "Explicit local learned-compression candidate emission only; ContextGuard does not run a learned compressor, "
        "model, embedding, reranker, subprocess, or external service, and byte reduction is not hosted API token or cost evidence."
    )
    bytes_after = candidate_meta["bytes"] if candidate_text is not None else 0
    payload["compression_evidence"] = {
        "bytes_before": payload["input"]["bytes"],
        "bytes_after": bytes_after,
        "byte_reduction": max(0, payload["input"]["bytes"] - bytes_after),
        "byte_reduction_proxy_only": True,
        "hosted_api_token_savings_claim_allowed": False,
        "hosted_api_cost_savings_claim_allowed": False,
    }
    if ready and candidate_text is not None:
        payload["candidate_replacement"] = {
            "text": candidate_text,
            "bytes": candidate_meta["bytes"],
            "lines": candidate_meta["lines"],
            "sha256": candidate_meta["sha256"],
            "source_label": candidate_meta["source_label"],
            "caller_supplied": True,
        }
    else:
        payload.pop("candidate_replacement", None)
    return payload


def command_emit_learned_compression(args: argparse.Namespace) -> int:
    payload = learned_compression_emit_payload(args)
    if args.json:
        emit_json(payload)
    else:
        if payload["status"] == "candidate_emitted":
            print("ContextGuard learned-compression candidate emitted")
            print(
                f"Candidate: bytes={payload['replacement']['bytes']} "
                f"sha256={payload['replacement']['sha256']}"
            )
            print(f"Exact fallback: {payload['exact_fallback']['cli']}")
        else:
            print("ContextGuard learned-compression candidate blocked")
            print(f"Status: {payload['status']}")
            if payload["review_plan"]["readiness_blockers"]:
                print(f"Readiness blockers: {', '.join(payload['review_plan']['readiness_blockers'])}")
        print(payload["claim_boundary"])
    return 0 if payload["status"] == "candidate_emitted" else 1


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", help="Project root for default project-local experiment config (default: cwd).")
    parser.add_argument("--config", help="Project-local config path. Relative paths resolve under --root; absolute paths must stay inside --root.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")


def load_args_context(args: argparse.Namespace) -> tuple[Path, Path, dict[str, Any]]:
    root = resolve_root(args.root)
    config_path = resolve_config_path(root, args.config)
    return root, config_path, load_config(config_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Inspect and manage default-off ContextGuard experimental feature opt-ins.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="List known experiments and metadata.")
    add_common_args(list_parser)
    list_parser.set_defaults(func=command_list)

    status_parser = sub.add_parser("status", help="Show project-local experiment enablement status.")
    add_common_args(status_parser)
    status_parser.set_defaults(func=command_status)

    enable_parser = sub.add_parser("enable", help="Enable one experiment in project-local config.")
    enable_parser.add_argument("experiment_id")
    add_common_args(enable_parser)
    enable_parser.set_defaults(func=command_enable)

    disable_parser = sub.add_parser("disable", help="Disable one experiment in project-local config.")
    disable_parser.add_argument("experiment_id")
    add_common_args(disable_parser)
    disable_parser.set_defaults(func=command_disable)

    plan_parser = sub.add_parser("plan", help="Run read-only dry-run planners for experimental lanes.")
    plan_sub = plan_parser.add_subparsers(dest="plan_command", required=True)

    context_diff = plan_sub.add_parser(
        "context-diff-compaction",
        help="Dry-run a reviewable context-diff compaction plan without emitting a replacement.",
    )
    context_diff.add_argument("--input", help="Read diff text from a file instead of stdin.")
    context_diff.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    context_diff.add_argument("--receipt-id", help="User-supplied exact receipt/artifact id for human review readiness.")
    context_diff.add_argument("--reexpand-command", help="User-supplied exact re-expand command for human review readiness.")
    context_diff.add_argument("--json", action="store_true", help="Emit JSON output.")
    context_diff.set_defaults(func=command_plan_context_diff_compaction)

    visual_ocr = plan_sub.add_parser(
        "visual-crop-ocr",
        help="Dry-run visual crop/OCR evidence metadata without calling OCR or image services.",
    )
    visual_ocr.add_argument("--full-evidence-receipt", help="User-supplied receipt/id for the original full visual evidence.")
    visual_ocr.add_argument("--full-evidence-label", help="Safe label for the full visual evidence.")
    visual_ocr.add_argument("--crop-label", help="Safe label for the cropped region or crop fixture.")
    visual_ocr.add_argument("--crop-bounds", help="Crop bounds as x,y,width,height integers.")
    visual_ocr.add_argument("--image-size", help="Original image size as width,height integers.")
    visual_ocr.add_argument("--ocr-text", help="Bounded OCR fixture text supplied inline.")
    visual_ocr.add_argument("--ocr-text-file", help="Read bounded OCR fixture text from a UTF-8 text file.")
    visual_ocr.add_argument("--ocr-source-label", help="Safe label for OCR text source; defaults to inline or file basename.")
    visual_ocr.add_argument("--ocr-confidence", help="OCR confidence as a finite decimal from 0.0 to 1.0.")
    visual_ocr.add_argument("--ocr-error-note", action="append", help="Known OCR error/uncertainty note. Repeatable.")
    visual_ocr.add_argument("--missed-context-note", action="append", help="Potential context outside crop/OCR text. Repeatable.")
    visual_ocr.add_argument("--json", action="store_true", help="Emit JSON output.")
    visual_ocr.set_defaults(func=command_plan_visual_crop_ocr)

    image_context_pack = plan_sub.add_parser(
        "image-context-pack",
        help="Dry-run a plan-only pxpipe-inspired image/context packing gate without rendering images.",
    )
    image_context_pack.add_argument("--source-label", help="Safe label for this image/context packing plan.")
    image_context_pack.add_argument("--image-size", help="Optional source image/context canvas size as width,height integers.")
    image_context_pack.add_argument("--packed-image-size", help="Optional planned packed image size as width,height integers.")
    image_context_pack.add_argument("--exact-text-fallback-receipt", help="Local exact text artifact receipt id for omitted source text.")
    image_context_pack.add_argument("--reexpand-command", help="Local exact text re-expand command bound to the receipt id.")
    image_context_pack.add_argument(
        "--provider-boundary-ack",
        action="store_true",
        help="Acknowledge hosted claims require provider-measured matched successful tasks for the target model.",
    )
    image_context_pack.add_argument(
        "--protected-zone-policy",
        default="deny",
        choices=("deny", "allow"),
        help="Protected evidence handling; only deny can pass the plan gate.",
    )
    image_context_pack.add_argument("--missed-context-note", action="append", help="Potential context omitted by a future pack. Repeatable.")
    image_context_pack.add_argument("--json", action="store_true", help="Emit JSON output.")
    image_context_pack.set_defaults(func=command_plan_image_context_pack)

    semantic_checkpoint = plan_sub.add_parser(
        "semantic-checkpoint",
        help="Dry-run a plan-only semantic checkpoint metadata gate without replacing raw context.",
    )
    semantic_checkpoint.add_argument("--goal", help="Planning goal for the semantic checkpoint metadata.")
    semantic_checkpoint.add_argument("--constraint", action="append", help="Constraint the checkpoint metadata must preserve. Repeatable.")
    semantic_checkpoint.add_argument("--decision", action="append", help="Decision captured by the checkpoint metadata. Repeatable.")
    semantic_checkpoint.add_argument("--open-task", action="append", help="Open task captured by the checkpoint metadata. Repeatable.")
    semantic_checkpoint.add_argument("--evidence-handle", action="append", help="Evidence/provenance handle supporting the checkpoint. Repeatable.")
    semantic_checkpoint.add_argument("--missing-provenance-note", action="append", help="Missing provenance review note or 'none known after review'. Repeatable.")
    semantic_checkpoint.add_argument("--unresolved-question", action="append", help="Unresolved question for checkpoint review. Repeatable.")
    semantic_checkpoint.add_argument("--exact-context-fallback-receipt", help="Local exact raw context artifact receipt id.")
    semantic_checkpoint.add_argument("--reexpand-command", help="Local exact context re-expand command bound to the receipt id.")
    semantic_checkpoint.add_argument(
        "--provider-boundary-ack",
        action="store_true",
        help="Acknowledge hosted claims require provider-measured matched successful tasks for the target model.",
    )
    semantic_checkpoint.add_argument(
        "--protected-zone-policy",
        default="deny",
        choices=("deny", "allow"),
        help="Protected evidence handling; only deny can pass the plan gate.",
    )
    semantic_checkpoint.add_argument("--missed-context-note", action="append", help="Potential context missed by checkpoint metadata. Repeatable.")
    semantic_checkpoint.add_argument("--json", action="store_true", help="Emit JSON output.")
    semantic_checkpoint.set_defaults(func=command_plan_semantic_checkpoint)

    proof_carrying_context = plan_sub.add_parser(
        "proof-carrying-context",
        help="Dry-run bounded proof-envelope metadata readiness without reading or verifying content.",
    )
    proof_carrying_context.add_argument(
        "--proof-unit-json",
        action="append",
        help="Inline literal proof-unit JSON object. Repeatable; never treated as a path.",
    )
    proof_carrying_context.add_argument(
        "--provider-boundary-ack",
        action="store_true",
        help="Acknowledge hosted claims require provider-measured matched successful tasks for the target model.",
    )
    proof_carrying_context.add_argument(
        "--protected-zone-policy",
        default="deny",
        choices=("deny", "allow"),
        help="Caller-declared protected evidence policy; only deny can pass and compliance remains unchecked.",
    )
    proof_carrying_context.add_argument("--json", action="store_true", help="Emit JSON output.")
    proof_carrying_context.set_defaults(func=command_plan_proof_carrying_context)

    semantic_gc = plan_sub.add_parser(
        "semantic-gc",
        allow_abbrev=False,
        help="Plan caller-declared graph reachability candidates without reading or omitting context.",
    )
    semantic_gc.add_argument(
        "--context-unit-json",
        action="append",
        help="Inline literal semantic-GC unit JSON object. Repeatable; never treated as a path.",
    )
    semantic_gc.add_argument(
        "--provider-boundary-ack",
        action="store_true",
        help="Acknowledge that provider behavior and hosted savings remain unverified.",
    )
    semantic_gc.add_argument(
        "--human-review-ack",
        action="store_true",
        help="Acknowledge that candidate review remains required; this does not perform review.",
    )
    semantic_gc.add_argument(
        "--protected-zone-policy",
        choices=("deny",),
        default=None,
        help="Explicit deny-only protected-zone declaration; omitted remains effective deny but blocks readiness.",
    )
    semantic_gc.add_argument("--json", action="store_true", help="Emit JSON output.")
    semantic_gc.set_defaults(func=command_plan_semantic_gc)

    self_hosted = plan_sub.add_parser(
        "self-hosted-metrics-ledger",
        help="Dry-run self-hosted/local metrics ledger sidecar evidence without writing a ledger.",
    )
    self_hosted.add_argument("--input", help="Read an explicit self_hosted_metrics JSON envelope from a file instead of stdin.")
    self_hosted.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    self_hosted.add_argument("--latency-ms", type=float, default=None, help="Local/model-server latency in milliseconds.")
    self_hosted.add_argument("--peak-memory-mb", type=float, default=None, help="Peak local/model-server memory in MiB/MB.")
    self_hosted.add_argument("--quality-score", type=float, default=None, help="Quality score from 0.0 to 1.0.")
    self_hosted.add_argument("--energy-wh", type=float, default=None, help="Diagnostic local energy use in watt-hours.")
    self_hosted.add_argument("--local-cost-usd", type=float, default=None, help="Diagnostic local/self-hosted cost in USD.")
    self_hosted.add_argument("--tokens-per-second", type=float, default=None, help="Diagnostic local throughput.")
    self_hosted.add_argument("--model-server", help="Sanitized label for local model server/runtime.")
    self_hosted.add_argument("--optimization", help="Sanitized label for the local optimization under test.")
    self_hosted.add_argument("--quality-metric", help="Sanitized label for quality metric.")
    self_hosted.add_argument("--hardware", help="Sanitized local hardware label.")
    self_hosted.add_argument("--runtime", help="Sanitized local runtime label.")
    self_hosted.add_argument("--dataset", help="Sanitized dataset label.")
    self_hosted.add_argument("--json", action="store_true", help="Emit JSON output.")
    self_hosted.set_defaults(func=command_plan_self_hosted_metrics_ledger)

    local_proxy = plan_sub.add_parser(
        "local-proxy",
        help="Dry-run a localhost-only local proxy advisory plan without starting a proxy.",
    )
    local_proxy.add_argument("--input", help="Read a local_proxy JSON envelope from a file instead of CLI flags.")
    local_proxy.add_argument("--bind-host", help="Advisory bind host; must be localhost/loopback.")
    local_proxy.add_argument("--bind-port", default=None, help="Advisory bind port; 0 means unspecified/ephemeral.")
    local_proxy.add_argument("--target-host", help="Advisory target host; must be localhost/loopback.")
    local_proxy.add_argument("--target-port", default=None, help="Advisory target port; 0 means unspecified.")
    local_proxy.add_argument("--upstream-url", help="Advisory upstream URL; host must be localhost/loopback.")
    local_proxy.add_argument("--ledger-jsonl", help="Advisory ledger path preview; dry-run only, not written.")
    local_proxy.add_argument("--proxy-label", help="Safe label for this local proxy plan.")
    local_proxy.add_argument("--api-key", help="Blocked/redacted API key material; never persisted or emitted raw.")
    local_proxy.add_argument("--authorization-header", help="Blocked/redacted Authorization header; never persisted or emitted raw.")
    local_proxy.add_argument("--persist-api-key", action="store_true", help="Declare API-key persistence intent; blocked by default.")
    local_proxy.add_argument(
        "--external-forwarding-intent",
        action="store_true",
        help="Declare future external forwarding intent; blocked in this dry-run planner.",
    )
    local_proxy.add_argument(
        "--runtime-gate-ack",
        action="store_true",
        help="Acknowledge that any future forwarding needs a separate runtime gate.",
    )
    local_proxy.add_argument("--json", action="store_true", help="Emit JSON output.")
    local_proxy.set_defaults(func=command_plan_local_proxy)

    external_proxy = plan_sub.add_parser(
        "local-proxy-external-forwarding",
        help="Dry-run an external-forwarding opt-in design gate without forwarding traffic.",
    )
    external_proxy.add_argument(
        "--external-forwarding-intent",
        action="store_true",
        help="Acknowledge intent to design a future external-forwarding proxy surface.",
    )
    external_proxy.add_argument(
        "--external-forwarding-design-ack",
        action="store_true",
        help="Acknowledge this command is design-only and does not enable external forwarding.",
    )
    external_proxy.add_argument("--allow-host", action="append", help="Explicit non-wildcard public host allowed by the future design. Repeatable.")
    external_proxy.add_argument("--allow-scheme", action="append", help="Allowed scheme for the future design; HTTPS is required. Repeatable.")
    external_proxy.add_argument("--threat-model-note", action="append", help="Threat-model note for the future external-forwarding design. Repeatable.")
    external_proxy.add_argument(
        "--credential-redaction-policy",
        help=f"Required policy: {LOCAL_PROXY_EXTERNAL_CREDENTIAL_REDACTION_POLICY}.",
    )
    external_proxy.add_argument(
        "--provider-evidence-boundary",
        help=f"Required policy: {LOCAL_PROXY_EXTERNAL_PROVIDER_EVIDENCE_BOUNDARY}.",
    )
    external_proxy.add_argument("--json", action="store_true", help="Emit JSON output.")
    external_proxy.set_defaults(func=command_plan_local_proxy_external_forwarding)

    learned = plan_sub.add_parser(
        "learned-compression",
        help="Dry-run a deny-by-default learned/synthetic compression safety gate.",
    )
    learned.add_argument("--input", help="Read candidate prose from a text file instead of stdin.")
    learned.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    learned.add_argument("--sanitized", action="store_true", help="Assert input is already sanitized.")
    learned.add_argument("--trusted-source", action="store_true", help="Assert input came from a trusted source.")
    learned.add_argument("--exact-fallback-receipt", help="Local exact fallback receipt id for the original text.")
    learned.add_argument("--reexpand-command", help="Local exact re-expand command bound to the receipt id.")
    learned.add_argument("--json", action="store_true", help="Emit JSON output.")
    learned.set_defaults(func=command_plan_learned_compression)

    emit_parser = sub.add_parser("emit", help="Emit explicit local runtime outputs for experimental lanes.")
    emit_sub = emit_parser.add_subparsers(dest="emit_command", required=True)
    emit_context_diff = emit_sub.add_parser(
        "context-diff-compaction",
        help="Emit a caller-supplied compact diff replacement only with exact retrieval metadata.",
    )
    emit_context_diff.add_argument("--input", help="Read original diff text from a file instead of stdin.")
    emit_context_diff.add_argument("--source-label", help="Safe label to use for the diff input source in reports.")
    emit_context_diff.add_argument("--receipt-id", required=True, help="Exact local artifact receipt id for the original diff.")
    emit_context_diff.add_argument("--reexpand-command", required=True, help="Exact command that restores the original diff.")
    replacement_group = emit_context_diff.add_mutually_exclusive_group(required=True)
    replacement_group.add_argument("--replacement-text", help="Caller-supplied compact replacement text to emit.")
    replacement_group.add_argument("--replacement-file", help="Read caller-supplied compact replacement text from a file.")
    emit_context_diff.add_argument("--json", action="store_true", help="Emit JSON output.")
    emit_context_diff.set_defaults(func=command_emit_context_diff_compaction)

    emit_visual_ocr = emit_sub.add_parser(
        "visual-crop-ocr",
        help="Emit a caller-supplied visual crop/OCR evidence pack without image/OCR services.",
    )
    emit_visual_ocr.add_argument("--full-evidence-receipt", help="User-supplied receipt/id for the original full visual evidence.")
    emit_visual_ocr.add_argument("--full-evidence-label", help="Safe label for the full visual evidence.")
    emit_visual_ocr.add_argument("--crop-label", help="Safe label for the cropped region or crop fixture.")
    emit_visual_ocr.add_argument("--crop-bounds", help="Crop bounds as x,y,width,height integers.")
    emit_visual_ocr.add_argument("--image-size", help="Original image size as width,height integers.")
    emit_visual_ocr.add_argument("--ocr-text", help="Bounded OCR fixture text supplied inline.")
    emit_visual_ocr.add_argument("--ocr-text-file", help="Read bounded OCR fixture text from a UTF-8 text file.")
    emit_visual_ocr.add_argument("--ocr-source-label", help="Safe label for OCR text source; defaults to inline or file basename.")
    emit_visual_ocr.add_argument("--ocr-confidence", help="OCR confidence as a finite decimal from 0.0 to 1.0.")
    emit_visual_ocr.add_argument("--ocr-error-note", action="append", help="Known OCR error/uncertainty note. Repeatable.")
    emit_visual_ocr.add_argument("--missed-context-note", action="append", help="Potential context outside crop/OCR text. Repeatable.")
    emit_visual_ocr.add_argument("--json", action="store_true", help="Emit JSON output.")
    emit_visual_ocr.set_defaults(func=command_emit_visual_crop_ocr)

    emit_learned = emit_sub.add_parser(
        "learned-compression",
        help="Emit a caller-supplied compact prose candidate only with verified exact fallback.",
    )
    emit_learned.add_argument("--input", help="Read original prose text from a file instead of stdin.")
    emit_learned.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    emit_learned.add_argument("--sanitized", action="store_true", help="Assert input is already sanitized.")
    emit_learned.add_argument("--trusted-source", action="store_true", help="Assert input came from a trusted source.")
    emit_learned.add_argument("--exact-fallback-receipt", required=True, help="Local exact fallback receipt id for the original text.")
    emit_learned.add_argument("--reexpand-command", required=True, help="Local exact re-expand command bound to the receipt id.")
    learned_replacement_group = emit_learned.add_mutually_exclusive_group(required=True)
    learned_replacement_group.add_argument("--replacement-text", help="Caller-supplied compact prose candidate to emit.")
    learned_replacement_group.add_argument("--replacement-file", help="Read caller-supplied compact prose candidate from a file.")
    emit_learned.add_argument("--json", action="store_true", help="Emit JSON output.")
    emit_learned.set_defaults(func=command_emit_learned_compression)

    record_parser = sub.add_parser("record", help="Run explicit local runtime recorders for experimental lanes.")
    record_sub = record_parser.add_subparsers(dest="record_command", required=True)
    record_self_hosted = record_sub.add_parser(
        "self-hosted-metrics-ledger",
        help="Append one self-hosted/local metrics sidecar row to a JSONL ledger.",
    )
    record_self_hosted.add_argument("--ledger-jsonl", required=True, help="Local JSONL ledger path to append.")
    record_self_hosted.add_argument("--input", help="Read an explicit self_hosted_metrics JSON envelope from a file instead of stdin.")
    record_self_hosted.add_argument("--source-label", help="Safe label to use for the input source in reports.")
    record_self_hosted.add_argument("--latency-ms", type=float, default=None, help="Local/model-server latency in milliseconds.")
    record_self_hosted.add_argument("--peak-memory-mb", type=float, default=None, help="Peak local/model-server memory in MiB/MB.")
    record_self_hosted.add_argument("--quality-score", type=float, default=None, help="Quality score from 0.0 to 1.0.")
    record_self_hosted.add_argument("--energy-wh", type=float, default=None, help="Diagnostic local energy use in watt-hours.")
    record_self_hosted.add_argument("--local-cost-usd", type=float, default=None, help="Diagnostic local/self-hosted cost in USD.")
    record_self_hosted.add_argument("--tokens-per-second", type=float, default=None, help="Diagnostic local throughput.")
    record_self_hosted.add_argument("--model-server", help="Sanitized label for local model server/runtime.")
    record_self_hosted.add_argument("--optimization", help="Sanitized label for the local optimization under test.")
    record_self_hosted.add_argument("--quality-metric", help="Sanitized label for quality metric.")
    record_self_hosted.add_argument("--hardware", help="Sanitized local hardware label.")
    record_self_hosted.add_argument("--runtime", help="Sanitized local runtime label.")
    record_self_hosted.add_argument("--dataset", help="Sanitized dataset label.")
    record_self_hosted.add_argument("--task-id", default="self-hosted-metrics-manual", help="Sanitized task id for the ledger row.")
    record_self_hosted.add_argument("--variant", default="self-hosted-metrics-ledger", help="Sanitized variant label for the ledger row.")
    record_self_hosted.add_argument(
        "--success",
        choices=("true", "false", "unknown"),
        default="unknown",
        help="Optional success value for the local run; unknown writes JSON null.",
    )
    record_self_hosted.add_argument(
        "--notes",
        default="explicit self-hosted metrics record; no hosted API savings claim",
        help="Sanitized note for the ledger row.",
    )
    record_self_hosted.add_argument("--json", action="store_true", help="Emit JSON output.")
    record_self_hosted.set_defaults(func=command_record_self_hosted_metrics_ledger)

    record_local_proxy = record_sub.add_parser(
        "local-proxy-runtime-gate",
        help="Append one localhost-only local proxy runtime-gate row without starting a proxy.",
    )
    record_local_proxy.add_argument("--input", help="Read a local_proxy JSON envelope from a file instead of CLI flags.")
    record_local_proxy.add_argument("--bind-host", help="Advisory bind host; must be localhost/loopback.")
    record_local_proxy.add_argument("--bind-port", default=None, help="Advisory bind port; 0 means unspecified/ephemeral.")
    record_local_proxy.add_argument("--target-host", help="Advisory target host; must be localhost/loopback.")
    record_local_proxy.add_argument("--target-port", default=None, help="Advisory target port; 0 means unspecified.")
    record_local_proxy.add_argument("--upstream-url", help="Advisory upstream URL; host must be localhost/loopback.")
    record_local_proxy.add_argument("--ledger-jsonl", required=True, help="Local JSONL ledger path to append the gate row.")
    record_local_proxy.add_argument("--proxy-label", help="Safe label for this local proxy gate record.")
    record_local_proxy.add_argument("--api-key", help="Blocked/redacted API key material; never persisted or emitted raw.")
    record_local_proxy.add_argument("--authorization-header", help="Blocked/redacted Authorization header; never persisted or emitted raw.")
    record_local_proxy.add_argument("--persist-api-key", action="store_true", help="Declare API-key persistence intent; blocked.")
    record_local_proxy.add_argument(
        "--external-forwarding-intent",
        action="store_true",
        help="Declare future external forwarding intent; blocked in this gate recorder.",
    )
    record_local_proxy.add_argument(
        "--runtime-gate-ack",
        action="store_true",
        help="Acknowledge this is only a local gate record and any forwarding needs a separate runtime gate.",
    )
    record_local_proxy.add_argument("--json", action="store_true", help="Emit JSON output.")
    record_local_proxy.set_defaults(func=command_record_local_proxy_runtime_gate)

    serve_parser = sub.add_parser("serve", help="Run explicit bounded local servers for experimental lanes.")
    serve_sub = serve_parser.add_subparsers(dest="serve_command", required=True)
    serve_local_proxy = serve_sub.add_parser(
        "local-proxy",
        help="Serve one bounded localhost-only HTTP forwarding request.",
    )
    serve_local_proxy.add_argument("--input", help="Read a local_proxy JSON envelope from a file instead of CLI flags.")
    serve_local_proxy.add_argument("--bind-host", help="Bind host; actual serving requires a literal loopback IP.")
    serve_local_proxy.add_argument("--bind-port", default=None, help="Bind port; must be a nonzero explicit port for serving.")
    serve_local_proxy.add_argument("--target-host", help="Target host; actual forwarding requires a literal loopback IP.")
    serve_local_proxy.add_argument("--target-port", default=None, help="Target port; must be a nonzero explicit port for forwarding.")
    serve_local_proxy.add_argument("--upstream-url", help="Optional upstream URL; host must be a literal loopback IP for serving.")
    serve_local_proxy.add_argument("--proxy-label", help="Safe label for this local proxy serve run.")
    serve_local_proxy.add_argument(
        "--diagnostic-ledger-jsonl",
        help="Append one shifted-cost diagnostic JSONL row only after a successful loopback forwarded request.",
    )
    serve_local_proxy.add_argument(
        "--response-sandbox",
        action="store_true",
        help="Return a compact JSON response envelope and store the sanitized upstream response body as a local artifact receipt.",
    )
    serve_local_proxy.add_argument(
        "--response-artifact-dir",
        default=None,
        help="Artifact directory for --response-sandbox receipts; defaults to .context-guard/artifacts.",
    )
    serve_local_proxy.add_argument(
        "--show-artifact-paths",
        action="store_true",
        help="Include exact local artifact paths in response-sandbox rehydration commands; otherwise custom dirs are redacted.",
    )
    serve_local_proxy.add_argument("--api-key", help="Blocked/redacted API key material; never persisted or emitted raw.")
    serve_local_proxy.add_argument("--authorization-header", help="Blocked/redacted Authorization header; never persisted or emitted raw.")
    serve_local_proxy.add_argument("--persist-api-key", action="store_true", help="Declare API-key persistence intent; blocked.")
    serve_local_proxy.add_argument(
        "--external-forwarding-intent",
        action="store_true",
        help="Declare external forwarding intent; blocked in this local-only runtime.",
    )
    serve_local_proxy.add_argument(
        "--runtime-gate-ack",
        action="store_true",
        help="Acknowledge this is an explicit experimental runtime.",
    )
    serve_local_proxy.add_argument(
        "--forwarding-gate-ack",
        action="store_true",
        help="Acknowledge this starts a loopback-only forwarding listener for one bounded request.",
    )
    serve_local_proxy.add_argument("--once", action="store_true", help="Serve exactly one accepted or blocked request; required for this MVP.")
    serve_local_proxy.add_argument(
        "--max-request-bytes",
        default=None,
        help=f"Maximum request body bytes, 1..{LOCAL_PROXY_MAX_FORWARD_BYTES}.",
    )
    serve_local_proxy.add_argument(
        "--max-response-bytes",
        default=None,
        help=f"Maximum upstream response bytes, 1..{LOCAL_PROXY_MAX_FORWARD_BYTES}.",
    )
    serve_local_proxy.add_argument(
        "--timeout-seconds",
        default=None,
        help=f"Listener/upstream timeout seconds, 0.1..{LOCAL_PROXY_MAX_TIMEOUT_SECONDS}.",
    )
    serve_local_proxy.add_argument("--ready-file", help=argparse.SUPPRESS)
    serve_local_proxy.add_argument("--json", action="store_true", help="Emit JSON output after the single request completes.")
    serve_local_proxy.set_defaults(func=command_serve_local_proxy)

    return parser


def normalize_negative_csv_option_values(argv: list[str] | None) -> list[str] | None:
    """Keep negative comma-separated option values portable across Python versions.

    Python 3.11/3.12 argparse treats a value such as ``-1,0,20,10`` after an
    option as another option token rather than as the option's value.  Python
    3.14 accepts the same test input, so normalize the small set of CSV-valued
    options that intentionally accepts negative numbers for validation.
    """
    if argv is None:
        argv = sys.argv[1:]
    normalized: list[str] = []
    pending_csv_option: str | None = None
    csv_options = {"--crop-bounds", "--image-size", "--packed-image-size"}
    for token in argv:
        if pending_csv_option is not None:
            normalized.append(f"{pending_csv_option}={token}")
            pending_csv_option = None
            continue
        if token in csv_options:
            pending_csv_option = token
            continue
        normalized.append(token)
    if pending_csv_option is not None:
        normalized.append(pending_csv_option)
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(normalize_negative_csv_option_values(argv))
    try:
        return int(args.func(args))
    except RegistryError as exc:
        fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
