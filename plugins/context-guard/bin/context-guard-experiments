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
import hashlib
import json
import math
import re
import shlex
from pathlib import Path
import sys
from typing import Any, NoReturn
import unicodedata

TOOL_NAME = "context-guard-experiments"
CONFIG_SCHEMA_VERSION = "contextguard.experiments.v1"
DEFAULT_CONFIG = Path(".context-guard") / "experiments.json"
MAX_CONTEXT_DIFF_INPUT_BYTES = 256_000
MAX_VISUAL_OCR_TEXT_BYTES = 64_000
MAX_LEARNED_COMPRESSION_INPUT_BYTES = 128_000
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
        summary="Dry-run advisory lane for human-reviewable compaction plans with stable exact handles.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Smaller local diffs are proxy evidence only; hosted savings require provider-measured matched tasks.",
        gate_requirements=("explicit opt-in", "human-reviewable diff", "local receipt", "exact re-expand handle"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan context-diff-compaction",),
        opt_in_flags=("plan context-diff-compaction", "--receipt-id", "--reexpand-command"),
        config_effect=(
            "Registry enablement records project-local intent only; context-diff compaction remains a dry-run plan "
            "unless a future story adds an explicit replacement command."
        ),
        evidence_contract=(
            "Dry-run plans require human-reviewable hunks plus user-supplied exact receipt and re-expand handles before "
            "any future lossy replacement can be reviewed."
        ),
    ),
    Experiment(
        id="visual-crop-ocr",
        name="Visual crop/OCR evidence planning",
        summary="Dry-run fixture lane for comparing full visual evidence with cropped or OCR-derived evidence.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Image/OCR byte reductions are proxy evidence until provider image/text token fields are measured.",
        gate_requirements=("explicit opt-in", "original evidence preserved", "confidence/error notes", "missed-context guardrail"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan visual-crop-ocr",),
        opt_in_flags=(
            "plan visual-crop-ocr",
            "--full-evidence-receipt",
            "--crop-bounds",
            "--image-size",
            "--ocr-text|--ocr-text-file",
            "--ocr-confidence",
            "--ocr-error-note",
            "--missed-context-note",
        ),
        config_effect=(
            "Registry enablement records project-local intent only; visual crop/OCR planning remains a dry-run "
            "metadata surface and does not run OCR, crop images, call providers, or change stable behavior."
        ),
        evidence_contract=(
            "Dry-run plans require retrievable full visual evidence plus crop/OCR confidence, error, and "
            "missed-context guardrails before human review."
        ),
    ),
    Experiment(
        id="learned-compression",
        name="Learned/synthetic compression safe gate",
        summary="Deny-by-default dry-run safety gate for already-sanitized unprotected prose only.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Semantic compression cannot claim savings or correctness without matched-task quality and provider token evidence.",
        gate_requirements=("explicit opt-in", "sanitized unprotected prose only", "protected-zone denial", "exact fallback or receipt"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan learned-compression",),
        opt_in_flags=("plan learned-compression", "--sanitized", "--trusted-source", "--exact-fallback-receipt", "--reexpand-command"),
        config_effect=(
            "Registry enablement records project-local intent only; learned compression remains a dry-run policy check "
            "and does not run learned compressors, embeddings, model calls, or replacements."
        ),
        evidence_contract=(
            "Dry-run eligibility requires caller-asserted sanitized trusted prose, exact local fallback handles, and "
            "denial of protected or prompt-like signals."
        ),
    ),
    Experiment(
        id="self-hosted-metrics-ledger",
        name="Self-hosted metrics ledger",
        summary="Dry-run checker for self-hosted/local metrics ledger sidecars kept separate from hosted API claims.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Self-hosted memory/latency metrics must stay separate from hosted API token/cost claims.",
        gate_requirements=("explicit opt-in", "separate ledger fields", "shifted-cost accounting"),
        runtime_status="available-dry-run",
        commands=("context-guard experiments plan self-hosted-metrics-ledger",),
        opt_in_flags=(
            "plan self-hosted-metrics-ledger",
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
            "Registry enablement records project-local intent only; self-hosted metrics planning remains a dry-run "
            "ledger-preview surface and does not write ledgers or alter benchmark/report behavior."
        ),
        evidence_contract=(
            "Real evidence belongs in context-guard-bench JSONL ledger sidecars; self-hosted metrics remain separate "
            "from hosted API token/cost savings."
        ),
    ),
    Experiment(
        id="local-proxy",
        name="Local proxy advisory lane",
        summary="Future localhost-only plan/dry-run/ledger advisory surface with no hidden forwarding.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Proxy metrics are diagnostic only; no hosted savings claim without provider-measured evidence.",
        gate_requirements=("explicit opt-in", "localhost-only default", "no API-key persistence", "no hidden external forwarding"),
        runtime_status="advisory-planned",
        evidence_contract="Future advisory/proxy-plan evidence only; no forwarding or API-key persistence is available by default.",
    ),
)

REGISTRY = {experiment.id: experiment for experiment in EXPERIMENTS}


class RegistryError(RuntimeError):
    pass


def fail(message: str, code: int = 2) -> NoReturn:
    print(f"{TOOL_NAME}: {message}", file=sys.stderr)
    raise SystemExit(code)


def resolve_root(raw_root: str | None) -> Path:
    root = Path(raw_root) if raw_root else Path.cwd()
    try:
        return root.expanduser().resolve()
    except OSError as exc:
        raise RegistryError(f"could not resolve root: {root}: {exc}") from exc


def resolve_config_path(root: Path, raw_config: str | None) -> Path:
    if raw_config:
        candidate = Path(raw_config).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
    else:
        candidate = root / DEFAULT_CONFIG
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise RegistryError(f"could not resolve config path: {candidate}: {exc}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RegistryError(f"config path must stay inside project root: {resolved}") from exc
    return resolved


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": CONFIG_SCHEMA_VERSION, "enabled": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
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
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RegistryError(f"could not write config: {path}: {exc}") from exc
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


def read_bounded_input(args: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    source_label = args.source_label
    if args.input:
        path = Path(args.input)
        source_label = source_label or str(path)
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_CONTEXT_DIFF_INPUT_BYTES + 1)
        except OSError as exc:
            raise RegistryError(f"could not read input: {path}: {exc}") from exc
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_CONTEXT_DIFF_INPUT_BYTES + 1)
    if not raw:
        raise RegistryError("context-diff-compaction plan requires diff input on stdin or --input")
    truncated = len(raw) > MAX_CONTEXT_DIFF_INPUT_BYTES
    raw = raw[:MAX_CONTEXT_DIFF_INPUT_BYTES]
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
    total_hunks = 0
    lines = text.splitlines()
    diff_header_count = 0
    for line_number, line in enumerate(lines, start=1):
        match = DIFF_GIT_RE.match(line)
        if match:
            diff_header_count += 1
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
                    continue
                current = {"old_path": None, "new_path": None, "diff_header_line": None, "hunks": []}
                files.append(current)
            if len(current["hunks"]) < max_hunks:
                current["hunks"].append(
                    {
                        "line": line_number,
                        "old_start": int(hunk.group("old_start")),
                        "old_count": int(hunk.group("old_count") or "1"),
                        "new_start": int(hunk.group("new_start")),
                        "new_count": int(hunk.group("new_count") or "1"),
                        "section": hunk.group("section").strip()[:120],
                    }
                )
    return {
        "file_count": len(files),
        "hunk_count": total_hunks,
        "truncated_files": max(0, diff_header_count - len(files)),
        "files": files,
    }


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
    if summary["file_count"] == 0 or summary["hunk_count"] == 0:
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
            "note": "G003 records user-supplied handles for human review only; it does not verify local receipt storage.",
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
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_VISUAL_OCR_TEXT_BYTES + 1)
        except OSError as exc:
            raise RegistryError(f"could not read OCR text file: {path}: {exc}") from exc
        source_type = "file"
    elif args.ocr_text is not None:
        raw = args.ocr_text.encode("utf-8")
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else "inline"
        source_type = "inline"
    else:
        raw = b""
        source_label = args.ocr_source_label.strip() if args.ocr_source_label else None
        source_type = None

    truncated = len(raw) > MAX_VISUAL_OCR_TEXT_BYTES
    raw = raw[:MAX_VISUAL_OCR_TEXT_BYTES]
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


SECRET_LABEL_KEY_RE = r"[A-Za-z0-9_.-]*(?:api[-_]?key|token|secret|password|client[-_]?secret)[A-Za-z0-9_.-]*"
SECRET_LABEL_VALUE_RE = r"(?:'[^']*'|\"[^\"]*\"|[^\s,}&#;]+)"
SECRET_LABEL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
    (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9._~+/=-]+"), "[REDACTED]"),
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
    return text or "empty_key"


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
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, list):
        return any(has_non_finite_json_number(item) for item in value)
    if isinstance(value, dict):
        return any(has_non_finite_json_number(item) for item in value.values())
    return False


def read_self_hosted_payload(args: argparse.Namespace) -> tuple[Any, dict[str, Any]]:
    source_label = sanitize_self_hosted_text(args.source_label) if args.source_label else None
    if args.input:
        path = Path(args.input)
        source_label = source_label or sanitize_self_hosted_text(path)
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_SELF_HOSTED_METRICS_INPUT_BYTES + 1)
        except OSError as exc:
            raise RegistryError(f"could not read self-hosted metrics input: {path}: {exc}") from exc
    else:
        source_label = source_label or "stdin"
        raw = sys.stdin.buffer.read(MAX_SELF_HOSTED_METRICS_INPUT_BYTES + 1)
    if len(raw) > MAX_SELF_HOSTED_METRICS_INPUT_BYTES:
        return None, {
            "source_label": source_label,
            "bytes": MAX_SELF_HOSTED_METRICS_INPUT_BYTES,
            "sha256": hashlib.sha256(raw[:MAX_SELF_HOSTED_METRICS_INPUT_BYTES]).hexdigest(),
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
        ledger_preview = {
            "schema_version": BENCH_RUN_EVIDENCE_SCHEMA_VERSION,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "claude_version": "dry-run",
            "task_id": "self-hosted-metrics-dry-run",
            "variant": "self-hosted-metrics-ledger",
            "transform_id": "self-hosted-metrics-ledger",
            "success": None,
            "primary_tokens_measured": False,
            "primary_tokens": 0,
            "primary_cost_measured": False,
            "primary_cost_usd": 0.0,
            "provider_cached_tokens": None,
            "provider_cached_tokens_measured": False,
            "wall_time_seconds": 0.0,
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
            "notes": "dry-run preview; no ledger file written",
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
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_LEARNED_COMPRESSION_INPUT_BYTES + 1)
        except OSError as exc:
            raise RegistryError(f"could not read learned-compression input: {path}: {exc}") from exc
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RegistryError as exc:
        fail(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
