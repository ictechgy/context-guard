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
import re
from pathlib import Path
import sys
from typing import Any, NoReturn

TOOL_NAME = "context-guard-experiments"
CONFIG_SCHEMA_VERSION = "contextguard.experiments.v1"
DEFAULT_CONFIG = Path(".context-guard") / "experiments.json"
MAX_CONTEXT_DIFF_INPUT_BYTES = 256_000


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
        summary="Future dry-run/fixture lane for comparing full visual evidence with cropped or OCR-derived evidence.",
        stability="experimental",
        default_enabled=False,
        risk_level="medium",
        claim_boundary="Image/OCR byte reductions are proxy evidence until provider image/text token fields are measured.",
        gate_requirements=("explicit opt-in", "original evidence preserved", "confidence/error notes", "missed-context guardrail"),
        runtime_status="advisory-planned",
        evidence_contract="Future fixture/advisory evidence only; original visual evidence must remain available before promotion.",
    ),
    Experiment(
        id="learned-compression",
        name="Learned/synthetic compression safe gate",
        summary="Future deny-by-default compression gate for already-sanitized unprotected prose only.",
        stability="experimental",
        default_enabled=False,
        risk_level="high",
        claim_boundary="Semantic compression cannot claim savings or correctness without matched-task quality and provider token evidence.",
        gate_requirements=("explicit opt-in", "sanitized unprotected prose only", "protected-zone denial", "exact fallback or receipt"),
        runtime_status="advisory-planned",
        evidence_contract="Future safety-gate evidence only; semantic compression cannot run on protected or untrusted text.",
    ),
    Experiment(
        id="self-hosted-metrics-ledger",
        name="Self-hosted metrics ledger",
        summary="Future ledger-compatible recording for local latency, memory, quality, energy, and shifted costs.",
        stability="experimental",
        default_enabled=False,
        risk_level="low",
        claim_boundary="Self-hosted memory/latency metrics must stay separate from hosted API token/cost claims.",
        gate_requirements=("explicit opt-in", "separate ledger fields", "shifted-cost accounting"),
        runtime_status="advisory-planned",
        evidence_contract="Future ledger evidence only; self-hosted metrics remain separate from hosted API token/cost savings.",
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



DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
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


def summarize_diff(text: str, *, max_files: int = 50, max_hunks: int = 200) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    total_hunks = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = DIFF_GIT_RE.match(line)
        if match:
            if len(files) >= max_files:
                current = None
                continue
            current = {
                "old_path": match.group(1),
                "new_path": match.group(2),
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
        "truncated_files": max(0, len([line for line in text.splitlines() if line.startswith("diff --git ")]) - len(files)),
        "files": files,
    }


def context_diff_plan_payload(args: argparse.Namespace) -> dict[str, Any]:
    text, input_meta = read_bounded_input(args)
    summary = summarize_diff(text)
    has_exact_handle = bool(args.receipt_id and args.reexpand_command)
    status = "ready_for_human_review" if has_exact_handle else "blocked_until_exact_receipt"
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
            "artifact_id": args.receipt_id if args.receipt_id else None,
            "cli": args.reexpand_command if args.reexpand_command else None,
            "verified": False,
            "note": "G003 records user-supplied handles for human review only; it does not verify local receipt storage.",
        },
        "review_plan": {
            "summary": summary,
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
