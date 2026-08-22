#!/usr/bin/env python3
"""Collect bounded paired subscription samples for advisory log compression."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import pwd
import runpy
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COST_GUARD = ROOT / "context-guard-kit" / "cost_guard.py"
COMPRESSOR = ROOT / "context-guard-kit" / "context_compress.py"
QUALITY_MARKERS = ("sample_suite", "sample_test_alpha", "retry")
EXPECTED_RESPONSE = "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry"
MAX_REPETITIONS = 4
MAX_CLI_INVOCATIONS = 16
MAX_PROMPT_BYTES = 100_000
MAX_LOCAL_PREPROCESSING_MS = 250


class SampleError(RuntimeError):
    """Raised for deterministic, non-reflective sample failures."""


def bounded_positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number not in {2, MAX_REPETITIONS}:
        raise argparse.ArgumentTypeError(
            f"must be even and equal to 2 or {MAX_REPETITIONS}"
        )
    return number


def bounded_timeout(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 30 or number > 300:
        raise argparse.ArgumentTypeError("must be between 30 and 300 seconds")
    return number


def synthetic_log() -> str:
    lines = [
        "command: python3 -m unittest sample_suite",
        "FAIL sample_test_alpha expected status ok actual status retry",
        "Traceback sample_module.py line 42 assertion failed",
    ]
    lines.extend("INFO worker heartbeat status=ok" for _ in range(512))
    return "\n".join(lines) + "\n"


def prompt_for(log_text: str) -> str:
    prompt = (
        "Synthetic sanitized log benchmark. Do not use tools. "
        "Identify the command, failing check, and actual status. "
        "Reply with exactly one line in this form: "
        "CG_RESULT command=<command> check=<failing_check> actual=<actual_status>\n\n"
        "LOG\n"
        + log_text
    )
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise SampleError("synthetic prompt exceeded its byte cap")
    return prompt


def compress_log(raw_log: str, max_output_bytes: int) -> tuple[str, float]:
    if (
        type(max_output_bytes) is not int
        or max_output_bytes < 1
        or max_output_bytes > MAX_PROMPT_BYTES
    ):
        raise SampleError("local compression output limit is invalid")
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(COMPRESSOR),
                "--type",
                "log",
                "--quiet",
                "--max-bytes",
                str(max_output_bytes),
            ],
            cwd=ROOT,
            env=environment,
            input=raw_log,
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SampleError("local ContextGuard compression failed") from exc
    elapsed_ms = (time.perf_counter() - started) * 1000
    compressed = completed.stdout
    if not compressed or not all(marker in compressed for marker in QUALITY_MARKERS):
        raise SampleError("compressed synthetic log lost required quality markers")
    if len(compressed.encode("utf-8")) >= len(raw_log.encode("utf-8")):
        raise SampleError("compressed synthetic log did not reduce bytes")
    return compressed, elapsed_ms


def advisory_plan(
    raw_log: str, vendor: str, estimated_local_overhead_ms: int
) -> dict[str, Any]:
    planner = runpy.run_path(
        str(COST_GUARD), run_name="contextguard_live_advisory"
    ).get("advisory_decision")
    if not callable(planner):
        raise SampleError("advisory planner is unavailable")
    raw_bytes = len(raw_log.encode("utf-8"))
    return planner(
        {
            "schema_version": "contextguard.advisory-workload.v1",
            "vendor": vendor,
            "invocation": {
                "safe_mode": vendor == "claude",
                "hooks_available": vendor == "claude",
                "explicit_wrappers_available": True,
                "rules_loaded": False,
                "skills_loaded": False,
                "host_tool_surface_equal_to_control": True,
            },
            "signals": {
                "candidate_context_bytes": raw_bytes,
                "estimated_local_overhead_ms": estimated_local_overhead_ms,
                "graph_candidate_bytes": 0,
                "graph_candidate_count": 0,
                "graph_replacement_bytes": 0,
                "largest_file_bytes": 0,
                "log_bytes": raw_bytes,
                "repo_map_cached": False,
                "selected_file_count": 0,
                "task_prompt_bytes": 256,
            },
            "limits": {
                "inline_log_bytes": 4096,
                "max_local_overhead_ms": 250,
                "minimum_gross_context_savings_bytes": 2048,
                "pack_bytes": 8192,
                "symbol_slice_bytes": 8192,
            },
        }
    )


def numeric_int(value: Any) -> int | None:
    if type(value) is int and value >= 0:
        return value
    return None


def numeric_float(value: Any) -> float | None:
    if type(value) not in {int, float}:
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def optional_token_field(usage: dict[str, Any], key: str) -> int | None:
    if key not in usage:
        return None
    value = numeric_int(usage[key])
    if value is None:
        raise SampleError("provider cache token field was invalid")
    return value


def cache_creation_tokens(usage: dict[str, Any]) -> int:
    flat = optional_token_field(usage, "cache_creation_input_tokens")
    if "cache_creation" not in usage:
        return 0 if flat is None else flat
    nested = usage["cache_creation"]
    if type(nested) is not dict:
        raise SampleError("provider cache token breakdown was invalid")
    allowed = {"ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"}
    if set(nested) - allowed:
        raise SampleError("provider cache token breakdown contained unknown fields")
    nested_total = sum(optional_token_field(nested, key) or 0 for key in allowed)
    if flat is not None and flat != nested_total:
        raise SampleError("provider cache token creation fields conflicted")
    return nested_total


def parsed_usage(
    response: str,
    usage: dict[str, Any],
    cost: Any = None,
    *,
    cached_is_input_breakout: bool,
) -> dict[str, Any]:
    allowed_token_fields = {
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    }
    if any(
        "token" in key and key not in allowed_token_fields
        for key in usage
    ):
        raise SampleError("provider cache token fields contained an unknown field")
    input_tokens = numeric_int(usage.get("input_tokens"))
    output_tokens = numeric_int(usage.get("output_tokens"))
    if input_tokens is None or output_tokens is None:
        raise SampleError("provider usage was incomplete")
    cached_alias = optional_token_field(usage, "cached_input_tokens")
    cache_read = optional_token_field(usage, "cache_read_input_tokens")
    if (
        cached_alias is not None
        and cache_read is not None
        and cached_alias != cache_read
    ):
        raise SampleError("provider cache token read aliases conflicted")
    cached = cached_alias if cached_alias is not None else cache_read
    cached = 0 if cached is None else cached
    cache_creation = cache_creation_tokens(usage)
    total_tokens = input_tokens + output_tokens
    if not cached_is_input_breakout:
        total_tokens += cached + cache_creation
    return {
        "response": response,
        "input_tokens": input_tokens,
        "cached_input_tokens": cached,
        "cache_creation_input_tokens": cache_creation,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cost_usd": numeric_float(cost),
    }


def parse_claude_result(raw: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise SampleError("Claude result was not valid JSON") from exc
    if type(payload) is not dict or type(payload.get("result")) is not str:
        raise SampleError("Claude result shape was incomplete")
    usage = payload.get("usage")
    if type(usage) is not dict:
        raise SampleError("Claude usage was unavailable")
    return parsed_usage(
        payload["result"],
        usage,
        payload.get("total_cost_usd"),
        cached_is_input_breakout=False,
    )


def parse_codex_result(raw: str) -> dict[str, Any]:
    response = None
    usage = None
    seen_thread_started = False
    seen_turn_started = False
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SampleError("Codex emitted invalid JSONL") from exc
        if type(event) is not dict:
            raise SampleError("Codex event was not an object")
        event_type = event.get("type")
        if event_type == "thread.started":
            if seen_thread_started or usage is not None:
                raise SampleError("Codex lifecycle event was duplicated or out of order")
            seen_thread_started = True
        elif event_type == "turn.started":
            if seen_turn_started or usage is not None:
                raise SampleError("Codex lifecycle event was duplicated or out of order")
            seen_turn_started = True
        elif event_type in {"item.started", "item.completed"}:
            item = event.get("item")
            if type(item) is not dict or usage is not None:
                raise SampleError("Codex item event shape was invalid")
            item_type = item.get("type")
            if event_type == "item.completed" and item_type == "agent_message":
                if response is not None or type(item.get("text")) is not str:
                    raise SampleError("Codex agent message was duplicated or invalid")
                response = item["text"]
            elif item_type != "reasoning":
                raise SampleError("Codex tool event is not allowed")
        elif event_type == "turn.completed":
            if usage is not None or response is None or type(event.get("usage")) is not dict:
                raise SampleError("Codex completion was duplicated or out of order")
            usage = event["usage"]
        else:
            raise SampleError("Codex event type is not allowed")
    if response is None or usage is None:
        raise SampleError("Codex result or usage was unavailable")
    return parsed_usage(response, usage, cached_is_input_breakout=True)


def quality_passed(response: str) -> bool:
    normalized = response.replace("\r\n", "\n")
    if normalized.endswith("\n"):
        normalized = normalized[:-1]
    return normalized == EXPECTED_RESPONSE


def _trusted_directory(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    trusted_owners = {0, os.getuid()}
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in trusted_owners
        or metadata.st_mode & 0o022
    ):
        return False
    return True


def _trusted_ancestor_chain(descendant: Path) -> bool:
    try:
        current = descendant.resolve(strict=True)
    except OSError:
        return False
    while True:
        if not _trusted_directory(current):
            return False
        parent = current.parent
        if parent == current:
            break
        current = parent
    return True


def trusted_executable_candidate(candidate: Path) -> Path | None:
    try:
        candidate_metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return None
    trusted_owners = {0, os.getuid()}
    if candidate_metadata.st_uid not in trusted_owners:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in trusted_owners
        or metadata.st_mode & 0o022
    ):
        return None
    if not _trusted_ancestor_chain(candidate.parent) or not _trusted_ancestor_chain(
        resolved.parent
    ):
        return None
    return resolved


def trusted_executable(vendor: str) -> Path:
    if vendor != "claude":
        raise SampleError("Codex live collection requires a supported no-tools mode")
    candidates = (
        Path.home() / ".local/bin/claude",
        Path("/opt/homebrew/bin/claude"),
        Path("/usr/local/bin/claude"),
    )
    for candidate in candidates:
        resolved = trusted_executable_candidate(candidate)
        if resolved is not None:
            return resolved
    raise SampleError(f"trusted {vendor} executable is unavailable")


def vendor_command(vendor: str, executable: Path) -> list[str]:
    if vendor != "claude":
        raise SampleError("Codex live collection requires a supported no-tools mode")
    return [
        str(executable),
        "--print",
        "--no-session-persistence",
        "--safe-mode",
        "--permission-mode",
        "plan",
        "--tools",
        "",
        "--output-format",
        "json",
        "--model",
        "claude-sonnet-5",
        "--effort",
        "high",
    ]


def provider_environment() -> dict[str, str]:
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    return {
        "HOME": str(account_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


def run_provider(vendor: str, prompt: str, timeout: int) -> dict[str, Any]:
    if vendor != "claude":
        raise SampleError("Codex live collection requires a supported no-tools mode")
    executable = trusted_executable(vendor)
    command = vendor_command(vendor, executable)
    with tempfile.TemporaryDirectory(prefix="contextguard-advisory-live-") as temp_dir:
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=temp_dir,
                env=provider_environment(),
                input=prompt,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SampleError(f"{vendor} provider process did not complete") from exc
        wall_time = time.perf_counter() - started
    if completed.returncode != 0:
        raise SampleError(f"{vendor} provider process failed")
    parsed = parse_claude_result(completed.stdout)
    parsed["wall_time_seconds"] = wall_time
    parsed["quality_passed"] = quality_passed(parsed["response"])
    parsed.pop("response", None)
    return parsed


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["vendor"], row["arm"]), []).append(row)
    summaries = []
    for (vendor, arm), members in sorted(groups.items()):
        costs = [row["cost_usd"] for row in members]
        summaries.append(
            {
                "vendor": vendor,
                "arm": arm,
                "sample_count": len(members),
                "quality_pass_count": sum(row["quality_passed"] for row in members),
                "median_total_tokens": statistics.median(row["total_tokens"] for row in members),
                "median_wall_time_seconds": round(
                    statistics.median(row["wall_time_seconds"] for row in members), 6
                ),
                "median_cost_usd": (
                    round(statistics.median(costs), 8)
                    if all(cost is not None for cost in costs)
                    else None
                ),
            }
        )
    paired_deltas = []
    by_pair: dict[tuple[str, int], dict[str, dict[str, Any]]] = {}
    for row in rows:
        by_pair.setdefault((row["vendor"], row["repetition"]), {})[row["arm"]] = row
    for (vendor, repetition), pair in sorted(by_pair.items()):
        if set(pair) != {"control", "advisory"}:
            raise SampleError("paired live sample was incomplete")
        control = pair["control"]
        advisory = pair["advisory"]
        pair_quality_passed = bool(
            control["quality_passed"] and advisory["quality_passed"]
        )
        paired_deltas.append(
            {
                "vendor": vendor,
                "repetition": repetition,
                "arm_order": control["arm_order"],
                "pair_quality_passed": pair_quality_passed,
                "total_tokens_delta": (
                    advisory["total_tokens"] - control["total_tokens"]
                    if pair_quality_passed
                    else None
                ),
                "total_wall_time_seconds_delta": (
                    round(
                        advisory["wall_time_seconds"]
                        + advisory["local_preprocessing_ms"] / 1000
                        - control["wall_time_seconds"],
                        6,
                    )
                    if pair_quality_passed
                    else None
                ),
                "cost_usd_delta": (
                    round(advisory["cost_usd"] - control["cost_usd"], 8)
                    if pair_quality_passed
                    and advisory["cost_usd"] is not None
                    and control["cost_usd"] is not None
                    else None
                ),
            }
        )
    eligible_pairs = sum(pair["pair_quality_passed"] for pair in paired_deltas)
    return {
        "schema_version": "contextguard.advisory-live-samples.v1",
        "runs": rows,
        "summaries": summaries,
        "paired_deltas": paired_deltas,
        "claim_boundary": {
            "descriptive_only": True,
            "long_term_savings_claim_allowed": False,
            "numeric_savings_claim_allowed": False,
            "requires_more_tasks_and_quality_review": True,
            "quality_eligible_pair_count": eligible_pairs,
            "quality_excluded_pair_count": len(paired_deltas) - eligible_pairs,
        },
    }


def emit_run_record(row: dict[str, Any], *, stream: Any = sys.stdout) -> None:
    print(json.dumps({"type": "run", "run": row}, sort_keys=True), file=stream, flush=True)


def arm_order(repetition: int) -> tuple[str, str]:
    return ("control", "advisory") if repetition % 2 else ("advisory", "control")


def dry_run_plan(
    vendors: list[str],
    repetitions: int,
    control: str,
    treatment: str,
    decisions: dict[str, dict[str, Any]],
    preview_preprocessing_ms: float,
) -> dict[str, Any]:
    return {
        "schema_version": "contextguard.advisory-live-plan.v2",
        "vendors": vendors,
        "repetitions": repetitions,
        "maximum_cli_invocations": len(vendors) * repetitions * 2,
        "provider_cli_invocations_performed": 0,
        "provider_transport_calls_observed": False,
        "task_or_repository_content_read": False,
        "control_prompt_bytes": len(control.encode("utf-8")),
        "treatment_prompt_bytes": len(treatment.encode("utf-8")),
        "advisory_decisions": {
            vendor: decisions[vendor]["decision"] for vendor in vendors
        },
        "provider_context_bytes": sum(
            decisions[vendor]["provider_context_bytes"] for vendor in vendors
        ),
        "arm_orders": [",".join(arm_order(repetition)) for repetition in range(1, repetitions + 1)],
        "compressed_log_bytes": len(
            treatment.split("LOG\n", 1)[-1].encode("utf-8")
        ),
        "selected_inline_log_bytes": min(
            int(decisions[vendor]["actions"][0]["max_inline_bytes"])
            for vendor in vendors
        ),
        "local_preview_compression": {
            "accounting": "excluded_dry_run_only",
            "wall_time_ms": round(preview_preprocessing_ms, 6),
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", choices=("claude", "codex", "all"), default="all")
    parser.add_argument("--repetitions", type=bounded_positive_int, default=4)
    parser.add_argument("--timeout-seconds", type=bounded_timeout, default=180)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-provider-egress", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    vendors = ["claude", "codex"] if args.vendor == "all" else [args.vendor]
    maximum_cli_invocations = len(vendors) * args.repetitions * 2
    if maximum_cli_invocations > MAX_CLI_INVOCATIONS:
        raise SampleError("provider CLI invocation cap exceeded")
    if not args.dry_run:
        if not args.confirm_provider_egress:
            print("--confirm-provider-egress is required", file=sys.stderr)
            return 2
        if "codex" in vendors:
            raise SampleError(
                "Codex live collection requires a provider-supported no-tools mode"
            )
    raw_log = synthetic_log()
    decisions = {
        vendor: advisory_plan(raw_log, vendor, MAX_LOCAL_PREPROCESSING_MS)
        for vendor in vendors
    }
    for decision in decisions.values():
        if (
            decision["decision"] != "trim_output"
            or decision["activation_status"] != "active"
            or not decision["measurement_eligible"]
            or decision["provider_context_bytes"] != 0
        ):
            raise SampleError("advisory planner did not select eligible zero-context trim output")
    selected_inline_log_bytes = min(
        int(decision["actions"][0]["max_inline_bytes"])
        for decision in decisions.values()
    )
    control_prompt = prompt_for(raw_log)
    if args.dry_run:
        preview_compressed, preview_preprocessing_ms = compress_log(
            raw_log, selected_inline_log_bytes
        )
        if math.ceil(preview_preprocessing_ms) > MAX_LOCAL_PREPROCESSING_MS:
            raise SampleError("local compression exceeded the overhead budget")
        if len(preview_compressed.encode("utf-8")) > selected_inline_log_bytes:
            raise SampleError("compressed log exceeded the selected inline byte limit")
        treatment_prompt = prompt_for(preview_compressed)
        print(
            json.dumps(
                dry_run_plan(
                    vendors,
                    args.repetitions,
                    control_prompt,
                    treatment_prompt,
                    decisions,
                    preview_preprocessing_ms,
                ),
                sort_keys=True,
                indent=2,
            )
        )
        return 0
    rows: list[dict[str, Any]] = []
    for vendor in vendors:
        for repetition in range(1, args.repetitions + 1):
            order = arm_order(repetition)
            for position, arm in enumerate(order, start=1):
                if arm == "advisory":
                    run_compressed, run_preprocessing_ms = compress_log(
                        raw_log, selected_inline_log_bytes
                    )
                    run_decision = advisory_plan(
                        raw_log, vendor, math.ceil(run_preprocessing_ms)
                    )
                    if (
                        run_decision["decision"] != "trim_output"
                        or run_decision["activation_status"] != "active"
                        or not run_decision["measurement_eligible"]
                    ):
                        raise SampleError(
                            "local compression exceeded the overhead budget"
                        )
                    if len(run_compressed.encode("utf-8")) > selected_inline_log_bytes:
                        raise SampleError("compressed log exceeded the selected inline byte limit")
                    prompt = prompt_for(run_compressed)
                else:
                    run_preprocessing_ms = 0.0
                    prompt = control_prompt
                result = run_provider(vendor, prompt, args.timeout_seconds)
                row = {
                    "vendor": vendor,
                    "arm": arm,
                    "repetition": repetition,
                    "sequence_position": position,
                    "arm_order": ",".join(order),
                    "prompt_bytes": len(prompt.encode("utf-8")),
                    "local_preprocessing_ms": round(run_preprocessing_ms, 6),
                    **result,
                }
                rows.append(row)
                emit_run_record(row)
    print(json.dumps({"type": "summary", "report": aggregate(rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SampleError as exc:
        print(f"advisory live sample error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
