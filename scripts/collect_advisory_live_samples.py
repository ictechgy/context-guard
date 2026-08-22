#!/usr/bin/env python3
"""Collect bounded paired subscription samples for advisory log compression."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
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
MAX_REPETITIONS = 5
MAX_PROVIDER_CALLS = 20
MAX_PROMPT_BYTES = 100_000


class SampleError(RuntimeError):
    """Raised for deterministic, non-reflective sample failures."""


def bounded_positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 1 or number > MAX_REPETITIONS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_REPETITIONS}")
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
    lines = ["command: python3 -m unittest sample_suite"]
    lines.extend("INFO worker heartbeat status=ok" for _ in range(512))
    lines.extend(
        [
            "FAIL sample_test_alpha expected status ok actual status retry",
            "Traceback sample_module.py line 42 assertion failed",
        ]
    )
    return "\n".join(lines) + "\n"


def prompt_for(log_text: str) -> str:
    prompt = (
        "Synthetic sanitized log benchmark. Do not use tools. "
        "Identify the command, failing check, and actual status. "
        "Reply with exactly one line in this form: "
        "CG_RESULT command=sample_suite check=sample_test_alpha actual=retry\n\n"
        "LOG\n"
        + log_text
    )
    if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
        raise SampleError("synthetic prompt exceeded its byte cap")
    return prompt


def compress_log(raw_log: str) -> tuple[str, float]:
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
                str(MAX_PROMPT_BYTES),
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


def advisory_plan(raw_log: str) -> dict[str, Any]:
    planner = runpy.run_path(
        str(COST_GUARD), run_name="contextguard_live_advisory"
    ).get("advisory_decision")
    if not callable(planner):
        raise SampleError("advisory planner is unavailable")
    raw_bytes = len(raw_log.encode("utf-8"))
    return planner(
        {
            "schema_version": "contextguard.advisory-workload.v1",
            "vendor": "claude",
            "invocation": {
                "safe_mode": True,
                "hooks_available": True,
                "explicit_wrappers_available": True,
                "rules_loaded": False,
                "skills_loaded": False,
                "host_tool_surface_equal_to_control": True,
            },
            "signals": {
                "candidate_context_bytes": raw_bytes,
                "estimated_local_overhead_ms": 0,
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
                "minimum_net_savings_bytes": 2048,
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


def cache_creation_tokens(usage: dict[str, Any]) -> int:
    flat = numeric_int(usage.get("cache_creation_input_tokens"))
    if flat is not None:
        return flat
    nested = usage.get("cache_creation")
    if type(nested) is not dict:
        return 0
    five_minutes = numeric_int(nested.get("ephemeral_5m_input_tokens")) or 0
    one_hour = numeric_int(nested.get("ephemeral_1h_input_tokens")) or 0
    return five_minutes + one_hour


def parsed_usage(
    response: str,
    usage: dict[str, Any],
    cost: Any = None,
    *,
    cached_is_input_breakout: bool,
) -> dict[str, Any]:
    input_tokens = numeric_int(usage.get("input_tokens"))
    output_tokens = numeric_int(usage.get("output_tokens"))
    if input_tokens is None or output_tokens is None:
        raise SampleError("provider usage was incomplete")
    cached = numeric_int(
        usage.get("cached_input_tokens", usage.get("cache_read_input_tokens", 0))
    )
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
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SampleError("Codex emitted invalid JSONL") from exc
        if type(event) is not dict:
            raise SampleError("Codex event was not an object")
        if event.get("type") == "item.completed":
            item = event.get("item")
            if type(item) is dict and item.get("type") == "agent_message" and type(item.get("text")) is str:
                response = item["text"]
        elif event.get("type") == "turn.completed" and type(event.get("usage")) is dict:
            usage = event["usage"]
    if response is None or usage is None:
        raise SampleError("Codex result or usage was unavailable")
    return parsed_usage(response, usage, cached_is_input_breakout=True)


def trusted_executable(vendor: str) -> Path:
    candidates = {
        "claude": (
            Path.home() / ".local/bin/claude",
            Path("/opt/homebrew/bin/claude"),
            Path("/usr/local/bin/claude"),
        ),
        "codex": (
            Path("/opt/homebrew/bin/codex"),
            Path("/usr/local/bin/codex"),
            Path.home() / ".local/bin/codex",
        ),
    }[vendor]
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and not metadata.st_mode & 0o022:
            return resolved
    raise SampleError(f"trusted {vendor} executable is unavailable")


def vendor_command(vendor: str, executable: Path) -> list[str]:
    if vendor == "claude":
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
    return [
        str(executable),
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--json",
        "--model",
        "gpt-5.6-luna",
        "-c",
        'model_reasoning_effort="high"',
        "-",
    ]


def run_provider(vendor: str, prompt: str, timeout: int) -> dict[str, Any]:
    executable = trusted_executable(vendor)
    command = vendor_command(vendor, executable)
    with tempfile.TemporaryDirectory(prefix="contextguard-advisory-live-") as temp_dir:
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=temp_dir,
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
    parsed = parse_claude_result(completed.stdout) if vendor == "claude" else parse_codex_result(completed.stdout)
    parsed["wall_time_seconds"] = wall_time
    parsed["quality_passed"] = all(marker in parsed["response"] for marker in QUALITY_MARKERS)
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
    return {
        "schema_version": "contextguard.advisory-live-samples.v1",
        "runs": rows,
        "summaries": summaries,
        "claim_boundary": {
            "descriptive_only": True,
            "long_term_savings_claim_allowed": False,
            "requires_more_tasks_and_quality_review": True,
        },
    }


def dry_run_plan(vendors: list[str], repetitions: int, control: str, treatment: str, decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "contextguard.advisory-live-plan.v1",
        "vendors": vendors,
        "repetitions": repetitions,
        "maximum_provider_calls": len(vendors) * repetitions * 2,
        "provider_calls_performed": False,
        "task_or_repository_content_read": False,
        "control_prompt_bytes": len(control.encode("utf-8")),
        "treatment_prompt_bytes": len(treatment.encode("utf-8")),
        "advisory_decision": decision["decision"],
        "provider_context_bytes": decision["provider_context_bytes"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", choices=("claude", "codex", "all"), default="all")
    parser.add_argument("--repetitions", type=bounded_positive_int, default=3)
    parser.add_argument("--timeout-seconds", type=bounded_timeout, default=180)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--confirm-provider-egress", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    vendors = ["claude", "codex"] if args.vendor == "all" else [args.vendor]
    maximum_calls = len(vendors) * args.repetitions * 2
    if maximum_calls > MAX_PROVIDER_CALLS:
        raise SampleError("provider call cap exceeded")
    raw_log = synthetic_log()
    compressed, preprocessing_ms = compress_log(raw_log)
    decision = advisory_plan(raw_log)
    if decision["decision"] != "trim_output" or decision["provider_context_bytes"] != 0:
        raise SampleError("advisory planner did not select zero-context trim output")
    control_prompt = prompt_for(raw_log)
    treatment_prompt = prompt_for(compressed)
    if args.dry_run:
        print(
            json.dumps(
                dry_run_plan(
                    vendors, args.repetitions, control_prompt, treatment_prompt, decision
                ),
                sort_keys=True,
                indent=2,
            )
        )
        return 0
    if not args.confirm_provider_egress:
        print("--confirm-provider-egress is required", file=sys.stderr)
        return 2
    rows: list[dict[str, Any]] = []
    for vendor in vendors:
        for repetition in range(1, args.repetitions + 1):
            for arm, prompt in (("control", control_prompt), ("advisory", treatment_prompt)):
                result = run_provider(vendor, prompt, args.timeout_seconds)
                rows.append(
                    {
                        "vendor": vendor,
                        "arm": arm,
                        "repetition": repetition,
                        "prompt_bytes": len(prompt.encode("utf-8")),
                        "local_preprocessing_ms": round(
                            preprocessing_ms if arm == "advisory" else 0.0, 6
                        ),
                        **result,
                    }
                )
    print(json.dumps(aggregate(rows), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SampleError as exc:
        print(f"advisory live sample error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
