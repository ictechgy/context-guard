#!/usr/bin/env python3
"""Measure provider-visible fixed overhead for a small advisory task."""
from __future__ import annotations

import argparse
import copy
import json
import runpy
import statistics
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def small_task_workload() -> dict:
    return {
        "schema_version": "contextguard.advisory-workload.v1",
        "vendor": "codex",
        "invocation": {
            "safe_mode": False,
            "hooks_available": False,
            "explicit_wrappers_available": True,
            "rules_loaded": False,
            "skills_loaded": False,
            "host_tool_surface_equal_to_control": True,
        },
        "signals": {
            "candidate_context_bytes": 2048,
            "estimated_local_overhead_ms": 0,
            "graph_candidate_bytes": 0,
            "graph_candidate_count": 0,
            "graph_replacement_bytes": 0,
            "largest_file_bytes": 2048,
            "log_bytes": 0,
            "repo_map_cached": False,
            "selected_file_count": 1,
            "task_prompt_bytes": 512,
        },
        "limits": {
            "inline_log_bytes": 4096,
            "max_local_overhead_ms": 250,
            "minimum_gross_context_savings_bytes": 2048,
            "pack_bytes": 8192,
            "symbol_slice_bytes": 8192,
        },
    }


def sample_matrix() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []
    small_codex = small_task_workload()
    cases.append(("small_codex", small_codex))

    small_claude = copy.deepcopy(small_codex)
    small_claude["vendor"] = "claude"
    small_claude["invocation"].update({"safe_mode": True, "hooks_available": True})
    cases.append(("small_claude_safe", small_claude))

    large_log = copy.deepcopy(small_claude)
    large_log["signals"].update({"candidate_context_bytes": 20000, "log_bytes": 16000})
    cases.append(("safe_mode_large_log", large_log))

    large_symbol = copy.deepcopy(small_codex)
    large_symbol["signals"].update(
        {"candidate_context_bytes": 14000, "largest_file_bytes": 12000}
    )
    cases.append(("large_symbol", large_symbol))

    broad = copy.deepcopy(small_codex)
    broad["signals"].update(
        {
            "candidate_context_bytes": 50000,
            "largest_file_bytes": 12000,
            "selected_file_count": 8,
        }
    )
    cases.append(("broad_adaptive", broad))

    graph_no_candidate = copy.deepcopy(broad)
    graph_no_candidate["signals"]["repo_map_cached"] = True
    cases.append(("graph_no_candidate", graph_no_candidate))

    graph_uncached = copy.deepcopy(broad)
    graph_uncached["signals"].update(
        {
            "graph_candidate_bytes": 1000,
            "graph_candidate_count": 1,
            "graph_replacement_bytes": 3000,
        }
    )
    cases.append(("graph_uncached_positive", graph_uncached))

    graph_cached = copy.deepcopy(graph_uncached)
    graph_cached["signals"]["repo_map_cached"] = True
    cases.append(("graph_cached_positive", graph_cached))

    high_overhead = copy.deepcopy(broad)
    high_overhead["signals"]["estimated_local_overhead_ms"] = 251
    cases.append(("local_overhead_bypass", high_overhead))

    persistent = copy.deepcopy(small_codex)
    persistent["invocation"]["rules_loaded"] = True
    cases.append(("persistent_context", persistent))
    return cases


def matrix_report(planner, repetitions: int) -> dict:
    rows: list[dict] = []
    for name, case in sample_matrix():
        durations_ms: list[float] = []
        decision = None
        for _ in range(repetitions):
            started = time.perf_counter_ns()
            decision = planner(case)
            durations_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        if not isinstance(decision, dict):
            raise SystemExit("advisory planner returned no decision")
        accounting = decision["accounting"]
        rows.append(
            {
                "name": name,
                "activation_status": decision["activation_status"],
                "decision": decision["decision"],
                "measurement_eligible": decision["measurement_eligible"],
                "selected_features": decision["selected_features"],
                "control_candidate_context_bytes": accounting[
                    "control_candidate_context_bytes"
                ],
                "estimated_treatment_context_bytes": accounting[
                    "estimated_treatment_context_bytes"
                ],
                "estimated_gross_context_saved_bytes": accounting[
                    "estimated_gross_context_saved_bytes"
                ],
                "provider_context_bytes": decision["provider_context_bytes"],
                "planner_median_ms": round(statistics.median(durations_ms), 6),
            }
        )
    return {
        "schema_version": "contextguard.advisory-benchmark.v1",
        "repetitions": repetitions,
        "cases": rows,
        "summary": {
            "case_count": len(rows),
            "active_count": sum(row["activation_status"] == "active" for row in rows),
            "bypass_count": sum(row["decision"] == "bypass" for row in rows),
            "measurement_ineligible_count": sum(
                not row["measurement_eligible"] for row in rows
            ),
            "control_candidate_context_bytes": sum(
                row["control_candidate_context_bytes"] for row in rows
            ),
            "estimated_treatment_context_bytes": sum(
                row["estimated_treatment_context_bytes"] for row in rows
            ),
            "estimated_gross_context_saved_bytes": sum(
                row["estimated_gross_context_saved_bytes"] for row in rows
            ),
            "provider_context_bytes": sum(row["provider_context_bytes"] for row in rows),
            "planner_median_ms": round(
                statistics.median(row["planner_median_ms"] for row in rows), 6
            ),
        },
    }


def repetition_count(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if count < 1 or count > 10_000:
        raise argparse.ArgumentTypeError("must be between 1 and 10000")
    return count


def final_provider_payload(
    decision: dict, *, control: bytes, transformed: bytes
) -> bytes:
    return control if decision.get("decision") == "bypass" else transformed


def provider_overhead_bytes(control: bytes, treatment: bytes) -> int:
    return max(0, len(treatment) - len(control))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix-json", action="store_true")
    parser.add_argument("--repetitions", type=repetition_count, default=100)
    args = parser.parse_args(argv)
    cost_guard = runpy.run_path(
        str(ROOT / "context-guard-kit" / "cost_guard.py"),
        run_name="contextguard_advisory_candidate",
    )
    planner = cost_guard.get("advisory_decision")
    if args.matrix_json:
        if not callable(planner):
            raise SystemExit("advisory planner is unavailable")
        print(json.dumps(matrix_report(planner, args.repetitions), sort_keys=True, indent=2))
        return 0
    if not callable(planner):
        raise SystemExit("advisory planner is unavailable")
    decision = planner(small_task_workload())
    if decision.get("decision") != "bypass":
        raise SystemExit("small advisory task did not bypass")
    if int(decision.get("provider_context_bytes", -1)) != 0:
        raise SystemExit("small advisory task exposed provider context")
    control_payload = b"synthetic provider request"
    treatment_payload = final_provider_payload(
        decision,
        control=control_payload,
        transformed=control_payload + b"unexpected context",
    )
    overhead = provider_overhead_bytes(control_payload, treatment_payload)
    print(f"reference_small_bypass_overhead_bytes={overhead}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
