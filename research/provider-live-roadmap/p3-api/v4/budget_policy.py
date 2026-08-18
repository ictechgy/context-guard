#!/usr/bin/env python3
"""Derive a no-growth provider-input policy from the frozen v3 cell matrix."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
V3 = ROOT / "research/provider-live-roadmap/p3-api/v3"
V4 = ROOT / "research/provider-live-roadmap/p3-api/v4"
CAPTURE_SHA256 = "314f018111f417ee8892ede95da97e407a81926c43a072bcd70658fa144034cd"
EVIDENCE_SHA256 = "c5496fea9de4e9ce0465de39a64b01f3c35a1073a8312e72469d11357e44bd90"
RESULT_SHA256 = "114441b7a87d0c3e66a710ec3d890b0b04288d43b32fb41cffb928a151b9bb51"
ARM_IDS = tuple(f"a{adaptive}{symbol}{graph}" for adaptive in "01" for symbol in "01" for graph in "01")
FACTOR_BITS = (
    ("adaptive", 1),
    ("symbol_memory", 2),
    ("graph_closure", 3),
)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("noncanonical_value") from error


def _load_exact_json(raw: bytes, *, expected_sha256: str, diagnostic: str) -> dict[str, object]:
    if sha256(raw) != expected_sha256:
        raise ValueError(diagnostic)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(diagnostic) from error
    if not isinstance(value, dict):
        raise ValueError(diagnostic)
    return value


def _arm_bits(arm_id: str) -> dict[str, bool]:
    if arm_id not in ARM_IDS:
        raise ValueError("invalid_frozen_arm")
    return {
        "adaptive": arm_id[1] == "1",
        "symbol_memory": arm_id[2] == "1",
        "graph_closure": arm_id[3] == "1",
    }


def _set_arm_bit(arm_id: str, position: int) -> str:
    bits = list(arm_id)
    bits[position] = "1"
    return "".join(bits)


def _index_cells(capture: dict[str, object]) -> dict[str, dict[str, dict[str, object]]]:
    cells = capture.get("cells")
    if not isinstance(cells, list) or len(cells) != 96:
        raise ValueError("invalid_frozen_cell_matrix")
    by_task: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    for cell in cells:
        if not isinstance(cell, dict):
            raise ValueError("invalid_frozen_cell_matrix")
        task_id = cell.get("task_id")
        arm = cell.get("arm")
        if not isinstance(task_id, str) or not isinstance(arm, dict):
            raise ValueError("invalid_frozen_cell_matrix")
        arm_id = arm.get("id")
        if not isinstance(arm_id, str) or arm_id not in ARM_IDS:
            raise ValueError("invalid_frozen_cell_matrix")
        if cell.get("cell_id") != f"{task_id}:{arm_id}" or arm != {"id": arm_id, **_arm_bits(arm_id)}:
            raise ValueError("invalid_frozen_cell_matrix")
        if arm_id in by_task[task_id]:
            raise ValueError("duplicate_frozen_cell")
        if type(cell.get("prompt_bytes")) is not int or cell["prompt_bytes"] <= 0:
            raise ValueError("invalid_frozen_cell_matrix")
        if not isinstance(cell.get("prompt_sha256"), str) or len(cell["prompt_sha256"]) != 64:
            raise ValueError("invalid_frozen_cell_matrix")
        by_task[task_id][arm_id] = cell
    if len(by_task) != 12 or any(set(cells_by_arm) != set(ARM_IDS) for cells_by_arm in by_task.values()):
        raise ValueError("invalid_frozen_cell_matrix")
    return dict(by_task)


def _choose_cell(
    task_id: str,
    requested_arm_id: str,
    cells: dict[str, dict[str, object]],
) -> dict[str, object]:
    requested = _arm_bits(requested_arm_id)
    ordinary = cells["a000"]
    ceiling = ordinary["prompt_bytes"]
    selected_arm_id = "a000"
    selected = ordinary
    outcomes: dict[str, str] = {}
    applied: list[str] = []

    for factor, position in FACTOR_BITS:
        if not requested[factor]:
            outcomes[factor] = "not_requested"
            continue
        candidate_arm_id = _set_arm_bit(selected_arm_id, position)
        candidate = cells[candidate_arm_id]
        if candidate["prompt_sha256"] == selected["prompt_sha256"]:
            outcomes[factor] = (
                "no_provider_byte_reduction" if factor == "adaptive" else "no_provider_byte_change"
            )
            continue
        if factor == "adaptive" and candidate["prompt_bytes"] >= selected["prompt_bytes"]:
            outcomes[factor] = "no_provider_byte_reduction"
            continue
        if candidate["prompt_bytes"] > ceiling:
            outcomes[factor] = "insufficient_adaptive_headroom"
            continue
        selected_arm_id = candidate_arm_id
        selected = candidate
        applied.append(factor)
        outcomes[factor] = "applied"

    return {
        "applied_factors": applied,
        "factor_outcomes": outcomes,
        "ordinary_prompt_ceiling_bytes": ceiling,
        "requested_arm_id": requested_arm_id,
        "requested_cell_id": f"{task_id}:{requested_arm_id}",
        "requested_factors": [name for name, _ in FACTOR_BITS if requested[name]],
        "requested_prompt_bytes": cells[requested_arm_id]["prompt_bytes"],
        "selected_arm_id": selected_arm_id,
        "selected_cell_id": f"{task_id}:{selected_arm_id}",
        "selected_prompt_bytes": selected["prompt_bytes"],
        "selected_prompt_sha256": selected["prompt_sha256"],
    }


def _diagnosis(
    by_task: dict[str, dict[str, dict[str, object]]],
    result: dict[str, object],
) -> dict[str, object]:
    cells = [cell for task in sorted(by_task) for cell in by_task[task].values()]
    growth = [cell["prompt_bytes"] - by_task[cell["task_id"]]["a000"]["prompt_bytes"] for cell in cells]
    symbol_sizes = sorted({cell["symbol_projection_bytes"] for cell in cells if cell["symbol_projection_bytes"]})
    graph_changed_tasks: list[str] = []
    graph_positive_deltas: list[int] = []
    for task_id, task_cells in sorted(by_task.items()):
        changed = False
        for adaptive in "01":
            for symbol in "01":
                without_graph = task_cells[f"a{adaptive}{symbol}0"]
                with_graph = task_cells[f"a{adaptive}{symbol}1"]
                delta = with_graph["context_pack_bytes"] - without_graph["context_pack_bytes"]
                if with_graph["prompt_sha256"] != without_graph["prompt_sha256"]:
                    changed = True
                if delta > 0:
                    graph_positive_deltas.append(delta)
        if changed:
            graph_changed_tasks.append(task_id)

    effects = result.get("factorial_effects")
    primary = result.get("primary_contrast")
    if not isinstance(effects, dict) or not isinstance(primary, dict):
        raise ValueError("invalid_observed_result")
    try:
        observed_effects = {
            factor: effects[factor]["metrics"]["total_provider_tokens"]["delta"]["decimal"]
            for factor in ("adaptive", "symbol_memory", "graph_closure")
        }
        primary_metrics = primary["metrics"]
        all_on = {
            "input_token_percent_reduction": primary_metrics["input_tokens"]["percent_reduction"],
            "output_token_percent_reduction": primary_metrics["output_tokens"]["percent_reduction"],
            "total_provider_token_percent_reduction": primary_metrics["total_provider_tokens"]["percent_reduction"],
        }
    except (KeyError, TypeError) as error:
        raise ValueError("invalid_observed_result") from error

    return {
        "all_on_a111_vs_a000": all_on,
        "graph_changed_factor_pairs": sum(
            by_task[task][f"a{adaptive}{symbol}0"]["prompt_sha256"]
            != by_task[task][f"a{adaptive}{symbol}1"]["prompt_sha256"]
            for task in by_task
            for adaptive in "01"
            for symbol in "01"
        ),
        "graph_changed_tasks": graph_changed_tasks,
        "graph_context_pack_growth_bytes_range": [min(graph_positive_deltas), max(graph_positive_deltas)],
        "historical_cells_over_ordinary_ceiling": sum(delta > 0 for delta in growth),
        "historical_max_prompt_growth_bytes": max(growth),
        "historical_prompt_bytes_above_ceiling": sum(max(0, delta) for delta in growth),
        "historical_total_prompt_bytes": sum(cell["prompt_bytes"] for cell in cells),
        "observed_total_provider_token_main_effect_per_unit": observed_effects,
        "root_causes": {
            "composition": "all_enabled_arm_was_not_normalized_to_the_ordinary_provider_input_budget",
            "graph_closure": "low_priority_direct_import_neighbors_were_appended_into_unused_global_pack_budget",
            "symbol_memory": "off_pack_symbol_signatures_were_appended_without_a_shared_prompt_ceiling",
        },
        "symbol_changed_factor_pairs": sum(
            by_task[task][f"a{adaptive}0{graph}"]["prompt_sha256"]
            != by_task[task][f"a{adaptive}1{graph}"]["prompt_sha256"]
            for task in by_task
            for adaptive in "01"
            for graph in "01"
        ),
        "symbol_projection_bytes_range": [min(symbol_sizes), max(symbol_sizes)],
    }


def select_provider_cell(
    capture_raw: bytes,
    *,
    task_id: str,
    requested_arm_id: str,
) -> dict[str, object]:
    """Select one exact frozen provider cell under the task's ordinary ceiling."""
    capture = _load_exact_json(
        capture_raw,
        expected_sha256=CAPTURE_SHA256,
        diagnostic="unexpected_provider_input_freeze",
    )
    by_task = _index_cells(capture)
    if task_id not in by_task:
        raise ValueError("unknown_budget_policy_task")
    if requested_arm_id not in ARM_IDS:
        raise ValueError("unknown_budget_policy_arm")
    return _choose_cell(task_id, requested_arm_id, by_task[task_id])


def _input_token_projection(
    evidence: dict[str, object],
    by_task: dict[str, dict[str, dict[str, object]]],
    decisions: list[dict[str, object]],
) -> dict[str, int | str]:
    units = evidence.get("sealed_units")
    if not isinstance(units, list) or len(units) != 288:
        raise ValueError("invalid_provider_input_token_evidence")
    input_tokens_by_cell: dict[tuple[str, str], int] = {}
    seen_units: set[tuple[str, int, str]] = set()
    historical_total = 0
    for unit in units:
        if not isinstance(unit, dict):
            raise ValueError("invalid_provider_input_token_evidence")
        task_id = unit.get("task_id")
        arm_id = unit.get("arm_id")
        repetition = unit.get("repetition")
        usage = unit.get("usage")
        if (
            task_id not in by_task
            or arm_id not in ARM_IDS
            or type(repetition) is not int
            or repetition not in (0, 1, 2)
            or unit.get("scheduled_unit_id") != f"{task_id}:r{repetition}:{arm_id}"
            or unit.get("status") != "completed"
            or unit.get("dispatched") is not True
            or unit.get("http_status") != 200
            or not isinstance(usage, dict)
            or type(usage.get("input_tokens")) is not int
            or usage["input_tokens"] <= 0
        ):
            raise ValueError("invalid_provider_input_token_evidence")
        unit_key = (task_id, repetition, arm_id)
        if unit_key in seen_units:
            raise ValueError("invalid_provider_input_token_evidence")
        seen_units.add(unit_key)
        cell_key = (task_id, arm_id)
        measured = input_tokens_by_cell.setdefault(cell_key, usage["input_tokens"])
        if measured != usage["input_tokens"]:
            raise ValueError("nonconstant_provider_input_tokens_for_frozen_prompt")
        historical_total += usage["input_tokens"]
    if len(seen_units) != 288 or len(input_tokens_by_cell) != 96:
        raise ValueError("invalid_provider_input_token_evidence")

    selected_arm_by_requested_cell = {
        decision["requested_cell_id"]: decision["selected_arm_id"] for decision in decisions
    }
    projected_total = sum(
        input_tokens_by_cell[
            (unit["task_id"], selected_arm_by_requested_cell[f"{unit['task_id']}:{unit['arm_id']}"])
        ]
        for unit in units
    )
    avoided = historical_total - projected_total
    percent = (Decimal(avoided) * Decimal(100) / Decimal(historical_total)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    return {
        "historical_scheduled_input_tokens": historical_total,
        "projected_selected_input_tokens": projected_total,
        "provider_observed_input_tokens_avoided": avoided,
        "provider_observed_input_tokens_avoided_percent": format(percent, "f"),
    }


def build_report(
    capture_raw: bytes,
    result_raw: bytes,
    evidence_raw: bytes,
) -> dict[str, object]:
    capture = _load_exact_json(
        capture_raw,
        expected_sha256=CAPTURE_SHA256,
        diagnostic="unexpected_provider_input_freeze",
    )
    result = _load_exact_json(
        result_raw,
        expected_sha256=RESULT_SHA256,
        diagnostic="unexpected_observed_result",
    )
    evidence = _load_exact_json(
        evidence_raw,
        expected_sha256=EVIDENCE_SHA256,
        diagnostic="unexpected_provider_evidence",
    )
    by_task = _index_cells(capture)
    decisions = [
        _choose_cell(task_id, arm_id, by_task[task_id])
        for task_id in sorted(by_task)
        for arm_id in ARM_IDS
    ]
    factor_counts = {factor: Counter() for factor, _ in FACTOR_BITS}
    for decision in decisions:
        for factor, outcome in decision["factor_outcomes"].items():
            if outcome == "not_requested":
                continue
            factor_counts[factor]["applied" if outcome == "applied" else "suppressed_or_no_op"] += 1

    historical_total = sum(cell["prompt_bytes"] for cells in by_task.values() for cell in cells.values())
    selected_total = sum(decision["selected_prompt_bytes"] for decision in decisions)
    selected_growth = [
        decision["selected_prompt_bytes"] - decision["ordinary_prompt_ceiling_bytes"]
        for decision in decisions
    ]
    avoided = historical_total - selected_total
    percent = (Decimal(avoided) * Decimal(100) / Decimal(historical_total)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    input_token_projection = _input_token_projection(evidence, by_task, decisions)
    try:
        if result["provider_usage"]["input_tokens"] != input_token_projection["historical_scheduled_input_tokens"]:
            raise ValueError("result_provider_input_token_mismatch")
    except (KeyError, TypeError) as error:
        raise ValueError("invalid_observed_result") from error

    return {
        "claims": {
            "historical_v3_result_changed": False,
            "input_prompt_byte_growth_prevented_by_construction": True,
            "input_token_replay_projection_proven_for_frozen_prompts": True,
            "output_token_reduction_proven": False,
            "provider_calls_for_this_policy": 0,
            "quality_preservation_proven": False,
            "total_provider_token_reduction_proven": False,
        },
        "decisions": decisions,
        "diagnosis": _diagnosis(by_task, result),
        "policy": {
            "activation_order": ["adaptive", "symbol_memory", "graph_closure"],
            "adaptive_requirement": "activate_only_when_the_frozen_prompt_is_strictly_smaller",
            "fallback": "select_an_existing_frozen_cell_and_never_construct_unsealed_prompt_bytes",
            "name": "self_financing_context_v1",
            "prompt_ceiling": "task_specific_a000_prompt_bytes",
        },
        "policy_summary": {
            "factor_decisions": {
                factor: {
                    "applied": factor_counts[factor]["applied"],
                    "suppressed_or_no_op": factor_counts[factor]["suppressed_or_no_op"],
                }
                for factor, _ in FACTOR_BITS
            },
            "historical_prompt_bytes_avoided": avoided,
            "historical_prompt_bytes_avoided_percent": format(percent, "f"),
            **input_token_projection,
            "selected_cells_over_ordinary_ceiling": sum(delta > 0 for delta in selected_growth),
            "selected_max_prompt_growth_bytes": max(selected_growth),
            "selected_total_prompt_bytes": selected_total,
            "selected_unique_provider_inputs": len({row["selected_prompt_sha256"] for row in decisions}),
        },
        "schema_version": "contextguard.p3-api-budget-policy-report/v1",
        "source": {
            "observed_result_sha256": RESULT_SHA256,
            "provider_evidence_sha256": EVIDENCE_SHA256,
            "provider_input_freeze_sha256": CAPTURE_SHA256,
        },
    }


def validate_report(
    report: dict[str, object],
    *,
    capture_raw: bytes,
    evidence_raw: bytes,
    result_raw: bytes,
) -> None:
    expected = build_report(capture_raw, result_raw, evidence_raw)
    if canonical(report) != canonical(expected):
        raise ValueError("budget_policy_report_mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    report = build_report(
        (V3 / "provider-input-freeze.json").read_bytes(),
        (V3 / "result.json").read_bytes(),
        (V3 / "provider-evidence.json").read_bytes(),
    )
    if args.write_report:
        (V4 / "budget-policy-report.json").write_bytes(canonical(report))
        print("wrote budget-policy-report.json")
    else:
        print(canonical(report).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
