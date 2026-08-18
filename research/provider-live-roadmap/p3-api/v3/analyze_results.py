#!/usr/bin/env python3
"""Recompute the preregistered v3 finite-corpus result from public evidence."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP, localcontext
from fractions import Fraction
from pathlib import Path
import tempfile
import types
from typing import Mapping, Sequence


ROOT = Path(__file__).resolve().parents[4]
V3 = Path(__file__).resolve().parent
RUNNER = V3 / "live_runner.py"
PUBLIC_EVIDENCE = V3 / "provider-evidence.json"
RESULT = V3 / "result.json"
EXPECTED_VALIDATOR_RUNNER_SHA256 = "5f44608ec1261720a15dc6ab8710b217367745f7c031f609e4c4fa196dde2e9e"
EXPECTED_VALIDATOR_CONTRACT_SHA256 = "1e7c1751e5b720c99e2b09b82502542bfa255da4858f012845ca335595eb5e16"
EXPECTED_EVIDENCE_RUNNER_SHA256 = "3dc212a7ee763628fe2b554502a457e702d25509ddb50b8431982368945372a9"
EXPECTED_EXECUTED_CONTRACT_SHA256 = "0bd1bc740079ad71851044860f12e0586c15ba968f85ec0926793e488d3a6168"
EXECUTED_ARTIFACT_SHA256 = {
    "evaluator": "0db688ebb441b29ebb36d69e5ee3a8ffa169a8d637eb0c4e230be6fd9ad57c67",
    "provider_input_capture": "314f018111f417ee8892ede95da97e407a81926c43a072bcd70658fa144034cd",
    "rehearsal_report": "b7440d238e76aed229c240eceb12dd3cbc67fe71508dc86a34870ac8324e7204",
}

ARM_IDS = tuple(f"a{value:03b}" for value in range(8))
FACTOR_INDEX = {"adaptive": 0, "symbol_memory": 1, "graph_closure": 2}
EFFECTS = (
    ("adaptive", ("adaptive",)),
    ("symbol_memory", ("symbol_memory",)),
    ("graph_closure", ("graph_closure",)),
    ("adaptive_x_symbol_memory", ("adaptive", "symbol_memory")),
    ("adaptive_x_graph_closure", ("adaptive", "graph_closure")),
    ("symbol_memory_x_graph_closure", ("symbol_memory", "graph_closure")),
    (
        "adaptive_x_symbol_memory_x_graph_closure",
        ("adaptive", "symbol_memory", "graph_closure"),
    ),
)
METRICS = (
    "input_tokens",
    "output_tokens",
    "total_provider_tokens",
    "list_price_micro_usd",
)
EXPECTED_ANALYSIS = {
    "complete_case_rule": "all_3_repetitions_and_all_8_arms_per_task",
    "independent_cluster": "project",
    "independent_cluster_count": 3,
    "inferential_claim_status": "unavailable_only_3_independent_project_clusters",
    "primary_usage_estimand": "task_balanced_mean_total_provider_tokens_a111_minus_a000",
    "technical_repetitions_reduced_within_task": 3,
    "total_provider_tokens": "input_tokens_plus_output_tokens",
}


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


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("nonfinite_json_value")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid_{label}") from error
    if type(value) is not dict:
        raise ValueError(f"invalid_{label}")
    return value


def _decimal(value: Fraction, places: int = 6) -> str:
    quantum = Decimal(1).scaleb(-places)
    with localcontext() as context:
        context.prec = 50
        number = Decimal(value.numerator) / Decimal(value.denominator)
        return format(number.quantize(quantum, rounding=ROUND_HALF_UP), f".{places}f")


def _fraction(value: Fraction) -> dict[str, object]:
    normalized = Fraction(value)
    return {
        "decimal": _decimal(normalized),
        "fraction": {
            "denominator": normalized.denominator,
            "numerator": normalized.numerator,
        },
    }


def _load_runner(raw: bytes):
    module = types.ModuleType("p3_v3_bound_live_runner")
    module.__file__ = str(RUNNER)
    try:
        exec(compile(raw, str(RUNNER), "exec"), module.__dict__, module.__dict__)
    except Exception as error:
        raise ValueError("runner_unavailable") from error
    return module


def _executed_contract_raw(current_raw: bytes) -> bytes:
    current = parse_json(current_raw, "contract")
    artifacts = current.get("artifacts")
    if type(artifacts) is not dict or any(
        type(artifacts.get(name)) is not dict for name in EXECUTED_ARTIFACT_SHA256
    ):
        raise ValueError("invalid_contract")
    raw = current_raw
    for name, digest in EXECUTED_ARTIFACT_SHA256.items():
        current_digest = artifacts[name].get("sha256")
        if not isinstance(current_digest, str):
            raise ValueError("invalid_contract")
        needle = current_digest.encode("ascii")
        if raw.count(needle) != 1:
            raise ValueError("invalid_contract")
        raw = raw.replace(needle, digest.encode("ascii"), 1)
    parse_json(raw, "executed_contract")
    if sha256(raw) != EXPECTED_EXECUTED_CONTRACT_SHA256:
        raise ValueError("executed_contract_mismatch")
    return raw


def _validate_current_artifact(
    contract: Mapping[str, object], name: str, raw: bytes
) -> None:
    artifacts = contract.get("artifacts")
    identity = artifacts.get(name) if type(artifacts) is dict else None
    if type(identity) is not dict or identity.get("sha256") != sha256(raw):
        raise ValueError(f"{name}_digest_mismatch")


def _validate_preregistration(preregistration: Mapping[str, object]) -> None:
    analysis = preregistration.get("analysis")
    if type(analysis) is not dict:
        raise ValueError("invalid_preregistration")
    if any(analysis.get(key) != value for key, value in EXPECTED_ANALYSIS.items()):
        raise ValueError("invalid_preregistration")
    if analysis.get("predeclared_contrasts") != [
        "a111_minus_a000",
        "adaptive_main_effect",
        "symbol_memory_main_effect",
        "graph_closure_main_effect",
    ]:
        raise ValueError("invalid_preregistration")
    if analysis.get("factorial_effect_count") != len(EFFECTS):
        raise ValueError("invalid_preregistration")
    uncertainty = analysis.get("uncertainty")
    if uncertainty != {
        "claim": "descriptive_finite_corpus_sensitivity_only",
        "leave_one_project_out_rows": 3,
        "method": "all_27_ordered_project_cluster_resamples",
    }:
        raise ValueError("invalid_preregistration")


def _schedule_units(schedule: Mapping[str, object]) -> dict[str, dict[str, object]]:
    if (
        schedule.get("scheduled_units") != 288
        or schedule.get("repetitions_per_task_arm") != 3
        or schedule.get("arms_per_block") != 8
        or schedule.get("block_count") != 36
    ):
        raise ValueError("invalid_schedule")
    blocks = schedule.get("blocks")
    if type(blocks) is not list or len(blocks) != 36:
        raise ValueError("invalid_schedule")
    result: dict[str, dict[str, object]] = {}
    for block in blocks:
        if type(block) is not dict or type(block.get("units")) is not list:
            raise ValueError("invalid_schedule")
        for unit in block["units"]:
            if type(unit) is not dict or set(unit) != {
                "arm_id", "repetition", "task_id", "unit_id"
            }:
                raise ValueError("invalid_schedule")
            unit_id = unit["unit_id"]
            if not isinstance(unit_id, str) or unit_id in result:
                raise ValueError("invalid_schedule")
            result[unit_id] = unit
    if len(result) != 288:
        raise ValueError("invalid_schedule")
    return result


def _task_projects(corpus: Mapping[str, object]) -> dict[str, str]:
    tasks = corpus.get("tasks")
    if type(tasks) is not list or len(tasks) != 12:
        raise ValueError("invalid_corpus")
    result: dict[str, str] = {}
    for task in tasks:
        if type(task) is not dict:
            raise ValueError("invalid_corpus")
        task_id = task.get("id")
        project_id = task.get("project_id")
        if (
            not isinstance(task_id, str)
            or not isinstance(project_id, str)
            or task_id in result
        ):
            raise ValueError("invalid_corpus")
        result[task_id] = project_id
    if len(set(result.values())) != 3:
        raise ValueError("invalid_corpus")
    if any(list(result.values()).count(project) != 4 for project in set(result.values())):
        raise ValueError("invalid_corpus")
    return result


def _task_taxonomies(corpus: Mapping[str, object]) -> dict[str, str]:
    tasks = corpus.get("tasks")
    if type(tasks) is not list or len(tasks) != 12:
        raise ValueError("invalid_corpus")
    result: dict[str, str] = {}
    for task in tasks:
        if type(task) is not dict:
            raise ValueError("invalid_corpus")
        task_id = task.get("id")
        taxonomy = task.get("taxonomy")
        if (
            not isinstance(task_id, str)
            or not isinstance(taxonomy, str)
            or task_id in result
        ):
            raise ValueError("invalid_corpus")
        result[task_id] = taxonomy
    if len(set(result.values())) != 4:
        raise ValueError("invalid_corpus")
    return result


def _validated_units(
    evidence: Mapping[str, object],
    *,
    schedule_units: Mapping[str, Mapping[str, object]],
    task_projects: Mapping[str, str],
) -> list[dict[str, object]]:
    units = evidence.get("sealed_units")
    if type(units) is not list or len(units) != 288:
        raise ValueError("incomplete_evidence")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for unit in units:
        if type(unit) is not dict:
            raise ValueError("invalid_evidence_unit")
        unit_id = unit.get("scheduled_unit_id")
        if not isinstance(unit_id, str) or unit_id in seen:
            raise ValueError("invalid_evidence_unit")
        seen.add(unit_id)
        scheduled = schedule_units.get(unit_id)
        if scheduled is None or any(
            unit.get(evidence_key) != scheduled[schedule_key]
            for evidence_key, schedule_key in (
                ("task_id", "task_id"),
                ("arm_id", "arm_id"),
                ("repetition", "repetition"),
            )
        ):
            raise ValueError("schedule_evidence_mismatch")
        if (
            unit.get("status") != "completed"
            or unit.get("dispatched") is not True
            or unit.get("http_status") != 200
            or type(unit.get("usage")) is not dict
            or unit.get("task_id") not in task_projects
            or unit.get("arm_id") not in ARM_IDS
        ):
            raise ValueError("incomplete_evidence")
        usage = unit["usage"]
        if usage.get("provider_total_tokens") != (
            usage.get("input_tokens", -1) + usage.get("output_tokens", -1)
        ):
            raise ValueError("invalid_provider_usage")
        result.append(unit)
    if seen != set(schedule_units):
        raise ValueError("schedule_evidence_mismatch")
    return result


def _metric_value(unit: Mapping[str, object], metric: str) -> int:
    usage = unit["usage"]
    assert isinstance(usage, dict)
    key = "provider_total_tokens" if metric == "total_provider_tokens" else metric
    value = usage.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("invalid_provider_usage")
    return value


def _arm_task_means(
    units: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, dict[str, Fraction]]]:
    grouped: dict[str, dict[str, dict[str, list[int]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )
    for unit in units:
        task_id = unit["task_id"]
        arm_id = unit["arm_id"]
        assert isinstance(task_id, str) and isinstance(arm_id, str)
        for metric in METRICS:
            grouped[task_id][arm_id][metric].append(_metric_value(unit, metric))
    result: dict[str, dict[str, dict[str, Fraction]]] = {}
    if len(grouped) != 12:
        raise ValueError("incomplete_evidence")
    for task_id, arms in grouped.items():
        if set(arms) != set(ARM_IDS):
            raise ValueError("incomplete_evidence")
        result[task_id] = {}
        for arm_id, metrics in arms.items():
            result[task_id][arm_id] = {}
            for metric, values in metrics.items():
                if len(values) != 3:
                    raise ValueError("incomplete_evidence")
                result[task_id][arm_id][metric] = Fraction(sum(values), len(values))
    return result


def _effect_sign(arm_id: str, factors: Sequence[str]) -> int:
    sign = 1
    for factor in factors:
        sign *= 1 if arm_id[1 + FACTOR_INDEX[factor]] == "1" else -1
    return sign


def _task_effect(
    task_means: Mapping[str, Mapping[str, Fraction]],
    metric: str,
    factors: Sequence[str],
) -> Fraction:
    return sum(
        (_effect_sign(arm_id, factors) * task_means[arm_id][metric] for arm_id in ARM_IDS),
        Fraction(),
    ) / 4


def _project_estimands(
    means: Mapping[str, Mapping[str, Mapping[str, Fraction]]],
    task_projects: Mapping[str, str],
    metric: str,
) -> dict[str, dict[str, Fraction]]:
    projects = sorted(set(task_projects.values()))
    result: dict[str, dict[str, Fraction]] = {}
    for project in projects:
        tasks = [task for task in sorted(means) if task_projects[task] == project]
        baseline = sum((means[task]["a000"][metric] for task in tasks), Fraction()) / 4
        comparison = sum((means[task]["a111"][metric] for task in tasks), Fraction()) / 4
        row = {
            "a000": baseline,
            "a111": comparison,
            "a111_minus_a000": comparison - baseline,
        }
        for name, factors in EFFECTS:
            row[name] = sum(
                (_task_effect(means[task], metric, factors) for task in tasks),
                Fraction(),
            ) / 4
        result[project] = row
    return result


def _percent_reduction(baseline: Fraction, comparison: Fraction) -> str:
    if baseline <= 0:
        raise ValueError("invalid_baseline")
    return _decimal(Fraction(100) * (baseline - comparison) / baseline)


def _arm_rows(
    units: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for arm_id in ARM_IDS:
        arm_units = [unit for unit in units if unit["arm_id"] == arm_id]
        if len(arm_units) != 36:
            raise ValueError("incomplete_evidence")
        metrics: dict[str, object] = {}
        for metric in METRICS:
            total = sum(_metric_value(unit, metric) for unit in arm_units)
            metrics[metric] = {
                "mean_per_unit": _fraction(Fraction(total, len(arm_units))),
                "sum": total,
            }
        result[arm_id] = {
            "failed_quality_units": len(arm_units),
            "metrics": metrics,
            "passed_quality_units": 0,
            "units": len(arm_units),
        }
    return result


def _primary_contrast(
    means: Mapping[str, Mapping[str, Mapping[str, Fraction]]]
) -> dict[str, object]:
    metrics: dict[str, object] = {}
    task_count = len(means)
    for metric in METRICS:
        baseline = sum(
            (task["a000"][metric] for task in means.values()), Fraction()
        ) / task_count
        comparison = sum(
            (task["a111"][metric] for task in means.values()), Fraction()
        ) / task_count
        metrics[metric] = {
            "a000_task_balanced_mean": _fraction(baseline),
            "a111_task_balanced_mean": _fraction(comparison),
            "delta": _fraction(comparison - baseline),
            "percent_reduction": _percent_reduction(baseline, comparison),
        }
    return {
        "contrast": "a111_minus_a000",
        "metrics": metrics,
        "orientation": "comparison_minus_baseline_negative_is_reduction",
    }


def _factorial_effects(
    means: Mapping[str, Mapping[str, Mapping[str, Fraction]]]
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for name, factors in EFFECTS:
        metrics: dict[str, object] = {}
        for metric in METRICS:
            value = sum(
                (_task_effect(task, metric, factors) for task in means.values()),
                Fraction(),
            ) / len(means)
            metrics[metric] = {
                "delta": _fraction(value),
                "reduction": _fraction(-value),
            }
        result[name] = {
            "factors": list(factors),
            "metrics": metrics,
            "orientation": "enabled_minus_disabled_negative_is_reduction",
        }
    return result


def _sensitivity_row(
    selected_projects: Sequence[str],
    project_rows: Mapping[str, Mapping[str, Fraction]],
) -> dict[str, object]:
    count = len(selected_projects)
    baseline = sum((project_rows[p]["a000"] for p in selected_projects), Fraction()) / count
    comparison = sum((project_rows[p]["a111"] for p in selected_projects), Fraction()) / count
    effects = {
        name: _fraction(
            sum((project_rows[p][name] for p in selected_projects), Fraction()) / count
        )
        for name, _factors in EFFECTS
    }
    return {
        "factorial_effects_total_provider_tokens": effects,
        "primary_total_provider_tokens": {
            "a000": _fraction(baseline),
            "a111": _fraction(comparison),
            "delta": _fraction(comparison - baseline),
            "percent_reduction": _percent_reduction(baseline, comparison),
        },
        "selected_projects": list(selected_projects),
    }


def _finite_corpus_sensitivity(
    means: Mapping[str, Mapping[str, Mapping[str, Fraction]]],
    task_projects: Mapping[str, str],
) -> dict[str, object]:
    projects = sorted(set(task_projects.values()))
    project_values = _project_estimands(
        means, task_projects, "total_provider_tokens"
    )
    project_rows = [
        {
            "project_id": project,
            **_sensitivity_row([project], project_values),
        }
        for project in projects
    ]
    leave_one_out = [
        {
            "excluded_project": excluded,
            **_sensitivity_row(
                [project for project in projects if project != excluded],
                project_values,
            ),
        }
        for excluded in projects
    ]
    resamples = [
        {
            "resample_index": index,
            **_sensitivity_row(selected, project_values),
        }
        for index, selected in enumerate(
            itertools.product(projects, repeat=3), start=1
        )
    ]
    return {
        "claim": "descriptive_finite_corpus_sensitivity_only",
        "independent_cluster": "project",
        "leave_one_project_out": leave_one_out,
        "ordered_project_cluster_resamples": resamples,
        "project_rows": project_rows,
    }


def _zero_pass_breakdown(
    units: Sequence[Mapping[str, object]],
    task_group: Mapping[str, str],
) -> dict[str, dict[str, int]]:
    counts: dict[str, int] = defaultdict(int)
    for unit in units:
        task_id = unit["task_id"]
        assert isinstance(task_id, str)
        counts[task_group[task_id]] += 1
    return {
        group: {
            "failed_units": count,
            "passed_units": 0,
            "total_units": count,
        }
        for group, count in sorted(counts.items())
    }


def build_result(
    evidence_raw: bytes,
    *,
    preregistration_raw: bytes,
    corpus_raw: bytes,
    schedule_raw: bytes,
    contract_raw: bytes,
) -> dict[str, object]:
    evidence = parse_json(evidence_raw, "provider_evidence")
    if canonical(evidence) != evidence_raw:
        raise ValueError("noncanonical_provider_evidence")
    if sha256(contract_raw) != EXPECTED_VALIDATOR_CONTRACT_SHA256:
        raise ValueError("validator_contract_mismatch")
    current_contract = parse_json(contract_raw, "contract")
    for name, raw in (
        ("preregistration", preregistration_raw),
        ("corpus", corpus_raw),
        ("schedule", schedule_raw),
    ):
        _validate_current_artifact(current_contract, name, raw)
    preregistration = parse_json(preregistration_raw, "preregistration")
    corpus = parse_json(corpus_raw, "corpus")
    schedule = parse_json(schedule_raw, "schedule")
    executed_contract_raw = _executed_contract_raw(contract_raw)
    contract = parse_json(executed_contract_raw, "contract")
    _validate_preregistration(preregistration)
    runner_raw = RUNNER.read_bytes()
    runner_digest = sha256(runner_raw)
    if runner_digest != EXPECTED_VALIDATOR_RUNNER_SHA256:
        raise ValueError("runner_digest_mismatch")
    if evidence.get("runner_sha256") != EXPECTED_EVIDENCE_RUNNER_SHA256:
        raise ValueError("runner_evidence_mismatch")
    runner = _load_runner(runner_raw)
    try:
        runner.validate_public_evidence(evidence, contract_raw=executed_contract_raw)
    except Exception as error:
        raise ValueError("invalid_provider_evidence") from error
    if evidence.get("plan_sha256") != contract.get("resume", {}).get(
        "previous_plan_sha256"
    ):
        raise ValueError("plan_evidence_mismatch")
    if evidence.get("status") != "completed":
        raise ValueError("incomplete_evidence")
    schedule_units = _schedule_units(schedule)
    task_projects = _task_projects(corpus)
    task_taxonomies = _task_taxonomies(corpus)
    units = _validated_units(
        evidence,
        schedule_units=schedule_units,
        task_projects=task_projects,
    )
    means = _arm_task_means(units)
    arm_rows = _arm_rows(units)
    primary = _primary_contrast(means)
    effects = _factorial_effects(means)
    scoring = evidence.get("scoring")
    if type(scoring) is not dict or scoring.get("status") != "complete":
        raise ValueError("incomplete_scoring")
    passed = scoring.get("passed_units")
    failed = scoring.get("failed_units")
    if passed != 0 or failed != 288:
        # The published arm quality rows rely on the observed global zero-pass result.
        raise ValueError("unexpected_quality_result")
    token_usage = evidence["token_usage"]
    assert isinstance(token_usage, dict)
    total_tokens = token_usage["provider_total_tokens"]
    if total_tokens != token_usage["input_tokens"] + token_usage["output_tokens"]:
        raise ValueError("invalid_provider_usage")
    quality_gate_met = passed == 288 and failed == 0
    total_delta = primary["metrics"]["total_provider_tokens"]["delta"]["fraction"]
    assert isinstance(total_delta, dict)
    primary_reduction = total_delta["numerator"] < 0
    adaptive_delta = effects["adaptive"]["metrics"]["total_provider_tokens"]["delta"]["fraction"]
    symbol_delta = effects["symbol_memory"]["metrics"]["total_provider_tokens"]["delta"]["fraction"]
    graph_delta = effects["graph_closure"]["metrics"]["total_provider_tokens"]["delta"]["fraction"]
    list_price_micro_usd = token_usage["list_price_micro_usd"]
    if not isinstance(list_price_micro_usd, int):
        raise ValueError("invalid_provider_usage")
    return {
        "arm_rows": arm_rows,
        "claims": {
            "adaptive_main_effect_reduction_observed": adaptive_delta["numerator"] < 0,
            "all_task_quality_guarantee": False,
            "future_project_generalization": False,
            "graph_closure_main_effect_reduction_observed": graph_delta["numerator"] < 0,
            "primary_total_token_reduction_observed": primary_reduction,
            "provider_confirmed_exact_usd_savings": False,
            "provider_token_usage_observed": True,
            "quality_preserving_savings": quality_gate_met and primary_reduction,
            "symbol_memory_main_effect_reduction_observed": symbol_delta["numerator"] < 0,
        },
        "cost_evidence": {
            "calculated_list_price_authority": "published_list_price_not_billing_receipt",
            "calculated_list_price_usd": _decimal(Fraction(list_price_micro_usd, 1_000_000)),
            "provider_billed_usd": {
                "reason": "request_level_provider_cost_receipt_unavailable",
                "status": "unavailable",
                "value": None,
            },
        },
        "factorial_effects": effects,
        "finite_corpus_sensitivity": _finite_corpus_sensitivity(
            means, task_projects
        ),
        "primary_contrast": primary,
        "provider_usage": {
            "authority": "anthropic_messages_api_response",
            "cache_creation_input_tokens": token_usage["cache_creation_input_tokens"],
            "cache_read_input_tokens": token_usage["cache_read_input_tokens"],
            "calculated_list_price_micro_usd": list_price_micro_usd,
            "completed_calls": token_usage["completed_calls"],
            "input_tokens": token_usage["input_tokens"],
            "output_tokens": token_usage["output_tokens"],
            "total_provider_tokens": total_tokens,
        },
        "quality": {
            "by_project": _zero_pass_breakdown(units, task_projects),
            "by_taxonomy": _zero_pass_breakdown(units, task_taxonomies),
            "failed_units": failed,
            "outcome": "exact_selected_path_historical_patch_reproduction_plus_source_assertions",
            "pass_rate": _decimal(Fraction(passed, 288)),
            "passed_units": passed,
            "quality_gate_met": quality_gate_met,
            "required_pass_rate": "1.000000",
            "semantic_alternative_patch_acceptance": False,
        },
        "schema_version": "contextguard.p3-api-factorial-live-result/v1",
        "scope": {
            "arms": 8,
            "independent_project_clusters": 3,
            "repetitions_per_task_arm": 3,
            "scheduled_units": 288,
            "tasks": 12,
        },
        "source": {
            "analyzer_sha256": sha256(Path(__file__).read_bytes()),
            "contract_sha256": sha256(executed_contract_raw),
            "corpus_sha256": sha256(corpus_raw),
            "plan_sha256": evidence["plan_sha256"],
            "preregistration_sha256": sha256(preregistration_raw),
            "provider_evidence_bytes": len(evidence_raw),
            "provider_evidence_sha256": sha256(evidence_raw),
            "runner_sha256": evidence["runner_sha256"],
            "validator_runner_sha256": runner_digest,
            "validator_contract_sha256": sha256(contract_raw),
            "schedule_sha256": sha256(schedule_raw),
        },
        "status": "complete_quality_gate_failed",
    }


def validate_result(
    result: Mapping[str, object],
    *,
    evidence_raw: bytes,
    preregistration_raw: bytes,
    corpus_raw: bytes,
    schedule_raw: bytes,
    contract_raw: bytes,
) -> None:
    expected = build_result(
        evidence_raw,
        preregistration_raw=preregistration_raw,
        corpus_raw=corpus_raw,
        schedule_raw=schedule_raw,
        contract_raw=contract_raw,
    )
    if result != expected:
        raise ValueError("result_mismatch")


def _atomic_public_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _inputs(evidence_raw: bytes) -> tuple[dict[str, object], dict[str, bytes]]:
    raw_inputs = {
        "preregistration_raw": (V3 / "preregistration.json").read_bytes(),
        "corpus_raw": (V3 / "corpus-manifest.json").read_bytes(),
        "schedule_raw": (V3 / "schedule.json").read_bytes(),
        "contract_raw": (V3 / "live-contract.json").read_bytes(),
    }
    return build_result(evidence_raw, **raw_inputs), raw_inputs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify or publish the preregistered v3 aggregate result."
    )
    parser.add_argument(
        "--source-evidence",
        type=Path,
        help="Validated public evidence to import; never a private capsule path.",
    )
    parser.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.write != (arguments.source_evidence is not None):
        raise SystemExit("--write and --source-evidence must be used together")
    if arguments.write:
        source_raw = arguments.source_evidence.read_bytes()
        result, _raw_inputs = _inputs(source_raw)
        _atomic_public_write(PUBLIC_EVIDENCE, source_raw)
        _atomic_public_write(RESULT, canonical(result))
        print(
            "published provider-live result: "
            f"evidence_sha256={sha256(source_raw)} units=288"
        )
        return 0
    evidence_raw = PUBLIC_EVIDENCE.read_bytes()
    result_raw = RESULT.read_bytes()
    result, raw_inputs = _inputs(evidence_raw)
    if result_raw != canonical(result):
        raise ValueError("result_mismatch")
    validate_result(
        parse_json(result_raw, "result"),
        evidence_raw=evidence_raw,
        **raw_inputs,
    )
    print(
        "provider-live result verified: "
        f"evidence_sha256={sha256(evidence_raw)} units=288"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
