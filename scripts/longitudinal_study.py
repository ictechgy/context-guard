#!/usr/bin/env python3
"""Provider-free runner for the closed ContextGuard longitudinal study protocol."""
from __future__ import annotations

import argparse
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


PROTOCOL_FILES = ("schedule.json", "preregistration.json", "observation.schema.json")
TASK_STRATA = ("maintenance", "bug", "feature", "security", "refactor")
ARMS = ("baseline", "adaptive_only", "symbol_only", "graph_only", "combined")
UNAVAILABLE_REASONS = {
    "offline_rehearsal", "not_in_provider_receipt", "billing_pending",
    "not_measured", "not_applicable", "excluded_unit", "failed_unit",
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed_pairs(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key in {label}: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=lambda pairs: _closed_pairs(pairs, str(path)),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid protocol artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"protocol artifact must be an object: {path}")
    return value


def protocol_sha256(protocol: Path) -> str:
    digest = hashlib.sha256(b"contextguard.longitudinal-protocol/v1\0")
    for name in PROTOCOL_FILES:
        raw = (protocol / name).read_bytes()
        encoded = name.encode("ascii")
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()


def closed_units(schedule: dict[str, Any]) -> list[dict[str, Any]]:
    projects = [item["project_id"] for item in schedule["projects"]]
    units: list[dict[str, Any]] = []
    for project_id in projects:
        for task_stratum in schedule["task_strata"]:
            block_id = f"{project_id}-{task_stratum}"
            ranked_arms = sorted(
                schedule["arms"],
                key=lambda arm: sha256(f"{schedule['schedule_seed']}|{block_id}|{arm}".encode()),
            )
            for order, arm in enumerate(ranked_arms, 1):
                units.append({
                    "scheduled_unit_id": f"unit-{project_id[-2:]}-{task_stratum}-{arm}",
                    "block_id": block_id,
                    "project_id": project_id,
                    "task_stratum": task_stratum,
                    "arm": arm,
                    "assigned_order": order,
                })
    return units


def validate_protocol(protocol: Path) -> dict[str, Any]:
    protocol = Path(protocol)
    schedule = read_json(protocol / "schedule.json")
    preregistration = read_json(protocol / "preregistration.json")
    schema = read_json(protocol / "observation.schema.json")
    if schedule.get("schema_version") != "contextguard.longitudinal-schedule/v1" or schedule.get("status") != "preregistered_closed":
        raise ValueError("schedule is not a closed v1 preregistration")
    projects = schedule.get("projects")
    if not isinstance(projects, list) or len(projects) < 5:
        raise ValueError("at least five project identities are required")
    project_ids = [item.get("project_id") for item in projects if isinstance(item, dict)]
    if len(project_ids) != len(projects) or len(set(project_ids)) != len(project_ids):
        raise ValueError("project identities must be unique")
    if tuple(schedule.get("task_strata", ())) != TASK_STRATA or tuple(schedule.get("arms", ())) != ARMS:
        raise ValueError("closed strata or arms changed")
    expected_factors = {
        "baseline": [], "adaptive_only": ["adaptive"], "symbol_only": ["symbol"],
        "graph_only": ["graph"], "combined": ["adaptive", "symbol", "graph"],
    }
    if schedule.get("factor_contract") != expected_factors:
        raise ValueError("factor isolation contract changed")
    units = closed_units(schedule)
    caps = schedule.get("caps", {})
    if len(units) != 125 or caps.get("max_units") != 125 or caps.get("max_attempts") != 125:
        raise ValueError("closed unit caps do not match schedule")
    if len({unit["scheduled_unit_id"] for unit in units}) != len(units):
        raise ValueError("duplicate scheduled unit identity")
    if preregistration.get("status") != "preregistered_closed_before_observation":
        raise ValueError("invalid preregistration status")
    if schema.get("$id") != "contextguard.longitudinal-observation/v1":
        raise ValueError("invalid observation schema identity")
    return {"protocol_sha256": protocol_sha256(protocol), "schedule": schedule, "units": units}


def unavailable_integer(reason: str = "offline_rehearsal") -> dict[str, Any]:
    return {"availability": "unavailable", "value": None, "unavailable_reason": reason}


def observed_integer(value: int) -> dict[str, Any]:
    return {"availability": "observed", "value": value, "unavailable_reason": None}


def unavailable_decimal(reason: str = "offline_rehearsal") -> dict[str, Any]:
    return {"availability": "unavailable", "value": None, "currency": None, "unavailable_reason": reason}


def observed_decimal(value: str, currency: str = "USD") -> dict[str, Any]:
    return {"availability": "observed", "value": value, "currency": currency, "unavailable_reason": None}


def observation_identity(observation: dict[str, Any]) -> str:
    clone = json.loads(json.dumps(observation))
    clone["receipt"]["observation_sha256"] = ""
    return sha256(canonical(clone))


def rehearsal_observation(unit: dict[str, Any]) -> dict[str, Any]:
    identity = sha256(canonical(unit))
    ordinal = int(identity[:8], 16)
    receipt_id = "rehearsal-receipt-" + identity[:32]
    observation: dict[str, Any] = {
        "schema_version": "contextguard.longitudinal-observation/v1",
        "scheduled_unit_id": unit["scheduled_unit_id"],
        "project_id": unit["project_id"],
        "task_stratum": unit["task_stratum"],
        "arm": unit["arm"],
        "outcome": "completed",
        "quality": {"outcome": "passed", "score": observed_integer(100), "evaluator_receipt_id": "local-evaluator-" + identity[:24]},
        "provider": {
            "tokens": {name: unavailable_integer() for name in ("input", "output", "cache_read", "cache_write")},
            "billed_cost": unavailable_decimal(),
            "billing_status": "not_applicable",
            "calculated_list_price": unavailable_decimal(),
        },
        "local": {"elapsed_ms": observed_integer(10 + ordinal % 91), "calculated_cost": observed_decimal(f"0.{ordinal % 10000:04d}")},
        "retrievals": {"count": observed_integer(ordinal % 7), "bytes": observed_integer(100 + ordinal % 10000)},
        "corrections": {"count": observed_integer(ordinal % 3), "provider_tokens": unavailable_integer(), "local_elapsed_ms": observed_integer(ordinal % 31)},
        "exclusion": {"excluded": False, "reason": None},
        "receipt": {"receipt_id": receipt_id, "request_id": "rehearsal-request-" + identity[:32], "provider_receipt_sha256": None, "observation_sha256": ""},
        "private": {"private_project_locator": "rehearsal://" + unit["project_id"], "provider_receipt_payload": None},
    }
    observation["receipt"]["observation_sha256"] = observation_identity(observation)
    return observation


def _validate_metric(metric: Any, *, decimal: bool = False) -> None:
    required = {"availability", "value", "unavailable_reason"} | ({"currency"} if decimal else set())
    if not isinstance(metric, dict) or set(metric) != required:
        raise ValueError("invalid metric shape")
    availability = metric["availability"]
    if availability == "unavailable":
        if metric["value"] is not None or (decimal and metric["currency"] is not None):
            raise ValueError("unavailable metric must use null")
        if metric["unavailable_reason"] not in UNAVAILABLE_REASONS:
            raise ValueError("unavailable metric requires a closed reason")
    elif availability == "observed":
        if metric["value"] is None or metric["unavailable_reason"] is not None:
            raise ValueError("observed metric requires a value and null reason")
        if decimal and (not isinstance(metric["value"], str) or metric["currency"] != "USD"):
            raise ValueError("observed decimal metric requires an exact USD string")
        if not decimal and (not isinstance(metric["value"], int) or isinstance(metric["value"], bool) or metric["value"] < 0):
            raise ValueError("observed integer metric requires a nonnegative integer")
    else:
        raise ValueError("invalid metric availability")


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ValueError(f"observation {label} fields are not closed")
    return value


def validate_observation(observation: dict[str, Any], protocol: Path) -> None:
    _closed(observation, {
        "schema_version", "scheduled_unit_id", "project_id", "task_stratum",
        "arm", "outcome", "quality", "provider", "local", "retrievals",
        "corrections", "exclusion", "receipt", "private",
    }, "root")
    _closed(observation["quality"], {"outcome", "score", "evaluator_receipt_id"}, "quality")
    _closed(observation["provider"], {"tokens", "billed_cost", "billing_status", "calculated_list_price"}, "provider")
    _closed(observation["provider"]["tokens"], {"input", "output", "cache_read", "cache_write"}, "provider tokens")
    _closed(observation["local"], {"elapsed_ms", "calculated_cost"}, "local")
    _closed(observation["retrievals"], {"count", "bytes"}, "retrievals")
    _closed(observation["corrections"], {"count", "provider_tokens", "local_elapsed_ms"}, "corrections")
    _closed(observation["exclusion"], {"excluded", "reason"}, "exclusion")
    _closed(observation["receipt"], {"receipt_id", "request_id", "provider_receipt_sha256", "observation_sha256"}, "receipt")
    _closed(observation["private"], {"private_project_locator", "provider_receipt_payload"}, "private")
    if observation["schema_version"] != "contextguard.longitudinal-observation/v1":
        raise ValueError("invalid observation schema version")
    if observation["outcome"] not in {"completed", "failed", "excluded"}:
        raise ValueError("invalid observation outcome")
    if observation["quality"]["outcome"] not in {"passed", "failed", "unavailable"}:
        raise ValueError("invalid observation quality outcome")
    if observation["provider"]["billing_status"] not in {
        "authoritative_receipt", "pending", "unavailable", "not_applicable",
    }:
        raise ValueError("invalid observation billing status")
    validated = validate_protocol(protocol)
    unit_by_id = {unit["scheduled_unit_id"]: unit for unit in validated["units"]}
    unit = unit_by_id.get(observation.get("scheduled_unit_id"))
    if unit is None or any(observation.get(key) != unit[key] for key in ("project_id", "task_stratum", "arm")):
        raise ValueError("observation schedule identity mismatch")
    for metric in observation["provider"]["tokens"].values():
        _validate_metric(metric)
    _validate_metric(observation["provider"]["billed_cost"], decimal=True)
    _validate_metric(observation["provider"]["calculated_list_price"], decimal=True)
    _validate_metric(observation["local"]["elapsed_ms"])
    _validate_metric(observation["local"]["calculated_cost"], decimal=True)
    for group in ("retrievals", "corrections"):
        for metric in observation[group].values():
            _validate_metric(metric)
    _validate_metric(observation["quality"]["score"])
    caps = validated["schedule"]["caps"]
    for metric, maximum, label in (
        (observation["retrievals"]["count"], caps["max_retrievals_per_unit"], "retrieval"),
        (observation["corrections"]["count"], caps["max_corrections_per_unit"], "correction"),
        (observation["local"]["elapsed_ms"], caps["max_local_elapsed_ms_per_unit"], "local elapsed"),
    ):
        if metric["availability"] == "observed" and metric["value"] > maximum:
            raise ValueError(f"{label} cap exceeded")
    if observation["receipt"]["observation_sha256"] != observation_identity(observation):
        raise ValueError("observation receipt identity mismatch")


def atomic_json(path: Path, value: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical(value))
    if private:
        os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _load_existing(output: Path, units: list[dict[str, Any]], protocol: Path) -> list[dict[str, Any]]:
    path = output / "private" / "observations.jsonl"
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    if len(rows) > len(units):
        raise ValueError("observation count exceeds closed schedule")
    receipts: set[str] = set()
    for index, row in enumerate(rows):
        if row.get("scheduled_unit_id") != units[index]["scheduled_unit_id"]:
            raise ValueError("resume sequence drift")
        validate_observation(row, protocol)
        receipt_id = row["receipt"]["receipt_id"]
        if receipt_id in receipts:
            raise ValueError("duplicate receipt identity")
        receipts.add(receipt_id)
    return rows


def _availability_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    paths = {
        "provider_tokens_input": lambda row: row["provider"]["tokens"]["input"],
        "provider_billed_cost": lambda row: row["provider"]["billed_cost"],
        "calculated_list_price": lambda row: row["provider"]["calculated_list_price"],
        "local_elapsed_ms": lambda row: row["local"]["elapsed_ms"],
        "local_calculated_cost": lambda row: row["local"]["calculated_cost"],
        "retrieval_count": lambda row: row["retrievals"]["count"],
        "correction_count": lambda row: row["corrections"]["count"],
    }
    return {
        name: {
            "observed": sum(getter(row)["availability"] == "observed" for row in rows),
            "unavailable": sum(getter(row)["availability"] == "unavailable" for row in rows),
        }
        for name, getter in paths.items()
    }


def _paired_project_contrasts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metrics = {
        "provider_tokens_input": lambda row: row["provider"]["tokens"]["input"],
        "provider_billed_cost": lambda row: row["provider"]["billed_cost"],
        "local_elapsed_ms": lambda row: row["local"]["elapsed_ms"],
        "retrieval_count": lambda row: row["retrievals"]["count"],
        "correction_count": lambda row: row["corrections"]["count"],
    }
    indexed = {
        (row["project_id"], row["task_stratum"], row["arm"]): row
        for row in rows
    }
    result: list[dict[str, Any]] = []
    for project_id in sorted({row["project_id"] for row in rows}):
        for arm in ARMS[1:]:
            for metric_name, getter in metrics.items():
                differences: list[Fraction] = []
                unavailable = 0
                for task_stratum in TASK_STRATA:
                    baseline = indexed.get((project_id, task_stratum, "baseline"))
                    treatment = indexed.get((project_id, task_stratum, arm))
                    if baseline is None or treatment is None:
                        unavailable += 1
                        continue
                    baseline_metric, treatment_metric = getter(baseline), getter(treatment)
                    if baseline_metric["availability"] != "observed" or treatment_metric["availability"] != "observed":
                        unavailable += 1
                        continue
                    if isinstance(baseline_metric["value"], str):
                        baseline_value = Fraction(Decimal(baseline_metric["value"]))
                        treatment_value = Fraction(Decimal(treatment_metric["value"]))
                    else:
                        baseline_value = Fraction(baseline_metric["value"])
                        treatment_value = Fraction(treatment_metric["value"])
                    differences.append(treatment_value - baseline_value)
                mean = sum(differences, Fraction()) / len(differences) if differences else None
                result.append({
                    "project_id": project_id,
                    "arm": arm,
                    "metric": metric_name,
                    "observed_pairs": len(differences),
                    "unavailable_pairs": unavailable,
                    "mean_arm_minus_baseline": None if mean is None else f"{mean.numerator}/{mean.denominator}",
                })
    return result


def public_report(rows: list[dict[str, Any]], protocol_id: str) -> dict[str, Any]:
    projects = sorted({row["project_id"] for row in rows})
    failures = sum(row["outcome"] != "completed" for row in rows)
    high_quality = sum(row["outcome"] == "completed" and row["quality"]["outcome"] == "passed" for row in rows)
    return {
        "schema_version": "contextguard.longitudinal-public-report/v1",
        "protocol_sha256": protocol_id,
        "provider_free": True,
        "scheduled_units": 125,
        "observed_units": len(rows),
        "completed_high_quality_units": high_quality,
        "failure_units": failures,
        "exclusion_reason_counts": {},
        "metric_availability": _availability_summary(rows),
        "receipt_identity": {"unique_receipts": len({row["receipt"]["receipt_id"] for row in rows}), "duplicate_receipts": 0},
        "descriptive_inference": {
            "cluster_unit": "project_id",
            "project_cluster_count": len(projects),
            "paired_contrast": "arm_minus_baseline_within_project_and_task_stratum",
            "paired_project_contrasts": _paired_project_contrasts(rows),
            "scope": "finite_closed_corpus_descriptive_only_no_confidence_interval_or_hypothesis_test",
        },
        "claims": {"provider_savings_allowed": False, "quality_guarantee": False, "generalization_allowed": False},
    }


def run_rehearsal(protocol: Path, output: Path, stop_after: int | None) -> int:
    validated = validate_protocol(protocol)
    units = validated["units"]
    rows = _load_existing(output, units, protocol)
    remaining = len(units) - len(rows)
    additional = remaining if stop_after is None else min(stop_after, remaining)
    if stop_after is not None and stop_after < 0:
        raise ValueError("stop-after must be nonnegative")
    new_rows = [rehearsal_observation(unit) for unit in units[len(rows):len(rows) + additional]]
    for row in new_rows:
        validate_observation(row, protocol)
    rows.extend(new_rows)
    private = output / "private"
    private.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(private, 0o700)
    observations = private / "observations.jsonl"
    temporary = observations.with_name("observations.jsonl.tmp")
    temporary.write_bytes(b"".join(canonical(row) for row in rows))
    os.chmod(temporary, 0o600)
    os.replace(temporary, observations)
    complete = len(rows) == len(units)
    state = {
        "schema_version": "contextguard.longitudinal-state/v1",
        "protocol_sha256": validated["protocol_sha256"],
        "completed_units": len(rows),
        "attempted_units": len(rows),
        "scheduled_units": len(units),
        "status": "complete" if complete else "interrupted",
        "provider_calls": 0,
        "spend_usd": "0.00",
    }
    atomic_json(output / "state.json", state)
    atomic_json(output / "public" / "report.json", public_report(rows, validated["protocol_sha256"]))
    return 0 if complete else 75


def validate_live_gate(protocol: Path, approval_file: Path | None, maximum: str | None) -> None:
    validated = validate_protocol(protocol)
    expected = validated["schedule"]["caps"]["maximum_live_budget_usd"]
    if approval_file is None or maximum is None:
        raise PermissionError("live execution requires a separate explicit budget approval and maximum")
    try:
        descriptor = os.open(approval_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 64 * 1024
            ):
                raise PermissionError("live approval must be an owner-private regular file")
            raw = os.read(descriptor, 64 * 1024 + 1)
            if len(raw) != metadata.st_size:
                raise PermissionError("live approval must be an owner-private regular file")
        finally:
            os.close(descriptor)
    except OSError:
        raise PermissionError("live approval must be an owner-private regular file") from None
    try:
        approval = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=lambda pairs: _closed_pairs(pairs, "live approval"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise PermissionError("live approval must be an owner-private regular file") from None
    exact = {
        "schema_version": "contextguard.longitudinal-budget-approval/v1",
        "protocol_sha256": validated["protocol_sha256"],
        "maximum_budget_usd": expected,
        "provider_calls_approved": True,
    }
    if maximum != expected or approval != exact:
        raise PermissionError("explicit budget approval does not exactly bind protocol and maximum")
    raise PermissionError("budget gate valid, but no live provider adapter is installed; zero provider calls made")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("validate", "rehearse", "resume", "live"):
        child = subparsers.add_parser(action)
        child.add_argument("--protocol", type=Path, required=True)
        if action != "validate":
            child.add_argument("--output", type=Path, required=True)
        if action == "rehearse":
            child.add_argument("--stop-after", type=int)
        if action == "live":
            child.add_argument("--approval-file", type=Path)
            child.add_argument("--max-budget-usd")
    args = parser.parse_args(argv)
    try:
        if args.action == "validate":
            print(json.dumps({"valid": True, **validate_protocol(args.protocol)}, default=lambda value: "<closed schedule>" if isinstance(value, list) else value, sort_keys=True))
            return 0
        if args.action in {"rehearse", "resume"}:
            return run_rehearsal(args.protocol, args.output, getattr(args, "stop_after", None))
        validate_live_gate(args.protocol, args.approval_file, args.max_budget_usd)
    except PermissionError as exc:
        print(str(exc), file=sys.stderr)
        return 77
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
