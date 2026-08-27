#!/usr/bin/env python3
"""Captured-byte semantic verifier for the G5 preregistration-only contract."""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from fractions import Fraction
from itertools import product
from typing import Mapping


ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
TASKS = (
    ("train_closed", "train", "closed_pack"),
    ("train_graph", "train", "realistic_fallback"),
    ("calibration_closed", "calibration", "closed_pack"),
    ("calibration_graph", "calibration", "realistic_fallback"),
    ("evaluation_closed", "evaluation", "closed_pack"),
    ("evaluation_graph", "evaluation", "realistic_fallback"),
)
G4_LOCK_SHA256 = "1cb0be185e5fc8942fbda8ba73aaedf532eaa42b8a679823aab95e61c80fd7ec"
G4_TREE_SHA256 = "6a97fb1c574232c78f4acc2aef84ddf9bc66e40d2ba287373bb5c00345d3a46c"
G4_VERIFIER_SHA256 = "b20ffcf8ac10e7cf0300c90ca91e63238e1f69bc1ed8ee1acbf6b0fc6bdd82e7"
G4_POLICY_SHA256 = "2d0b990a34eebb882039f4443f3527c9955875d8f1696f082af4660ecaeafef0"
G4_SCHEMA_SET = {"bytes": 6533, "sha256": "b3eb2111ec7e61c55fa7deb5230c6ade238acf3cf6a61956d9e607a806269075"}
SCHEDULE_SHA256 = "326fc47df7871e39b2f9af2d888b8385ab91fe4347c6467f08dd4a6e386e7965"
OBSERVATION_SCHEMA_SHA256 = "a1934fd8a22513d070e040a3afcd24a37f7dd073ded8fba4ea0fe33820321a91"
SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs", "$ref", "$schema", "additionalProperties", "const", "enum",
    "items", "maxItems", "maximum", "minItems", "minLength", "minimum",
    "pattern", "properties", "required", "type", "uniqueItems",
}
FORBIDDEN_PRIVATE_KEYS = {
    "adaptive_labels", "answer_signature", "authorization", "credential_value",
    "environment", "graph_evidence", "headers", "hidden_oracle", "oracle",
    "prompt", "required_paths", "required_symbols", "response_body", "scorer_private",
    "secret", "token_value", "url",
}
FORBIDDEN_PREREG_KEYS = {
    "approval", "evidence", "observation", "observations", "outcome", "results",
    "run_receipt", "sample_mean", "test_result",
}
EXCLUSION_REASONS = (
    "unscheduled_unit", "duplicate_request_id", "duplicate_receipt_id",
    "assignment_identity_mismatch", "payload_identity_mismatch",
    "task_arm_stratum_partition_or_repetition_mismatch", "observer_version_mismatch",
    "model_identity_mismatch", "provider_receipt_not_authoritative", "transport_error",
    "timeout", "cancellation", "missing_required_field", "malformed_required_field",
    "nonmonotonic_timestamp", "incomplete_four_arm_block",
)
DESCRIPTIVE_METRIC_DEFINITIONS = {
    "authoritative_total_cost_minor": "sum_provider_input_provider_output_provider_correction_amount_minor_when_all_observed_from_one_receipt_and_one_currency_else_unavailable",
    "correctness": "correct_equals_1_incorrect_equals_0_unavailable_is_null",
    "input_usage": "input_usage.value_when_observed_else_null",
    "pack_latency_ns": "pack_end_monotonic_ns_minus_pack_start_monotonic_ns_for_eligible_completed_unit",
    "retrieval_count": "retrieval_count.value_when_observed_else_null",
    "total_usage": "input_usage.value_plus_output_usage.value_plus_correction_tokens.value_when_all_observed_else_null",
}


class VerificationError(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse(raw: bytes, label: str, *, require_canonical: bool = False) -> dict:
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=duplicate_keys)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"object required: {label}")
    if require_canonical and raw != canonical(value):
        raise VerificationError(f"noncanonical {label}")
    return value


def map_identity(files: Mapping[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256(b"contextguard.g4-captured-map/v1\x00")
    total = 0
    for name, raw in sorted(files.items()):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        total += len(raw)
    return {"bytes": total, "sha256": digest.hexdigest()}


def recursive_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        found.update(value)
        for item in value.values():
            found.update(recursive_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(recursive_keys(item))
    return found


def reject_private(value: object, label: str) -> None:
    forbidden = recursive_keys(value) & FORBIDDEN_PRIVATE_KEYS
    if forbidden:
        raise VerificationError(f"private key in {label}: {sorted(forbidden)[0]}")


def json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unsupported"


def resolve_ref(root: dict, reference: str) -> dict:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise VerificationError("unsupported schema reference")
    value: object = root
    for part in reference[2:].split("/"):
        if not isinstance(value, dict) or part not in value:
            raise VerificationError("invalid schema reference")
        value = value[part]
    if not isinstance(value, dict):
        raise VerificationError("schema reference target must be an object")
    return value


def audit_schema(schema: object, location: str = "schema") -> None:
    if not isinstance(schema, dict):
        raise VerificationError(f"schema node must be an object: {location}")
    unsupported = set(schema) - SUPPORTED_SCHEMA_KEYWORDS
    if unsupported:
        raise VerificationError(f"unsupported schema keyword: {sorted(unsupported)[0]}")
    if schema.get("type") == "object":
        if schema.get("additionalProperties") is not False:
            raise VerificationError(f"schema object is not closed: {location}")
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict) or not isinstance(required, list)
            or len(required) != len(set(required)) or set(required) != set(properties)
        ):
            raise VerificationError(f"schema object fields are not exactly required: {location}")
    for key in ("$defs", "properties"):
        children = schema.get(key, {})
        if isinstance(children, dict):
            for name, child in children.items():
                audit_schema(child, f"{location}.{key}.{name}")
    items = schema.get("items")
    if isinstance(items, dict):
        audit_schema(items, f"{location}.items")


def validate_schema(value: object, schema: dict, root: dict, location: str) -> None:
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            raise VerificationError(f"schema reference has siblings: {location}")
        validate_schema(value, resolve_ref(root, schema["$ref"]), root, location)
        return
    expected = schema.get("type")
    if expected is not None:
        allowed = [expected] if isinstance(expected, str) else expected
        if not isinstance(allowed, list) or json_type(value) not in allowed:
            raise VerificationError(f"schema type mismatch: {location}")
    if "const" in schema and value != schema["const"]:
        raise VerificationError(f"schema const mismatch: {location}")
    if "enum" in schema and value not in schema["enum"]:
        raise VerificationError(f"schema enum mismatch: {location}")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        unknown = sorted(set(value) - set(properties)) if schema.get("additionalProperties") is False else []
        if missing or unknown:
            raise VerificationError(f"schema object mismatch: {location}")
        for name, item in value.items():
            if name in properties:
                validate_schema(item, properties[name], root, f"{location}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or (
            "maxItems" in schema and len(value) > schema["maxItems"]
        ):
            raise VerificationError(f"schema array length mismatch: {location}")
        encoded = [canonical(item) for item in value]
        if schema.get("uniqueItems") is True and len(encoded) != len(set(encoded)):
            raise VerificationError(f"schema array duplicate: {location}")
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], root, f"{location}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise VerificationError(f"schema string too short: {location}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise VerificationError(f"schema pattern mismatch: {location}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise VerificationError(f"schema minimum mismatch: {location}")
        if "maximum" in schema and value > schema["maximum"]:
            raise VerificationError(f"schema maximum mismatch: {location}")


def fnv1a64(raw: bytes) -> int:
    value = 14695981039346656037
    for byte in raw:
        value ^= byte
        value = (value * 1099511628211) & ((1 << 64) - 1)
    return value


def expected_arm_order(seed: str, block_id: str) -> list[str]:
    return sorted(
        ARMS,
        key=lambda arm: (
            fnv1a64((seed + "\x00" + block_id + "\x00" + arm).encode("utf-8")), arm
        ),
    )


def validate_schedule(schedule: dict) -> None:
    blocks = schedule["blocks"]
    if len(blocks) != 60 or schedule["block_count"] != 60 or schedule["unit_count"] != 240:
        raise VerificationError("fixed schedule cardinality mismatch")
    seen_blocks: set[str] = set()
    seen_units: set[str] = set()
    primary_counts = {(stratum, arm): 0 for stratum in ("closed_pack", "realistic_fallback") for arm in ARMS}
    task_map = {task: (partition, stratum) for task, partition, stratum in TASKS}
    seed = schedule["seed"]
    for index, block in enumerate(blocks, 1):
        expected_id = f"primary-{index:03d}"
        if block["block_id"] != expected_id or block["kind"] != "primary":
            raise VerificationError("fixed schedule block order mismatch")
        expected_task = TASKS[(index - 1) % 6]
        task_id, partition, stratum = expected_task
        expected_repetition = (index - 1) // 6 + 1
        if (
            (block["task_id"], block["lineage_id"], block["partition"], block["stratum"])
            != (task_id, task_id, partition, stratum)
            or block["repetition"] != expected_repetition
            or block["replacement_index"] != 0
            or task_map[block["task_id"]] != (block["partition"], block["stratum"])
        ):
            raise VerificationError("fixed schedule task lineage mapping mismatch")
        if block["block_id"] in seen_blocks:
            raise VerificationError("duplicate fixed schedule block")
        seen_blocks.add(block["block_id"])
        order = expected_arm_order(seed, block["block_id"])
        if [unit["arm"] for unit in block["units"]] != order:
            raise VerificationError("fixed schedule deterministic assignment mismatch")
        for ordinal, unit in enumerate(block["units"], 1):
            if unit != {
                "arm": order[ordinal - 1], "assigned_order": ordinal,
                "assignment_id": f"assignment-{block['block_id']}-{order[ordinal - 1]}",
                "scheduled_unit_id": f"unit-{block['block_id']}-{ordinal:02d}",
            }:
                raise VerificationError("fixed schedule unit identity mismatch")
            if unit["scheduled_unit_id"] in seen_units:
                raise VerificationError("duplicate fixed schedule unit")
            seen_units.add(unit["scheduled_unit_id"])
            primary_counts[(stratum, unit["arm"])] += 1
    if set(primary_counts.values()) != {30} or len(seen_units) != 240:
        raise VerificationError("fixed schedule stratum/arm balance mismatch")


def validate_observation_schema_contract(schema: dict) -> None:
    serialized = canonical(schema).lower()
    for forbidden in (b'"prompt"', b'"response_body"', b'"headers"', b'"url"', b'"credential"', b'"environment"'):
        if forbidden in serialized:
            raise VerificationError("observer schema contains a prohibited raw surface")
    required = set(schema.get("required", []))
    expected = {
        "scheduled_unit_id", "block_id", "task_id", "lineage_id", "partition",
        "stratum", "arm", "assigned_order", "repetition", "assignment_id",
        "payload_sha256", "model_identity", "observer_version", "request_id",
        "receipt_id", "unit_status", "completion_event", "event_count",
        "pack_start_monotonic_ns", "pack_end_monotonic_ns", "correctness",
        "input_usage", "output_usage", "correction_count", "correction_tokens",
        "retrieval_count", "retrieval_bytes", "retrieval_tokens", "billing_receipt",
        "cost_components", "exclusion_reason", "audit_status", "schema_version",
    }
    if required != expected:
        raise VerificationError("observer schema minimized field contract mismatch")


def validate_observation(value: dict, schema_bytes: bytes, scheduled_unit: dict) -> None:
    schema = parse(schema_bytes, "authoritative observation schema")
    audit_schema(schema, "authoritative observation schema")
    reject_private(value, "authoritative observation")
    validate_schema(value, schema, schema, "authoritative observation")
    expected_projection = {
        key: scheduled_unit[key]
        for key in (
            "scheduled_unit_id", "block_id", "task_id", "lineage_id", "partition",
            "stratum", "arm", "assigned_order", "repetition", "assignment_id",
        )
    }
    if any(value[key] != expected for key, expected in expected_projection.items()):
        raise VerificationError("observation differs from frozen schedule assignment")
    if value["pack_end_monotonic_ns"] < value["pack_start_monotonic_ns"]:
        raise VerificationError("nonmonotonic pack boundary")
    completed = value["unit_status"] == "completed"
    normal = value["completion_event"] == "normal_completion"
    eligible = value["audit_status"] == "eligible"
    no_exclusion = value["exclusion_reason"] == "none"
    if not (completed == normal == eligible == no_exclusion):
        raise VerificationError("unit completion/normal/eligible/exclusion state mismatch")
    if not completed and value["completion_event"] != value["exclusion_reason"]:
        raise VerificationError("excluded unit event/reason mismatch")
    metric_names = (
        "input_usage", "output_usage", "correction_count", "correction_tokens",
        "retrieval_count", "retrieval_bytes", "retrieval_tokens",
    )
    for name in metric_names:
        metric = value[name]
        observed = metric["availability"] == "observed"
        if observed:
            if (
                not completed or isinstance(metric["value"], bool)
                or not isinstance(metric["value"], int)
                or metric["unavailable_reason"] != "not_applicable"
            ):
                raise VerificationError(f"metric observed state mismatch: {name}")
        else:
            allowed_reason = (
                {"not_in_authoritative_receipt", "receipt_unavailable", "not_observed"}
                if completed else {"excluded_unit"}
            )
            if metric["value"] is not None or metric["unavailable_reason"] not in allowed_reason:
                raise VerificationError(f"metric unavailable state/reason mismatch: {name}")
    correctness = value["correctness"]
    correctness_observed = correctness["availability"] == "observed"
    if correctness_observed:
        if (
            not completed or correctness["outcome"] not in {"correct", "incorrect"}
            or correctness["unavailable_reason"] != "not_applicable"
        ):
            raise VerificationError("correctness observed state/reason mismatch")
    elif correctness != {
        "availability": "unavailable", "outcome": "unavailable",
        "unavailable_reason": "not_observed" if completed else "excluded_unit",
    }:
        raise VerificationError("correctness unavailable state/reason mismatch")
    components = value["cost_components"]
    if {item["component"] for item in components} != {
        "provider_input", "provider_output", "provider_correction"
    }:
        raise VerificationError("authoritative cost component identity mismatch")
    receipt = value["billing_receipt"]
    receipt_observed = receipt == {
        "authority": "authoritative_provider_receipt",
        "reference": receipt["reference"], "status": "observed",
    } and isinstance(receipt["reference"], str)
    receipt_unavailable = receipt == {
        "authority": "unavailable", "reference": None, "status": "unavailable",
    }
    if not (receipt_observed or receipt_unavailable):
        raise VerificationError("billing receipt authority/status/reference state mismatch")
    if not completed and not receipt_unavailable:
        raise VerificationError("excluded unit billing receipt must be unavailable")
    observed_currencies: set[str] = set()
    for component in components:
        observed = component["availability"] == "observed"
        if observed:
            if (
                not completed or not receipt_observed
                or isinstance(component["amount_minor"], bool)
                or not isinstance(component["amount_minor"], int)
                or not isinstance(component["currency"], str)
                or component["receipt_reference"] != receipt["reference"]
                or component["unavailable_reason"] != "not_applicable"
            ):
                raise VerificationError("cost must originate in authoritative billing receipt")
            observed_currencies.add(component["currency"])
        else:
            expected_reason = (
                "excluded_unit" if not completed else
                "not_in_authoritative_receipt" if receipt_observed else
                "receipt_unavailable"
            )
            if (
                any(component[key] is not None for key in ("amount_minor", "currency", "receipt_reference"))
                or component["unavailable_reason"] != expected_reason
            ):
                raise VerificationError("unavailable cost null/reason state mismatch")
    if len(observed_currencies) > 1:
        raise VerificationError("authoritative receipt components use mixed currency")
    if not completed:
        if (
            any(value[name] != {"availability": "unavailable", "unavailable_reason": "excluded_unit", "value": None} for name in metric_names)
            or correctness != {"availability": "unavailable", "outcome": "unavailable", "unavailable_reason": "excluded_unit"}
            or not receipt_unavailable
            or any(
                component["availability"] != "unavailable"
                or component["unavailable_reason"] != "excluded_unit"
                or any(component[key] is not None for key in ("amount_minor", "currency", "receipt_reference"))
                for component in components
            )
        ):
            raise VerificationError("excluded unit metrics must be unavailable and null")


def validate_paired_currency(left: dict, right: dict) -> str | None:
    def currency(value: dict) -> str | None:
        observed = {
            component["currency"] for component in value["cost_components"]
            if component["availability"] == "observed"
        }
        if len(observed) > 1:
            raise VerificationError("mixed currency within authoritative receipt")
        return next(iter(observed), None)
    left_currency = currency(left)
    right_currency = currency(right)
    if left_currency is None or right_currency is None:
        return None
    if left_currency != right_currency:
        raise VerificationError("paired cost summary requires same currency")
    return left_currency


def derive_descriptive_metric(value: dict, metric_name: str) -> dict[str, object]:
    """Derive one frozen G5 metric from one already validated observation."""
    if metric_name not in DESCRIPTIVE_METRIC_DEFINITIONS:
        raise VerificationError("unknown descriptive metric")
    unavailable = {"currency": None, "value": None}
    if not (
        value.get("unit_status") == "completed"
        and value.get("completion_event") == "normal_completion"
        and value.get("audit_status") == "eligible"
        and value.get("exclusion_reason") == "none"
    ):
        return unavailable
    if metric_name in {"input_usage", "retrieval_count"}:
        source = value[metric_name]
        return {
            "currency": None,
            "value": source["value"] if source["availability"] == "observed" else None,
        }
    if metric_name == "total_usage":
        sources = [value[name] for name in ("input_usage", "output_usage", "correction_tokens")]
        return {
            "currency": None,
            "value": sum(source["value"] for source in sources)
            if all(source["availability"] == "observed" for source in sources)
            else None,
        }
    if metric_name == "pack_latency_ns":
        return {
            "currency": None,
            "value": value["pack_end_monotonic_ns"] - value["pack_start_monotonic_ns"],
        }
    if metric_name == "correctness":
        correctness = value["correctness"]
        encoded = {"correct": 1, "incorrect": 0}
        return {
            "currency": None,
            "value": encoded.get(correctness["outcome"])
            if correctness["availability"] == "observed" else None,
        }
    receipt = value["billing_receipt"]
    components = value["cost_components"]
    observed = (
        receipt.get("authority") == "authoritative_provider_receipt"
        and receipt.get("status") == "observed"
        and isinstance(receipt.get("reference"), str)
        and {component["component"] for component in components}
        == {"provider_input", "provider_output", "provider_correction"}
        and all(
            component["availability"] == "observed"
            and component["receipt_reference"] == receipt["reference"]
            for component in components
        )
    )
    currencies = {component["currency"] for component in components} if observed else set()
    if not observed or len(currencies) != 1:
        return unavailable
    return {
        "currency": next(iter(currencies)),
        "value": sum(component["amount_minor"] for component in components),
    }


def _rational(value: Fraction) -> dict[str, int]:
    return {"denominator": value.denominator, "numerator": value.numerator}


def _validate_descriptive_pairs(
    pairs: list[dict], metric_name: str,
) -> dict[str, list[dict]]:
    if metric_name not in DESCRIPTIVE_METRIC_DEFINITIONS:
        raise VerificationError("unknown descriptive metric")
    expected_keys = {
        "combined", "currency", "lineage_id", "ordinary", "repetition", "stratum",
    }
    if not pairs or any(set(pair) != expected_keys for pair in pairs):
        raise VerificationError("descriptive pair fields are not closed")
    grouped: dict[str, list[dict]] = {}
    seen: set[tuple[str, int]] = set()
    strata: set[str] = set()
    for pair in pairs:
        lineage_id = pair["lineage_id"]
        repetition = pair["repetition"]
        stratum = pair["stratum"]
        if (
            not isinstance(lineage_id, str) or not lineage_id
            or isinstance(repetition, bool) or not isinstance(repetition, int) or repetition < 1
            or (lineage_id, repetition) in seen
        ):
            raise VerificationError("descriptive pair identity mismatch")
        seen.add((lineage_id, repetition))
        if stratum not in {"closed_pack", "realistic_fallback"}:
            raise VerificationError("descriptive pair stratum mismatch")
        strata.add(stratum)
        for name in ("ordinary", "combined"):
            item = pair[name]
            if item is not None and (isinstance(item, bool) or not isinstance(item, int)):
                raise VerificationError("descriptive pair value must be integer or null")
            if item is not None and metric_name == "correctness" and item not in {0, 1}:
                raise VerificationError("correctness pair value is outside the zero-or-one domain")
            if item is not None and metric_name != "correctness" and item < 0:
                raise VerificationError("descriptive pair value must be nonnegative")
        if metric_name == "authoritative_total_cost_minor":
            pair_available = pair["ordinary"] is not None and pair["combined"] is not None
            currency_valid = (
                isinstance(pair["currency"], str)
                and re.fullmatch(r"[A-Z]{3}", pair["currency"]) is not None
            )
            if pair_available != currency_valid:
                raise VerificationError("descriptive cost pair currency mismatch")
        elif pair["currency"] is not None:
            raise VerificationError("non-cost descriptive pair cannot have currency")
        grouped.setdefault(lineage_id, []).append(pair)
    if len(strata) != 1:
        raise VerificationError("descriptive pairs must contain exactly one stratum")
    stratum = next(iter(strata))
    expected_lineages = {task for task, _, task_stratum in TASKS if task_stratum == stratum}
    if set(grouped) != expected_lineages or any(
        {pair["repetition"] for pair in lineage_pairs} != set(range(1, 11))
        for lineage_pairs in grouped.values()
    ):
        raise VerificationError("descriptive pairs must cover ten repetitions of three task lineages")
    observed_currencies = {
        pair["currency"] for pair in pairs
        if pair["ordinary"] is not None and pair["combined"] is not None
    }
    if metric_name == "authoritative_total_cost_minor" and len(observed_currencies) > 1:
        raise VerificationError("descriptive cost pairs use mixed currency")
    return grouped


def summarize_descriptive_pairs(pairs: list[dict], metric_name: str) -> dict[str, object]:
    """Refuse caller-authored pair rows; public results require observation authentication."""
    _validate_descriptive_pairs(pairs, metric_name)
    raise VerificationError("descriptive pair rows are unauthenticated; supply frozen observations")


def summarize_authenticated_observations(
    observations: list[dict], *, schedule_bytes: bytes, schema_bytes: bytes,
) -> dict[str, object]:
    """Validate the frozen 240-unit batch before deriving any descriptive result."""
    if sha256(schedule_bytes) != SCHEDULE_SHA256:
        raise VerificationError("descriptive batch schedule binding drift")
    if sha256(schema_bytes) != OBSERVATION_SCHEMA_SHA256:
        raise VerificationError("descriptive batch observation schema binding drift")
    schedule = parse(schedule_bytes, "descriptive batch schedule", require_canonical=True)
    validate_schedule(schedule)
    if not isinstance(observations, list) or len(observations) != 240:
        raise VerificationError("descriptive batch requires exactly 240 terminal observations")

    scheduled_by_unit: dict[str, dict] = {}
    block_units: dict[str, list[str]] = {}
    for block in schedule["blocks"]:
        for unit in block["units"]:
            projection = {
                **{key: block[key] for key in (
                    "block_id", "task_id", "lineage_id", "partition", "stratum",
                    "repetition",
                )},
                **unit,
            }
            scheduled_by_unit[unit["scheduled_unit_id"]] = projection
            block_units.setdefault(block["block_id"], []).append(unit["scheduled_unit_id"])

    observed_by_unit: dict[str, dict] = {}
    request_ids: set[str] = set()
    receipt_ids: set[str] = set()
    for value in observations:
        if not isinstance(value, dict):
            raise VerificationError("descriptive batch observation must be an object")
        unit_id = value.get("scheduled_unit_id")
        if unit_id not in scheduled_by_unit:
            raise VerificationError("unscheduled observation identity")
        if unit_id in observed_by_unit:
            raise VerificationError("duplicate scheduled-unit observation")
        if value.get("request_id") in request_ids:
            raise VerificationError("duplicate request identity")
        if value.get("receipt_id") in receipt_ids:
            raise VerificationError("duplicate receipt identity")
        validate_observation(value, schema_bytes, scheduled_by_unit[unit_id])
        observed_by_unit[unit_id] = value
        request_ids.add(value["request_id"])
        receipt_ids.add(value["receipt_id"])
    if set(observed_by_unit) != set(scheduled_by_unit):
        raise VerificationError("descriptive batch is missing a scheduled observation")

    eligible_blocks: dict[str, bool] = {}
    for block_id, unit_ids in block_units.items():
        block_values = [observed_by_unit[unit_id] for unit_id in unit_ids]
        if {value["arm"] for value in block_values} != set(ARMS):
            raise VerificationError("descriptive batch four-arm block identity mismatch")
        eligible_blocks[block_id] = all(
            value["unit_status"] == "completed" for value in block_values
        )

    analyzed_blocks = sum(eligible_blocks.values())
    terminal_reason_counts = {reason: 0 for reason in EXCLUSION_REASONS}
    block_reason_sets: dict[str, list[str]] = {}
    for block_id, unit_ids in block_units.items():
        reasons = sorted({
            observed_by_unit[unit_id]["exclusion_reason"]
            for unit_id in unit_ids
            if observed_by_unit[unit_id]["unit_status"] == "excluded"
        })
        for unit_id in unit_ids:
            value = observed_by_unit[unit_id]
            if value["unit_status"] == "excluded":
                terminal_reason_counts[value["exclusion_reason"]] += 1
        if reasons:
            block_reason_sets[block_id] = reasons
    accounting = {
        "analyzed_blocks": analyzed_blocks,
        "analyzed_units": analyzed_blocks * 4,
        "excluded_blocks": 60 - analyzed_blocks,
        "excluded_units": (60 - analyzed_blocks) * 4,
        "randomized_blocks": 60,
        "randomized_units": 240,
    }
    accounting["randomized_blocks_equals_analyzed_blocks_plus_excluded_blocks"] = (
        accounting["randomized_blocks"]
        == accounting["analyzed_blocks"] + accounting["excluded_blocks"]
    )
    accounting["randomized_units_equals_analyzed_units_plus_excluded_units"] = (
        accounting["randomized_units"]
        == accounting["analyzed_units"] + accounting["excluded_units"]
    )
    if not all(
        accounting[name] for name in (
            "randomized_blocks_equals_analyzed_blocks_plus_excluded_blocks",
            "randomized_units_equals_analyzed_units_plus_excluded_units",
        )
    ):
        raise VerificationError("descriptive batch accounting conservation mismatch")
    result: dict[str, object] = {
        "accounting": accounting,
        "block_exclusion_counts": {
            "block_policy_analytic_exclusion": 60 - analyzed_blocks,
            "terminal_excluded_unit": sum(terminal_reason_counts.values()),
        },
        "block_exclusion_reason_sets": block_reason_sets,
        "metrics": {},
        "terminal_exclusion_reason_counts": terminal_reason_counts,
    }

    def reduce_validated_pairs(pairs: list[dict], metric_name: str) -> dict[str, object]:
        grouped = _validate_descriptive_pairs(pairs, metric_name)
        observed_currencies = {
            pair["currency"] for pair in pairs
            if pair["ordinary"] is not None and pair["combined"] is not None
        }
        summary_currency = next(iter(observed_currencies), None)
        lineages = []
        lineage_means: list[Fraction] = []
        for lineage_id in sorted(grouped):
            lineage_pairs = grouped[lineage_id]
            differences = [
                Fraction(pair["combined"] - pair["ordinary"], 1)
                for pair in lineage_pairs
                if pair["ordinary"] is not None and pair["combined"] is not None
            ]
            mean = (
                sum(differences, Fraction(0, 1)) / len(differences)
                if differences else None
            )
            if mean is not None:
                lineage_means.append(mean)
            lineages.append({
                "currency": summary_currency,
                "difference_mean": _rational(mean) if mean is not None else None,
                "lineage_id": lineage_id,
                "observed_pair_count": len(differences),
                "unavailable_pair_count": len(lineage_pairs) - len(differences),
            })
        if len(lineage_means) != 3:
            sensitivity = {
                "assignment_count": 0, "currency": summary_currency,
                "endpoints": None, "ties": "retained",
            }
        else:
            signed_means = sorted(
                sum(
                    (sign * mean for sign, mean in zip(signs, lineage_means)),
                    Fraction(0, 1),
                ) / 3
                for signs in product((-1, 1), repeat=3)
            )
            sensitivity = {
                "assignment_count": 8,
                "currency": summary_currency,
                "endpoints": {
                    "lower_median_rank_4": _rational(signed_means[3]),
                    "maximum_rank_8": _rational(signed_means[7]),
                    "minimum_rank_1": _rational(signed_means[0]),
                    "upper_median_rank_5": _rational(signed_means[4]),
                },
                "ties": "retained",
            }
        return {"lineages": lineages, "signed_cluster_sensitivity": sensitivity}

    metrics: dict[str, object] = result["metrics"]  # type: ignore[assignment]
    for metric_name in DESCRIPTIVE_METRIC_DEFINITIONS:
        metric_strata: dict[str, object] = {}
        for stratum in ("closed_pack", "realistic_fallback"):
            pairs = []
            arm_availability = {
                arm: {"denominator": 30, "observed": 0, "unavailable": 0}
                for arm in ARMS
            }
            for block in schedule["blocks"]:
                if block["stratum"] != stratum:
                    continue
                values = {
                    observed_by_unit[unit_id]["arm"]: observed_by_unit[unit_id]
                    for unit_id in block_units[block["block_id"]]
                }
                ordinary = combined = {"currency": None, "value": None}
                arm_metrics = {
                    arm: {"currency": None, "value": None} for arm in ARMS
                }
                if eligible_blocks[block["block_id"]]:
                    arm_metrics = {
                        arm: derive_descriptive_metric(values[arm], metric_name)
                        for arm in ARMS
                    }
                for arm, derived in arm_metrics.items():
                    state = "observed" if derived["value"] is not None else "unavailable"
                    arm_availability[arm][state] += 1
                ordinary = arm_metrics["ordinary"]
                combined = arm_metrics["combined"]
                ordinary_value = ordinary["value"]
                combined_value = combined["value"]
                pair_currency = None
                if metric_name == "authoritative_total_cost_minor" and (
                    ordinary_value is not None and combined_value is not None
                ):
                    if ordinary["currency"] != combined["currency"]:
                        raise VerificationError("paired cost summary requires same currency")
                    pair_currency = ordinary["currency"]
                pairs.append({
                    "combined": combined_value,
                    "currency": pair_currency,
                    "lineage_id": block["lineage_id"],
                    "ordinary": ordinary_value,
                    "repetition": block["repetition"],
                    "stratum": block["stratum"],
                })
            observed_pair_count = sum(
                pair["ordinary"] is not None and pair["combined"] is not None
                for pair in pairs
            )
            summary = reduce_validated_pairs(pairs, metric_name)
            summary["availability"] = {
                "denominator": 30,
                "observed_pair_count": observed_pair_count,
                "unavailable_pair_count": 30 - observed_pair_count,
            }
            if any(
                availability["denominator"]
                != availability["observed"] + availability["unavailable"]
                for availability in arm_availability.values()
            ) or summary["availability"]["denominator"] != (
                summary["availability"]["observed_pair_count"]
                + summary["availability"]["unavailable_pair_count"]
            ):
                raise VerificationError("metric availability conservation mismatch")
            metric_strata[stratum] = {"arms": arm_availability, "contrast": summary}
        metrics[metric_name] = metric_strata
    return result


_ACTIVE_PROBE: dict[str, int] | None = None
_AUDIT_INSTALLED = False


def _audit(event: str, args: tuple[object, ...]) -> None:
    if _ACTIVE_PROBE is None:
        return
    if event == "socket.getaddrinfo":
        _ACTIVE_PROBE["dns_denials"] += 1
        raise PermissionError("G5 denied DNS")
    if event.startswith("socket."):
        _ACTIVE_PROBE["network_denials"] += 1
        raise PermissionError("G5 denied network")
    if event == "subprocess.Popen":
        _ACTIVE_PROBE["process_denials"] += 1
        raise PermissionError("G5 denied process")
    if event == "open" and len(args) > 1 and any(flag in str(args[1]) for flag in ("w", "a", "x", "+")):
        _ACTIVE_PROBE["write_denials"] += 1
        raise PermissionError("G5 denied write")


def audited_negative_probes() -> dict[str, int]:
    global _ACTIVE_PROBE, _AUDIT_INSTALLED
    if not _AUDIT_INSTALLED:
        sys.addaudithook(_audit)
        _AUDIT_INSTALLED = True
    counters = {"dns_denials": 0, "network_denials": 0, "process_denials": 0, "write_denials": 0}
    _ACTIVE_PROBE = counters
    operations = (
        lambda: socket.socket(),
        lambda: socket.getaddrinfo("203.0.113.1", 443, flags=socket.AI_NUMERICHOST),
        lambda: subprocess.run(["/g5-process-decoy"], check=False),
        lambda: open("/g5-write-decoy", "wb"),
    )
    try:
        for operation in operations:
            try:
                operation()
            except (PermissionError, OSError):
                continue
            raise VerificationError("G5 negative probe was not denied")
    finally:
        _ACTIVE_PROBE = None
    if set(counters.values()) != {1}:
        raise VerificationError("G5 negative probe counters drift")
    return counters


def validate_upstream(
    prereg: dict, *, g4_lock_bytes: bytes, g4_verifier_bytes: bytes,
    g4_policy_bytes: bytes, g4_schema_bytes: Mapping[str, bytes],
) -> None:
    if (
        sha256(g4_lock_bytes) != G4_LOCK_SHA256
        or sha256(g4_verifier_bytes) != G4_VERIFIER_SHA256
        or sha256(g4_policy_bytes) != G4_POLICY_SHA256
        or map_identity(g4_schema_bytes) != G4_SCHEMA_SET
    ):
        raise VerificationError("authenticated G4 input binding drift")
    lock = parse(g4_lock_bytes, "captured G4 freeze lock")
    if lock.get("tree_root_sha256") != G4_TREE_SHA256:
        raise VerificationError("authenticated G4 tree binding drift")
    if prereg["upstream_contract"] != {
        "g4_claim_policy_sha256": G4_POLICY_SHA256,
        "g4_freeze_lock_path": "research/provider-free-roadmap/g4/freeze-lock.json",
        "g4_freeze_lock_sha256": G4_LOCK_SHA256,
        "g4_schema_set_bytes": G4_SCHEMA_SET["bytes"],
        "g4_schema_set_sha256": G4_SCHEMA_SET["sha256"],
        "g4_tree_sha256": G4_TREE_SHA256,
        "g4_verifier_sha256": G4_VERIFIER_SHA256,
    }:
        raise VerificationError("preregistration G4 contract binding drift")


def validate_captured(
    *, prereg_bytes: bytes, schedule_bytes: bytes, schema_bytes: Mapping[str, bytes],
    g4_lock_bytes: bytes, g4_verifier_bytes: bytes, g4_policy_bytes: bytes,
    g4_schema_bytes: Mapping[str, bytes],
) -> dict[str, object]:
    if set(schema_bytes) != {
        "authoritative-observation.schema.json", "preregistration.schema.json",
        "schedule.schema.json",
    }:
        raise VerificationError("G5 schema set mismatch")
    prereg = parse(prereg_bytes, "captured preregistration", require_canonical=True)
    schedule = parse(schedule_bytes, "captured schedule", require_canonical=True)
    reject_private(prereg, "preregistration")
    reject_private(schedule, "schedule")
    forbidden = recursive_keys(prereg) & FORBIDDEN_PREREG_KEYS
    if forbidden:
        raise VerificationError(f"outcome or result field in preregistration: {sorted(forbidden)[0]}")
    parsed_schemas = {name: parse(raw, name) for name, raw in schema_bytes.items()}
    for name, schema in parsed_schemas.items():
        audit_schema(schema, name)
    validate_schema(prereg, parsed_schemas["preregistration.schema.json"], parsed_schemas["preregistration.schema.json"], "preregistration")
    validate_schema(schedule, parsed_schemas["schedule.schema.json"], parsed_schemas["schedule.schema.json"], "schedule")
    validate_observation_schema_contract(parsed_schemas["authoritative-observation.schema.json"])
    validate_schedule(schedule)
    if prereg["design"]["randomization"]["schedule_sha256"] != sha256(schedule_bytes):
        raise VerificationError("preregistered schedule hash drift")
    if not (
        prereg["status"] == "preregistered_contract_only"
        and prereg["observation_status"] == "no_observations"
        and prereg["execution_authorized"] is False
        and prereg["sample_size_rationale"] == "capacity_fixed_not_effect_estimate"
        and prereg["sample_size_derived_from_g3_g4_outcomes"] is False
        and set(prereg["claims"].values()) == {False}
        and prereg["future_execution_boundary"]["runner"] == "absent"
        and prereg["future_execution_boundary"]["maximum_scheduled_units"] == 240
        and prereg["analysis"]["mode"] == "descriptive_measurement_readiness_only"
        and prereg["analysis"]["independent_clusters_per_stratum"] == 3
        and prereg["analysis"]["repetition_role"] == "technical_repeats_never_independent_clusters"
        and prereg["analysis"]["metric_definitions"] == DESCRIPTIVE_METRIC_DEFINITIONS
    ):
        raise VerificationError("preregistration-only authorization boundary drift")
    validate_upstream(
        prereg, g4_lock_bytes=g4_lock_bytes, g4_verifier_bytes=g4_verifier_bytes,
        g4_policy_bytes=g4_policy_bytes, g4_schema_bytes=g4_schema_bytes,
    )
    return {"block_count": 60, "status": "preregistered_contract_only", "unit_count": 240}


def validate_candidate(candidate_bytes: bytes, *, expected_prereg_bytes: bytes, **inputs: object) -> None:
    candidate = parse(candidate_bytes, "candidate preregistration", require_canonical=True)
    expected = parse(expected_prereg_bytes, "captured preregistration", require_canonical=True)
    if canonical(candidate) != canonical(expected):
        raise VerificationError("candidate differs from exact captured preregistration contract")
    validate_captured(prereg_bytes=candidate_bytes, **inputs)


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable G5 verifier is unavailable; use the independently pinned G5 profile",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
