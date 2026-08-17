"""One-use Anthropic Messages API measurement over the frozen G5 schedule."""

from __future__ import annotations

import copy
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import time
import types
from decimal import Decimal, InvalidOperation
from typing import Callable, Mapping


SCHEMA = "contextguard.p3-anthropic-api-live-contract/v1"
BASE_RUNNER_RELATIVE = Path("research/provider-live-roadmap/p2/v1/live_runner.py")
BASE_CONTRACT_RELATIVE = Path("research/provider-live-roadmap/p2/v1/contract.json")
EXPECTED_BASE = {
    "contract_sha256": "8c38cc3d61fd79003b56fc3357334fd22b0aea72739f3b66e41ad07b6d16a9c0",
    "runner_sha256": "ec201cb9f8cb931131875218aa02c606899e75aa15ebc9eac6b07398eb597e28",
}
EXPECTED_APPROVAL = {
    "module_sha256": "809405655f7b171f7b564f5ad381ae88237e325e1fe3a7e2bbb9f1442d20c6d0",
    "schema_sha256": "c535d464311d9f7dd5b326face7596e6b930da4fb3e0350a5d3e0942e735eb69",
}
EXPECTED_PROVIDER = {
    "auth_method": "standard_api_key_in_memory",
    "id": "anthropic-first-party",
    "model_id": "claude-sonnet-5",
}
EXPECTED_REQUEST = {
    "anthropic_version": "2023-06-01",
    "cache_control": "omitted",
    "endpoint": "/v1/messages",
    "max_tokens": 2048,
    "temperature": "omitted",
    "thinking": "disabled",
    "tools": "omitted",
}
EXPECTED_LIMITS = {
    "call_cap": 240,
    "currency": "USD",
    "max_answer_bytes": 32768,
    "max_request_bytes": 16_384,
    "max_response_bytes": 1_048_576,
    "per_call_budget_usd": "0.25",
    "spend_cap_usd": "20.00",
    "timeout_seconds": 120,
}
EXPECTED_PRICING = {
    "authority": "published_list_price_not_billing_receipt",
    "currency": "USD",
    "effective_end": "2026-08-31",
    "effective_start": "2026-07-01",
    "input_micro_usd_per_token": 2,
    "output_micro_usd_per_token": 10,
    "source": "anthropic_sonnet_5_introductory_pricing",
}
EXPECTED_CLAIMS = {
    "activation": False,
    "authoritative_provider_cost": False,
    "external_validity": False,
    "generalization": False,
    "production_readiness": False,
    "provider_cost_savings": False,
    "token_savings": False,
}
EXPECTED_USAGE = {
    "cache_creation_input_tokens_must_be_zero": True,
    "cache_read_input_tokens_must_be_zero": True,
    "provider_total_input_formula": (
        "input_tokens + cache_creation_input_tokens + cache_read_input_tokens"
    ),
    "provider_total_tokens_formula": "provider_total_input_tokens + output_tokens",
}
EVIDENCE_SCHEMA = "contextguard.p3-anthropic-api-live-evidence/v1"
_FORBIDDEN_PUBLIC_KEYS = frozenset(
    {
        "answer",
        "api_key",
        "authorization",
        "credential",
        "environment",
        "headers",
        "prompt",
        "raw",
        "response",
        "secret",
        "token",
        "url",
    }
)


class AnthropicAPILiveError(RuntimeError):
    """Value-free refusal from the API measurement runner."""


def refuse(code: str) -> None:
    raise AnthropicAPILiveError(code)


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
    except (TypeError, ValueError, UnicodeError):
        refuse("noncanonical_value")


def duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate_json_key")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=duplicate_keys,
            parse_constant=lambda _value: refuse("nonfinite_json_value"),
        )
    except AnthropicAPILiveError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse(f"invalid_{label}")
    if type(value) is not dict:
        refuse(f"invalid_{label}")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        refuse(f"invalid_{label}")
    return value


def _read_bound(path: Path, expected_sha256: str, label: str) -> bytes:
    try:
        if path.is_symlink():
            refuse(f"changed_{label}")
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            refuse(f"changed_{label}")
        raw = path.read_bytes()
    except OSError:
        refuse(f"changed_{label}")
    if sha256(raw) != expected_sha256:
        refuse(f"changed_{label}")
    return raw


def _load_module(raw: bytes, expected_sha256: str, name: str) -> types.ModuleType:
    if sha256(raw) != expected_sha256:
        refuse("changed_module")
    module = types.ModuleType(name)
    module.__file__ = f"<captured-{name}>"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


def load_base(contract: dict[str, object], *, repo_root: Path) -> types.ModuleType:
    declared = _exact(
        contract.get("base_measurement"),
        {"contract_sha256", "runner_sha256"},
        "base_measurement",
    )
    if declared != EXPECTED_BASE:
        refuse("invalid_base_measurement")
    runner_raw = _read_bound(
        repo_root / BASE_RUNNER_RELATIVE,
        declared["runner_sha256"],
        "base_runner",
    )
    base = _load_module(runner_raw, declared["runner_sha256"], "captured_p3_api_base")
    contract_raw = _read_bound(
        repo_root / BASE_CONTRACT_RELATIVE,
        declared["contract_sha256"],
        "base_contract",
    )
    base_contract = base.parse_json(contract_raw, "base_contract")
    try:
        base.validate_contract(base_contract, repo_root=repo_root)
    except Exception:
        refuse("invalid_base_measurement")
    base.CAPTURED_CONTRACT_RAW = contract_raw
    base.CAPTURED_CONTRACT = base_contract
    return base


def validate_contract(contract: dict[str, object], *, repo_root: Path) -> None:
    top = _exact(
        contract,
        {
            "approval_boundary",
            "base_measurement",
            "claims",
            "destination_allowlist",
            "limits",
            "observer",
            "operation",
            "pricing",
            "provider",
            "request",
            "runtime",
            "safety",
            "schema_version",
            "source_candidate",
            "status",
            "usage_semantics",
        },
        "contract",
    )
    if top["schema_version"] != SCHEMA:
        refuse("invalid_contract")
    if top["approval_boundary"] != EXPECTED_APPROVAL:
        refuse("invalid_approval_boundary")
    if top["base_measurement"] != EXPECTED_BASE:
        refuse("invalid_base_measurement")
    if top["provider"] != EXPECTED_PROVIDER:
        refuse("invalid_provider")
    if top["request"] != EXPECTED_REQUEST:
        refuse("invalid_request")
    if top["limits"] != EXPECTED_LIMITS:
        refuse("invalid_limits")
    if top["pricing"] != EXPECTED_PRICING:
        refuse("invalid_pricing")
    if top["claims"] != EXPECTED_CLAIMS:
        refuse("invalid_claims")
    if top["usage_semantics"] != EXPECTED_USAGE:
        refuse("invalid_usage_semantics")
    if top["destination_allowlist"] != [
        {"host": "api.anthropic.com", "port": 443, "scheme": "https"}
    ]:
        refuse("invalid_destination")
    if top["observer"] != {
        "id": "anthropic-messages-json-v1",
        "phase": "P3",
        "schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "anthropic-messages-api/v1",
    }:
        refuse("invalid_observer")
    if top["operation"] != {
        "receipt_schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "p3-g5-fixed-schedule-anthropic-api-measurement",
        "version": "v1",
    }:
        refuse("invalid_operation")
    if top["runtime"] != {
        "client": "python-http.client",
        "proxies": False,
        "redirects": False,
        "tls": "default_verified",
    }:
        refuse("invalid_runtime")
    if top["safety"] != {
        "network_redirects": False,
        "network_proxies": False,
        "output_mode": "owner_private",
        "raw_content_publication": False,
        "retention_seconds": 604800,
        "scorer_load_after_all_calls": True,
    }:
        refuse("invalid_safety")
    if top["source_candidate"] != {
        "artifact_ids": ["9163551917", "9163551685"],
        "checksums_sha256": "a20f2fc93bfa0e2774f8288eb9d31e9c83c962a816a65cfb829351610e7c5efb",
        "commit_sha": "540c6e02222f25346ca9c797197882cebbe5331d",
        "manifest_sha256": "149d26383663f57a5bac2f79f52acb53ed8b3f8a7675176557120dd3ec353050",
    }:
        refuse("invalid_source_candidate")
    if top["status"] != "approved_scope_requires_one_use_external_envelope":
        refuse("invalid_status")
    _read_bound(
        repo_root
        / "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py",
        EXPECTED_APPROVAL["module_sha256"],
        "approval_module",
    )
    _read_bound(
        repo_root / "packages/context-guard-receipt/schemas/external-approval.schema.json",
        EXPECTED_APPROVAL["schema_sha256"],
        "approval_schema",
    )
    load_base(contract, repo_root=repo_root)


def validate_pricing_window(
    contract: dict[str, object], *, observed_date: datetime.date | None = None
) -> None:
    if contract.get("pricing") != EXPECTED_PRICING:
        refuse("invalid_pricing")
    current = observed_date or datetime.datetime.now(datetime.timezone.utc).date()
    try:
        start = datetime.date.fromisoformat(EXPECTED_PRICING["effective_start"])
        end = datetime.date.fromisoformat(EXPECTED_PRICING["effective_end"])
    except (TypeError, ValueError):
        refuse("invalid_pricing")
    if current < start or current > end:
        refuse("pricing_window_unavailable")


def build_request_body(item: dict[str, object], *, contract: dict[str, object]) -> bytes:
    prompt = item.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        refuse("payload_unavailable")
    request = contract.get("request")
    provider = contract.get("provider")
    limits = contract.get("limits")
    if request != EXPECTED_REQUEST or provider != EXPECTED_PROVIDER or limits != EXPECTED_LIMITS:
        refuse("invalid_contract")
    raw = canonical(
        {
            "max_tokens": request["max_tokens"],
            "messages": [{"content": prompt, "role": "user"}],
            "model": provider["model_id"],
            "thinking": {"type": request["thinking"]},
        }
    )
    if len(raw) > limits["max_request_bytes"]:
        refuse("request_limit")
    return raw


def _nonnegative_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        refuse(label)
    return value


def parse_anthropic_response(
    raw: bytes, *, contract: dict[str, object]
) -> dict[str, object]:
    limits = contract.get("limits")
    if limits != EXPECTED_LIMITS or not raw or len(raw) > EXPECTED_LIMITS["max_response_bytes"]:
        refuse("provider_output_limit")
    value = parse_json(raw, "provider_result")
    required_response_keys = {
        "content",
        "id",
        "model",
        "role",
        "stop_reason",
        "stop_sequence",
        "type",
        "usage",
    }
    if frozenset(value) not in {
        frozenset(required_response_keys),
        frozenset(required_response_keys | {"stop_details"}),
    } or value.get("stop_details") is not None:
        refuse("provider_result_unavailable")
    if (
        value["type"] != "message"
        or value["role"] != "assistant"
        or value["model"] != EXPECTED_PROVIDER["model_id"]
        or value["stop_reason"] != "end_turn"
        or value["stop_sequence"] is not None
    ):
        refuse("provider_result_unavailable")
    message_id = value["id"]
    if (
        not isinstance(message_id, str)
        or not message_id.startswith("msg_")
        or len(message_id.encode("ascii", errors="ignore")) != len(message_id)
        or len(message_id) > 128
    ):
        refuse("provider_result_unavailable")
    content = value["content"]
    if type(content) is not list or len(content) != 1:
        refuse("provider_result_unavailable")
    block = content[0]
    if type(block) is not dict or set(block) != {"text", "type"} or block["type"] != "text":
        refuse("provider_result_unavailable")
    answer = block["text"]
    if (
        not isinstance(answer, str)
        or not answer.strip()
        or len(answer.encode("utf-8")) > EXPECTED_LIMITS["max_answer_bytes"]
    ):
        refuse("provider_result_unavailable")
    usage = value["usage"]
    if type(usage) is not dict:
        refuse("provider_usage_unavailable")
    allowed_usage = {
        "cache_creation",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
        "inference_geo",
        "input_tokens",
        "output_tokens",
        "output_tokens_details",
        "service_tier",
    }
    if not {"input_tokens", "output_tokens"}.issubset(usage) or not set(usage) <= allowed_usage:
        refuse("provider_usage_unavailable")
    input_tokens = _nonnegative_integer(usage["input_tokens"], "provider_usage_unavailable")
    output_tokens = _nonnegative_integer(usage["output_tokens"], "provider_usage_unavailable")
    cache_creation_value = usage.get("cache_creation_input_tokens")
    cache_read_value = usage.get("cache_read_input_tokens")
    cache_creation = 0 if cache_creation_value is None else _nonnegative_integer(
        cache_creation_value, "provider_usage_unavailable"
    )
    cache_read = 0 if cache_read_value is None else _nonnegative_integer(
        cache_read_value, "provider_usage_unavailable"
    )
    if cache_creation != 0 or cache_read != 0:
        refuse("prompt_cache_observed")
    total_input = input_tokens + cache_creation + cache_read
    list_price = (
        total_input * EXPECTED_PRICING["input_micro_usd_per_token"]
        + output_tokens * EXPECTED_PRICING["output_micro_usd_per_token"]
    )
    try:
        per_call_limit = int(
            Decimal(EXPECTED_LIMITS["per_call_budget_usd"]) * Decimal(1_000_000)
        )
    except (InvalidOperation, ValueError):
        refuse("invalid_limits")
    if list_price > per_call_limit:
        refuse("per_call_budget_exceeded")
    return {
        "answer": answer.strip(),
        "message_id_sha256": sha256(message_id.encode("ascii")),
        "usage": {
            "cache_creation_input_tokens": cache_creation,
            "cache_read_input_tokens": cache_read,
            "input_tokens": input_tokens,
            "list_price_micro_usd": list_price,
            "output_tokens": output_tokens,
            "provider_total_input_tokens": total_input,
            "provider_total_tokens": total_input + output_tokens,
        },
    }


def validate_api_key(api_key: bytes) -> str:
    if (
        type(api_key) is not bytes
        or not 20 <= len(api_key) <= 512
        or not api_key.startswith(b"sk-ant-api")
        or any(byte <= 0x20 or byte >= 0x7F for byte in api_key)
    ):
        refuse("credential_unavailable")
    try:
        return api_key.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        refuse("credential_unavailable")


def invoke_anthropic(
    item: dict[str, object],
    *,
    contract: dict[str, object],
    api_key: bytes,
    connection_factory=http.client.HTTPSConnection,
) -> bytes:
    secret = validate_api_key(api_key)
    body = build_request_body(item, contract=contract)
    connection = None
    try:
        connection = connection_factory(
            "api.anthropic.com",
            port=443,
            timeout=contract["limits"]["timeout_seconds"],
            context=ssl.create_default_context(),
        )
        connection.request(
            "POST",
            contract["request"]["endpoint"],
            body=body,
            headers={
                "anthropic-version": contract["request"]["anthropic_version"],
                "content-type": "application/json",
                "x-api-key": secret,
            },
        )
        response = connection.getresponse()
        raw = response.read(contract["limits"]["max_response_bytes"] + 1)
        if response.status != 200:
            refuse("transport_error")
        if not raw or len(raw) > contract["limits"]["max_response_bytes"]:
            refuse("provider_output_limit")
        return raw
    except AnthropicAPILiveError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError):
        refuse("transport_error")
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _empty_token_usage() -> dict[str, int]:
    return {
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "completed_calls": 0,
        "input_tokens": 0,
        "list_price_micro_usd": 0,
        "output_tokens": 0,
        "provider_total_input_tokens": 0,
        "provider_total_tokens": 0,
    }


def execute_schedule(
    *,
    contract: dict[str, object],
    schedule: dict[str, object],
    observation_schema_bytes: bytes,
    tasks: Mapping[str, dict[str, object]],
    packs: Mapping[tuple[str, str], dict[str, object]],
    invoke: Callable[[dict[str, object]], bytes],
    scorer_loader: Callable[[], object],
    repo_root: Path,
) -> dict[str, object]:
    base = load_base(contract, repo_root=repo_root)
    plan = base.build_request_plan(
        contract=contract,
        schedule=schedule,
        tasks=tasks,
        packs=packs,
    )
    observations: list[dict[str, object]] = []
    answers: list[str | None] = []
    sealed_runs: list[dict[str, object]] = []
    totals = _empty_token_usage()
    spend_cap = int(Decimal(contract["limits"]["spend_cap_usd"]) * Decimal(1_000_000))

    for item in plan:
        pack_started = time.monotonic_ns()
        prompt = base._prompt(
            tasks[item["task_id"]],
            packs[(item["task_id"], item["arm"])]["rendered_pack"],
        )
        pack_finished = time.monotonic_ns()
        if sha256(prompt.encode("utf-8")) != item["payload_sha256"]:
            refuse("payload_identity_mismatch")
        live_item = dict(item, prompt=prompt)
        completed = True
        exclusion = "none"
        parsed: dict[str, object] | None = None
        raw = b""
        try:
            raw = invoke(live_item)
            parsed = parse_anthropic_response(raw, contract=contract)
            projected_spend = (
                totals["list_price_micro_usd"]
                + parsed["usage"]["list_price_micro_usd"]
            )
            if projected_spend > spend_cap:
                refuse("spend_cap_exceeded")
        except AnthropicAPILiveError as exc:
            code = exc.args[0] if exc.args else "transport_error"
            if code in {
                "per_call_budget_exceeded",
                "prompt_cache_observed",
                "spend_cap_exceeded",
            }:
                raise
            completed = False
            exclusion = (
                code
                if code in {"timeout", "transport_error", "model_identity_mismatch"}
                else "malformed_required_field"
            )
        usage = parsed["usage"] if parsed is not None else None
        if usage is not None:
            totals["completed_calls"] += 1
            for key, value in usage.items():
                totals[key] += value
        answer = parsed["answer"] if parsed is not None else None
        answers.append(answer)
        sealed_core = {
            "message_id_sha256": parsed["message_id_sha256"] if parsed else None,
            "model_ids": [EXPECTED_PROVIDER["model_id"]] if parsed else [],
            "payload_sha256": item["payload_sha256"],
            "request_id": item["request_id"],
            "response_bytes": len(raw),
            "response_sha256": sha256(raw),
            "scheduled_unit_id": item["scheduled_unit_id"],
            "usage": copy.deepcopy(usage),
        }
        sealed_runs.append(
            {**sealed_core, "seal_sha256": sha256(canonical(sealed_core))}
        )
        receipt_id = "receipt-" + sha256(
            canonical(
                {"request_id": item["request_id"], "response_sha256": sha256(raw)}
            )
        )
        observations.append(
            {
                "schema_version": "contextguard.g5-authoritative-observation/v1",
                "observer_version": "contextguard.g5-minimized-observer/v1",
                **{
                    key: item[key]
                    for key in (
                        "scheduled_unit_id",
                        "block_id",
                        "task_id",
                        "lineage_id",
                        "partition",
                        "stratum",
                        "arm",
                        "assigned_order",
                        "repetition",
                        "assignment_id",
                        "payload_sha256",
                        "request_id",
                    )
                },
                "receipt_id": receipt_id,
                "model_identity": EXPECTED_PROVIDER["model_id"],
                "unit_status": "completed" if completed else "excluded",
                "completion_event": "normal_completion" if completed else exclusion,
                "event_count": 1,
                "pack_start_monotonic_ns": pack_started,
                "pack_end_monotonic_ns": pack_finished,
                "correctness": {
                    "availability": "unavailable",
                    "outcome": "unavailable",
                    "unavailable_reason": "not_observed" if completed else "excluded_unit",
                },
                "input_usage": base._metric(
                    usage["provider_total_input_tokens"] if usage else None,
                    completed=completed,
                ),
                "output_usage": base._metric(
                    usage["output_tokens"] if usage else None,
                    completed=completed,
                ),
                "correction_count": base._metric(0 if parsed else None, completed=completed),
                "correction_tokens": base._metric(0 if parsed else None, completed=completed),
                "retrieval_count": base._metric(0 if parsed else None, completed=completed),
                "retrieval_bytes": base._metric(0 if parsed else None, completed=completed),
                "retrieval_tokens": base._metric(0 if parsed else None, completed=completed),
                "billing_receipt": {
                    "authority": "unavailable",
                    "reference": None,
                    "status": "unavailable",
                },
                "cost_components": base._cost_components(completed=completed),
                "exclusion_reason": "none" if completed else exclusion,
                "audit_status": "eligible" if completed else "excluded",
            }
        )

    if len(sealed_runs) != contract["limits"]["call_cap"]:
        refuse("incomplete_schedule")
    scorer = scorer_loader()
    expected_answers = (
        scorer.get("answers") if type(scorer) is dict and "answers" in scorer else scorer
    )
    if type(expected_answers) is not dict or set(expected_answers) != set(tasks):
        refuse("invalid_scorer")
    for observation, answer in zip(observations, answers, strict=True):
        if observation["unit_status"] != "completed":
            continue
        expected = expected_answers.get(observation["task_id"])
        if not isinstance(expected, str):
            refuse("invalid_scorer")
        observation["correctness"] = {
            "availability": "observed",
            "outcome": "correct" if answer == expected else "incorrect",
            "unavailable_reason": "not_applicable",
        }
    base_contract = base.CAPTURED_CONTRACT
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    summary = base.summarize_with_frozen_g5(
        observations,
        schedule_bytes=schedule_raw,
        schema_bytes=observation_schema_bytes,
        repo_root=repo_root,
    )
    return {
        "observations": observations,
        "request_plan_sha256": base.request_plan_sha256(plan),
        "sealed_runs": sealed_runs,
        "summary": summary,
        "token_usage": totals,
    }


def _recursive_keys(value: object) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key).lower())
            keys.update(_recursive_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_recursive_keys(child))
    return keys


def build_public_evidence(
    *,
    contract_raw: bytes,
    execution: dict[str, object],
    phase_records: dict[str, dict[str, object]],
    phase_results: dict[str, dict[str, object]],
    runner_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "authority": {"activation": False, "claim": False, "runtime_mutation": False},
        "auth_method": EXPECTED_PROVIDER["auth_method"],
        "base_measurement": copy.deepcopy(EXPECTED_BASE),
        "call_count": len(execution["sealed_runs"]),
        "contract_sha256": sha256(contract_raw),
        "g5_summary": copy.deepcopy(execution["summary"]),
        "list_price_estimate": {
            "amount_micro_usd": execution["token_usage"]["list_price_micro_usd"],
            "authority": EXPECTED_PRICING["authority"],
            "currency": "USD",
            "pricing_source": EXPECTED_PRICING["source"],
        },
        "model_id": EXPECTED_PROVIDER["model_id"],
        "observations": copy.deepcopy(execution["observations"]),
        "p2_phase_records": copy.deepcopy(phase_records),
        "p2_phase_results": copy.deepcopy(phase_results),
        "provider_cost": {
            "availability": "unavailable",
            "currency": None,
            "reason": "admin_usage_cost_receipt_unavailable",
            "value": None,
        },
        "provider_usage_receipt": {
            "authority": "anthropic_messages_api_response",
            "availability": "observed",
            "completed_calls": execution["token_usage"]["completed_calls"],
        },
        "request_plan_sha256": execution["request_plan_sha256"],
        "runner_sha256": runner_sha256,
        "sealed_runs": copy.deepcopy(execution["sealed_runs"]),
        "token_usage": copy.deepcopy(execution["token_usage"]),
    }


def validate_public_evidence(
    evidence: dict[str, object], *, contract_raw: bytes, repo_root: Path
) -> None:
    expected_keys = {
        "auth_method",
        "authority",
        "base_measurement",
        "call_count",
        "contract_sha256",
        "g5_summary",
        "list_price_estimate",
        "model_id",
        "observations",
        "p2_phase_records",
        "p2_phase_results",
        "provider_cost",
        "provider_usage_receipt",
        "request_plan_sha256",
        "runner_sha256",
        "schema_version",
        "sealed_runs",
        "token_usage",
    }
    if type(evidence) is not dict or set(evidence) != expected_keys:
        refuse("invalid_public_evidence")
    if _FORBIDDEN_PUBLIC_KEYS & _recursive_keys(evidence):
        refuse("private_surface_in_public_evidence")
    if (
        evidence["schema_version"] != EVIDENCE_SCHEMA
        or evidence["contract_sha256"] != sha256(contract_raw)
        or evidence["auth_method"] != EXPECTED_PROVIDER["auth_method"]
        or evidence["base_measurement"] != EXPECTED_BASE
        or evidence["model_id"] != EXPECTED_PROVIDER["model_id"]
        or evidence["call_count"] != 240
        or evidence["authority"]
        != {"activation": False, "claim": False, "runtime_mutation": False}
        or evidence["provider_cost"]
        != {
            "availability": "unavailable",
            "currency": None,
            "reason": "admin_usage_cost_receipt_unavailable",
            "value": None,
        }
    ):
        refuse("invalid_public_evidence")
    if (
        not isinstance(evidence["runner_sha256"], str)
        or len(evidence["runner_sha256"]) != 64
        or not isinstance(evidence["request_plan_sha256"], str)
        or len(evidence["request_plan_sha256"]) != 64
    ):
        refuse("invalid_public_evidence")
    observations = evidence["observations"]
    sealed_runs = evidence["sealed_runs"]
    if (
        type(observations) is not list
        or len(observations) != 240
        or type(sealed_runs) is not list
        or len(sealed_runs) != 240
    ):
        refuse("invalid_public_evidence")
    observation_ids = [row.get("scheduled_unit_id") for row in observations]
    sealed_ids = [row.get("scheduled_unit_id") for row in sealed_runs]
    if observation_ids != sealed_ids or len(set(observation_ids)) != 240:
        refuse("public_evidence_identity_mismatch")
    totals = _empty_token_usage()
    for sealed in sealed_runs:
        if type(sealed) is not dict or set(sealed) != {
            "message_id_sha256",
            "model_ids",
            "payload_sha256",
            "request_id",
            "response_bytes",
            "response_sha256",
            "scheduled_unit_id",
            "seal_sha256",
            "usage",
        }:
            refuse("invalid_public_evidence_seal")
        core = {key: value for key, value in sealed.items() if key != "seal_sha256"}
        if sealed["seal_sha256"] != sha256(canonical(core)):
            refuse("invalid_public_evidence_seal")
        usage = sealed["usage"]
        if usage is not None:
            if type(usage) is not dict or set(usage) != set(totals) - {"completed_calls"}:
                refuse("invalid_public_evidence_seal")
            totals["completed_calls"] += 1
            for key, value in usage.items():
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    refuse("invalid_public_evidence_seal")
                totals[key] += value
    if evidence["token_usage"] != totals:
        refuse("public_evidence_usage_mismatch")
    if evidence["list_price_estimate"] != {
        "amount_micro_usd": totals["list_price_micro_usd"],
        "authority": EXPECTED_PRICING["authority"],
        "currency": "USD",
        "pricing_source": EXPECTED_PRICING["source"],
    }:
        refuse("public_evidence_cost_mismatch")
    if evidence["provider_usage_receipt"] != {
        "authority": "anthropic_messages_api_response",
        "availability": "observed",
        "completed_calls": totals["completed_calls"],
    }:
        refuse("public_evidence_usage_mismatch")
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    base = load_base(contract, repo_root=repo_root)
    base_contract = base.CAPTURED_CONTRACT
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        base_contract["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    recomputed = base.summarize_with_frozen_g5(
        observations,
        schedule_bytes=schedule_raw,
        schema_bytes=schema_raw,
        repo_root=repo_root,
    )
    if evidence["g5_summary"] != recomputed:
        refuse("public_evidence_summary_mismatch")
    if set(evidence["p2_phase_records"]) != {"closed_pack", "realistic_fallback"}:
        refuse("public_evidence_phase_mismatch")
    phase_results = {
        name: base.evaluate_phase_record(record, repo_root=repo_root)
        for name, record in evidence["p2_phase_records"].items()
    }
    if evidence["p2_phase_results"] != phase_results:
        refuse("public_evidence_phase_mismatch")


def _approval_plan_sha256(
    *, contract: dict[str, object], plan: list[dict[str, object]]
) -> str:
    projection = [
        {
            "body_sha256": sha256(build_request_body(item, contract=contract)),
            "method": "POST",
            "path": contract["request"]["endpoint"],
            "request_id": item["request_id"],
        }
        for item in plan
    ]
    return sha256(
        b"contextguard.p3-anthropic-api-request-plan/v1\0" + canonical(projection)
    )


def build_approval_scope(
    *,
    contract: dict[str, object],
    output_root: Path,
    plan: list[dict[str, object]],
    runner_sha256: str,
) -> dict[str, object]:
    if not output_root.is_absolute():
        refuse("output_unavailable")
    runtime_description = {
        "client": contract["runtime"]["client"],
        "proxy_environment": "ignored",
        "tls": contract["runtime"]["tls"],
    }
    return {
        "source_candidate": copy.deepcopy(contract["source_candidate"]),
        "provider": {
            "provider_id": contract["provider"]["id"],
            "model_id": contract["provider"]["model_id"],
        },
        "observer": {
            "observer_id": contract["observer"]["id"],
            "phase": contract["observer"]["phase"],
            "receipt_schema": contract["observer"]["schema"],
            "surface_id": contract["observer"]["surface"],
        },
        "operation": {
            "receipt_schema": contract["operation"]["receipt_schema"],
            "surface_id": contract["operation"]["surface"],
            "version": contract["operation"]["version"],
        },
        "runtime": {
            "argv_sha256": _approval_plan_sha256(contract=contract, plan=plan),
            "environment_sha256": sha256(canonical(runtime_description)),
            "executable_sha256": runner_sha256,
            "identity": "python-http.client-p3-runner",
            "version": "v1",
        },
        "credential": {
            "consumer_id": "anthropic-messages-api",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": copy.deepcopy(contract["destination_allowlist"]),
        "network_policy": {"proxies_allowed": False, "redirects_allowed": False},
        "limits": {
            "call_cap": contract["limits"]["call_cap"],
            "currency": contract["limits"]["currency"],
            "spend_cap": contract["limits"]["spend_cap_usd"],
            "timeout_seconds": contract["limits"]["timeout_seconds"],
        },
        "output": {"mode": "owner_private", "root": str(output_root)},
        "retention": {"seconds": contract["safety"]["retention_seconds"]},
    }


def resolve_external_approval(
    approval: object | Callable[[dict[str, object]], object],
    scope: dict[str, object],
) -> object:
    if not callable(approval):
        return approval
    try:
        return approval(copy.deepcopy(scope))
    except Exception:
        refuse("approval_unavailable")


def run_live_authorized(
    *,
    contract_path: Path,
    repo_root: Path,
    output_root: Path,
    state_root: Path,
    approval: object | Callable[[dict[str, object]], object],
    verification_key: bytes,
    registry_key: bytes,
    api_key: bytes,
    invoke: Callable[[dict[str, object]], bytes] | None = None,
) -> dict[str, object]:
    validate_api_key(api_key)
    try:
        runner_path = Path(__file__).resolve(strict=True)
        runner_metadata = runner_path.stat()
        if (
            runner_path.is_symlink()
            or not stat.S_ISREG(runner_metadata.st_mode)
            or runner_metadata.st_nlink != 1
        ):
            refuse("changed_runner")
        runner_raw = runner_path.read_bytes()
    except OSError:
        refuse("changed_runner")
    runner_digest = sha256(runner_raw)
    contract_raw = contract_path.read_bytes()
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    validate_pricing_window(contract)
    base = load_base(contract, repo_root=repo_root)
    base._private_root(output_root)
    base._private_root(state_root)
    base_contract = base.CAPTURED_CONTRACT
    capture = base.capture_frozen_packs(contract=base_contract, repo_root=repo_root)
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        base_contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    schedule = parse_json(schedule_raw, "g5_schedule")
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        base_contract["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    plan = base.build_request_plan(
        contract=contract,
        schedule=schedule,
        tasks=capture.tasks,
        packs=capture.packs,
    )
    scope = build_approval_scope(
        contract=contract,
        output_root=output_root,
        plan=plan,
        runner_sha256=runner_digest,
    )

    def materialize(_scope: dict[str, object]) -> dict[str, object]:
        scorer_box: dict[str, object] = {}

        def load_scorer() -> object:
            scorer = capture.load_scorer()
            scorer_box.update(scorer)
            return scorer

        active_invoke = invoke or (
            lambda item: invoke_anthropic(
                item,
                contract=contract,
                api_key=api_key,
            )
        )
        execution = execute_schedule(
            contract=contract,
            schedule=schedule,
            observation_schema_bytes=schema_raw,
            tasks=capture.tasks,
            packs=capture.packs,
            invoke=active_invoke,
            scorer_loader=load_scorer,
            repo_root=repo_root,
        )
        if sha256(runner_path.read_bytes()) != runner_digest:
            refuse("changed_runner")
        phase_records = base.build_p2_phase_records(
            observed_at=int(time.time()),
            retention_seconds=contract["safety"]["retention_seconds"],
            tasks=capture.tasks,
            packs=capture.packs,
            oracle=scorer_box["oracle"],
        )
        phase_results = {
            name: base.evaluate_phase_record(record, repo_root=repo_root)
            for name, record in phase_records.items()
        }
        evidence = build_public_evidence(
            contract_raw=contract_raw,
            execution=execution,
            phase_records=phase_records,
            phase_results=phase_results,
            runner_sha256=runner_digest,
        )
        validate_public_evidence(
            evidence,
            contract_raw=contract_raw,
            repo_root=repo_root,
        )
        evidence_raw = canonical(evidence)
        base._write_private(output_root / "p3-api-evidence.json", evidence_raw)
        return {
            "call_count": 240,
            "evidence_sha256": sha256(evidence_raw),
            "status": "p3_api_measurement_recorded",
        }

    resolved_approval = resolve_external_approval(approval, scope)
    result = base.consume_authorized(
        contract=contract,
        approval=resolved_approval,
        requested_scope=scope,
        verification_key=verification_key,
        registry_key=registry_key,
        state_root=state_root,
        materialize=materialize,
        repo_root=repo_root,
    )
    if type(result) is not dict:
        refuse("materialization_failed")
    return result


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable Anthropic API execution is unavailable; use a one-use external approval envelope",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
