#!/usr/bin/env python3
"""Fail-closed V4 Anthropic live gate for the budget-selected 288-unit run.

The live surface deliberately has no command-line execution mode.  Callers
must provide an already prepared plan, a one-argument approval consumer, and
an in-memory API credential.  Prompt preparation for an actual run is bound to
the committed V3 evaluator and its captured corpus; the small injectable
surface exists for deterministic tests only.
"""

from __future__ import annotations

import copy
import datetime
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
from pathlib import Path
import ssl
import stat
import sys
import tempfile
import threading
import time
import types
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "contextguard.p3-anthropic-api-live-contract/v4"
EVIDENCE_SCHEMA = "contextguard.p3-anthropic-api-live-evidence/v4"
EXPECTED_CONTRACT_SHA256 = "492c440b8aa3836a59671900d5e21438614e27ee9cdffb680ee7c78859bfbb07"
EXPECTED_SCORER_SHA256 = "179e4cb2bbab5ce1290f1c0c190881c1dd38fd3a7f5a881b223f4b81f0872db8"
EXPECTED_ARTIFACTS = {
    "approval_core_v1": {
        "path": "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py",
        "sha256": "809405655f7b171f7b564f5ad381ae88237e325e1fe3a7e2bbb9f1442d20c6d0",
    },
    "approval_module": {
        "path": "packages/context-guard-receipt/python/context_guard_receipt/external_approval_v2.py",
        "sha256": "67e3d487a3df42bb30d7debf8f7fa7e85d62c75c62cd3a7308babaa92fae189a",
    },
    "approval_schema": {
        "path": "packages/context-guard-receipt/schemas/external-approval-v2.schema.json",
        "sha256": "d82bf2ea94d63bc6f1840b607167167891e767a13839d52c9debbbe046c62158",
    },
    "behavioral_quality_evaluator": {
        "path": "research/provider-live-roadmap/p3-api/v4/behavioral_quality.py",
        "sha256": "d548881424637a4ea764197395fefa271daf519e6533d6bf4a127282eba0efa8",
    },
    "behavioral_quality_schema": {
        "path": "research/provider-live-roadmap/p3-api/v4/behavioral-quality.schema.json",
        "sha256": "1c1b528b05a66ef40a22b0b6c615fc48cd95b365b3ffc882863e91820d457ef7",
    },
    "budget_policy": {
        "path": "research/provider-live-roadmap/p3-api/v4/budget_policy.py",
        "sha256": "b789e303985144c2509e68cb65b869732e23be29c20e751ec467929a152ba8c1",
    },
    "budget_policy_report": {
        "path": "research/provider-live-roadmap/p3-api/v4/budget-policy-report.json",
        "sha256": "b506bde5e0dab3916e46bbcc6e6dd015ae839a6628b468a3dbe294a9c301fcda",
    },
    "canonical_credential_policy": {
        "path": "context-guard-kit/credential_policy.py",
        "sha256": "c7322d6d9fb1db0f294205fddd664137b9d797b9c8636db7cd3353fc986c15e6",
    },
    "canonical_packer": {
        "path": "context-guard-kit/context_pack.py",
        "sha256": "86f69c93d80ba6907e2131659f0e73dac0c24f45e09f304ea288c1558e08e08e",
    },
    "canonical_sanitizer": {
        "path": "context-guard-kit/sanitize_output.py",
        "sha256": "666d1f8bf3b75d049e580c0d0b806373b7bb2ae5c083a016e256e16f8ce7de9e",
    },
    "corpus": {
        "path": "research/provider-live-roadmap/p3-api/v3/corpus-manifest.json",
        "sha256": "9bcb35534348c631aa6eed49effa7d8d534fe755d1e7367a57f618d817007d63",
    },
    "evaluator": {
        "path": "research/provider-live-roadmap/p3-api/v3/evaluator.py",
        "sha256": "955fa958ac113b04c9f2d8fbe3b610dda55bfd3edf252ab02ba69bc1a0a39888",
    },
    "preregistration": {
        "path": "research/provider-live-roadmap/p3-api/v3/preregistration.json",
        "sha256": "9ee7eeada34ccc836326ef2451e061c99084ffdfb60852f1e96d9c9d5c278a83",
    },
    "observed_result": {
        "path": "research/provider-live-roadmap/p3-api/v3/result.json",
        "sha256": "00b803d30061378ea92463af4ef8bf003cf92ffa03b36efefb5c99744361e875",
    },
    "provider_evidence": {
        "path": "research/provider-live-roadmap/p3-api/v3/provider-evidence.json",
        "sha256": "f3334e7a70439c17c198b3771930b3cf798c60e60a13b46d4ff95f7dd469e2b5",
    },
    "provider_input_capture": {
        "path": "research/provider-live-roadmap/p3-api/v3/provider-input-freeze.json",
        "sha256": "8e3fcb2cf046f3abda1439b107ea774e05b4f654caa8f46472c539073904a4d8",
    },
    "rehearsal_report": {
        "path": "research/provider-live-roadmap/p3-api/v3/rehearsal-report.json",
        "sha256": "7651b72392c14f7e5da8a9b551869ec76664b717ca5ada5be5de0b4c344c1549",
    },
    "schedule": {
        "path": "research/provider-live-roadmap/p3-api/v3/schedule.json",
        "sha256": "5ca56b87906b72384fe8d3e7e643cb50502befd8c5d7ad3632a977846a5001fc",
    },
    "plugin_credential_policy": {
        "path": "plugins/context-guard/lib/credential_policy.py",
        "sha256": "c7322d6d9fb1db0f294205fddd664137b9d797b9c8636db7cd3353fc986c15e6",
    },
    "plugin_packer": {
        "path": "plugins/context-guard/bin/context-guard-pack",
        "sha256": "86f69c93d80ba6907e2131659f0e73dac0c24f45e09f304ea288c1558e08e08e",
    },
    "plugin_sanitizer": {
        "path": "plugins/context-guard/bin/context-guard-sanitize-output",
        "sha256": "666d1f8bf3b75d049e580c0d0b806373b7bb2ae5c083a016e256e16f8ce7de9e",
    },
    "prompt_template": {
        "path": "research/provider-live-roadmap/p3-api/v3/provider-prompt-template.txt",
        "sha256": "a60429640b5c89ecae4febfb8da33616ba6ac909661fa393398ce17f55263cf1",
    },
    "protocol_amendment": {
        "path": "research/provider-live-roadmap/p3-api/v3/protocol-amendment.json",
        "sha256": "7795f456bbe083f2776cee252463627c80245f2032dc7b7f1a5f8078f2b294bd",
    },
    "response_amendment": {
        "path": "research/provider-live-roadmap/p3-api/v3/response-amendment.json",
        "sha256": "2e41c5d35a3f8746944f746a9eb740779d0dc5f97c8fd209ed179a17c1f98c4c",
    },
}
EXPECTED_POLICY_IDENTITY = {
    "budget_policy_report_sha256": EXPECTED_ARTIFACTS["budget_policy_report"]["sha256"],
    "budget_policy_sha256": EXPECTED_ARTIFACTS["budget_policy"]["sha256"],
    "name": "self_financing_context_v1",
    "provider_input_capture_sha256": EXPECTED_ARTIFACTS["provider_input_capture"]["sha256"],
    "schema_version": "contextguard.p3-api-budget-policy-report/v1",
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
EXPECTED_PROVIDER = {
    "auth_method": "standard_api_key_in_memory",
    "id": "anthropic-first-party",
    "model_id": "claude-sonnet-5",
}
EXPECTED_REQUEST = {
    "anthropic_version": "2023-06-01",
    "endpoint": "/v1/messages",
    "max_tokens": 4096,
    "sampling_parameters": "provider_default_unset",
    "thinking": "provider_default_private_ignored_for_scoring",
}
EXPECTED_RESUME = {
    "approval_schema_migration": False,
    "fresh_external_approvals_required": True,
    "policy": "fresh_v4_state_no_cross_version_capsule_migration",
    "previous_capsule_migration": False,
}
EXPECTED_LIMITS = {
    "batch_count": 2,
    "batch_units": 144,
    "call_cap": 288,
    "currency": "USD",
    "cumulative_spend_cap_usd": "40.00",
    "max_answer_bytes": 32768,
    "max_request_bytes": 96000,
    "max_response_bytes": 4194304,
    "per_batch_spend_cap_usd": "20.00",
    "prior_protocol_validation_calls": 1,
    "scheduled_units": 288,
    "timeout_seconds": 120,
    "total_external_call_cap": 289,
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
EXPECTED_SAFETY = {
    "ledger_file_mode": "0600",
    "ledger_hmac": "sha256",
    "ledger_root_mode": "0700",
    "network_proxies": False,
    "network_redirects": False,
    "output_mode": "owner_private",
    "raw_content_publication": False,
    "retention": {
        "maximum_seconds": None,
        "mode": "manual_owner_cleanup",
    },
    "scorer_load_after_all_calls": True,
}
EXPECTED_RESERVATION = {
    "prior_protocol_validation": {
        "attempted_calls": 1,
        "included_in_cumulative_cap": True,
        "spend_status": "unknown",
        "worst_case_list_price_micro_usd": 249344,
    },
    "whole_batch_worst_case": {
        "body_bytes_per_unit": "exact_utf8_request_body_length",
        "input_overhead_tokens_per_unit": 8192,
        "input_tokens_formula": "body_bytes_per_unit+input_overhead_tokens_per_unit",
        "list_price_micro_usd_formula": "input_tokens*input_micro_usd_per_token+output_tokens*output_micro_usd_per_token",
        "output_tokens_per_unit": 4096,
        "sum_all_144_units_before_approval": True,
    }
}
PRIVATE_KEYS = frozenset(
    {
        "answer",
        "api_key",
        "body",
        "capsule",
        "content",
        "headers",
        "prompt",
        "provider_request_id",
        "request",
        "request_id",
        "raw",
        "response",
        "secret",
        "token",
    }
)
_AUTHORIZED_RUN_PROCESS_LOCK = threading.Lock()
_AUTHORIZED_RUN_LOCK_WAIT_SECONDS = 30.0
_SELECTION_SNAPSHOT_LOCK = threading.Lock()
_SELECTION_SNAPSHOT_KEY: tuple[tuple[object, ...], ...] | None = None
_SELECTION_SNAPSHOT: dict[str, dict[str, object]] | None = None


class LiveRunError(RuntimeError):
    """Value-free refusal from the live boundary."""


def refuse(code: str) -> None:
    raise LiveRunError(code)


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
    except LiveRunError:
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


def _hash_declared_artifacts(contract: Mapping[str, object], repo_root: Path) -> None:
    artifacts = contract.get("artifacts")
    if artifacts != EXPECTED_ARTIFACTS:
        refuse("invalid_artifacts")
    for name, declaration in EXPECTED_ARTIFACTS.items():
        path = repo_root / str(declaration["path"])
        _read_bound(path, str(declaration["sha256"]), name)


def validate_contract(contract: dict[str, object], *, repo_root: Path) -> None:
    top = _exact(
        contract,
        {
            "artifacts",
            "claims",
            "destination_allowlist",
            "limits",
            "observer",
            "operation",
            "pricing",
            "provider",
            "reservation",
            "request",
            "resume",
            "runtime",
            "safety",
            "schema_version",
            "status",
        },
        "contract",
    )
    if top["schema_version"] != SCHEMA:
        refuse("invalid_contract")
    if top["claims"] != EXPECTED_CLAIMS:
        refuse("invalid_claims")
    if top["provider"] != EXPECTED_PROVIDER:
        refuse("invalid_provider")
    if top["request"] != EXPECTED_REQUEST:
        refuse("invalid_request")
    if top["resume"] != EXPECTED_RESUME:
        refuse("invalid_resume")
    if top["limits"] != EXPECTED_LIMITS:
        refuse("invalid_limits")
    if top["reservation"] != EXPECTED_RESERVATION:
        refuse("invalid_reservation")
    if top["pricing"] != EXPECTED_PRICING:
        refuse("invalid_pricing")
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
        "surface": "p3-g5-budget-selected-anthropic-api-v4-live",
        "version": "v4",
    }:
        refuse("invalid_operation")
    if top["runtime"] != {
        "client": "python-http.client",
        "proxies": False,
        "redirects": False,
        "tls": "default_verified",
    }:
        refuse("invalid_runtime")
    if top["safety"] != EXPECTED_SAFETY:
        refuse("invalid_safety")
    if top["status"] != "approved_scope_requires_two_fresh_v4_external_envelopes":
        refuse("invalid_status")
    _hash_declared_artifacts(contract, repo_root)


def validate_pricing_window(
    contract: Mapping[str, object], *, observed_date: datetime.date | None = None
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


def _prompt_from_item(item: Mapping[str, object], *, require_identity: bool = False) -> str:
    prompt = item.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        refuse("payload_unavailable")
    prompt_raw = prompt.encode("utf-8", errors="strict")
    if not prompt_raw or len(prompt_raw) > EXPECTED_LIMITS["max_request_bytes"]:
        refuse("request_limit")
    declared = item.get("payload_sha256")
    if require_identity and (not isinstance(declared, str) or sha256(prompt_raw) != declared):
        refuse("payload_identity_mismatch")
    return prompt


def build_request_body(item: Mapping[str, object], *, contract: Mapping[str, object]) -> bytes:
    if (
        contract.get("request") != EXPECTED_REQUEST
        or contract.get("provider") != EXPECTED_PROVIDER
        or contract.get("limits") != EXPECTED_LIMITS
    ):
        refuse("invalid_contract")
    selection = _bound_selection_identity(item)
    prompt = _prompt_from_item(item, require_identity=True)
    if item.get("arm_id") != selection["requested"]["arm_id"]:
        refuse("selection_identity_mismatch")
    raw = canonical(
        {
            "max_tokens": 4096,
            "messages": [{"content": prompt, "role": "user"}],
            "model": "claude-sonnet-5",
        }
    )
    if len(raw) > EXPECTED_LIMITS["max_request_bytes"]:
        refuse("request_limit")
    return raw


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        refuse(label)
    return value


def parse_anthropic_response(
    raw: bytes, *, contract: Mapping[str, object]
) -> dict[str, object]:
    if contract.get("provider") != EXPECTED_PROVIDER or contract.get("limits") != EXPECTED_LIMITS:
        refuse("invalid_contract")
    if type(raw) is not bytes or not raw or len(raw) > EXPECTED_LIMITS["max_response_bytes"]:
        refuse("provider_output_limit")
    value = parse_json(raw, "provider_result")
    if value.get("type") != "message" or value.get("role") != "assistant":
        refuse("malformed_provider_result")
    if value.get("model") != "claude-sonnet-5":
        refuse("model_identity_mismatch")
    message_id = value.get("id")
    if not isinstance(message_id, str) or not message_id or any(
        ord(char) > 127 or ord(char) <= 32 for char in message_id
    ):
        refuse("malformed_provider_result")
    content = value.get("content")
    if type(content) is not list or not content:
        refuse("malformed_provider_result")
    answer_parts: list[str] = []
    saw_text = False
    for block in content:
        if type(block) is not dict:
            refuse("unsupported_provider_content")
        block_type = block.get("type")
        if block_type == "thinking":
            if (
                saw_text
                or set(block) != {"signature", "thinking", "type"}
                or not isinstance(block.get("signature"), str)
                or not isinstance(block.get("thinking"), str)
            ):
                refuse("unsupported_provider_content")
            continue
        if (
            block_type != "text"
            or saw_text
            or set(block) != {"text", "type"}
            or not isinstance(block.get("text"), str)
        ):
            refuse("unsupported_provider_content")
        saw_text = True
        answer_parts.append(block["text"])
    stop_reason = value.get("stop_reason")
    if saw_text:
        if content[-1].get("type") != "text":
            refuse("unsupported_provider_content")
    elif stop_reason != "max_tokens" or any(
        block.get("type") != "thinking" for block in content
    ):
        refuse("unsupported_provider_content")
    answer = "".join(answer_parts)
    if (
        (not answer and stop_reason != "max_tokens")
        or len(answer.encode("utf-8")) > EXPECTED_LIMITS["max_answer_bytes"]
    ):
        refuse("provider_answer_limit")
    usage = value.get("usage")
    if type(usage) is not dict:
        refuse("malformed_provider_usage")
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
    if not set(usage).issubset(allowed_usage) or not {"input_tokens", "output_tokens"}.issubset(usage):
        refuse("malformed_provider_usage")
    for key in ("service_tier", "inference_geo"):
        value = usage.get(key)
        if value is not None and (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 64
        ):
            refuse("malformed_provider_usage")
    cache_creation_detail = usage.get("cache_creation")
    if cache_creation_detail is not None:
        if type(cache_creation_detail) is not dict or not set(cache_creation_detail) <= {
            "ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"
        }:
            refuse("malformed_provider_usage")
        for value in cache_creation_detail.values():
            _nonnegative_int(value, "malformed_provider_usage")
        if any(cache_creation_detail.values()):
            refuse("prompt_cache_observed")
    output_detail = usage.get("output_tokens_details")
    if output_detail is not None:
        if type(output_detail) is not dict or not set(output_detail) <= {
            "text_tokens", "thinking_tokens"
        }:
            refuse("malformed_provider_usage")
        for value in output_detail.values():
            _nonnegative_int(value, "malformed_provider_usage")
    input_tokens = _nonnegative_int(usage["input_tokens"], "malformed_provider_usage")
    output_tokens = _nonnegative_int(usage["output_tokens"], "malformed_provider_usage")
    cache_creation_value = usage.get("cache_creation_input_tokens", 0)
    cache_read_value = usage.get("cache_read_input_tokens", 0)
    cache_creation = 0 if cache_creation_value is None else _nonnegative_int(
        cache_creation_value, "malformed_provider_usage"
    )
    cache_read = 0 if cache_read_value is None else _nonnegative_int(
        cache_read_value, "malformed_provider_usage"
    )
    if cache_creation or cache_read:
        refuse("prompt_cache_observed")
    total_input = input_tokens + cache_creation + cache_read
    list_price = (
        total_input * EXPECTED_PRICING["input_micro_usd_per_token"]
        + output_tokens * EXPECTED_PRICING["output_micro_usd_per_token"]
    )
    return {
        "answer": answer,
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
    item: Mapping[str, object],
    *,
    contract: Mapping[str, object],
    api_key: bytes,
    connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
) -> dict[str, object]:
    secret = validate_api_key(api_key)
    body = build_request_body(item, contract=contract)
    connection: Any = None
    try:
        connection = connection_factory(
            "api.anthropic.com",
            port=443,
            timeout=120,
            context=ssl.create_default_context(),
        )
        connection.request(
            "POST",
            "/v1/messages",
            body=body,
            headers={
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
                "x-api-key": secret,
            },
        )
        response = connection.getresponse()
        raw = response.read(EXPECTED_LIMITS["max_response_bytes"] + 1)
        request_id = None
        getheader = getattr(response, "getheader", None)
        if callable(getheader):
            request_id = getheader("request-id") or getheader("x-request-id")
        if request_id is not None and (
            not isinstance(request_id, str)
            or len(request_id.encode("utf-8")) > 512
            or any(ord(char) < 32 or ord(char) == 127 for char in request_id)
        ):
            refuse("malformed_transport_metadata")
        return {
            "body": raw,
            "http_status": response.status,
            "provider_request_id": request_id,
        }
    except LiveRunError:
        raise
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError):
        refuse("transport_error")
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _normalize_transport_capsule(value: object) -> dict[str, object]:
    if type(value) is bytes:
        return {"body": value, "http_status": 200, "provider_request_id": None}
    if type(value) is not dict or set(value) != {
        "body", "http_status", "provider_request_id"
    }:
        refuse("malformed_transport_capsule")
    body = value["body"]
    status = value["http_status"]
    request_id = value["provider_request_id"]
    if type(body) is not bytes or len(body) > EXPECTED_LIMITS["max_response_bytes"] + 1:
        refuse("malformed_transport_capsule")
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        refuse("malformed_transport_capsule")
    if request_id is not None and (
        not isinstance(request_id, str)
        or len(request_id.encode("utf-8")) > 512
        or any(ord(char) < 32 or ord(char) == 127 for char in request_id)
    ):
        refuse("malformed_transport_capsule")
    return {"body": body, "http_status": status, "provider_request_id": request_id}


def _load_bound_evaluator(contract: Mapping[str, object], repo_root: Path) -> types.ModuleType:
    declaration = EXPECTED_ARTIFACTS["evaluator"]
    path = repo_root / str(declaration["path"])
    raw = _read_bound(path, str(declaration["sha256"]), "evaluator")
    module_name = "contextguard_v4_captured_evaluator"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    sys.modules[module_name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__, module.__dict__)
    except Exception:
        refuse("evaluator_unavailable")
    return module


def _load_bound_approval_module(
    *, contract: Mapping[str, object], repo_root: Path
) -> types.ModuleType:
    core_declaration = EXPECTED_ARTIFACTS["approval_core_v1"]
    declaration = EXPECTED_ARTIFACTS["approval_module"]
    schema_declaration = EXPECTED_ARTIFACTS["approval_schema"]
    schema_raw = _read_bound(
        repo_root / schema_declaration["path"],
        schema_declaration["sha256"],
        "approval_schema",
    )
    parse_json(schema_raw, "approval_schema")
    core_path = repo_root / core_declaration["path"]
    core_raw = _read_bound(
        core_path, core_declaration["sha256"], "approval_core_v1"
    )
    core_module = types.ModuleType("contextguard_v4_captured_external_approval_v1")
    core_module.__file__ = str(core_path)
    sys.modules[core_module.__name__] = core_module
    try:
        exec(
            compile(core_raw, str(core_path), "exec"),
            core_module.__dict__,
            core_module.__dict__,
        )
    except Exception:
        refuse("approval_module_unavailable")
    path = repo_root / declaration["path"]
    raw = _read_bound(path, declaration["sha256"], "approval_module")
    module_name = "contextguard_v4_captured_external_approval"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__dict__["_V1"] = core_module
    sys.modules[module_name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__, module.__dict__)
    except Exception:
        refuse("approval_module_unavailable")
    return module


def _load_pinned_capture(
    *, contract: Mapping[str, object], repo_root: Path, evaluator: types.ModuleType
) -> dict[str, object]:
    declaration = EXPECTED_ARTIFACTS["provider_input_capture"]
    raw = _read_bound(
        repo_root / declaration["path"], declaration["sha256"], "provider_input_capture"
    )
    try:
        capture = evaluator.parse_object(raw, "provider_input_capture")
        evaluator.validate_capture(capture, repo_root=repo_root)
    except Exception:
        refuse("invalid_provider_input_capture")
    return capture


def _load_bound_budget_policy(
    *, repo_root: Path, capture_raw: bytes
) -> tuple[types.ModuleType, dict[str, object]]:
    """Load and validate the exact offline selector and its frozen report."""

    declaration = EXPECTED_ARTIFACTS["budget_policy"]
    path = repo_root / declaration["path"]
    raw = _read_bound(path, declaration["sha256"], "budget_policy")
    module = types.ModuleType("contextguard_v4_budget_policy")
    module.__file__ = str(path)
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__, module.__dict__)
        report_declaration = EXPECTED_ARTIFACTS["budget_policy_report"]
        report = parse_json(
            _read_bound(
                repo_root / report_declaration["path"],
                report_declaration["sha256"],
                "budget_policy_report",
            ),
            "budget_policy_report",
        )
        evidence_declaration = EXPECTED_ARTIFACTS["provider_evidence"]
        result_declaration = EXPECTED_ARTIFACTS["observed_result"]
        module.validate_report(
            report,
            capture_raw=capture_raw,
            evidence_raw=_read_bound(
                repo_root / evidence_declaration["path"],
                evidence_declaration["sha256"],
                "provider_evidence",
            ),
            result_raw=_read_bound(
                repo_root / result_declaration["path"],
                result_declaration["sha256"],
                "observed_result",
            ),
        )
    except LiveRunError:
        raise
    except Exception:
        refuse("invalid_budget_policy")
    if (
        report.get("schema_version") != EXPECTED_POLICY_IDENTITY["schema_version"]
        or not isinstance(report.get("policy"), dict)
        or report["policy"].get("name") != EXPECTED_POLICY_IDENTITY["name"]
    ):
        refuse("invalid_budget_policy")
    return module, report


def _capture_cells(capture: Mapping[str, object]) -> dict[str, dict[str, object]]:
    cells = capture.get("cells")
    if type(cells) is not list or len(cells) != 96:
        refuse("invalid_provider_input_capture")
    by_id: dict[str, dict[str, object]] = {}
    for cell in cells:
        if type(cell) is not dict or not isinstance(cell.get("cell_id"), str):
            refuse("invalid_provider_input_capture")
        by_id[cell["cell_id"]] = cell
    if len(by_id) != 96:
        refuse("invalid_provider_input_capture")
    return by_id


def _selection_identity(
    decision: Mapping[str, object], *, cells_by_id: Mapping[str, Mapping[str, object]]
) -> dict[str, object]:
    requested_cell = cells_by_id.get(decision.get("requested_cell_id"))
    selected_cell = cells_by_id.get(decision.get("selected_cell_id"))
    if type(requested_cell) is not dict or type(selected_cell) is not dict:
        refuse("selection_identity_mismatch")
    expected_requested = {
        "arm_id": decision.get("requested_arm_id"),
        "cell_id": decision.get("requested_cell_id"),
        "prompt_bytes": decision.get("requested_prompt_bytes"),
        "prompt_sha256": requested_cell.get("prompt_sha256"),
    }
    expected_selected = {
        "arm_id": decision.get("selected_arm_id"),
        "cell_id": decision.get("selected_cell_id"),
        "prompt_bytes": decision.get("selected_prompt_bytes"),
        "prompt_sha256": decision.get("selected_prompt_sha256"),
    }
    if (
        requested_cell.get("arm", {}).get("id") != expected_requested["arm_id"]
        or requested_cell.get("prompt_bytes") != expected_requested["prompt_bytes"]
        or selected_cell.get("arm", {}).get("id") != expected_selected["arm_id"]
        or selected_cell.get("prompt_bytes") != expected_selected["prompt_bytes"]
        or selected_cell.get("prompt_sha256") != expected_selected["prompt_sha256"]
        or not isinstance(decision.get("ordinary_prompt_ceiling_bytes"), int)
        or expected_selected["prompt_bytes"] > decision["ordinary_prompt_ceiling_bytes"]
    ):
        refuse("selection_identity_mismatch")
    return {
        "decision_sha256": sha256(canonical(decision)),
        "ordinary_prompt_ceiling_bytes": decision["ordinary_prompt_ceiling_bytes"],
        "policy": copy.deepcopy(EXPECTED_POLICY_IDENTITY),
        "requested": expected_requested,
        "selected": expected_selected,
    }


def _selection_artifact_identity(
    path: Path, expected_sha256: str, label: str
) -> tuple[object, ...]:
    try:
        if path.is_symlink():
            refuse(f"changed_{label}")
        metadata = path.stat()
    except OSError:
        refuse(f"changed_{label}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        refuse(f"changed_{label}")
    return (
        str(path),
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        expected_sha256,
    )


def _bound_selection_snapshot() -> dict[str, dict[str, object]]:
    global _SELECTION_SNAPSHOT_KEY, _SELECTION_SNAPSHOT

    repo_root = Path(__file__).resolve().parents[4]
    declarations = tuple(
        (
            repo_root / EXPECTED_ARTIFACTS[name]["path"],
            EXPECTED_ARTIFACTS[name]["sha256"],
            name,
        )
        for name in (
            "budget_policy",
            "provider_input_capture",
            "budget_policy_report",
        )
    )
    snapshot_key = tuple(
        _selection_artifact_identity(path, expected, label)
        for path, expected, label in declarations
    )
    with _SELECTION_SNAPSHOT_LOCK:
        if snapshot_key == _SELECTION_SNAPSHOT_KEY and _SELECTION_SNAPSHOT is not None:
            return _SELECTION_SNAPSHOT

        _read_bound(*declarations[0])
        capture = parse_json(
            _read_bound(*declarations[1]), "provider_input_capture"
        )
        report = parse_json(
            _read_bound(*declarations[2]), "budget_policy_report"
        )
        decisions = report.get("decisions")
        if type(decisions) is not list:
            refuse("selection_identity_mismatch")
        cells_by_id = _capture_cells(capture)
        snapshot: dict[str, dict[str, object]] = {}
        for decision in decisions:
            if type(decision) is not dict:
                refuse("selection_identity_mismatch")
            requested_cell_id = decision.get("requested_cell_id")
            if not isinstance(requested_cell_id, str) or requested_cell_id in snapshot:
                refuse("selection_identity_mismatch")
            snapshot[requested_cell_id] = _selection_identity(
                decision, cells_by_id=cells_by_id
            )
        if len(snapshot) != len(cells_by_id):
            refuse("selection_identity_mismatch")
        _SELECTION_SNAPSHOT_KEY = snapshot_key
        _SELECTION_SNAPSHOT = snapshot
        return snapshot


def _expected_bound_selection(task_id: object, arm_id: object) -> dict[str, object]:
    selection = _bound_selection_snapshot().get(f"{task_id}:{arm_id}")
    if selection is None:
        refuse("selection_identity_mismatch")
    return copy.deepcopy(selection)


def _bound_selection_identity(item: Mapping[str, object]) -> dict[str, object]:
    """Recheck an item's selection against exact bound V4 policy artifacts."""

    expected = _expected_bound_selection(item.get("task_id"), item.get("arm_id"))
    if item.get("selection_identity") != expected:
        refuse("selection_identity_mismatch")
    prompt = _prompt_from_item(item, require_identity=True)
    prompt_raw = prompt.encode("utf-8", errors="strict")
    selected = expected["selected"]
    if (
        selected["prompt_sha256"] != sha256(prompt_raw)
        or selected["prompt_bytes"] != len(prompt_raw)
        or item.get("payload_sha256") != selected["prompt_sha256"]
    ):
        refuse("selection_identity_mismatch")
    return expected


def _schedule_object(contract: Mapping[str, object], repo_root: Path) -> dict[str, object]:
    declaration = EXPECTED_ARTIFACTS["schedule"]
    raw = _read_bound(repo_root / declaration["path"], declaration["sha256"], "schedule")
    return parse_json(raw, "schedule")


def _request_identity(item: Mapping[str, object]) -> str:
    identity = {
        "arm_id": item.get("arm_id"),
        "payload_sha256": item.get("payload_sha256"),
        "repetition": item.get("repetition"),
        "scheduled_unit_id": item.get("scheduled_unit_id"),
        "selection_identity": item.get("selection_identity"),
        "task_id": item.get("task_id"),
    }
    return "v4-request-" + sha256(
        b"contextguard/p3-v4-request-identity/v1\0" + canonical(identity)
    )


def _validate_plan(plan: object) -> list[dict[str, object]]:
    if type(plan) is not list or len(plan) != EXPECTED_LIMITS["scheduled_units"]:
        refuse("invalid_schedule_cardinality")
    result: list[dict[str, object]] = []
    unit_ids: set[str] = set()
    request_ids: set[str] = set()
    for item in plan:
        if type(item) is not dict:
            refuse("invalid_schedule")
        for key in (
            "scheduled_unit_id", "task_id", "arm_id", "repetition", "prompt",
            "payload_sha256", "selection_identity",
        ):
            if key not in item:
                refuse("invalid_schedule")
        unit_id = item["scheduled_unit_id"]
        if not isinstance(unit_id, str) or not unit_id or unit_id in unit_ids:
            refuse("invalid_schedule")
        unit_ids.add(unit_id)
        if not isinstance(item["task_id"], str) or not isinstance(item["arm_id"], str):
            refuse("invalid_schedule")
        if (
            isinstance(item["repetition"], bool)
            or not isinstance(item["repetition"], int)
            or not 0 <= item["repetition"] <= 2
        ):
            refuse("invalid_schedule")
        _bound_selection_identity(item)
        request_id = item.get("request_id")
        expected_request_id = _request_identity(item)
        if request_id is None:
            request_id = expected_request_id
        if request_id != expected_request_id or not isinstance(request_id, str) or request_id in request_ids:
            refuse("request_identity_mismatch")
        request_ids.add(request_id)
        result.append({**item, "request_id": request_id})
    return result


def build_batch_plans(plan: object) -> list[dict[str, object]]:
    """Bind a frozen plan into exactly two immutable 144-unit batch views."""

    validated = _validate_plan(plan)
    batches: list[dict[str, object]] = []
    for index in range(EXPECTED_LIMITS["batch_count"]):
        start = index * EXPECTED_LIMITS["batch_units"]
        items = validated[start : start + EXPECTED_LIMITS["batch_units"]]
        if len(items) != EXPECTED_LIMITS["batch_units"]:
            refuse("invalid_batch_cardinality")
        projection = [
            {
                key: item[key]
                for key in (
                    "arm_id",
                    "payload_sha256",
                    "repetition",
                    "request_id",
                    "scheduled_unit_id",
                    "selection_identity",
                    "task_id",
                )
            }
            for item in items
        ]
        batches.append({
            "batch_id": f"batch-{index + 1}",
            "batch_index": index + 1,
            "plan_sha256": sha256(canonical(projection)),
            "unit_ids": [item["scheduled_unit_id"] for item in items],
            "items": items,
        })
    return batches


def calculate_worst_case_reservation(
    *, contract: Mapping[str, object], batches: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Reserve list-price headroom before any approval or provider dispatch."""

    if contract.get("reservation") != EXPECTED_RESERVATION:
        refuse("invalid_reservation")
    if type(batches) not in {list, tuple} or len(batches) != EXPECTED_LIMITS["batch_count"]:
        refuse("invalid_batch_cardinality")
    batch_costs: list[dict[str, object]] = []
    prior = EXPECTED_RESERVATION["prior_protocol_validation"]
    cumulative = prior["worst_case_list_price_micro_usd"]
    for batch in batches:
        units = batch.get("items")
        if type(units) is not list or len(units) != EXPECTED_LIMITS["batch_units"]:
            refuse("invalid_batch_cardinality")
        unit_costs: list[int] = []
        body_lengths: list[int] = []
        for item in units:
            body_bytes = len(build_request_body(item, contract=contract))
            body_lengths.append(body_bytes)
            input_tokens = body_bytes + EXPECTED_RESERVATION["whole_batch_worst_case"][
                "input_overhead_tokens_per_unit"
            ]
            output_tokens = EXPECTED_RESERVATION["whole_batch_worst_case"][
                "output_tokens_per_unit"
            ]
            unit_costs.append(
                input_tokens * EXPECTED_PRICING["input_micro_usd_per_token"]
                + output_tokens * EXPECTED_PRICING["output_micro_usd_per_token"]
            )
        batch_total = sum(unit_costs)
        cumulative += batch_total
        batch_costs.append({
            "batch_id": batch["batch_id"],
            "body_bytes_total": sum(body_lengths),
            "worst_case_list_price_micro_usd": batch_total,
            "unit_count": len(units),
        })
    if any(
        item["worst_case_list_price_micro_usd"]
        > 20_000_000
        for item in batch_costs
    ):
        refuse("worst_case_batch_reservation_exceeded")
    if cumulative > 40_000_000:
        refuse("worst_case_cumulative_reservation_exceeded")
    return {
        "batches": batch_costs,
        "cumulative_worst_case_list_price_micro_usd": cumulative,
        "formula": copy.deepcopy(EXPECTED_RESERVATION["whole_batch_worst_case"]),
        "prior_protocol_validation": copy.deepcopy(prior),
    }


def build_request_plan(
    *,
    contract: Mapping[str, object],
    schedule: Mapping[str, object],
    capture: Mapping[str, object],
    capture_raw: bytes,
    prompt_by_cell: Mapping[str, bytes],
    budget_policy: types.ModuleType,
) -> list[dict[str, object]]:
    """Map requested schedule cells to exact policy-selected provider prompts."""

    if contract.get("limits") != EXPECTED_LIMITS:
        refuse("invalid_contract")
    cells_by_id = _capture_cells(capture)
    blocks = schedule.get("blocks")
    if type(blocks) is not list:
        refuse("invalid_schedule")
    plan: list[dict[str, object]] = []
    for block in blocks:
        if type(block) is not dict or type(block.get("units")) is not list:
            refuse("invalid_schedule")
        for unit in block["units"]:
            if type(unit) is not dict:
                refuse("invalid_schedule")
            unit_id = unit.get("unit_id")
            task_id = unit.get("task_id")
            requested_arm_id = unit.get("arm_id")
            try:
                decision = budget_policy.select_provider_cell(
                    capture_raw,
                    task_id=task_id,
                    requested_arm_id=requested_arm_id,
                )
            except Exception:
                refuse("selection_unavailable")
            if type(decision) is not dict:
                refuse("selection_unavailable")
            selection = _selection_identity(decision, cells_by_id=cells_by_id)
            selected_cell_id = selection["selected"]["cell_id"]
            raw = prompt_by_cell.get(selected_cell_id)
            if type(raw) is not bytes:
                refuse("payload_unavailable")
            if (
                sha256(raw) != selection["selected"]["prompt_sha256"]
                or len(raw) != selection["selected"]["prompt_bytes"]
                or len(raw) > selection["ordinary_prompt_ceiling_bytes"]
            ):
                refuse("payload_identity_mismatch")
            try:
                prompt = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                refuse("payload_unavailable")
            item = {
                # The requested arm remains the scorer/factorial identity.
                "arm_id": requested_arm_id,
                "prompt": prompt,
                "payload_sha256": selection["selected"]["prompt_sha256"],
                "repetition": unit.get("repetition"),
                "scheduled_unit_id": unit_id,
                "selection_identity": selection,
                "task_id": task_id,
            }
            item["request_id"] = _request_identity(item)
            plan.append(item)
    return _validate_plan(plan)


def prepare_live_plan(
    *, contract: Mapping[str, object], repo_root: Path, corpus_root: Path
) -> list[dict[str, object]]:
    """Prepare provider prompts through the committed evaluator only.

    The scorer-only checker is intentionally never opened here.  The returned
    prompt text is private and is consumed immediately by the live gate.
    """

    validate_contract(dict(contract), repo_root=repo_root)
    evaluator = _load_bound_evaluator(contract, repo_root)
    capture_declaration = EXPECTED_ARTIFACTS["provider_input_capture"]
    capture_raw = _read_bound(
        repo_root / capture_declaration["path"],
        capture_declaration["sha256"],
        "provider_input_capture",
    )
    capture = _load_pinned_capture(
        contract=contract, repo_root=repo_root, evaluator=evaluator
    )
    budget_policy, _report = _load_bound_budget_policy(
        repo_root=repo_root, capture_raw=capture_raw
    )
    try:
        task_contexts, _corpus = evaluator.preflight_sources(corpus_root)
        packer_bytes = evaluator.CANONICAL_PACKER.read_bytes()
        sanitizer_bytes = evaluator.CANONICAL_SANITIZER.read_bytes()
        credential_policy_bytes = evaluator.CANONICAL_CREDENTIAL_POLICY.read_bytes()
    except Exception:
        refuse("corpus_unavailable")
    prompts_by_cell: dict[str, bytes] = {}
    cells: list[dict[str, object]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="contextguard-v4-live-") as directory:
            temp_root = Path(directory)
            for task_id in sorted(task_contexts):
                context = task_contexts[task_id]
                task = context["task"]
                inventory = context["inventory"]
                snapshot = temp_root / "snapshots" / task_id
                evaluator.export_snapshot(context["repo"], task["parent_commit"], inventory, snapshot)
                identity = evaluator.inventory_identity(inventory)
                metadata = {
                    "inventory_file_count": identity["file_count"],
                    "inventory_sha256": identity["sha256"],
                    "inventory_source_bytes": identity["source_bytes"],
                    "parent_commit": task["parent_commit"],
                    "parent_tree_sha": task["parent_tree_sha"],
                    "project_id": task["project_id"],
                    "task_id": task_id,
                }
                task_cells, task_prompts = evaluator.capture_task_cells(
                    task=task,
                    workspace=snapshot,
                    packer_bytes=packer_bytes,
                    sanitizer_bytes=sanitizer_bytes,
                    credential_policy_bytes=credential_policy_bytes,
                    source_metadata=metadata,
                )
                cells.extend(task_cells)
                prompts_by_cell.update(task_prompts)
    except Exception:
        refuse("prompt_preparation_failed")
    cells.sort(key=lambda item: item["cell_id"])
    if cells != capture["cells"]:
        refuse("provider_input_regeneration_mismatch")
    try:
        bindings = evaluator.schedule_bindings(cells)
    except Exception:
        refuse("schedule_binding_failed")
    if len(bindings) != EXPECTED_LIMITS["scheduled_units"]:
        refuse("invalid_schedule_cardinality")
    if bindings != capture["prepared_unit_bindings"]:
        refuse("schedule_binding_regeneration_mismatch")
    return build_request_plan(
        contract=contract,
        schedule=_schedule_object(contract, repo_root),
        capture=capture,
        capture_raw=capture_raw,
        prompt_by_cell=prompts_by_cell,
        budget_policy=budget_policy,
    )


# Explicit aliases make the preparation boundary readable to callers without
# creating a second implementation or an unbound prompt path.
prepare_request_plan = prepare_live_plan


def _bound_scorer_loader(
    *, contract: Mapping[str, object], repo_root: Path, corpus_root: Path
) -> Callable[[], object]:
    """Return a deferred scorer bound to the pinned evaluator and corpus."""

    def load() -> object:
        evaluator = _load_bound_evaluator(contract, repo_root)
        capture = _load_pinned_capture(
            contract=contract, repo_root=repo_root, evaluator=evaluator
        )
        try:
            report_declaration = EXPECTED_ARTIFACTS["rehearsal_report"]
            report_raw = _read_bound(
                repo_root / report_declaration["path"],
                report_declaration["sha256"],
                "rehearsal_report",
            )
            report = evaluator.parse_object(report_raw, "rehearsal_report")
            evaluator.validate_report(report, capture=capture, repo_root=repo_root)
            checkers, artifact = evaluator.load_scorer_contract(
                capture, repo_root=repo_root
            )
            task_contexts, _corpus = evaluator.preflight_sources(corpus_root)
        except Exception:
            refuse("scorer_unavailable")

        def score(
            capsules: Mapping[str, Mapping[str, object] | None],
            plan: Sequence[Mapping[str, object]],
        ) -> dict[str, object]:
            passed = 0
            failed = 0
            exact_historical_patch_units = 0
            for item in plan:
                capsule = capsules.get(item["scheduled_unit_id"])
                context = task_contexts.get(item["task_id"])
                checker = checkers.get(item["task_id"])
                if capsule is None or context is None or checker is None:
                    failed += 1
                    continue
                parsed = parse_anthropic_response(
                    capsule["body"], contract=contract
                )
                raw = parsed["answer"].encode("utf-8")
                task = context["task"]
                try:
                    changed = evaluator.validate_patch_envelope(
                        raw, set(task["allowed_patch_paths"])
                    )
                    historical = evaluator.selected_patch(context["repo"], task)
                    exact_historical_patch = raw == historical
                    with tempfile.TemporaryDirectory(prefix="contextguard-v4-score-") as directory:
                        workspace = Path(directory) / "workspace"
                        evaluator.export_snapshot(
                            context["repo"], task["parent_commit"], context["inventory"], workspace
                        )
                        evaluator.run_git(
                            workspace, ["apply", "--check", "-"], input_bytes=raw
                        )
                        evaluator.run_git(workspace, ["apply", "-"], input_bytes=raw)
                        if not evaluator.assertions_pass(workspace, checker):
                            failed += 1
                            continue
                        if changed:
                            passed += 1
                            if exact_historical_patch:
                                exact_historical_patch_units += 1
                        else:
                            failed += 1
                except Exception:
                    failed += 1
            return {
                "exact_historical_patch_units": exact_historical_patch_units,
                "failed_units": failed,
                "passed_units": passed,
                "scorer_artifact_sha256": artifact["sha256"],
                "status": "complete",
                "total_units": len(plan),
            }

        return score

    return load


def _private_dir(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        refuse("private_root_unavailable")
    try:
        if path.is_symlink():
            refuse("private_root_unavailable")
        if not path.exists():
            path.mkdir(mode=0o700, parents=False)
        metadata = path.stat()
    except OSError:
        refuse("private_root_unavailable")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        refuse("private_root_unavailable")


def _with_authorized_run_lock(
    output_root: Path,
    operation: Callable[[], object],
    *,
    wait_timeout_seconds: float = _AUTHORIZED_RUN_LOCK_WAIT_SECONDS,
) -> object:
    """Serialize authorized runs sharing an approval-bound output root."""

    if (
        not callable(operation)
        or isinstance(wait_timeout_seconds, bool)
        or not isinstance(wait_timeout_seconds, (int, float))
        or not math.isfinite(float(wait_timeout_seconds))
        or wait_timeout_seconds < 0
        or wait_timeout_seconds > _AUTHORIZED_RUN_LOCK_WAIT_SECONDS
    ):
        refuse("callback_unavailable")
    _private_dir(output_root)
    lock_path = output_root / ".authorized-run.lock"
    deadline = time.monotonic() + float(wait_timeout_seconds)
    if not _AUTHORIZED_RUN_PROCESS_LOCK.acquire(timeout=float(wait_timeout_seconds)):
        refuse("authorization_busy")
    try:
        descriptor = -1
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                refuse("authorization_unavailable")
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        refuse("authorization_busy")
                    time.sleep(min(0.05, remaining))
        except LiveRunError:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        except OSError:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            refuse("authorization_unavailable")
        try:
            if descriptor < 0:
                refuse("authorization_unavailable")
            return operation()
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(descriptor)
            except OSError:
                pass
    finally:
        _AUTHORIZED_RUN_PROCESS_LOCK.release()


def _private_file(path: Path, data: bytes) -> None:
    try:
        if path.exists() or path.is_symlink():
            refuse("private_state_exists")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    raise OSError("short private write")
                offset += written
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
    except LiveRunError:
        raise
    except OSError:
        refuse("private_state_unavailable")


def _capsule_stem(unit_id: str) -> str:
    return "capsule-" + sha256(unit_id.encode("utf-8"))


def _write_transport_capsule(
    private_root: Path,
    unit_id: str,
    capsule: Mapping[str, object],
    ledger_key: bytes,
    identity: Mapping[str, object],
) -> dict[str, object]:
    body = capsule["body"]
    metadata = {
        "arm_id": identity["arm_id"],
        "body_bytes": len(body),
        "body_sha256": sha256(body),
        "http_status": capsule["http_status"],
        "provider_request_id": capsule["provider_request_id"],
        "repetition": identity["repetition"],
        "request_id": identity["request_id"],
        "scheduled_unit_id": identity["scheduled_unit_id"],
        "selection_identity": copy.deepcopy(identity["selection_identity"]),
        "task_id": identity["task_id"],
    }
    metadata["capsule_hmac_sha256"] = hmac.new(
        ledger_key,
        b"contextguard/p3-v4-transport-capsule/v1\0"
        + canonical(metadata),
        hashlib.sha256,
    ).hexdigest()
    stem = _capsule_stem(unit_id)
    _private_file(private_root / (stem + ".body"), body)
    _private_file(private_root / (stem + ".json"), canonical(metadata))
    return metadata


def _read_transport_capsule(
    private_root: Path,
    unit_id: str,
    ledger_key: bytes,
    identity: Mapping[str, object],
) -> dict[str, object] | None:
    stem = _capsule_stem(unit_id)
    body_path = private_root / (stem + ".body")
    metadata_path = private_root / (stem + ".json")
    if body_path.is_symlink() or metadata_path.is_symlink():
        refuse("private_state_unavailable")
    if not body_path.exists() or not metadata_path.exists():
        return None
    try:
        body_metadata = body_path.stat()
        json_metadata = metadata_path.stat()
        if (
            not stat.S_ISREG(body_metadata.st_mode)
            or not stat.S_ISREG(json_metadata.st_mode)
            or body_metadata.st_nlink != 1
            or json_metadata.st_nlink != 1
            or stat.S_IMODE(body_metadata.st_mode) != 0o600
            or stat.S_IMODE(json_metadata.st_mode) != 0o600
        ):
            refuse("private_state_unavailable")
        body = body_path.read_bytes()
        metadata = parse_json(metadata_path.read_bytes(), "transport_capsule")
    except OSError:
        refuse("private_state_unavailable")
    if set(metadata) != {
        "arm_id", "body_bytes", "body_sha256", "capsule_hmac_sha256",
        "http_status", "provider_request_id", "repetition", "request_id",
        "scheduled_unit_id", "selection_identity", "task_id",
    }:
        refuse("malformed_transport_capsule")
    if (
        metadata["body_bytes"] != len(body)
        or metadata["body_sha256"] != sha256(body)
        or any(metadata[key] != identity[key] for key in (
            "arm_id", "repetition", "request_id", "scheduled_unit_id",
            "selection_identity", "task_id"
        ))
    ):
        refuse("malformed_transport_capsule")
    supplied_hmac = metadata["capsule_hmac_sha256"]
    unsigned = {
        key: value for key, value in metadata.items() if key != "capsule_hmac_sha256"
    }
    expected_hmac = hmac.new(
        ledger_key,
        b"contextguard/p3-v4-transport-capsule/v1\0" + canonical(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(supplied_hmac, str) or not hmac.compare_digest(
        supplied_hmac, expected_hmac
    ):
        refuse("transport_capsule_tampered")
    return _normalize_transport_capsule({
        "body": body,
        "http_status": metadata["http_status"],
        "provider_request_id": metadata["provider_request_id"],
    })


def _derive_ledger_key(registry_key: bytes) -> bytes:
    if type(registry_key) is not bytes or len(registry_key) < 32:
        refuse("ledger_key_unavailable")
    return hmac.new(
        registry_key,
        b"contextguard/p3-v4-ledger-hmac/v1\0",
        hashlib.sha256,
    ).digest()


def _read_owner_private_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        refuse("private_state_unavailable")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > maximum_bytes
        ):
            refuse("private_state_unavailable")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            refuse("private_state_unavailable")
        return raw
    finally:
        os.close(descriptor)


def _copy_owner_private_exact(source: Path, target: Path, *, maximum_bytes: int) -> None:
    raw = _read_owner_private_bytes(source, maximum_bytes=maximum_bytes)
    if target.exists() or target.is_symlink():
        if _read_owner_private_bytes(target, maximum_bytes=maximum_bytes) != raw:
            refuse("migration_target_mismatch")
        return
    _private_file(target, raw)


def _migrate_verified_capsules_core(
    *,
    contract: Mapping[str, object],
    plan: object,
    previous_state_root: Path,
    previous_output_root: Path,
    state_root: Path,
    output_root: Path,
    registry_key: bytes,
    expected_resume: Mapping[str, object],
) -> None:
    refuse("cross_version_migration_unavailable")
    expected_keys = {
        "failed_response_sha256", "policy", "previous_ledger_contract_sha256",
        "previous_plan_sha256", "sealed_provider_receipt_count",
    }
    if (
        type(expected_resume) is not dict
        or set(expected_resume) != expected_keys
        or expected_resume.get("policy")
        != "hmac_verify_sealed_capsules_without_redispatch"
    ):
        refuse("invalid_resume")
    validated_plan = _validate_plan(plan)
    batches = build_batch_plans(validated_plan)
    plan_sha = _plan_digest(batches)
    if plan_sha != expected_resume["previous_plan_sha256"]:
        refuse("migration_plan_mismatch")
    item_by_id = {item["scheduled_unit_id"]: item for item in validated_plan}
    if previous_state_root == state_root or previous_output_root == output_root:
        refuse("migration_root_mismatch")
    ledger_key = _derive_ledger_key(registry_key)
    previous = _ledger_snapshot(previous_state_root, ledger_key)
    if (
        previous.get("schema_version") != "contextguard.p3-v4-ledger/v1"
        or previous.get("contract_sha256")
        != expected_resume["previous_ledger_contract_sha256"]
        or previous.get("plan_sha256") != plan_sha
        or previous.get("spend_status") != "unknown"
    ):
        refuse("migration_source_mismatch")
    previous_units = previous.get("units")
    if type(previous_units) is not dict or set(previous_units) != set(item_by_id):
        refuse("migration_source_mismatch")
    dispatched: list[tuple[str, dict[str, object]]] = []
    for candidate_id, unit in previous_units.items():
        terminal = unit.get("terminal") if type(unit) is dict else None
        if type(terminal) is not dict:
            refuse("migration_source_mismatch")
        if terminal.get("dispatched"):
            dispatched.append((candidate_id, terminal))
        elif unit.get("status") != "not_dispatched_spend_unknown":
            refuse("migration_source_mismatch")
    expected_count = expected_resume["sealed_provider_receipt_count"]
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count < 1
        or len(dispatched) != expected_count
    ):
        refuse("migration_source_mismatch")
    previous_private = previous_output_root / "private"
    failed_matches = 0
    migrated_ids: list[str] = []
    for unit_id, terminal in dispatched:
        item = item_by_id.get(unit_id)
        if item is None or terminal.get("http_status") != 200:
            refuse("migration_source_mismatch")
        response_sha = terminal.get("response_sha256")
        if response_sha == expected_resume["failed_response_sha256"]:
            failed_matches += 1
            if (
                terminal.get("status") != "failed"
                or terminal.get("completion_event") != "provider_receipt_missing"
            ):
                refuse("migration_source_mismatch")
        elif (
            terminal.get("status") != "completed"
            or terminal.get("completion_event") != "normal_completion"
        ):
            refuse("migration_source_mismatch")
        capsule = _read_transport_capsule(
            previous_private, unit_id, ledger_key, item
        )
        if capsule is None or sha256(capsule["body"]) != response_sha:
            refuse("migration_source_mismatch")
        status, _error, parsed = _classify_capsule(capsule, contract=contract)
        if status != "completed" or parsed is None:
            refuse("migration_reclassification_failed")
        migrated_ids.append(unit_id)
    if failed_matches != 1:
        refuse("migration_source_mismatch")

    _private_dir(state_root)
    _private_dir(output_root)
    private_root = output_root / "private"
    _private_dir(private_root)
    for unit_id in migrated_ids:
        stem = _capsule_stem(unit_id)
        _copy_owner_private_exact(
            previous_private / (stem + ".body"),
            private_root / (stem + ".body"),
            maximum_bytes=EXPECTED_LIMITS["max_response_bytes"],
        )
        _copy_owner_private_exact(
            previous_private / (stem + ".json"),
            private_root / (stem + ".json"),
            maximum_bytes=65536,
        )
    reservation = calculate_worst_case_reservation(
        contract=contract, batches=batches
    )
    migration = {
        "policy": expected_resume["policy"],
        "previous_ledger_contract_sha256": expected_resume[
            "previous_ledger_contract_sha256"
        ],
        "failed_response_sha256": expected_resume["failed_response_sha256"],
        "sealed_provider_receipt_count": expected_count,
        "status": "verified_capsules_ready_for_reclassification",
    }

    def initialize(state: dict[str, object], _key: bytes) -> None:
        _initialize_ledger(
            state,
            contract=contract,
            batches=batches,
            plan_sha256=plan_sha,
            reservation=reservation,
        )
        if state.get("migration") is not None:
            if state["migration"] != migration:
                refuse("migration_target_mismatch")
            for unit_id in migrated_ids:
                migrated_unit = state["units"].get(unit_id)
                if type(migrated_unit) is not dict or migrated_unit.get("status") not in {
                    "reserved", "completed",
                }:
                    refuse("migration_target_mismatch")
            return
        for unit_id in migrated_ids:
            migrated_unit = state["units"].get(unit_id)
            if type(migrated_unit) is not dict or migrated_unit.get("status") != "pending":
                refuse("migration_target_mismatch")
            migrated_unit["reserved"] = True
            migrated_unit["status"] = "reserved"
        state["migration"] = migration

    _with_ledger(state_root, ledger_key, initialize)
    for unit_id in migrated_ids:
        if _read_transport_capsule(
            private_root, unit_id, ledger_key, item_by_id[unit_id]
        ) is None:
            refuse("migration_target_mismatch")


def _migrate_verified_capsules(
    *,
    contract: Mapping[str, object],
    plan: object,
    previous_state_root: Path,
    previous_output_root: Path,
    state_root: Path,
    output_root: Path,
    registry_key: bytes,
) -> None:
    del (
        contract, plan, previous_state_root, previous_output_root, state_root,
        output_root, registry_key,
    )
    refuse("cross_version_migration_unavailable")


def _ledger_seal(value: Mapping[str, object], key: bytes) -> str:
    return hmac.new(key, b"contextguard/p3-v4-ledger/v1\0" + canonical(value), hashlib.sha256).hexdigest()


def _ledger_load(state_root: Path, key: bytes) -> dict[str, object] | None:
    path = state_root / "ledger.json"
    if not path.exists():
        return None
    try:
        metadata = path.stat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600:
            refuse("ledger_unavailable")
        value = parse_json(path.read_bytes(), "ledger")
    except OSError:
        refuse("ledger_unavailable")
    supplied = value.pop("hmac_sha256", None)
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, _ledger_seal(value, key)):
        refuse("ledger_tampered")
    value["hmac_sha256"] = supplied
    return value


def _ledger_write(state_root: Path, value: dict[str, object], key: bytes) -> None:
    unsigned = {key_name: child for key_name, child in value.items() if key_name != "hmac_sha256"}
    value = copy.deepcopy(unsigned)
    value["hmac_sha256"] = _ledger_seal(unsigned, key)
    target = state_root / "ledger.json"
    temporary = state_root / f".ledger.{os.getpid()}.tmp"
    try:
        if temporary.exists() or temporary.is_symlink():
            refuse("ledger_unavailable")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            raw = canonical(value)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short ledger write")
                offset += written
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, target)
        os.chmod(target, 0o600)
        directory_fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except LiveRunError:
        raise
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        refuse("ledger_unavailable")


def _with_ledger(
    state_root: Path,
    ledger_key: bytes,
    fn: Callable[[dict[str, object], bytes], object],
    *,
    write_back: bool = True,
) -> object:
    _private_dir(state_root)
    lock_path = state_root / "ledger.lock"
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError:
        refuse("ledger_unavailable")
    try:
        state = _ledger_load(state_root, ledger_key)
        if state is None:
            state = {}
        result = fn(state, ledger_key)
        if state and write_back:
            _ledger_write(state_root, state, ledger_key)
        return result
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        except OSError:
            pass


def _empty_usage() -> dict[str, int]:
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


def _public_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        result = {str(key).lower() for key in value}
        for child in value.values():
            result.update(_public_keys(child))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for child in value:
            result.update(_public_keys(child))
        return result
    return set()


def _runner_identity() -> str:
    path = Path(__file__).resolve()
    try:
        metadata = path.stat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            refuse("changed_runner")
        raw = path.read_bytes()
    except OSError:
        refuse("changed_runner")
    return sha256(raw)


def _scope(
    contract: Mapping[str, object],
    batch: Mapping[str, object],
    plan_sha256: str,
    runner_sha256: str,
) -> dict[str, object]:
    items = batch["items"]
    return {
        "batch_id": batch["batch_id"],
        "batch_index": batch["batch_index"],
        "body_sha256": [sha256(build_request_body(item, contract=contract)) for item in items],
        "destination": {"host": "api.anthropic.com", "port": 443, "scheme": "https"},
        "limits": {
            "call_cap": 144,
            "currency": "USD",
            "spend_cap_usd": "20.00",
            "timeout_seconds": 120,
        },
        "model_id": "claude-sonnet-5",
        "plan_sha256": plan_sha256,
        "request_count": 144,
        "request_ids": [item["request_id"] for item in items],
        "runner_sha256": runner_sha256,
        "selection_identities": [
            copy.deepcopy(item["selection_identity"]) for item in items
        ],
        "surface": "p3-g5-budget-selected-anthropic-api-v4-live",
        "unit_ids": list(batch["unit_ids"]),
    }


def _external_scope(
    *,
    contract: Mapping[str, object],
    batch: Mapping[str, object],
    plan_sha256: str,
    runner_sha256: str,
    output_root: Path,
) -> dict[str, object]:
    """Build exactly the pinned external-approval schema scope."""

    items = batch["items"]
    argv_projection = [
        {
            "body_sha256": sha256(build_request_body(item, contract=contract)),
            "method": "POST",
            "path": "/v1/messages",
            "request_id": item["request_id"],
            "selection_identity": copy.deepcopy(item["selection_identity"]),
        }
        for item in items
    ]
    source_candidate = {
        "artifact_ids": [
            "p3-v4-budget-policy",
            "p3-v4-budget-policy-report",
            "p3-v4-provider-input-capture",
            "p3-v4-schedule",
        ],
        "checksums_sha256": sha256(canonical(EXPECTED_ARTIFACTS)),
        "commit_sha": "f90486837269d3a74279422cb44542ded03878e2",
        "manifest_sha256": EXPECTED_ARTIFACTS["corpus"]["sha256"],
    }
    receipt_schema = "contextguard.g5-authoritative-observation/v1"
    return {
        "source_candidate": source_candidate,
        "provider": {
            "model_id": "claude-sonnet-5",
            "provider_id": "anthropic-first-party",
        },
        "observer": {
            "observer_id": "anthropic-messages-json-v1",
            "phase": "P3",
            "receipt_schema": receipt_schema,
            "surface_id": "anthropic-messages-api/v1",
        },
        "operation": {
            "receipt_schema": receipt_schema,
            "surface_id": "p3-g5-budget-selected-anthropic-api-v4-live",
            "version": "v4",
        },
        "runtime": {
            "argv_sha256": sha256(
                b"contextguard/p3-v4-approval-argv/v1\0" + canonical(argv_projection)
            ),
            "environment_sha256": sha256(
                canonical({
                    "client": "python-http.client",
                    "proxies": False,
                    "redirects": False,
                    "tls": "default_verified",
                })
            ),
            "executable_sha256": runner_sha256,
            "identity": "python-http.client-p3-v4-live",
            "version": "v4",
        },
        "credential": {
            "consumer_id": "anthropic-messages-api",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": [
            {"host": "api.anthropic.com", "port": 443, "scheme": "https"}
        ],
        "network_policy": {"proxies_allowed": False, "redirects_allowed": False},
        "limits": {
            "call_cap": 144,
            "currency": "USD",
            "spend_cap": "20.00",
            "timeout_seconds": 120,
        },
        "output": {"mode": "owner_private", "root": str(output_root)},
        "retention": copy.deepcopy(EXPECTED_SAFETY["retention"]),
    }


def build_external_approval_scope(
    *,
    contract: Mapping[str, object],
    batch: Mapping[str, object],
    plan_sha256: str,
    runner_sha256: str,
    output_root: Path,
) -> dict[str, object]:
    return _external_scope(
        contract=contract,
        batch=batch,
        plan_sha256=plan_sha256,
        runner_sha256=runner_sha256,
        output_root=output_root,
    )


def _plan_digest(batches: list[dict[str, object]]) -> str:
    projection = [
        {
            "batch_id": batch["batch_id"],
            "batch_index": batch["batch_index"],
            "plan_sha256": batch["plan_sha256"],
            "unit_ids": batch["unit_ids"],
        }
        for batch in batches
    ]
    return sha256(b"contextguard/p3-v4-request-plan/v1\0" + canonical(projection))


def request_plan_sha256(plan: object) -> str:
    """Return the sealed identity used by both approval scopes and the ledger."""

    return _plan_digest(build_batch_plans(plan))


def build_approval_scope(
    *,
    contract: Mapping[str, object],
    batch: Mapping[str, object],
    plan_sha256: str,
    runner_sha256: str | None = None,
) -> dict[str, object]:
    """Build the metadata-only, closed approval callback argument."""

    return _scope(
        contract,
        batch,
        plan_sha256,
        runner_sha256 or _runner_identity(),
    )


def _initialize_ledger(
    state: dict[str, object],
    *,
    contract: Mapping[str, object],
    batches: list[dict[str, object]],
    plan_sha256: str,
    reservation: Mapping[str, object],
) -> None:
    if state:
        if state.get("schema_version") != "contextguard.p3-v4-ledger/v1":
            refuse("ledger_schema_mismatch")
        if state.get("contract_sha256") != sha256(canonical(contract)) or state.get("plan_sha256") != plan_sha256:
            refuse("ledger_plan_mismatch")
        if state.get("reservation") != reservation:
            refuse("ledger_reservation_mismatch")
        return
    units: dict[str, object] = {}
    for batch in batches:
        for item in batch["items"]:
            units[item["scheduled_unit_id"]] = {
                "arm_id": item["arm_id"],
                "batch_id": batch["batch_id"],
                "repetition": item["repetition"],
                "request_id": item["request_id"],
                "reserved": False,
                "selection_identity": copy.deepcopy(item["selection_identity"]),
                "task_id": item["task_id"],
                "status": "pending",
            }
    state.update({
        "batches": {
            batch["batch_id"]: {
                "authorization": None,
                "authorization_journal": None,
                "status": "pending",
                "unit_ids": list(batch["unit_ids"]),
            }
            for batch in batches
        },
        "contract_sha256": sha256(canonical(contract)),
        "evidence_sha256": None,
        "plan_sha256": plan_sha256,
        "pending_evidence_sha256": None,
        "reservation": copy.deepcopy(reservation),
        "schema_version": "contextguard.p3-v4-ledger/v1",
        "spend_status": EXPECTED_RESERVATION["prior_protocol_validation"]["spend_status"],
        "status": "pending",
        "token_usage": _empty_usage(),
        "units": units,
    })


def _authorize_batch(
    state_root: Path,
    ledger_key: bytes,
    batch: Mapping[str, object],
    authorization: Mapping[str, object],
) -> None:
    def authorize(state: dict[str, object], key: bytes) -> None:
        del key
        batch_states = state.get("batches")
        if type(batch_states) is not dict:
            refuse("ledger_schema_mismatch")
        batch_id = batch["batch_id"]
        batch_state = batch_states.get(batch_id)
        if type(batch_state) is not dict:
            refuse("ledger_schema_mismatch")
        if batch_state.get("status") == "terminal":
            return
        if batch_state.get("status") == "authorized":
            return
        if batch_state.get("status") != "pending":
            refuse("batch_authorization_state_mismatch")
        batch_state["authorization"] = copy.deepcopy(authorization)
        journal = batch_state.get("authorization_journal")
        if type(journal) is dict:
            journal = copy.deepcopy(journal)
            journal["status"] = "committed"
            batch_state["authorization_journal"] = journal
        batch_state["status"] = "authorized"
        state["status"] = "running"
    _with_ledger(state_root, ledger_key, authorize)


def _prepare_authorization_journal(
    state_root: Path,
    ledger_key: bytes,
    *,
    batch_id: str,
    journal: Mapping[str, object],
) -> None:
    def prepare(state: dict[str, object], key: bytes) -> None:
        del key
        batches = state.get("batches")
        if type(batches) is not dict or type(batches.get(batch_id)) is not dict:
            refuse("ledger_schema_mismatch")
        batch_state = batches[batch_id]
        existing = batch_state.get("authorization_journal")
        if existing is not None and existing != journal:
            refuse("authorization_journal_mismatch")
        if existing is None:
            batch_state["authorization_journal"] = copy.deepcopy(journal)
    _with_ledger(state_root, ledger_key, prepare)


def _external_registry_status(
    state_root: Path,
    registry_key: bytes,
    nonce_sha256: str,
    revocation_sha256: str | None = None,
) -> dict[str, object]:
    path = state_root / "registry.json"
    if not path.exists():
        return {
            "nonce_present": False,
            "revoked": False,
            "state_sha256": None,
        }
    try:
        if path.is_symlink():
            refuse("approval_registry_unavailable")
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            refuse("approval_registry_unavailable")
        state = parse_json(path.read_bytes(), "approval_registry")
    except OSError:
        refuse("approval_registry_unavailable")
    expected_keys = {
        "consumed_nonce_sha256",
        "integrity_hmac_sha256",
        "revoked_handle_sha256",
        "schema_version",
    }
    if set(state) != expected_keys or state.get("schema_version") != "contextguard.external-approval-state/v1":
        refuse("approval_registry_unavailable")
    for field in ("consumed_nonce_sha256", "revoked_handle_sha256"):
        values = state[field]
        if (
            type(values) is not list
            or any(not isinstance(value, str) or len(value) != 64 for value in values)
            or len(values) != len(set(values))
            or values != sorted(values)
        ):
            refuse("approval_registry_unavailable")
    supplied = state["integrity_hmac_sha256"]
    unsigned = {key: value for key, value in state.items() if key != "integrity_hmac_sha256"}
    expected = hmac.new(
        registry_key,
        b"contextguard/external-approval-state/v1\0" + canonical(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        refuse("approval_registry_unavailable")
    return {
        "nonce_present": nonce_sha256 in state["consumed_nonce_sha256"],
        "revoked": revocation_sha256 in state["revoked_handle_sha256"]
        if revocation_sha256 is not None
        else False,
        "state_sha256": sha256(canonical(state)),
    }


def _external_registry_contains_nonce(
    state_root: Path, registry_key: bytes, nonce_sha256: str
) -> bool:
    return bool(
        _external_registry_status(state_root, registry_key, nonce_sha256)[
            "nonce_present"
        ]
    )


def _reconcile_external_journal(
    *,
    approval_module: types.ModuleType,
    approval: object,
    requested_scope: Mapping[str, object],
    verification_key: bytes,
    registry_status: Mapping[str, object],
    journal: Mapping[str, object],
    state_root: Path,
    ledger_key: bytes,
    batch: Mapping[str, object],
    authorization_metadata: Mapping[str, object],
) -> dict[str, object] | None:
    if not registry_status.get("nonce_present"):
        return None
    if (
        journal.get("registry_nonce_present_before")
        or registry_status.get("revoked")
        or registry_status.get("state_sha256")
        == journal.get("registry_state_sha256_before")
    ):
        refuse("approval_reconciliation_unproven")
    validator = getattr(approval_module, "_validate_approval", None)
    if not callable(validator):
        refuse("approval_reconciliation_unproven")
    try:
        validator(approval, requested_scope, verification_key)
    except Exception:
        refuse("approval_reconciliation_unproven")
    _authorize_batch(
        state_root,
        ledger_key,
        batch,
        authorization_metadata,
    )
    return dict(authorization_metadata)


def _reserve_unit(state_root: Path, ledger_key: bytes, unit_id: str) -> None:
    def reserve(state: dict[str, object], key: bytes) -> None:
        del key
        units = state.get("units")
        if type(units) is not dict or type(units.get(unit_id)) is not dict:
            refuse("ledger_schema_mismatch")
        unit = units[unit_id]
        if unit.get("status") == "pending":
            unit["status"] = "reserved"
            unit["reserved"] = True
            return
        if unit.get("status") in {
            "completed", "failed", "technical_missing_transport_ambiguous",
            "not_dispatched_spend_unknown",
        }:
            return
        if unit.get("status") == "reserved":
            refuse("unit_already_reserved")
        refuse("unit_state_mismatch")
    _with_ledger(state_root, ledger_key, reserve)


def _update_ledger(
    state_root: Path, ledger_key: bytes, mutator: Callable[[dict[str, object]], None]
) -> None:
    def update(state: dict[str, object], key: bytes) -> None:
        del key
        if not state:
            refuse("ledger_unavailable")
        mutator(state)
    _with_ledger(state_root, ledger_key, update)


def _terminal_count(state: Mapping[str, object]) -> int:
    units = state.get("units")
    if type(units) is not dict:
        return 0
    return sum(
        1
        for item in units.values()
        if isinstance(item, dict)
        and item.get("status")
        in {
            "completed",
            "failed",
            "technical_missing_transport_ambiguous",
            "not_dispatched_spend_unknown",
        }
    )


def _ledger_snapshot(state_root: Path, ledger_key: bytes) -> dict[str, object]:
    holder: dict[str, object] = {}

    def read(state: dict[str, object], key: bytes) -> None:
        del key
        holder.update(copy.deepcopy(state))

    _with_ledger(state_root, ledger_key, read, write_back=False)
    return holder


def _classify_capsule(
    capsule: Mapping[str, object], *, contract: Mapping[str, object]
) -> tuple[str, str, dict[str, object] | None]:
    status = capsule["http_status"]
    body = capsule["body"]
    if status != 200:
        return "failed", "provider_http_error", None
    if not body:
        return "failed", "provider_receipt_missing", None
    try:
        parsed = parse_anthropic_response(body, contract=contract)
    except LiveRunError:
        return "failed", "provider_receipt_missing", None
    return "completed", "none", parsed


def _terminal_record(
    *,
    item: Mapping[str, object],
    capsule: Mapping[str, object] | None,
    status: str,
    error: str,
    parsed: Mapping[str, object] | None,
    started: int | None,
    ended: int | None,
) -> dict[str, object]:
    body = capsule["body"] if capsule is not None else b""
    request_id = capsule.get("provider_request_id") if capsule is not None else None
    record = {
        "arm_id": item["arm_id"],
        "completion_event": "normal_completion" if status == "completed" else error,
        "dispatched": capsule is not None,
        "error": error,
        "http_status": capsule["http_status"] if capsule is not None else None,
        "provider_request_id_sha256": sha256(request_id.encode("utf-8"))
        if isinstance(request_id, str)
        else None,
        "repetition": item["repetition"],
        "response_bytes": len(body),
        "response_sha256": sha256(body),
        "scheduled_unit_id": item["scheduled_unit_id"],
        "selection_identity": copy.deepcopy(item["selection_identity"]),
        "status": status,
        "task_id": item["task_id"],
        "timing": {
            "end_monotonic_ns": ended,
            "start_monotonic_ns": started,
        },
        "usage": copy.deepcopy(parsed["usage"]) if parsed is not None else None,
    }
    record["seal_sha256"] = sha256(
        canonical({key: value for key, value in record.items() if key != "seal_sha256"})
    )
    return record


def _apply_terminal(
    state: dict[str, object],
    *,
    unit_id: str,
    record: Mapping[str, object],
) -> None:
    units = state.get("units")
    if type(units) is not dict or type(units.get(unit_id)) is not dict:
        refuse("ledger_schema_mismatch")
    unit = units[unit_id]
    if unit.get("status") in {
        "completed",
        "failed",
        "technical_missing_transport_ambiguous",
        "not_dispatched_spend_unknown",
    }:
        return
    unit.update({
        "status": record["status"],
        "terminal": copy.deepcopy(record),
    })
    usage = record.get("usage")
    if type(usage) is dict:
        totals = state.get("token_usage")
        if type(totals) is not dict:
            refuse("ledger_schema_mismatch")
        totals["completed_calls"] += 1
        for key, value in usage.items():
            totals[key] += value
    elif record.get("dispatched") or record.get("status") in {
        "technical_missing_transport_ambiguous", "not_dispatched_spend_unknown"
    }:
        state["spend_status"] = "unknown"


def _cumulative_list_price_micro_usd(state: Mapping[str, object]) -> int:
    usage = state.get("token_usage")
    if type(usage) is not dict:
        refuse("ledger_schema_mismatch")
    measurement = usage.get("list_price_micro_usd")
    if type(measurement) is not int or measurement < 0:
        refuse("ledger_schema_mismatch")
    prior = EXPECTED_RESERVATION["prior_protocol_validation"]
    return measurement + prior["worst_case_list_price_micro_usd"]


def _mark_not_dispatched(
    state: dict[str, object], *, reason: str = "not_dispatched_spend_unknown"
) -> None:
    units = state.get("units")
    if type(units) is not dict:
        refuse("ledger_schema_mismatch")
    now = time.monotonic_ns()
    for unit_id, unit in units.items():
        if type(unit) is not dict:
            refuse("ledger_schema_mismatch")
        if unit.get("status") == "pending":
            unit.update({
                "status": reason,
                "terminal": {
                    "arm_id": unit["arm_id"],
                    "completion_event": reason,
                    "dispatched": False,
                    "error": reason,
                    "http_status": None,
                    "provider_request_id_sha256": None,
                    "repetition": unit["repetition"],
                    "response_bytes": 0,
                    "response_sha256": sha256(b""),
                    "scheduled_unit_id": unit_id,
                    "selection_identity": copy.deepcopy(unit["selection_identity"]),
                    "status": reason,
                    "task_id": unit["task_id"],
                    "timing": {"end_monotonic_ns": now, "start_monotonic_ns": now},
                    "usage": None,
                },
            })
            state["spend_status"] = "unknown"


def _mark_terminal_batches(
    state: dict[str, object], batches: Sequence[Mapping[str, object]]
) -> None:
    units = state.get("units")
    batch_states = state.get("batches")
    if type(units) is not dict or type(batch_states) is not dict:
        refuse("ledger_schema_mismatch")
    terminal_statuses = {
        "completed", "failed", "technical_missing_transport_ambiguous",
        "not_dispatched_spend_unknown",
    }
    for batch in batches:
        batch_state = batch_states[batch["batch_id"]]
        if all(units[unit_id]["status"] in terminal_statuses for unit_id in batch["unit_ids"]):
            batch_state["status"] = "terminal"


def _record_terminal(
    state_root: Path,
    ledger_key: bytes,
    *,
    unit_id: str,
    record: Mapping[str, object],
) -> None:
    _update_ledger(
        state_root,
        ledger_key,
        lambda state: _apply_terminal(state, unit_id=unit_id, record=record),
    )


def _batch_list_price_micro_usd(
    state: Mapping[str, object], batch: Mapping[str, object]
) -> int:
    units = state.get("units")
    if type(units) is not dict:
        refuse("ledger_schema_mismatch")
    total = 0
    for unit_id in batch["unit_ids"]:
        unit = units.get(unit_id)
        if type(unit) is not dict:
            refuse("ledger_schema_mismatch")
        terminal = unit.get("terminal")
        usage = terminal.get("usage") if type(terminal) is dict else None
        if type(usage) is dict:
            total += usage["list_price_micro_usd"]
    return total


def _execute_schedule_test_core(
    *,
    contract: Mapping[str, object],
    plan: object,
    state_root: Path,
    output_root: Path,
    approval_consume: Callable[[dict[str, object]], object],
    invoke: Callable[[Mapping[str, object]], object],
    scorer_loader: Callable[[], object],
    contract_raw: bytes | None = None,
    ledger_key: bytes | None = None,
    _authorized_lock_root: Path | None = None,
) -> dict[str, object]:
    """Testable execution core; authorized entry supplies external approval."""

    if _authorized_lock_root is not None:
        return _with_authorized_run_lock(
            _authorized_lock_root,
            lambda: _execute_schedule_test_core(
                contract=contract,
                plan=plan,
                state_root=state_root,
                output_root=output_root,
                approval_consume=approval_consume,
                invoke=invoke,
                scorer_loader=scorer_loader,
                contract_raw=contract_raw,
                ledger_key=ledger_key,
            ),
        )

    if not callable(approval_consume) or not callable(invoke) or not callable(scorer_loader):
        refuse("callback_unavailable")
    contract_value = dict(contract)
    if (
        contract_value.get("schema_version") != SCHEMA
        or contract_value.get("claims") != EXPECTED_CLAIMS
        or contract_value.get("destination_allowlist") != [
            {"host": "api.anthropic.com", "port": 443, "scheme": "https"}
        ]
        or contract_value.get("limits") != EXPECTED_LIMITS
        or contract_value.get("pricing") != EXPECTED_PRICING
        or contract_value.get("provider") != EXPECTED_PROVIDER
        or contract_value.get("request") != EXPECTED_REQUEST
        or contract_value.get("resume") != EXPECTED_RESUME
        or contract_value.get("safety") != EXPECTED_SAFETY
        or contract_value.get("reservation") != EXPECTED_RESERVATION
        or contract_value.get("status")
        != "approved_scope_requires_two_fresh_v4_external_envelopes"
    ):
        refuse("invalid_contract")
    validated_plan = _validate_plan(plan)
    batches = build_batch_plans(validated_plan)
    reservation = calculate_worst_case_reservation(
        contract=contract_value, batches=batches
    )
    plan_sha = _plan_digest(batches)
    runner_sha = _runner_identity()
    if ledger_key is None:
        ledger_key = hashlib.sha256(
            b"contextguard/p3-v4-test-ledger/v1\0"
            + canonical({"contract": contract_value, "plan_sha256": plan_sha})
        ).digest()
    else:
        ledger_key = _derive_ledger_key(ledger_key)
    _private_dir(state_root)
    _private_dir(output_root)
    private_root = output_root / "private"
    _private_dir(private_root)
    effective_contract_raw = (
        contract_raw if type(contract_raw) is bytes else canonical(contract_value)
    )
    evidence_path = output_root / "p3-api-evidence.json"
    existing_evidence = _read_existing_evidence(
        evidence_path,
        contract_raw=effective_contract_raw,
        plan_sha256=plan_sha,
    )

    ledger_preexisted = False

    def initialize(state: dict[str, object], key: bytes) -> None:
        del key
        nonlocal ledger_preexisted
        ledger_preexisted = bool(state)
        _initialize_ledger(
            state,
            contract=contract_value,
            batches=batches,
            plan_sha256=plan_sha,
            reservation=reservation,
        )
    _with_ledger(state_root, ledger_key, initialize)

    initial_state = _ledger_snapshot(state_root, ledger_key)
    if existing_evidence is not None and not ledger_preexisted:
        # A completed or pending output cannot authenticate a fresh, unrelated
        # ledger.  Refuse before any approval or provider dispatch rather than
        # letting a caller reuse the shared output root with a new state root.
        refuse("output_exists")
    expected_existing_evidence_hash = initial_state.get(
        "pending_evidence_sha256", initial_state.get("evidence_sha256")
    )
    if (
        existing_evidence is not None
        and expected_existing_evidence_hash is not None
        and expected_existing_evidence_hash != sha256(canonical(existing_evidence))
    ):
        refuse("ledger_evidence_mismatch")
    if initial_state.get("status") == "completed":
        if existing_evidence is None or existing_evidence.get("status") != "completed":
            refuse("ledger_evidence_mismatch")
        return {
            "evidence_sha256": sha256(canonical(existing_evidence)),
            "status": "completed",
            "token_usage": copy.deepcopy(initial_state["token_usage"]),
        }
    if (
        existing_evidence is not None
        and existing_evidence.get("status") == "completed"
        and type(initial_state.get("scoring")) is dict
        and initial_state["scoring"].get("status") == "complete"
    ):
        _update_ledger(
            state_root,
            ledger_key,
            lambda current: current.update({
                "evidence_sha256": sha256(canonical(existing_evidence)),
                "status": "completed",
            }),
        )
        final_state = _ledger_snapshot(state_root, ledger_key)
        return {
            "evidence_sha256": sha256(canonical(existing_evidence)),
            "status": "completed",
            "token_usage": copy.deepcopy(final_state["token_usage"]),
        }

    item_by_id = {item["scheduled_unit_id"]: item for item in validated_plan}
    recovery_halt = False

    def recover(state: dict[str, object], key: bytes) -> None:
        del key
        nonlocal recovery_halt
        if state.get("status") == "completed":
            refuse("already_consumed")
        units = state.get("units")
        if type(units) is not dict:
            refuse("ledger_schema_mismatch")
        for unit_id, unit in units.items():
            if type(unit) is not dict or unit.get("status") != "reserved":
                continue
            item = item_by_id.get(unit_id)
            if item is None:
                refuse("ledger_plan_mismatch")
            capsule = _read_transport_capsule(private_root, unit_id, ledger_key, item)
            if capsule is None:
                record = _terminal_record(
                    item=item,
                    capsule=None,
                    status="technical_missing_transport_ambiguous",
                    error="technical_missing_transport_ambiguous",
                    parsed=None,
                    started=None,
                    ended=None,
                )
                _apply_terminal(state, unit_id=unit_id, record=record)
                recovery_halt = True
                continue
            status, error, parsed = _classify_capsule(capsule, contract=contract_value)
            record = _terminal_record(
                item=item,
                capsule=capsule,
                status=status,
                error=error,
                parsed=parsed,
                started=None,
                ended=None,
            )
            _apply_terminal(state, unit_id=unit_id, record=record)
            if status != "completed":
                recovery_halt = True
        if recovery_halt:
            _mark_not_dispatched(state)
        _mark_terminal_batches(state, batches)

    _with_ledger(state_root, ledger_key, recover)

    recovered_state = _ledger_snapshot(state_root, ledger_key)
    if _cumulative_list_price_micro_usd(recovered_state) > 40_000_000:
        recovery_halt = True
        _update_ledger(
            state_root,
            ledger_key,
            lambda current: _mark_not_dispatched(current),
        )

    for batch in batches:
        state = _ledger_snapshot(state_root, ledger_key)
        batch_state = state["batches"][batch["batch_id"]]
        if batch_state["status"] == "terminal":
            continue
        if recovery_halt:
            break
        if batch_state["status"] == "pending":
            scope = build_approval_scope(
                contract=contract_value,
                batch=batch,
                plan_sha256=plan_sha,
                runner_sha256=runner_sha,
            )
            try:
                authorization = approval_consume(copy.deepcopy(scope))
            except Exception:
                refuse("approval_unavailable")
            if authorization is None or authorization is False:
                refuse("approval_unavailable")
            if type(authorization) is not dict:
                authorization = {"acknowledged": True}
            _authorize_batch(
                state_root,
                ledger_key,
                batch,
                authorization,
            )
        for item in batch["items"]:
            unit_id = item["scheduled_unit_id"]
            state = _ledger_snapshot(state_root, ledger_key)
            unit_state = state["units"][unit_id]
            if unit_state["status"] in {
                "completed",
                "failed",
                "technical_missing_transport_ambiguous",
                "not_dispatched_spend_unknown",
            }:
                continue
            if unit_state["status"] != "pending":
                refuse("unit_state_mismatch")
            _reserve_unit(state_root, ledger_key, unit_id)
            started = time.monotonic_ns()
            capsule: dict[str, object] | None = None
            status = "technical_missing_transport_ambiguous"
            error = "technical_missing_transport_ambiguous"
            parsed: dict[str, object] | None = None
            try:
                capsule = _normalize_transport_capsule(invoke(item))
                _write_transport_capsule(private_root, unit_id, capsule, ledger_key, item)
                status, error, parsed = _classify_capsule(
                    capsule, contract=contract_value
                )
                if status == "completed" and parsed is not None:
                    current_state = _ledger_snapshot(state_root, ledger_key)
                    projected_batch = _batch_list_price_micro_usd(
                        current_state, batch
                    ) + parsed["usage"]["list_price_micro_usd"]
                    projected_total = (
                        _cumulative_list_price_micro_usd(current_state)
                        + parsed["usage"]["list_price_micro_usd"]
                    )
                    if projected_batch > 20_000_000 or projected_total > 40_000_000:
                        status = "failed"
                        error = "parsed_spend_cap_violation"
                        parsed = None
            except LiveRunError:
                capsule = None
                status = "technical_missing_transport_ambiguous"
                error = "technical_missing_transport_ambiguous"
                parsed = None
            except Exception:
                capsule = None
                status = "technical_missing_transport_ambiguous"
                error = "technical_missing_transport_ambiguous"
                parsed = None
            ended = time.monotonic_ns()
            record = _terminal_record(
                item=item,
                capsule=capsule,
                status=status,
                error=error,
                parsed=parsed,
                started=started,
                ended=ended,
            )
            _record_terminal(
                state_root,
                ledger_key,
                unit_id=unit_id,
                record=record,
            )
            if status != "completed":
                recovery_halt = True
                _update_ledger(
                    state_root,
                    ledger_key,
                    lambda state: _mark_not_dispatched(state),
                )
                break
        state = _ledger_snapshot(state_root, ledger_key)
        if all(
            state["units"][unit_id]["status"]
            in {
                "completed",
                "failed",
                "technical_missing_transport_ambiguous",
                "not_dispatched_spend_unknown",
            }
            for unit_id in batch["unit_ids"]
        ):
            _update_ledger(
                state_root,
                ledger_key,
                lambda state, batch_id=batch["batch_id"]: state["batches"][batch_id].update(
                    {"status": "terminal"}
                ),
            )
        if recovery_halt:
            break

    state = _ledger_snapshot(state_root, ledger_key)
    if _terminal_count(state) != EXPECTED_LIMITS["scheduled_units"]:
        _update_ledger(
            state_root,
            ledger_key,
            lambda current: (_mark_not_dispatched(current), _mark_terminal_batches(current, batches)),
        )
        state = _ledger_snapshot(state_root, ledger_key)
    else:
        _update_ledger(
            state_root,
            ledger_key,
            lambda current: _mark_terminal_batches(current, batches),
        )
        state = _ledger_snapshot(state_root, ledger_key)
    if _runner_identity() != runner_sha:
        refuse("changed_runner")

    score = None
    if all(
        unit.get("status") == "completed"
        for unit in state["units"].values()
        if type(unit) is dict
    ) and _terminal_count(state) == EXPECTED_LIMITS["scheduled_units"]:
        try:
            scorer = scorer_loader()
            if callable(scorer):
                capsules = {
                    item["scheduled_unit_id"]: _read_transport_capsule(
                        private_root, item["scheduled_unit_id"], ledger_key, item
                    )
                    for item in validated_plan
                }
                score = scorer(capsules, validated_plan)
        except Exception:
            score = None
    if _runner_identity() != runner_sha:
        refuse("changed_runner")

    state = _ledger_snapshot(state_root, ledger_key)
    score_complete = type(score) is dict and score.get("status") == "complete"
    final_status = "completed" if score_complete else "provider_receipts_sealed_pending_scoring"
    pending_scoring = copy.deepcopy(score) if score_complete else {
        "status": "pending",
        "reason": "provider_receipts_sealed_pending_scoring",
    }
    _update_ledger(
        state_root,
        ledger_key,
        lambda current: current.update({
            "scoring": pending_scoring,
            "status": "provider_receipts_sealed_pending_scoring",
        }),
    )
    state = _ledger_snapshot(state_root, ledger_key)
    provider_receipt_units = sum(
        1
        for unit in state["units"].values()
        if isinstance(unit, dict)
        and isinstance(unit.get("terminal"), dict)
        and unit["terminal"].get("dispatched") is True
    )
    usage_complete_units = sum(
        1
        for unit in state["units"].values()
        if isinstance(unit, dict)
        and isinstance(unit.get("terminal"), dict)
        and isinstance(unit["terminal"].get("usage"), dict)
    )
    sealed_units = []
    for item in validated_plan:
        unit = state["units"][item["scheduled_unit_id"]]
        terminal = unit.get("terminal", {})
        sealed_units.append({
            key: terminal.get(key)
            for key in (
                "arm_id", "completion_event", "dispatched", "http_status",
                "repetition", "response_bytes", "response_sha256",
                "scheduled_unit_id", "selection_identity", "status", "task_id",
                "timing", "usage",
            )
        })
    public = {
        "schema_version": EVIDENCE_SCHEMA,
        "analysis": copy.deepcopy(state.get("scoring")),
        "accounting": {
            "provider_receipt_units": provider_receipt_units,
            "reserved_units": sum(
                unit.get("reserved") is True
                for unit in state["units"].values()
                if isinstance(unit, dict)
            ),
            "scheduled_units": EXPECTED_LIMITS["scheduled_units"],
            "spend_status": state["spend_status"],
            "terminal_units": _terminal_count(state),
            "usage_complete_units": usage_complete_units,
        },
        "claims": copy.deepcopy(EXPECTED_CLAIMS),
        "contract_sha256": sha256(effective_contract_raw),
        "plan_sha256": plan_sha,
        "list_price_estimate": {
            "amount_micro_usd": state["token_usage"]["list_price_micro_usd"],
            "authority": EXPECTED_PRICING["authority"],
            "currency": "USD",
        },
        "model_id": "claude-sonnet-5",
        "provider_cost": {
            "availability": "unavailable",
            "currency": None,
            "reason": "request_level_provider_cost_receipt_unavailable",
            "value": None,
        },
        "provider_usage": {
            "authority": "anthropic_messages_api_response",
            "availability": "observed",
            "completed_calls": state["token_usage"]["completed_calls"],
            "model_id": "claude-sonnet-5",
        },
        "runner_sha256": runner_sha,
        "scoring": copy.deepcopy(state.get("scoring")),
        "sealed_units": sealed_units,
        "status": final_status,
        "token_usage": copy.deepcopy(state["token_usage"]),
    }
    if PRIVATE_KEYS & _public_keys(public):
        refuse("private_surface_in_public_evidence")
    evidence_raw = canonical(public)
    validate_public_evidence(public, contract_raw=effective_contract_raw)
    _update_ledger(
        state_root,
        ledger_key,
        lambda current: current.update({
            "pending_evidence_sha256": sha256(evidence_raw),
        }),
    )
    _write_public_evidence(
        evidence_path,
        evidence_raw,
        existing=existing_evidence,
    )
    evidence_updates = {
        "evidence_sha256": sha256(evidence_raw),
        "pending_evidence_sha256": None,
    }
    if score_complete:
        evidence_updates["status"] = "completed"
    _update_ledger(
        state_root,
        ledger_key,
        lambda current: current.update(evidence_updates),
    )
    return {
        "evidence_sha256": sha256(evidence_raw),
        "status": final_status,
        "token_usage": copy.deepcopy(state["token_usage"]),
    }


def validate_public_evidence(
    evidence: dict[str, object], *, contract_raw: bytes
) -> None:
    """Validate the minimized public projection without opening private data."""

    expected_keys = {
        "accounting", "analysis", "claims", "contract_sha256", "list_price_estimate",
        "model_id", "provider_cost", "provider_usage", "runner_sha256",
        "plan_sha256", "schema_version", "scoring", "sealed_units", "status", "token_usage",
    }
    if type(evidence) is not dict or set(evidence) != expected_keys:
        refuse("invalid_public_evidence")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        refuse("invalid_public_evidence")
    if type(contract_raw) is not bytes or evidence["contract_sha256"] != sha256(contract_raw):
        refuse("invalid_public_evidence")
    if not isinstance(evidence["plan_sha256"], str) or len(evidence["plan_sha256"]) != 64:
        refuse("invalid_public_evidence")
    if evidence["claims"] != EXPECTED_CLAIMS or evidence["model_id"] != "claude-sonnet-5":
        refuse("invalid_public_evidence")
    if evidence["status"] not in {"completed", "provider_receipts_sealed_pending_scoring"}:
        refuse("invalid_public_evidence")
    if not isinstance(evidence["runner_sha256"], str) or len(evidence["runner_sha256"]) != 64:
        refuse("invalid_public_evidence")
    if evidence["provider_cost"] != {
        "availability": "unavailable", "currency": None,
        "reason": "request_level_provider_cost_receipt_unavailable", "value": None,
    }:
        refuse("invalid_public_evidence")
    if _public_keys(evidence) & PRIVATE_KEYS:
        refuse("private_surface_in_public_evidence")
    accounting = evidence["accounting"]
    accounting_keys = {
        "provider_receipt_units", "reserved_units", "scheduled_units",
        "spend_status", "terminal_units", "usage_complete_units",
    }
    if type(accounting) is not dict or set(accounting) != accounting_keys:
        refuse("invalid_public_evidence")
    if accounting["scheduled_units"] != EXPECTED_LIMITS["scheduled_units"]:
        refuse("invalid_public_evidence")
    if accounting["spend_status"] not in {"known", "unknown"}:
        refuse("invalid_public_evidence")
    numeric_accounting_keys = accounting_keys - {"spend_status"}
    if any(
        isinstance(accounting[key], bool) or not isinstance(accounting[key], int)
        or accounting[key] < 0 for key in numeric_accounting_keys
    ):
        refuse("invalid_public_evidence")
    usage = evidence["token_usage"]
    expected_usage = _empty_usage()
    if type(usage) is not dict or set(usage) != set(expected_usage):
        refuse("invalid_public_evidence")
    for key, value in usage.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            refuse("invalid_public_evidence")
        expected_usage[key] = value
    units = evidence["sealed_units"]
    if type(units) is not list or len(units) != EXPECTED_LIMITS["scheduled_units"]:
        refuse("invalid_public_evidence")
    unit_ids: set[str] = set()
    recomputed = _empty_usage()
    unit_keys = {
        "arm_id", "completion_event", "dispatched", "http_status", "repetition",
        "response_bytes", "response_sha256", "scheduled_unit_id", "status",
        "selection_identity", "task_id", "timing", "usage",
    }
    for unit in units:
        if type(unit) is not dict or set(unit) != unit_keys:
            refuse("invalid_public_evidence")
        unit_id = unit["scheduled_unit_id"]
        if not isinstance(unit_id, str) or unit_id in unit_ids:
            refuse("invalid_public_evidence")
        unit_ids.add(unit_id)
        if unit.get("selection_identity") != _expected_bound_selection(
            unit.get("task_id"), unit.get("arm_id")
        ):
            refuse("invalid_public_evidence")
        if (
            not isinstance(unit["response_sha256"], str)
            or len(unit["response_sha256"]) != 64
            or not isinstance(unit["response_bytes"], int)
            or unit["response_bytes"] < 0
            or type(unit["dispatched"]) is not bool
            or unit["status"] not in {
                "completed", "failed", "technical_missing_transport_ambiguous",
                "not_dispatched_spend_unknown",
            }
            or type(unit["timing"]) is not dict
        ):
            refuse("invalid_public_evidence")
        item_usage = unit["usage"]
        if item_usage is None:
            if unit["status"] == "completed":
                refuse("invalid_public_evidence")
            continue
        if type(item_usage) is not dict or set(item_usage) != set(expected_usage) - {"completed_calls"}:
            refuse("invalid_public_evidence")
        recomputed["completed_calls"] += 1
        for key, value in item_usage.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                refuse("invalid_public_evidence")
            recomputed[key] += value
    if expected_usage != recomputed:
        refuse("invalid_public_evidence")
    if evidence["provider_usage"] != {
        "authority": "anthropic_messages_api_response", "availability": "observed",
        "completed_calls": recomputed["completed_calls"], "model_id": "claude-sonnet-5",
    }:
        refuse("invalid_public_evidence")
    if evidence["list_price_estimate"] != {
        "amount_micro_usd": recomputed["list_price_micro_usd"],
        "authority": EXPECTED_PRICING["authority"], "currency": "USD",
    }:
        refuse("invalid_public_evidence")
    if accounting["terminal_units"] != len(units):
        refuse("invalid_public_evidence")
    if not accounting["provider_receipt_units"] <= accounting["reserved_units"] <= accounting["scheduled_units"]:
        refuse("invalid_public_evidence")
    if accounting["provider_receipt_units"] != sum(unit["dispatched"] for unit in units):
        refuse("invalid_public_evidence")
    if accounting["usage_complete_units"] != recomputed["completed_calls"]:
        refuse("invalid_public_evidence")
    if evidence["status"] == "completed":
        scoring = evidence["scoring"]
        scoring_keys = {
            "exact_historical_patch_units", "failed_units", "passed_units", "scorer_artifact_sha256",
            "status", "total_units",
        }
        if type(scoring) is not dict or set(scoring) != scoring_keys:
            refuse("invalid_public_evidence")
        if (
            scoring["status"] != "complete"
            or scoring["scorer_artifact_sha256"] != EXPECTED_SCORER_SHA256
            or any(
                isinstance(scoring[key], bool)
                or not isinstance(scoring[key], int)
                or scoring[key] < 0
                for key in ("exact_historical_patch_units", "failed_units", "passed_units", "total_units")
            )
            or scoring["total_units"] != EXPECTED_LIMITS["scheduled_units"]
            or scoring["failed_units"] + scoring["passed_units"] != scoring["total_units"]
            or scoring["exact_historical_patch_units"] > scoring["passed_units"]
        ):
            refuse("invalid_public_evidence")
    elif evidence["scoring"] != {
        "reason": "provider_receipts_sealed_pending_scoring",
        "status": "pending",
    }:
        refuse("invalid_public_evidence")
    if evidence["analysis"] != evidence["scoring"]:
        refuse("invalid_public_evidence")


def _read_existing_evidence(
    path: Path, *, contract_raw: bytes | None, plan_sha256: str
) -> dict[str, object] | None:
    if not path.exists() and not path.is_symlink():
        return None
    if contract_raw is None or path.is_symlink():
        refuse("output_unavailable")
    try:
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            refuse("output_unavailable")
        evidence = parse_json(path.read_bytes(), "public_evidence")
    except OSError:
        refuse("output_unavailable")
    validate_public_evidence(evidence, contract_raw=contract_raw)
    if evidence["plan_sha256"] != plan_sha256:
        refuse("output_plan_mismatch")
    return evidence


def _write_public_evidence(
    path: Path,
    raw: bytes,
    *,
    existing: dict[str, object] | None,
) -> None:
    if existing is not None and existing.get("status") != "provider_receipts_sealed_pending_scoring":
        refuse("output_exists")
    temporary = path.with_name(f".p3-api-evidence.{os.getpid()}.tmp")
    try:
        if temporary.exists() or temporary.is_symlink():
            refuse("output_unavailable")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short evidence write")
                offset += written
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except LiveRunError:
        raise
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        refuse("output_unavailable")


def run_live_authorized(
    *,
    contract_path: Path,
    repo_root: Path,
    corpus_root: Path,
    output_root: Path,
    state_root: Path,
    approvals: Sequence[object],
    verification_key: bytes,
    registry_key: bytes,
    api_key: bytes,
) -> dict[str, object]:
    """Run only through two exact pinned external approval envelopes."""

    validate_api_key(api_key)
    if (
        type(approvals) not in {list, tuple}
        or len(approvals) != EXPECTED_LIMITS["batch_count"]
        or type(verification_key) is not bytes
        or len(verification_key) < 32
        or type(registry_key) is not bytes
        or len(registry_key) < 32
        or hmac.compare_digest(verification_key, registry_key)
    ):
        refuse("approval_unavailable")
    if any(
        type(approval) is not dict
        or approval.get("schema_version") != "contextguard.external-approval/v2"
        for approval in approvals
    ):
        refuse("approval_unavailable")
    try:
        contract_raw = contract_path.read_bytes()
    except OSError:
        refuse("contract_unavailable")
    if sha256(contract_raw) != EXPECTED_CONTRACT_SHA256:
        refuse("contract_digest_mismatch")
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    validate_pricing_window(contract)
    plan = prepare_live_plan(contract=contract, repo_root=repo_root, corpus_root=corpus_root)
    batches = build_batch_plans(plan)
    runner_sha = _runner_identity()
    approval_module = _load_bound_approval_module(
        contract=contract, repo_root=repo_root
    )
    # The approval nonce registry is anchored to the approval-bound output
    # root, not the caller-selected resumable ledger root. Reusing an envelope
    # with a fresh state root therefore observes the same consumed nonce.
    approval_state_root = output_root / ".external-approval-registry"
    authorized_ledger_key = _derive_ledger_key(registry_key)
    batch_by_id = {batch["batch_id"]: batch for batch in batches}

    def consume(internal_scope: dict[str, object]) -> dict[str, object]:
        _private_dir(approval_state_root)
        batch_id = internal_scope.get("batch_id")
        batch = batch_by_id.get(batch_id)
        if batch is None:
            refuse("approval_scope_mismatch")
        index = int(batch["batch_index"]) - 1
        requested_scope = build_external_approval_scope(
            contract=contract,
            batch=batch,
            plan_sha256=internal_scope["plan_sha256"],
            runner_sha256=runner_sha,
            output_root=output_root,
        )
        approval = approvals[index]
        nonce = approval.get("nonce") if type(approval) is dict else None
        revocation_handle = approval.get("revocation_handle") if type(approval) is dict else None
        envelope_hmac = approval.get("authentication_hmac_sha256") if type(approval) is dict else None
        if not all(
            isinstance(value, str)
            and len(value) == 64
            for value in (nonce, revocation_handle, envelope_hmac)
        ):
            refuse("approval_scope_mismatch")
        try:
            nonce_sha256 = sha256(nonce.encode("ascii"))
            revocation_sha256 = sha256(revocation_handle.encode("ascii"))
        except UnicodeEncodeError:
            refuse("approval_scope_mismatch")
        authorization_metadata = {
            "batch_id": batch_id,
            "nonce_sha256": nonce_sha256,
            "scope_sha256": sha256(canonical(requested_scope)),
        }
        registry_before = _external_registry_status(
            approval_state_root, registry_key, nonce_sha256, revocation_sha256
        )
        ledger_before = _ledger_snapshot(state_root, authorized_ledger_key)
        existing_journal = ledger_before["batches"][batch_id].get(
            "authorization_journal"
        )
        journal = {
            "authentication_hmac_sha256": envelope_hmac,
            "batch_id": batch_id,
            "nonce_sha256": authorization_metadata["nonce_sha256"],
            "revocation_handle_sha256": revocation_sha256,
            "registry_nonce_present_before": registry_before["nonce_present"],
            "registry_state_sha256_before": registry_before["state_sha256"],
            "scope_sha256": authorization_metadata["scope_sha256"],
            "status": "pending_external_consumption",
        }
        if existing_journal is not None:
            if type(existing_journal) is not dict or existing_journal.get("status") != "pending_external_consumption":
                refuse("authorization_journal_mismatch")
            for field in (
                "authentication_hmac_sha256", "batch_id", "nonce_sha256",
                "revocation_handle_sha256", "scope_sha256",
            ):
                if existing_journal.get(field) != journal[field]:
                    refuse("authorization_journal_mismatch")
            journal = copy.deepcopy(existing_journal)
        _prepare_authorization_journal(
            state_root,
            authorized_ledger_key,
            batch_id=batch_id,
            journal=journal,
        )

        registry_after = _external_registry_status(
            approval_state_root, registry_key, nonce_sha256, revocation_sha256
        )
        reconciled = _reconcile_external_journal(
            approval_module=approval_module,
            approval=approval,
            requested_scope=requested_scope,
            verification_key=verification_key,
            registry_status=registry_after,
            journal=journal,
            state_root=state_root,
            ledger_key=authorized_ledger_key,
            batch=batch,
            authorization_metadata=authorization_metadata,
        )
        if reconciled is not None:
            return reconciled

        def materialize(scope: dict[str, object]) -> dict[str, object]:
            del scope
            # Persist authorization from inside the external module's
            # materialization callback, closing the consume/ledger crash gap.
            _authorize_batch(
                state_root,
                authorized_ledger_key,
                batch,
                authorization_metadata,
            )
            return requested_scope

        try:
            consumed_scope = approval_module.authorize_and_consume(
                approval=approval,
                requested_scope=requested_scope,
                verification_key=verification_key,
                registry_key=registry_key,
                state_root=approval_state_root,
                materialize=materialize,
            )
        except Exception:
            refuse("approval_unavailable")
        return {
            "batch_id": batch_id,
            "nonce_sha256": authorization_metadata["nonce_sha256"],
            "scope_sha256": sha256(canonical(consumed_scope)),
        }

    return _execute_schedule_test_core(
        contract=contract,
        plan=plan,
        state_root=state_root,
        output_root=output_root,
        approval_consume=consume,
        invoke=lambda item: invoke_anthropic(
            item, contract=contract, api_key=api_key
        ),
        scorer_loader=_bound_scorer_loader(
            contract=contract, repo_root=repo_root, corpus_root=corpus_root
        ),
        contract_raw=contract_raw,
        ledger_key=registry_key,
        _authorized_lock_root=output_root,
    )


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct V4 Anthropic API execution is unavailable; use the separately activated production launcher",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
