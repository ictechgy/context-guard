"""Authorized, fail-closed Claude P2 shadow measurement runner.

Direct mutable execution is intentionally unavailable.  The public API accepts
an already authenticated one-use approval and publishes only minimized evidence.
"""

from __future__ import annotations

import base64
import copy
from decimal import Decimal, InvalidOperation
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
from typing import Callable, Mapping


SCHEMA = "contextguard.p2-claude-live-contract/v1"
EVIDENCE_SCHEMA = "contextguard.p2-claude-live-evidence/v1"
MAX_CLAUDE_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_CLAUDE_STDERR_BYTES = 64 * 1024
MAX_ANSWER_BYTES = 256
G5_VERIFY_SHA256 = "520ad6e66cb8116afcb128e49812511297844571103a39f11ea50262d437a686"
PHASE_EVALUATOR_SHA256 = "2ee911bb898e28d5ba23e7bd3599a41125a0e7d13c9e4c9359a84e7ff721dc46"
PHASE_EVALUATOR_RELATIVE = Path(
    "packages/context-guard-receipt/python/context_guard_receipt/phase_evaluation.py"
)
EXPECTED_APPROVAL_BOUNDARY = {
    "module_sha256": "809405655f7b171f7b564f5ad381ae88237e325e1fe3a7e2bbb9f1442d20c6d0",
    "schema_sha256": "c535d464311d9f7dd5b326face7596e6b930da4fb3e0350a5d3e0942e735eb69",
}
EXPECTED_G3 = {
    "freeze_lock_sha256": "0d1cc0ed6ccae0671f2fff3c0060ab7ed5c0e4bc6ee0a07efe7321a27b6e3105",
    "manifest_sha256": "ceb3c9807dad9f5ddc501f3439ac0bc5e7350e67e5c56ac27aa84e80cbd5d677",
    "runner_sha256": "6683de5244428714a273dd50f9b12a84c9a4c47e96f3cc97e1c18272c5b50f23",
    "tree_sha256": "ef13371780b940826dd5a1134777e1bae84b578702ee1fe5c83fa6698032fa6b",
}
EXPECTED_G5 = {
    "freeze_lock_sha256": "c5f6e732eba9c500655f48e18ccd570ecb79eeb4f363c03dc7e6fc1f2735d307",
    "observation_schema_sha256": "a1934fd8a22513d070e040a3afcd24a37f7dd073ded8fba4ea0fe33820321a91",
    "schedule_sha256": "326fc47df7871e39b2f9af2d888b8385ab91fe4347c6467f08dd4a6e386e7965",
    "tree_sha256": "2125e12cd82d8f0b8fe156a59c706cf389117864f2d76d5962a47dfcdb9b54f8",
    "verifier_sha256": G5_VERIFY_SHA256,
}


class LiveRunError(RuntimeError):
    """Value-free refusal from the live runner."""


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


def validate_contract(contract: dict[str, object], *, repo_root: Path) -> None:
    top = _exact(
        contract,
        {
            "approval_boundary", "claims", "destination_allowlist", "g3", "g5", "limits",
            "observer", "operation", "provider", "runtime", "safety",
            "schema_version", "source_candidate", "status",
        },
        "contract",
    )
    if top["schema_version"] != SCHEMA:
        refuse("invalid_contract")
    if top["source_candidate"] != {
        "artifact_ids": ["9163551917", "9163551685"],
        "checksums_sha256": "a20f2fc93bfa0e2774f8288eb9d31e9c83c962a816a65cfb829351610e7c5efb",
        "commit_sha": "540c6e02222f25346ca9c797197882cebbe5331d",
        "manifest_sha256": "149d26383663f57a5bac2f79f52acb53ed8b3f8a7675176557120dd3ec353050",
    }:
        refuse("invalid_source_candidate")
    provider = _exact(top["provider"], {"id", "model_id"}, "provider")
    if provider != {"id": "anthropic-first-party", "model_id": "claude-sonnet-5"}:
        refuse("invalid_provider")
    limits = _exact(
        top["limits"],
        {"call_cap", "currency", "per_call_budget_usd", "spend_cap_usd", "timeout_seconds"},
        "limits",
    )
    if limits != {
        "call_cap": 240,
        "currency": "USD",
        "per_call_budget_usd": "0.35",
        "spend_cap_usd": "100.00",
        "timeout_seconds": 120,
    }:
        refuse("invalid_limits")
    observer = _exact(top["observer"], {"id", "phase", "schema", "surface"}, "observer")
    if observer != {
        "id": "claude-code-print-json-v1",
        "phase": "P2",
        "schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "claude-print-json/v1",
    }:
        refuse("invalid_observer")
    if top["operation"] != {
        "receipt_schema": "contextguard.g5-authoritative-observation/v1",
        "surface": "p2-g5-fixed-schedule-shadow",
        "version": "v1",
    }:
        refuse("invalid_operation")
    if top["destination_allowlist"] != [
        {"host": "api.anthropic.com", "port": 443, "scheme": "https"}
    ]:
        refuse("invalid_destination")
    if top["runtime"] != {
        "cli_version": "2.1.229",
        "executable_sha256": "d732f0ba0a539c58c2ffcaef06ed03b4e523726f0cb6cc27b3a5b7e7ae0a7a21",
        "internal_model_usage_must_be_accounted": True,
        "safe_mode": True,
        "session_persistence": False,
        "tools": [],
    }:
        refuse("invalid_runtime")
    if top["status"] != "approved_scope_requires_one_use_external_envelope":
        refuse("invalid_contract_status")
    if top["claims"] != {
        "activation": False,
        "external_validity": False,
        "generalization": False,
        "production_readiness": False,
        "provider_cost_savings": False,
        "token_savings": False,
    }:
        refuse("invalid_claim_boundary")
    safety = _exact(
        top["safety"],
        {
            "baseline_fallback", "network_redirects", "network_proxies",
            "output_mode", "raw_content_publication", "retention_seconds",
            "scorer_load_after_all_calls",
        },
        "safety",
    )
    if safety != {
        "baseline_fallback": "exact_unchanged",
        "network_redirects": False,
        "network_proxies": False,
        "output_mode": "owner_private",
        "raw_content_publication": False,
        "retention_seconds": 604800,
        "scorer_load_after_all_calls": True,
    }:
        refuse("invalid_safety")

    bindings = {
        "approval_boundary": {
            "module_sha256": (
                repo_root
                / "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py"
            ),
            "schema_sha256": (
                repo_root / "packages/context-guard-receipt/schemas/external-approval.schema.json"
            ),
        },
        "g3": {
            "freeze_lock_sha256": repo_root / "research/provider-free-roadmap/g3/freeze-lock.json",
            "manifest_sha256": repo_root / "research/provider-free-roadmap/g3/v1/manifest.json",
            "runner_sha256": repo_root / "research/provider-free-roadmap/g3/v1/rehearse.py",
        },
        "g5": {
            "freeze_lock_sha256": repo_root / "research/provider-free-roadmap/g5/freeze-lock.json",
            "schedule_sha256": repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
            "observation_schema_sha256": (
                repo_root
                / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json"
            ),
            "verifier_sha256": repo_root / "research/provider-free-roadmap/g5/v1/verify.py",
        },
    }
    expected_bindings = {
        "approval_boundary": EXPECTED_APPROVAL_BOUNDARY,
        "g3": EXPECTED_G3,
        "g5": EXPECTED_G5,
    }
    for group_name, group in bindings.items():
        declared = _exact(top[group_name], set(expected_bindings[group_name]), group_name)
        if declared != expected_bindings[group_name]:
            refuse(f"invalid_{group_name}")
        for field, path in group.items():
            expected = declared.get(field)
            if not isinstance(expected, str):
                refuse(f"invalid_{group_name}")
            _read_bound(path, expected, f"{group_name}_{field}")
    _read_bound(
        repo_root / PHASE_EVALUATOR_RELATIVE,
        PHASE_EVALUATOR_SHA256,
        "p2_phase_evaluator",
    )


def _prompt(task: Mapping[str, object], rendered: bytes) -> str:
    try:
        pack = rendered.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        refuse("invalid_rendered_pack")
    prompt = task.get("prompt")
    if not isinstance(prompt, str) or not prompt or len(prompt.encode("utf-8")) > 4096:
        refuse("invalid_public_task")
    value = (
        "Task:\n" + prompt + "\n\n"
        "Authenticated read-only context pack:\n" + pack + "\n\n"
        "Return exactly one answer token and nothing else."
    )
    if len(value.encode("utf-8")) > 16 * 1024:
        refuse("prompt_limit")
    return value


def build_request_plan(
    *, contract: dict[str, object], schedule: dict[str, object],
    tasks: Mapping[str, dict[str, object]], packs: Mapping[tuple[str, str], dict[str, object]],
) -> list[dict[str, object]]:
    if contract["limits"]["call_cap"] != 240:
        refuse("invalid_call_cap")
    blocks = schedule.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != 60:
        refuse("invalid_schedule")
    plan: list[dict[str, object]] = []
    for block in blocks:
        if type(block) is not dict or not isinstance(block.get("units"), list):
            refuse("invalid_schedule")
        task_id = block.get("task_id")
        task = tasks.get(task_id) if isinstance(task_id, str) else None
        if task is None:
            refuse("invalid_task_binding")
        for unit in sorted(block["units"], key=lambda value: value.get("assigned_order", 0)):
            arm = unit.get("arm") if isinstance(unit, dict) else None
            pack = packs.get((task_id, arm)) if isinstance(arm, str) else None
            if pack is None or not isinstance(pack.get("rendered_pack"), bytes):
                refuse("invalid_pack_binding")
            prompt = _prompt(task, pack["rendered_pack"])
            payload_hash = sha256(prompt.encode("utf-8"))
            identity = {
                "arm": arm,
                "assignment_id": unit.get("assignment_id"),
                "block_id": block.get("block_id"),
                "payload_sha256": payload_hash,
                "scheduled_unit_id": unit.get("scheduled_unit_id"),
                "task_id": task_id,
            }
            request_id = "request-" + sha256(canonical(identity))
            plan.append({
                **{key: block[key] for key in (
                    "block_id", "task_id", "lineage_id", "partition", "stratum", "repetition"
                )},
                **unit,
                "payload_sha256": payload_hash,
                "prompt": prompt,
                "request_id": request_id,
            })
    if len(plan) != 240 or len({item["scheduled_unit_id"] for item in plan}) != 240:
        refuse("invalid_schedule_cardinality")
    return plan


def request_plan_sha256(plan: list[dict[str, object]]) -> str:
    projection = [
        {key: value for key, value in item.items() if key != "prompt"}
        for item in plan
    ]
    return sha256(b"contextguard.p2-live-request-plan/v1\0" + canonical(projection))


def argv_plan_sha256(
    *, contract: dict[str, object], executable: Path,
    plan: list[dict[str, object]],
) -> str:
    argv_values = [
        claude_argv(executable, contract=contract, prompt=item["prompt"])
        for item in plan
    ]
    return sha256(b"contextguard.p2-live-argv-plan/v1\0" + canonical(argv_values))


def build_approval_scope(
    *, contract: dict[str, object], executable: Path, executable_sha256: str,
    environment: dict[str, str], output_root: Path,
    plan: list[dict[str, object]],
) -> dict[str, object]:
    if not output_root.is_absolute():
        refuse("output_unavailable")
    return {
        "source_candidate": {
            "artifact_ids": list(contract["source_candidate"]["artifact_ids"]),
            "checksums_sha256": contract["source_candidate"]["checksums_sha256"],
            "commit_sha": contract["source_candidate"]["commit_sha"],
            "manifest_sha256": contract["source_candidate"]["manifest_sha256"],
        },
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
            "argv_sha256": argv_plan_sha256(
                contract=contract, executable=executable, plan=plan
            ),
            "environment_sha256": sha256(canonical(environment)),
            "executable_sha256": executable_sha256,
            "identity": "claude-code-cli",
            "version": contract["runtime"]["cli_version"],
        },
        "credential": {
            "consumer_id": "claude-code-cli",
            "scope_allowlist": ["provider:model.invoke"],
        },
        "destinations": copy.deepcopy(contract["destination_allowlist"]),
        "network_policy": {
            "proxies_allowed": False,
            "redirects_allowed": False,
        },
        "limits": {
            "call_cap": contract["limits"]["call_cap"],
            "currency": contract["limits"]["currency"],
            "spend_cap": contract["limits"]["spend_cap_usd"],
            "timeout_seconds": contract["limits"]["timeout_seconds"],
        },
        "output": {"mode": "owner_private", "root": str(output_root)},
        "retention": {"seconds": contract["safety"]["retention_seconds"]},
    }


def load_approval_boundary(
    contract: dict[str, object], *, repo_root: Path,
) -> types.ModuleType:
    expected = contract["approval_boundary"]["module_sha256"]
    raw = _read_bound(
        repo_root
        / "packages/context-guard-receipt/python/context_guard_receipt/external_approval.py",
        expected,
        "approval_boundary",
    )
    return _load_module(raw, expected, "captured_external_approval")


def consume_authorized(
    *, contract: dict[str, object], approval: object, requested_scope: object,
    verification_key: bytes, registry_key: bytes, state_root: Path,
    materialize: Callable[[dict[str, object]], object], repo_root: Path,
) -> object:
    boundary = load_approval_boundary(contract, repo_root=repo_root)
    return boundary.authorize_and_consume(
        approval=approval,
        requested_scope=requested_scope,
        verification_key=verification_key,
        registry_key=registry_key,
        state_root=state_root,
        materialize=materialize,
    )


def parse_claude_result(raw: bytes, *, expected_model: str) -> dict[str, object]:
    if len(raw) > MAX_CLAUDE_OUTPUT_BYTES:
        refuse("provider_output_limit")
    value = parse_json(raw, "provider_result")
    if (
        value.get("is_error") is not False
        or value.get("type") != "result"
        or value.get("subtype") != "success"
        or value.get("num_turns") != 1
    ):
        refuse("provider_result_unavailable")
    answer = value.get("result")
    if not isinstance(answer, str) or not answer or len(answer.encode("utf-8")) > MAX_ANSWER_BYTES:
        refuse("provider_result_unavailable")
    usage = value.get("usage")
    if type(usage) is not dict:
        refuse("provider_usage_unavailable")
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if (
        isinstance(input_tokens, bool) or not isinstance(input_tokens, int) or input_tokens < 0
        or isinstance(output_tokens, bool) or not isinstance(output_tokens, int) or output_tokens < 0
    ):
        refuse("provider_usage_unavailable")
    model_usage = value.get("modelUsage")
    selected = model_usage.get(expected_model) if type(model_usage) is dict else None
    if (
        type(selected) is not dict
        or selected.get("canonicalModel") != expected_model
        or selected.get("provider") != "firstParty"
    ):
        refuse("model_identity_mismatch")
    cost = value.get("total_cost_usd")
    try:
        parsed_cost = Decimal(str(cost))
    except (InvalidOperation, ValueError):
        refuse("client_cost_unavailable")
    if not parsed_cost.is_finite() or parsed_cost < 0:
        refuse("client_cost_unavailable")
    models = sorted(model_usage)
    if any(not isinstance(name, str) or len(name) > 128 for name in models):
        refuse("model_usage_invalid")
    return {
        "answer": answer.strip(),
        "client_cost_micro_usd": int(parsed_cost * Decimal(1_000_000)),
        "input_tokens": input_tokens,
        "model_ids": models,
        "output_tokens": output_tokens,
    }


def _metric(value: int | None, *, completed: bool, reason: str = "not_observed") -> dict[str, object]:
    if completed and value is not None:
        return {"availability": "observed", "unavailable_reason": "not_applicable", "value": value}
    return {
        "availability": "unavailable",
        "unavailable_reason": reason if completed else "excluded_unit",
        "value": None,
    }


def _cost_components(*, completed: bool) -> list[dict[str, object]]:
    reason = "receipt_unavailable" if completed else "excluded_unit"
    return [
        {
            "amount_minor": None,
            "availability": "unavailable",
            "component": component,
            "currency": None,
            "receipt_reference": None,
            "unavailable_reason": reason,
        }
        for component in ("provider_input", "provider_output", "provider_correction")
    ]


def _write_private(path: Path, raw: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        refuse("output_unavailable")


def _private_root(path: Path) -> None:
    try:
        metadata = path.stat()
    except OSError:
        refuse("output_unavailable")
    if (
        path.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        refuse("output_unavailable")


def _load_module(raw: bytes, expected_sha256: str, name: str) -> types.ModuleType:
    if sha256(raw) != expected_sha256:
        refuse("changed_verifier")
    module = types.ModuleType(name)
    module.__file__ = f"<captured-{name}>"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


def summarize_with_frozen_g5(
    observations: list[dict[str, object]], *, schedule_bytes: bytes,
    schema_bytes: bytes, repo_root: Path,
) -> dict[str, object]:
    verifier_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/verify.py",
        G5_VERIFY_SHA256,
        "g5_verifier",
    )
    module = _load_module(verifier_raw, G5_VERIFY_SHA256, "captured_g5_live_verifier")
    try:
        return module.summarize_authenticated_observations(
            copy.deepcopy(observations),
            schedule_bytes=bytes(schedule_bytes),
            schema_bytes=bytes(schema_bytes),
        )
    except Exception:
        refuse("g5_observation_validation_failed")


class FrozenPackCapture:
    def __init__(
        self,
        *,
        tasks: dict[str, dict[str, object]],
        packs: dict[tuple[str, str], dict[str, object]],
        runner: types.ModuleType,
        capture: object,
    ) -> None:
        self.tasks = tasks
        self.packs = packs
        self._runner = runner
        self._capture = capture
        self.scorer_load_count = 0

    def load_scorer(self) -> dict[str, object]:
        if self.scorer_load_count != 0:
            refuse("scorer_replay_forbidden")
        self.scorer_load_count = 1
        runner = self._runner
        capture = self._capture
        try:
            scorer_files = runner.capture_scorer_files(capture)
            capture.policy.phase = "post_scorer"
            runner._ACTIVE_POLICY = capture.policy
            score = runner.score_capture(capture, scorer_files)
            capture.g2._post_capture_drift_check(capture.root, capture.lock_raw, capture.lock)
            public = capture.g2._validate_instances_from_files(
                dict(capture.public_files), include_scorer=False
            )
            tasks, _profiles = capture.g2.validate_public_tasks(
                dict(capture.public_files), public["tasks"], public["arms"]
            )
            all_files = dict(capture.public_files)
            all_files.update(scorer_files)
            scorer = capture.g2._validate_instances_from_files(
                all_files, include_scorer=True
            )
            oracle = capture.g2.validate_oracle(tasks, scorer["oracle"])
        except Exception:
            refuse("scorer_validation_failed")
        finally:
            runner._ACTIVE_POLICY = None
        return {
            "answers": {
                task_id: value["expected_output"] for task_id, value in oracle.items()
            },
            "oracle": copy.deepcopy(oracle),
            "score": score,
        }


def capture_frozen_packs(
    *, contract: dict[str, object], repo_root: Path,
) -> FrozenPackCapture:
    validate_contract(contract, repo_root=repo_root)
    g3_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g3/v1/rehearse.py",
        contract["g3"]["runner_sha256"],
        "g3_runner",
    )
    runner = _load_module(g3_raw, contract["g3"]["runner_sha256"], "captured_g3_live_runner")
    manifest_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g3/v1/manifest.json",
        contract["g3"]["manifest_sha256"],
        "g3_manifest",
    )
    manifest = parse_json(manifest_raw, "g3_manifest")
    cost_model_raw = (
        repo_root / "research/provider-free-roadmap/g3/v1/cost-model.json"
    ).read_bytes()
    schema_root = repo_root / "research/provider-free-roadmap/g3/v1/schemas"
    schema_names = set(manifest.get("schemas", {}).values())
    if not schema_names or any(not isinstance(name, str) for name in schema_names):
        refuse("invalid_g3_manifest")
    schema_bytes = {name: (schema_root / name).read_bytes() for name in schema_names}
    g2_source = manifest.get("g2_source")
    if type(g2_source) is not dict:
        refuse("invalid_g3_manifest")
    g2_verifier_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g2/v1/verify.py",
        g2_source["verifier_sha256"],
        "g2_verifier",
    )
    g2_lock_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g2/freeze-lock.json",
        g2_source["lock_sha256"],
        "g2_lock",
    )
    try:
        capture = runner.capture_pre_oracle(
            repo_root,
            manifest_bytes=manifest_raw,
            cost_model_bytes=cost_model_raw,
            schema_bytes=schema_bytes,
            g2_verifier_bytes=g2_verifier_raw,
            g2_lock_bytes=g2_lock_raw,
            expected_g2_lock_sha256=g2_source["lock_sha256"],
            expected_g2_tree_root=g2_source["tree_root_sha256"],
            expected_g2_verifier_sha256=g2_source["verifier_sha256"],
        )
    except Exception:
        refuse("g3_public_capture_failed")
    tasks: dict[str, dict[str, object]] = {}
    packs: dict[tuple[str, str], dict[str, object]] = {}
    for receipt_raw in capture.receipt_bytes:
        receipt = runner.parse_json(receipt_raw, "captured P2 G3 receipt")
        task = runner.unseal_json(receipt["public_task"], "P2 public task")
        task_id = receipt["task_id"]
        arm = receipt["arm"]
        if type(task) is not dict or task.get("task_id") != task_id:
            refuse("invalid_public_task")
        existing = tasks.setdefault(task_id, task)
        if existing != task:
            refuse("public_task_drift")
        packer = receipt["packer_receipt"]
        try:
            rendered = base64.b64decode(packer["rendered_pack_base64"], validate=True)
        except (KeyError, ValueError):
            refuse("invalid_rendered_pack")
        if (
            len(rendered) != packer.get("pack_bytes")
            or sha256(rendered) != packer.get("rendered_pack_sha256")
        ):
            refuse("invalid_rendered_pack")
        packs[(task_id, arm)] = {
            "cost_microunits": receipt["cost"]["total"],
            "manifest_sources": copy.deepcopy(packer["manifest_sources"]),
            "packer_receipt_sha256": sha256(runner.canonical(packer)),
            "rendered_pack": rendered,
            "retrieval_plan": copy.deepcopy(receipt["retrieval_plan"]),
            "selected_paths": list(packer["selected_paths"]),
        }
    if len(tasks) != 6 or len(packs) != 24:
        refuse("g3_public_capture_incomplete")
    return FrozenPackCapture(tasks=tasks, packs=packs, runner=runner, capture=capture)


def execute_schedule(
    *, contract: dict[str, object], schedule: dict[str, object],
    observation_schema_bytes: bytes, tasks: Mapping[str, dict[str, object]],
    packs: Mapping[tuple[str, str], dict[str, object]], output_root: Path,
    invoke: Callable[[dict[str, object]], bytes], scorer_loader: Callable[[], object],
    repo_root: Path | None = None,
) -> dict[str, object]:
    _private_root(output_root)
    plan = build_request_plan(contract=contract, schedule=schedule, tasks=tasks, packs=packs)
    provisional: list[dict[str, object]] = []
    answers: list[str | None] = []
    sealed_runs: list[dict[str, object]] = []
    total_client_cost = 0
    model_id = contract["provider"]["model_id"]
    per_call_limit = int(Decimal(contract["limits"]["per_call_budget_usd"]) * 1_000_000)
    aggregate_limit = int(Decimal(contract["limits"]["spend_cap_usd"]) * 1_000_000)

    for item in plan:
        pack_started = time.monotonic_ns()
        prompt = _prompt(tasks[item["task_id"]], packs[(item["task_id"], item["arm"])]["rendered_pack"])
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
            parsed = parse_claude_result(raw, expected_model=model_id)
            if parsed["client_cost_micro_usd"] > per_call_limit:
                refuse("per_call_budget_exceeded")
            if total_client_cost + parsed["client_cost_micro_usd"] > aggregate_limit:
                refuse("spend_cap_exceeded")
            total_client_cost += parsed["client_cost_micro_usd"]
        except LiveRunError as exc:
            if exc.args and exc.args[0] in {
                "per_call_budget_exceeded", "spend_cap_exceeded",
            }:
                raise
            completed = False
            exclusion = exc.args[0] if exc.args and exc.args[0] in {
                "timeout", "transport_error", "model_identity_mismatch",
                "missing_required_field", "malformed_required_field",
            } else "transport_error"
        receipt_id = "receipt-" + sha256(
            canonical({"request_id": item["request_id"], "response_sha256": sha256(raw)})
        )
        answer = parsed["answer"] if parsed is not None else None
        answers.append(answer)
        sealed_core = {
            "client_cost_micro_usd": parsed["client_cost_micro_usd"] if parsed else None,
            "model_ids": parsed["model_ids"] if parsed else [],
            "payload_sha256": item["payload_sha256"],
            "request_id": item["request_id"],
            "response_bytes": len(raw),
            "response_sha256": sha256(raw),
            "scheduled_unit_id": item["scheduled_unit_id"],
        }
        sealed_runs.append({**sealed_core, "seal_sha256": sha256(canonical(sealed_core))})
        observation = {
            "schema_version": "contextguard.g5-authoritative-observation/v1",
            "observer_version": "contextguard.g5-minimized-observer/v1",
            **{key: item[key] for key in (
                "scheduled_unit_id", "block_id", "task_id", "lineage_id", "partition",
                "stratum", "arm", "assigned_order", "repetition", "assignment_id",
                "payload_sha256", "request_id",
            )},
            "receipt_id": receipt_id,
            "model_identity": model_id,
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
            "input_usage": _metric(parsed["input_tokens"] if parsed else None, completed=completed),
            "output_usage": _metric(parsed["output_tokens"] if parsed else None, completed=completed),
            "correction_count": _metric(0 if parsed else None, completed=completed),
            "correction_tokens": _metric(0 if parsed else None, completed=completed),
            "retrieval_count": _metric(0 if parsed else None, completed=completed),
            "retrieval_bytes": _metric(0 if parsed else None, completed=completed),
            "retrieval_tokens": _metric(0 if parsed else None, completed=completed),
            "billing_receipt": {
                "authority": "unavailable", "reference": None, "status": "unavailable",
            },
            "cost_components": _cost_components(completed=completed),
            "exclusion_reason": "none" if completed else exclusion,
            "audit_status": "eligible" if completed else "excluded",
        }
        provisional.append(observation)

    if len(sealed_runs) != 240:
        refuse("incomplete_schedule")
    scorer = scorer_loader()
    if type(scorer) is dict and "answers" in scorer:
        expected_answers = scorer.get("answers")
    else:
        expected_answers = scorer
    if type(expected_answers) is not dict or set(expected_answers) != set(tasks):
        refuse("invalid_scorer")
    for observation, answer in zip(provisional, answers, strict=True):
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
    root = repo_root or Path(__file__).resolve().parents[4]
    schedule_raw = _read_bound(
        root / "research/provider-free-roadmap/g5/v1/schedule.json",
        contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    summary = summarize_with_frozen_g5(
        provisional,
        schedule_bytes=schedule_raw,
        schema_bytes=observation_schema_bytes,
        repo_root=root,
    )
    return {
        "observations": provisional,
        "request_plan_sha256": request_plan_sha256(plan),
        "sealed_runs": sealed_runs,
        "summary": summary,
        "total_client_cost_micro_usd": total_client_cost,
    }


def _path_identity(path: str, pack: dict[str, object]) -> tuple[str | None, bool]:
    for item in pack.get("manifest_sources", []):
        if item.get("path") == path:
            source = item.get("source")
            return source.get("sha256") if isinstance(source, dict) else None, True
    plan = pack.get("retrieval_plan")
    for step in plan.get("steps", []) if isinstance(plan, dict) else []:
        if step.get("path") == path:
            source = step.get("source")
            return source.get("sha256") if isinstance(source, dict) else None, False
    return None, False


def build_p2_phase_records(
    *, observed_at: int, retention_seconds: int, tasks: Mapping[str, dict[str, object]],
    packs: Mapping[tuple[str, str], dict[str, object]], oracle: Mapping[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    by_stratum: dict[str, list[dict[str, object]]] = {"closed_pack": [], "realistic_fallback": []}
    for (task_id, arm), pack in sorted(packs.items()):
        task = tasks[task_id]
        required = oracle[task_id].get("required_paths")
        if not isinstance(required, list) or not required:
            refuse("invalid_oracle")
        for ordinal, path in enumerate(required):
            digest, selected = _path_identity(path, pack)
            valid_digest = isinstance(digest, str) and len(digest) == 64
            omission = not selected
            by_stratum[task["stratum"]].append({
                "record_id": f"{task_id}-{arm}-{ordinal + 1}",
                "stratum": task["stratum"],
                "relevant": True,
                "candidate_omission": omission,
                "recalled": selected or valid_digest,
                "source_digest": "sha256:" + (digest if valid_digest else "0" * 64),
                "rehydrated_digest": (
                    "sha256:" + digest if omission and valid_digest else None
                ),
                "fresh_until": observed_at + retention_seconds,
                "protection": "protected" if omission else "eligible",
                "construction_cost_microunits": (
                    int(pack.get("cost_microunits", 0)) if ordinal == 0 else 0
                ),
            })
    return {
        stratum: {
            "schema_version": "contextguard.phase-evaluation.p2/v1",
            "phase_id": "p2",
            "baseline_fallback_verified": True,
            "activation_authorized": False,
            "dependency_gates_passed": True,
            "observed_at": observed_at,
            "minimum_recall_basis_points": 10_000,
            "records": rows,
        }
        for stratum, rows in by_stratum.items()
    }


_PUBLIC_FORBIDDEN_KEYS = frozenset(
    {
        "answer", "authorization", "credential", "environment", "headers",
        "home", "prompt", "raw", "response", "result", "session_id", "token",
        "url",
    }
)


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
    *, contract_raw: bytes, execution: dict[str, object],
    phase_records: dict[str, dict[str, object]],
    phase_results: dict[str, dict[str, object]], executable_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "authority": {
            "activation": False,
            "claim": False,
            "runtime_mutation": False,
        },
        "call_count": len(execution["sealed_runs"]),
        "client_cost": {
            "amount_micro_usd": execution["total_client_cost_micro_usd"],
            "authority": "non_authoritative_cli_estimate",
            "currency": "USD",
        },
        "contract_sha256": sha256(contract_raw),
        "executable_sha256": executable_sha256,
        "g5_summary": copy.deepcopy(execution["summary"]),
        "model_id": "claude-sonnet-5",
        "observations": copy.deepcopy(execution["observations"]),
        "p2_phase_records": copy.deepcopy(phase_records),
        "p2_phase_results": copy.deepcopy(phase_results),
        "request_plan_sha256": execution["request_plan_sha256"],
        "sealed_runs": copy.deepcopy(execution["sealed_runs"]),
    }


def validate_public_evidence(
    evidence: dict[str, object], *, contract_raw: bytes,
    repo_root: Path | None = None, recompute: bool = True,
) -> None:
    expected_keys = {
        "authority", "call_count", "client_cost", "contract_sha256",
        "executable_sha256", "g5_summary", "model_id", "observations",
        "p2_phase_records", "p2_phase_results", "request_plan_sha256",
        "schema_version", "sealed_runs",
    }
    if type(evidence) is not dict or set(evidence) != expected_keys:
        refuse("invalid_public_evidence")
    if _PUBLIC_FORBIDDEN_KEYS & _recursive_keys(evidence):
        refuse("private_surface_in_public_evidence")
    if (
        evidence["schema_version"] != EVIDENCE_SCHEMA
        or evidence["contract_sha256"] != sha256(contract_raw)
        or evidence["model_id"] != "claude-sonnet-5"
        or evidence["call_count"] != 240
        or not isinstance(evidence["observations"], list)
        or len(evidence["observations"]) != 240
        or not isinstance(evidence["sealed_runs"], list)
        or len(evidence["sealed_runs"]) != 240
        or evidence["authority"] != {
            "activation": False, "claim": False, "runtime_mutation": False,
        }
    ):
        refuse("invalid_public_evidence")
    observation_ids = [item.get("scheduled_unit_id") for item in evidence["observations"]]
    sealed_ids = [item.get("scheduled_unit_id") for item in evidence["sealed_runs"]]
    if observation_ids != sealed_ids or len(set(observation_ids)) != 240:
        refuse("public_evidence_identity_mismatch")
    for sealed in evidence["sealed_runs"]:
        if type(sealed) is not dict or set(sealed) != {
            "client_cost_micro_usd", "model_ids", "payload_sha256", "request_id",
            "response_bytes", "response_sha256", "scheduled_unit_id", "seal_sha256",
        }:
            refuse("invalid_public_evidence_seal")
        core = {key: value for key, value in sealed.items() if key != "seal_sha256"}
        if sealed["seal_sha256"] != sha256(canonical(core)):
            refuse("invalid_public_evidence_seal")
    client = evidence["client_cost"]
    if type(client) is not dict or client != {
        "amount_micro_usd": sum(
            item.get("client_cost_micro_usd") or 0 for item in evidence["sealed_runs"]
        ),
        "authority": "non_authoritative_cli_estimate",
        "currency": "USD",
    }:
        refuse("public_evidence_cost_mismatch")
    if recompute:
        if repo_root is None:
            refuse("public_evidence_replay_unavailable")
        contract = parse_json(contract_raw, "contract")
        schedule_raw = _read_bound(
            repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
            contract["g5"]["schedule_sha256"],
            "g5_schedule",
        )
        schema_raw = _read_bound(
            repo_root
            / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
            contract["g5"]["observation_schema_sha256"],
            "g5_observation_schema",
        )
        recomputed = summarize_with_frozen_g5(
            evidence["observations"],
            schedule_bytes=schedule_raw,
            schema_bytes=schema_raw,
            repo_root=repo_root,
        )
        if evidence["g5_summary"] != recomputed:
            refuse("public_evidence_summary_mismatch")
        if set(evidence["p2_phase_records"]) != {"closed_pack", "realistic_fallback"}:
            refuse("public_evidence_phase_mismatch")
        phase_results = {
            name: evaluate_phase_record(record, repo_root=repo_root)
            for name, record in evidence["p2_phase_records"].items()
        }
        if evidence["p2_phase_results"] != phase_results:
            refuse("public_evidence_phase_mismatch")


def _probe_claude_version(
    executable: Path, environment: dict[str, str], expected_version: str,
) -> None:
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            cwd="/tmp",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        refuse("runtime_unavailable")
    if (
        result.returncode != 0
        or len(result.stdout) > 4096
        or not result.stdout.decode("utf-8", "replace").startswith(expected_version + " ")
    ):
        refuse("runtime_version_mismatch")


def resolve_claude_runtime(
    contract: dict[str, object], *, executable: Path | None = None,
) -> tuple[Path, dict[str, str], str]:
    candidate = executable
    if candidate is None:
        resolved = shutil.which("claude")
        if resolved is None:
            refuse("runtime_unavailable")
        candidate = Path(resolved)
    try:
        candidate = candidate.resolve(strict=True)
        metadata = candidate.stat()
        if not stat.S_ISREG(metadata.st_mode):
            refuse("runtime_unavailable")
        digest = sha256(candidate.read_bytes())
    except OSError:
        refuse("runtime_unavailable")
    if digest != contract["runtime"]["executable_sha256"]:
        refuse("runtime_identity_mismatch")
    environment = build_claude_environment()
    _probe_claude_version(candidate, environment, contract["runtime"]["cli_version"])
    return candidate, environment, digest


def run_live_authorized(
    *, contract_path: Path, repo_root: Path, output_root: Path, state_root: Path,
    approval: object, verification_key: bytes, registry_key: bytes,
    executable: Path | None = None,
) -> dict[str, object]:
    contract_raw = contract_path.read_bytes()
    contract = parse_json(contract_raw, "contract")
    validate_contract(contract, repo_root=repo_root)
    _private_root(output_root)
    _private_root(state_root)
    schedule_raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        contract["g5"]["schedule_sha256"],
        "g5_schedule",
    )
    schedule = parse_json(schedule_raw, "g5_schedule")
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        contract["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    capture = capture_frozen_packs(contract=contract, repo_root=repo_root)
    plan = build_request_plan(
        contract=contract, schedule=schedule, tasks=capture.tasks, packs=capture.packs
    )
    claude, environment, executable_digest = resolve_claude_runtime(
        contract, executable=executable
    )
    scope = build_approval_scope(
        contract=contract,
        executable=claude,
        executable_sha256=executable_digest,
        environment=environment,
        output_root=output_root,
        plan=plan,
    )

    def materialize(_scope: dict[str, object]) -> dict[str, object]:
        workspace = output_root / "workspace"
        try:
            workspace.mkdir(mode=0o700)
        except OSError:
            refuse("output_unavailable")
        scorer_box: dict[str, object] = {}

        def load_scorer() -> object:
            scorer = capture.load_scorer()
            scorer_box.update(scorer)
            return scorer

        execution = execute_schedule(
            contract=contract,
            schedule=schedule,
            observation_schema_bytes=schema_raw,
            tasks=capture.tasks,
            packs=capture.packs,
            output_root=output_root,
            invoke=lambda item: invoke_claude(
                item,
                contract=contract,
                executable=claude,
                environment=environment,
                cwd=workspace,
            ),
            scorer_loader=load_scorer,
            repo_root=repo_root,
        )
        if sha256(claude.read_bytes()) != executable_digest:
            refuse("runtime_identity_mismatch")
        observed_at = int(time.time())
        phase_records = build_p2_phase_records(
            observed_at=observed_at,
            retention_seconds=contract["safety"]["retention_seconds"],
            tasks=capture.tasks,
            packs=capture.packs,
            oracle=scorer_box["oracle"],
        )
        phase_results = {
            name: evaluate_phase_record(record, repo_root=repo_root)
            for name, record in phase_records.items()
        }
        evidence = build_public_evidence(
            contract_raw=contract_raw,
            execution=execution,
            phase_records=phase_records,
            phase_results=phase_results,
            executable_sha256=executable_digest,
        )
        validate_public_evidence(
            evidence, contract_raw=contract_raw, repo_root=repo_root
        )
        evidence_raw = canonical(evidence)
        _write_private(output_root / "p2-live-evidence.json", evidence_raw)
        return {
            "call_count": 240,
            "evidence_sha256": sha256(evidence_raw),
            "p2_closed_pack_ready": phase_results["closed_pack"]["implementation_readiness"],
            "p2_realistic_fallback_ready": phase_results["realistic_fallback"]["implementation_readiness"],
            "status": "p2_shadow_recorded",
        }

    result = consume_authorized(
        contract=contract,
        approval=approval,
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


def evaluate_phase_record(record: dict[str, object], *, repo_root: Path) -> dict[str, object]:
    raw = _read_bound(
        repo_root / PHASE_EVALUATOR_RELATIVE,
        PHASE_EVALUATOR_SHA256,
        "p2_phase_evaluator",
    )
    module = _load_module(raw, PHASE_EVALUATOR_SHA256, "captured_p2_phase_evaluator")
    return module.evaluate_p2(copy.deepcopy(record))


def build_claude_environment() -> dict[str, str]:
    result = {
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    if not result["HOME"] or not Path(result["HOME"]).is_absolute():
        refuse("runtime_environment_unavailable")
    return result


def claude_argv(
    executable: Path, *, contract: dict[str, object], prompt: str,
) -> list[str]:
    return [
        str(executable), "-p", "--model", contract["provider"]["model_id"],
        "--effort", "low", "--max-budget-usd", contract["limits"]["per_call_budget_usd"],
        "--output-format", "json", "--safe-mode", "--no-session-persistence",
        "--disable-slash-commands", "--permission-mode", "dontAsk",
        "--prompt-suggestions", "false", "--tools", "", "--strict-mcp-config",
        "--mcp-config", '{"mcpServers":{}}', "--", prompt,
    ]


def invoke_claude(
    item: dict[str, object], *, contract: dict[str, object], executable: Path,
    environment: dict[str, str], cwd: Path,
) -> bytes:
    argv = claude_argv(executable, contract=contract, prompt=item["prompt"])
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=contract["limits"]["timeout_seconds"])
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            refuse("timeout")
    except LiveRunError:
        raise
    except OSError:
        refuse("transport_error")
    if len(stdout) > MAX_CLAUDE_OUTPUT_BYTES or len(stderr) > MAX_CLAUDE_STDERR_BYTES:
        refuse("transport_error")
    if process.returncode != 0:
        refuse("transport_error")
    return stdout


def main(argv: list[str] | None = None) -> int:
    del argv
    print(
        "direct mutable P2 live execution is unavailable; use a one-use external approval envelope",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
