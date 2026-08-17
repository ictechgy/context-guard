"""P3 v2 Anthropic measurement with public two-hop graph closure."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
from typing import Callable


SCHEMA = "contextguard.p3-anthropic-api-live-contract/v2"
EVIDENCE_SCHEMA = "contextguard.p3-anthropic-api-live-evidence/v2"
V1_RUNNER = Path("research/provider-live-roadmap/p3-api/v1/live_runner.py")
V1_CONTRACT = Path("research/provider-live-roadmap/p3-api/v1/contract.json")
EXPECTED_BASE = {
    "contract_sha256": "5fcd5e3bd061fbb3e880863401c3eaa2ab753e7c2f3e29837a1c9315fdc7c1b4",
    "runner_sha256": "021965a2f3f7ff6b8a0eba9a3240e7198da090ae53f3910714ac0852b1538db6",
}
EXPECTED_PROMPT_SUFFIXES = {
    "calibration_graph": "Invoke amberWindow() and return only its result.",
    "evaluation_graph": "Invoke verifyIndigo(800, 17) and return only its result.",
    "train_graph": "Invoke resolver_entrypoint() and return only its result.",
}
EXPECTED_REQUIREMENTS = {
    "calibration_graph": [
        "src/controllers/entry.ts",
        "src/calibration/amber-calibrator.ts",
    ],
    "evaluation_graph": ["app/runner.js", "validators/index.js"],
    "train_graph": [
        "app/entry.py",
        "app/routing/checksum.py",
        "app/routing/constants.py",
    ],
}
EXPECTED_CANDIDATE = {
    "graph_closure_depth": 2,
    "id": "public-two-hop-graph-plus-explicit-entrypoint-v1",
    "prompt_suffixes": EXPECTED_PROMPT_SUFFIXES,
    "public_context_requirements": EXPECTED_REQUIREMENTS,
    "secondary_seed_policy": "captured_direct_graph_neighbors",
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
EXPECTED_LIMITS = {"call_cap": 240, "currency": "USD", "spend_cap_usd": "20.00"}


class P3V2Error(RuntimeError):
    """Value-free refusal from the v2 measurement boundary."""


def refuse(code: str) -> None:
    raise P3V2Error(code)


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


class V1Context:
    def __init__(
        self,
        *,
        module: types.ModuleType,
        base: types.ModuleType,
        contract: dict[str, object],
        contract_raw: bytes,
    ) -> None:
        self.module = module
        self.base = base
        self.contract = contract
        self.contract_raw = contract_raw


class Candidate:
    def __init__(
        self,
        *,
        v1: V1Context,
        capture: object,
        baseline_packs: dict[tuple[str, str], dict[str, object]],
        packs: dict[tuple[str, str], dict[str, object]],
        tasks: dict[str, dict[str, object]],
        metrics: dict[str, int],
    ) -> None:
        self.v1 = v1
        self.capture = capture
        self.baseline_packs = baseline_packs
        self.packs = packs
        self.tasks = tasks
        self.metrics = metrics


def _parse_contract(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        refuse("invalid_contract")
    if type(value) is not dict:
        refuse("invalid_contract")
    return value


def load_v1(contract: dict[str, object], *, repo_root: Path) -> V1Context:
    if contract.get("base_v1") != EXPECTED_BASE:
        refuse("invalid_base_v1")
    runner_raw = _read_bound(
        repo_root / V1_RUNNER,
        EXPECTED_BASE["runner_sha256"],
        "v1_runner",
    )
    module = _load_module(runner_raw, EXPECTED_BASE["runner_sha256"], "captured_p3_api_v1")
    contract_raw = _read_bound(
        repo_root / V1_CONTRACT,
        EXPECTED_BASE["contract_sha256"],
        "v1_contract",
    )
    v1_contract = module.parse_json(contract_raw, "v1_contract")
    try:
        module.validate_contract(v1_contract, repo_root=repo_root)
        base = module.load_base(v1_contract, repo_root=repo_root)
    except Exception:
        refuse("invalid_base_v1")
    return V1Context(
        module=module,
        base=base,
        contract=v1_contract,
        contract_raw=contract_raw,
    )


def validate_contract(contract: dict[str, object], *, repo_root: Path) -> None:
    if type(contract) is not dict or set(contract) != {
        "base_v1",
        "candidate",
        "claims",
        "limits",
        "operation",
        "safety",
        "schema_version",
        "status",
    }:
        refuse("invalid_contract")
    if contract["schema_version"] != SCHEMA:
        refuse("invalid_contract")
    if contract["base_v1"] != EXPECTED_BASE:
        refuse("invalid_base_v1")
    if contract["candidate"] != EXPECTED_CANDIDATE:
        refuse("invalid_candidate")
    if contract["claims"] != EXPECTED_CLAIMS:
        refuse("invalid_claims")
    if contract["limits"] != EXPECTED_LIMITS:
        refuse("invalid_limits")
    if contract["operation"] != {
        "surface": "p3-g5-fixed-schedule-anthropic-api-v2-measurement",
        "version": "v2",
    }:
        refuse("invalid_operation")
    if contract["safety"] != {
        "output_mode": "owner_private",
        "raw_content_publication": False,
        "retention_seconds": 604800,
        "scorer_load_after_all_calls": True,
    }:
        refuse("invalid_safety")
    if contract["status"] != "approved_scope_requires_one_use_external_envelope":
        refuse("invalid_status")
    load_v1(contract, repo_root=repo_root)


def _source_bytes(
    *, public_files: dict[str, bytes], task: dict[str, object], relative: str
) -> bytes:
    prefix = "research/provider-free-roadmap/g2/v1/" + task["fixture_root"] + "/"
    raw = public_files.get(prefix + relative)
    if not isinstance(raw, bytes):
        refuse("candidate_source_unavailable")
    return raw


def _slice_bytes(raw: bytes, *, start: int, end: int) -> bytes:
    if isinstance(start, bool) or isinstance(end, bool) or not 1 <= start <= end:
        refuse("invalid_candidate_range")
    lines = raw.splitlines(keepends=True)
    if end > len(lines):
        refuse("invalid_candidate_range")
    return b"".join(lines[start - 1 : end])


def _pack_from_payload(
    *,
    candidate_capture: object,
    task: dict[str, object],
    payload: dict[str, object],
    original: dict[str, object],
) -> dict[str, object]:
    try:
        sources = payload["manifest"]["sources"]
        rendered = payload["build"]["pack"].encode("utf-8")
        selected_paths = candidate_capture._capture.g2.selected_paths(payload)
    except (AttributeError, KeyError, TypeError, UnicodeEncodeError):
        refuse("invalid_candidate_pack")
    if not isinstance(sources, list) or not rendered:
        refuse("invalid_candidate_pack")
    public_files = dict(candidate_capture._capture.public_files)
    manifest_sources: list[dict[str, object]] = []
    for item in sources:
        if type(item) is not dict or set(item) != {"label", "lines", "path", "priority"}:
            refuse("invalid_candidate_pack")
        line_range = item["lines"]
        if type(line_range) is not dict or set(line_range) != {"end", "start"}:
            refuse("invalid_candidate_pack")
        source_raw = _source_bytes(
            public_files=public_files,
            task=task,
            relative=item["path"],
        )
        slice_raw = _slice_bytes(
            source_raw,
            start=line_range["start"],
            end=line_range["end"],
        )
        manifest_sources.append(
            {
                "label": item["label"],
                "path": item["path"],
                "priority": item["priority"],
                "range": copy.deepcopy(line_range),
                "slice": {"bytes": len(slice_raw), "sha256": sha256(slice_raw)},
                "source": {"bytes": len(source_raw), "sha256": sha256(source_raw)},
            }
        )
    receipt_projection = {
        "manifest_sources": manifest_sources,
        "rendered_pack_sha256": sha256(rendered),
        "selected_paths": selected_paths,
    }
    return {
        "cost_microunits": int(payload["pack_bytes"]),
        "manifest_sources": manifest_sources,
        "packer_receipt_sha256": sha256(canonical(receipt_projection)),
        "rendered_pack": rendered,
        "retrieval_plan": copy.deepcopy(original["retrieval_plan"]),
        "selected_paths": selected_paths,
    }


def _coverage(
    packs: dict[tuple[str, str], dict[str, object]],
) -> tuple[int, int]:
    complete = 0
    missing = 0
    for task_id, required in EXPECTED_REQUIREMENTS.items():
        selected = set(packs[(task_id, "combined")]["selected_paths"])
        absent = set(required) - selected
        if not absent:
            complete += 1
        missing += len(absent)
    return complete, missing


def prepare_candidate(*, contract: dict[str, object], repo_root: Path) -> Candidate:
    validate_contract(contract, repo_root=repo_root)
    v1 = load_v1(contract, repo_root=repo_root)
    capture = v1.base.capture_frozen_packs(
        contract=v1.base.CAPTURED_CONTRACT,
        repo_root=repo_root,
    )
    baseline_packs = copy.deepcopy(capture.packs)
    tasks = copy.deepcopy(capture.tasks)
    for task_id, suffix in EXPECTED_PROMPT_SUFFIXES.items():
        task = tasks.get(task_id)
        if type(task) is not dict or not isinstance(task.get("prompt"), str):
            refuse("invalid_public_task")
        task["prompt"] = task["prompt"] + " " + suffix
    packs = copy.deepcopy(baseline_packs)
    g2 = capture._capture.g2
    for task_id in EXPECTED_REQUIREMENTS:
        original_task = capture.tasks[task_id]
        for arm in ("symbol_only", "combined"):
            original_pack = baseline_packs[(task_id, arm)]
            secondary_seeds = [
                item["path"]
                for item in original_pack["manifest_sources"]
                if isinstance(item.get("label"), str)
                and item["label"].startswith("graph:")
            ]
            task_for_pack = copy.deepcopy(original_task)
            files = list(task_for_pack["pack"]["files"])
            for path in secondary_seeds:
                if path not in files:
                    files.append(path)
            task_for_pack["pack"]["files"] = files
            with tempfile.TemporaryDirectory() as name:
                destination = Path(name) / "projection"
                _projection, inventory = g2._materialize_from_snapshot(
                    dict(capture._capture.public_files),
                    task_for_pack,
                    arm,
                    destination,
                )
                payload = g2.execute_arm(
                    capture._capture.packer_bytes,
                    destination / "workspace",
                    inventory,
                    task_for_pack,
                    arm,
                )
            packs[(task_id, arm)] = _pack_from_payload(
                candidate_capture=capture,
                task=task_for_pack,
                payload=payload,
                original=original_pack,
            )
    baseline_complete, _baseline_missing = _coverage(baseline_packs)
    candidate_complete, candidate_missing = _coverage(packs)
    metrics = {
        "baseline_complete_tasks": baseline_complete,
        "candidate_complete_tasks": candidate_complete,
        "denominator": len(EXPECTED_REQUIREMENTS),
        "missing_dependency_edges": candidate_missing,
    }
    if metrics != {
        "baseline_complete_tasks": 2,
        "candidate_complete_tasks": 3,
        "denominator": 3,
        "missing_dependency_edges": 0,
    }:
        refuse("candidate_target_unmet")
    return Candidate(
        v1=v1,
        capture=capture,
        baseline_packs=baseline_packs,
        packs=packs,
        tasks=tasks,
        metrics=metrics,
    )


def load_schedule(v1: V1Context, *, repo_root: Path) -> dict[str, object]:
    expected = v1.base.CAPTURED_CONTRACT["g5"]["schedule_sha256"]
    raw = _read_bound(
        repo_root / "research/provider-free-roadmap/g5/v1/schedule.json",
        expected,
        "g5_schedule",
    )
    return v1.module.parse_json(raw, "g5_schedule")


def _candidate_identity(candidate: Candidate) -> dict[str, object]:
    prompt_hashes = {
        task_id: sha256(candidate.tasks[task_id]["prompt"].encode("utf-8"))
        for task_id in sorted(candidate.tasks)
    }
    pack_hashes = {
        task_id + "/" + arm: sha256(pack["rendered_pack"])
        for (task_id, arm), pack in sorted(candidate.packs.items())
    }
    value = {
        "candidate_id": EXPECTED_CANDIDATE["id"],
        "pack_sha256": pack_hashes,
        "prompt_sha256": prompt_hashes,
    }
    return {**value, "identity_sha256": sha256(canonical(value))}


def build_approval_scope(
    *,
    candidate: Candidate,
    contract: dict[str, object],
    output_root: Path,
    plan: list[dict[str, object]],
    runner_sha256: str,
) -> dict[str, object]:
    if contract.get("candidate") != EXPECTED_CANDIDATE:
        refuse("invalid_candidate")
    scope = candidate.v1.module.build_approval_scope(
        contract=candidate.v1.contract,
        output_root=output_root,
        plan=plan,
        runner_sha256=runner_sha256,
    )
    scope["operation"] = {
        "receipt_schema": candidate.v1.contract["operation"]["receipt_schema"],
        "surface_id": contract["operation"]["surface"],
        "version": "v2",
    }
    scope["runtime"]["identity"] = "python-http.client-p3-v2-runner"
    return scope


def build_evidence(
    *,
    candidate: Candidate,
    contract_raw: bytes,
    v1_evidence: dict[str, object],
) -> dict[str, object]:
    return {
        "authority": {"activation": False, "claim": False, "runtime_mutation": False},
        "candidate_identity": _candidate_identity(candidate),
        "candidate_metrics": copy.deepcopy(candidate.metrics),
        "contract_sha256": sha256(contract_raw),
        "schema_version": EVIDENCE_SCHEMA,
        "v1_evidence": copy.deepcopy(v1_evidence),
    }


def validate_evidence(
    evidence: dict[str, object],
    *,
    contract_raw: bytes,
    candidate: Candidate,
    repo_root: Path,
) -> None:
    if type(evidence) is not dict or set(evidence) != {
        "authority",
        "candidate_identity",
        "candidate_metrics",
        "contract_sha256",
        "schema_version",
        "v1_evidence",
    }:
        refuse("invalid_evidence")
    if (
        evidence["schema_version"] != EVIDENCE_SCHEMA
        or evidence["contract_sha256"] != sha256(contract_raw)
        or evidence["authority"]
        != {"activation": False, "claim": False, "runtime_mutation": False}
        or evidence["candidate_identity"] != _candidate_identity(candidate)
        or evidence["candidate_metrics"] != candidate.metrics
    ):
        refuse("invalid_evidence")
    runner_raw = _read_current_regular(Path(__file__).resolve(strict=True), "runner")
    if evidence["v1_evidence"].get("runner_sha256") != sha256(runner_raw):
        refuse("invalid_evidence")
    try:
        candidate.v1.module.validate_public_evidence(
            evidence["v1_evidence"],
            contract_raw=candidate.v1.contract_raw,
            repo_root=repo_root,
        )
    except Exception:
        refuse("invalid_evidence")


def _read_current_regular(path: Path, label: str) -> bytes:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            refuse(f"changed_{label}")
        return resolved.read_bytes()
    except OSError:
        refuse(f"changed_{label}")


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
    runner_path = Path(__file__).resolve(strict=True)
    runner_raw = _read_current_regular(runner_path, "runner")
    runner_digest = sha256(runner_raw)
    contract_raw = _read_current_regular(contract_path, "contract")
    contract = _parse_contract(contract_raw)
    validate_contract(contract, repo_root=repo_root)
    candidate = prepare_candidate(contract=contract, repo_root=repo_root)
    candidate.v1.module.validate_api_key(api_key)
    candidate.v1.module.validate_pricing_window(candidate.v1.contract)
    candidate.v1.base._private_root(output_root)
    candidate.v1.base._private_root(state_root)
    schedule = load_schedule(candidate.v1, repo_root=repo_root)
    schema_raw = _read_bound(
        repo_root
        / "research/provider-free-roadmap/g5/v1/schemas/authoritative-observation.schema.json",
        candidate.v1.base.CAPTURED_CONTRACT["g5"]["observation_schema_sha256"],
        "g5_observation_schema",
    )
    plan = candidate.v1.base.build_request_plan(
        contract=candidate.v1.contract,
        schedule=schedule,
        tasks=candidate.tasks,
        packs=candidate.packs,
    )
    scope = build_approval_scope(
        candidate=candidate,
        contract=contract,
        output_root=output_root,
        plan=plan,
        runner_sha256=runner_digest,
    )

    def materialize(_scope: dict[str, object]) -> dict[str, object]:
        scorer_box: dict[str, object] = {}

        def load_scorer() -> object:
            scorer = candidate.capture.load_scorer()
            scorer_box.update(scorer)
            return scorer

        active_invoke = invoke or (
            lambda item: candidate.v1.module.invoke_anthropic(
                item,
                contract=candidate.v1.contract,
                api_key=api_key,
            )
        )
        execution = candidate.v1.module.execute_schedule(
            contract=candidate.v1.contract,
            schedule=schedule,
            observation_schema_bytes=schema_raw,
            tasks=candidate.tasks,
            packs=candidate.packs,
            invoke=active_invoke,
            scorer_loader=load_scorer,
            repo_root=repo_root,
        )
        if sha256(_read_current_regular(runner_path, "runner")) != runner_digest:
            refuse("changed_runner")
        phase_records = candidate.v1.base.build_p2_phase_records(
            observed_at=int(time.time()),
            retention_seconds=contract["safety"]["retention_seconds"],
            tasks=candidate.tasks,
            packs=candidate.packs,
            oracle=scorer_box["oracle"],
        )
        phase_results = {
            name: candidate.v1.base.evaluate_phase_record(record, repo_root=repo_root)
            for name, record in phase_records.items()
        }
        v1_evidence = candidate.v1.module.build_public_evidence(
            contract_raw=candidate.v1.contract_raw,
            execution=execution,
            phase_records=phase_records,
            phase_results=phase_results,
            runner_sha256=runner_digest,
        )
        candidate.v1.module.validate_public_evidence(
            v1_evidence,
            contract_raw=candidate.v1.contract_raw,
            repo_root=repo_root,
        )
        evidence = build_evidence(
            candidate=candidate,
            contract_raw=contract_raw,
            v1_evidence=v1_evidence,
        )
        validate_evidence(
            evidence,
            contract_raw=contract_raw,
            candidate=candidate,
            repo_root=repo_root,
        )
        evidence_raw = canonical(evidence)
        candidate.v1.base._write_private(
            output_root / "p3-api-v2-evidence.json",
            evidence_raw,
        )
        return {
            "call_count": 240,
            "evidence_sha256": sha256(evidence_raw),
            "status": "p3_api_v2_measurement_recorded",
        }

    resolved_approval = candidate.v1.module.resolve_external_approval(approval, scope)
    result = candidate.v1.base.consume_authorized(
        contract=candidate.v1.contract,
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
        "direct mutable Anthropic API v2 execution is unavailable; use a one-use external approval envelope",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
