#!/usr/bin/env python3
"""Authenticated provider-free G4 claim gate over a freshly captured G3 run."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Mapping


ARMS = ("ordinary", "adaptive_only", "symbol_only", "combined")
PARTITIONS = ("train", "calibration", "evaluation")
STRATA = ("closed_pack", "realistic_fallback")
TASKS = (
    "train_closed", "train_graph", "calibration_closed", "calibration_graph",
    "evaluation_closed", "evaluation_graph",
)
TASK_MAPPING = {
    "train_closed": ("train", "closed_pack"),
    "train_graph": ("train", "realistic_fallback"),
    "calibration_closed": ("calibration", "closed_pack"),
    "calibration_graph": ("calibration", "realistic_fallback"),
    "evaluation_closed": ("evaluation", "closed_pack"),
    "evaluation_graph": ("evaluation", "realistic_fallback"),
}
ALLOWED_CLAIMS = (
    "provider_free_rehearsal", "correctness_of_local_contract",
    "reproducibility", "measurement_readiness",
)
FORBIDDEN_CLAIMS = (
    "token_savings", "provider_performance", "production_readiness",
    "external_validity", "generalization",
)
CLAIMS = ALLOWED_CLAIMS + FORBIDDEN_CLAIMS
FORBIDDEN_PUBLIC_KEYS = {
    "adaptive_labels", "answer_signature", "canonical_base64", "cost",
    "expected_output", "graph_evidence", "hidden_oracle", "latency", "oracle",
    "prompt", "required_paths", "required_symbols", "scorer_private",
    "sealed_fields", "timing",
}
G3_LOCK_SHA256 = "20cf16e701e3d55a11c084033efaa06c0129f80fcf1ae7743514953d7440624a"
G3_TREE_SHA256 = "593dbd277dd044264140bb748d30ef45c7e029e9c9fbe2bea5877c99ef421c36"
G3_RUNNER_SHA256 = "6683de5244428714a273dd50f9b12a84c9a4c47e96f3cc97e1c18272c5b50f23"
G3_MANIFEST_SHA256 = "e647db61ac92c80b59f7fa653aa53d0618f84069a6ecbc01dfc204740af17e4b"
G3_SCHEMA_SET = {"bytes": 25254, "sha256": "2ad1c70def6011139ecc76d4761268d6534af564f39bcce381fcbcf9a1cc2a7c"}
G2_LOCK_SHA256 = "722b1b65a3d927b2549ba1befe9c60ffcaceea6b32fc6cbd1ebbd35f3adb91f8"
G2_TREE_SHA256 = "9ed2bafba81227924fb0d09ff0bc1697426f05944d3da33d94d1f2f4b0c4ccb6"
G2_VERIFIER_SHA256 = "bd5e83e646d3db943452a99501e44c83ab50be6474235c8d3c30316a793fb520"
G3_VALIDATION = "full_g2_oracle_graph_topology_adaptive_symbol_arm_passed"


class GateError(ValueError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=duplicate_keys)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise GateError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"object required: {label}")
    return value


def map_identity(files: Mapping[str, bytes]) -> dict[str, object]:
    digest = hashlib.sha256(b"contextguard.g3-captured-map/v1\x00")
    total = 0
    for name, raw in sorted(files.items()):
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big") + encoded)
        digest.update(len(raw).to_bytes(8, "big") + raw)
        total += len(raw)
    return {"bytes": total, "sha256": digest.hexdigest()}


def recursive_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        result.update(value)
        for child in value.values():
            result.update(recursive_keys(child))
    elif isinstance(value, list):
        for child in value:
            result.update(recursive_keys(child))
    return result


def reject_private(value: object, label: str) -> None:
    keys = recursive_keys(value)
    forbidden = FORBIDDEN_PUBLIC_KEYS & keys
    if forbidden:
        raise GateError(f"private or sealed key in {label}: {sorted(forbidden)[0]}")


def load_module(raw: bytes, expected: str, name: str) -> types.ModuleType:
    if sha256(raw) != expected:
        raise GateError(f"changed captured module: {name}")
    module = types.ModuleType(name)
    module.__file__ = f"<captured-{name}>"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__, module.__dict__)
    return module


def validate_upstream(
    *, g3_lock_bytes: bytes, g3_runner_bytes: bytes, g3_manifest_bytes: bytes,
    g3_cost_model_bytes: bytes, g3_schema_bytes: Mapping[str, bytes],
    g2_verifier_bytes: bytes, g2_lock_bytes: bytes,
) -> dict:
    if sha256(g3_lock_bytes) != G3_LOCK_SHA256:
        raise GateError("changed authenticated G3 freeze lock")
    lock = parse(g3_lock_bytes, "G3 freeze lock")
    if lock.get("tree_root_sha256") != G3_TREE_SHA256:
        raise GateError("changed authenticated G3 freeze tree")
    if lock.get("g2_source") != {
        "lock_sha256": G2_LOCK_SHA256, "tree_root_sha256": G2_TREE_SHA256,
        "verifier_sha256": G2_VERIFIER_SHA256,
    }:
        raise GateError("changed authenticated G2 source")
    if sha256(g3_runner_bytes) != G3_RUNNER_SHA256 or sha256(g3_manifest_bytes) != G3_MANIFEST_SHA256:
        raise GateError("changed authenticated G3 runner or manifest")
    if map_identity(g3_schema_bytes) != G3_SCHEMA_SET:
        raise GateError("changed authenticated G3 schema set")
    if sha256(g2_verifier_bytes) != G2_VERIFIER_SHA256 or sha256(g2_lock_bytes) != G2_LOCK_SHA256:
        raise GateError("changed authenticated G2 bytes")
    inventory = {item["path"]: item for item in lock.get("inventory", [])}
    expected = {
        "research/provider-free-roadmap/g3/v1/rehearse.py": g3_runner_bytes,
        "research/provider-free-roadmap/g3/v1/manifest.json": g3_manifest_bytes,
        "research/provider-free-roadmap/g3/v1/cost-model.json": g3_cost_model_bytes,
    }
    expected.update({f"research/provider-free-roadmap/g3/v1/schemas/{name}": raw for name, raw in g3_schema_bytes.items()})
    for path, raw in expected.items():
        item = inventory.get(path)
        if item is None or item.get("bytes") != len(raw) or item.get("sha256") != sha256(raw):
            raise GateError(f"G3 freeze inventory binding drift: {path}")
    return lock


class ProbePolicy:
    def __init__(self, allowed_root: Path):
        self.allowed_root = allowed_root.resolve(strict=True)
        self.network_denials = self.dns_denials = self.process_denials = self.write_denials = 0

    def audit(self, event: str, args: tuple[object, ...]) -> None:
        if event == "socket.getaddrinfo":
            self.dns_denials += 1
            raise PermissionError("G4 denied DNS")
        if event.startswith("socket."):
            self.network_denials += 1
            raise PermissionError("G4 denied network")
        if event == "subprocess.Popen":
            self.process_denials += 1
            raise PermissionError("G4 denied process")
        if event == "open" and len(args) > 1:
            mode = str(args[1])
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                try:
                    candidate = Path(os.fspath(args[0])).resolve(strict=False)
                except (TypeError, ValueError, OSError):
                    candidate = Path("/")
                if candidate != self.allowed_root and self.allowed_root not in candidate.parents:
                    self.write_denials += 1
                    raise PermissionError("G4 denied write")

    def receipt(self) -> dict:
        return {
            "claim": "audited_cpython_process_boundary_not_os_sandbox",
            "dns_denials": self.dns_denials, "network_denials": self.network_denials,
            "process_denials": self.process_denials, "write_denials": self.write_denials,
        }


_ACTIVE_POLICY: ProbePolicy | None = None
_AUDIT_INSTALLED = False


def _audit(event: str, args: tuple[object, ...]) -> None:
    if _ACTIVE_POLICY is not None:
        _ACTIVE_POLICY.audit(event, args)


def audited_probes(private_root: Path) -> dict:
    global _ACTIVE_POLICY, _AUDIT_INSTALLED
    if not _AUDIT_INSTALLED:
        sys.addaudithook(_audit)
        _AUDIT_INSTALLED = True
    policy = ProbePolicy(private_root)
    _ACTIVE_POLICY = policy
    operations = (
        lambda: socket.socket(),
        lambda: socket.getaddrinfo("203.0.113.1", 443, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST),
        lambda: subprocess.run(["/g4-process-decoy"], check=False),
        lambda: open(private_root.parent / "g4-write-decoy", "wb"),
    )
    try:
        for operation in operations:
            try:
                operation()
            except (PermissionError, OSError):
                continue
            raise GateError("G4 audited negative probe was not denied")
    finally:
        _ACTIVE_POLICY = None
    receipt = policy.receipt()
    if set(receipt.values()) - {receipt["claim"], 1}:
        raise GateError("G4 audited denial counters drift")
    return receipt


def _validate_claim_request(claims: list[str]) -> list[dict[str, object]]:
    if not isinstance(claims, list) or not claims or len(claims) != len(set(claims)):
        raise GateError("claim request must be a unique nonempty list")
    if any(claim not in CLAIMS for claim in claims):
        raise GateError("claim request contains a non-contract claim")
    return [{"claim": claim, "claim_allowed": claim in ALLOWED_CLAIMS} for claim in claims]


def _validate_source_records(value: dict) -> list[dict]:
    reject_private(value, "G4 sanitized source")
    if set(value) != {"record_count", "records", "schema_version"} or value["schema_version"] != "contextguard.g4-source-records/v1":
        raise GateError("invalid sanitized source keys")
    records = value.get("records")
    if not isinstance(records, list) or value.get("record_count") != 24 or len(records) != 24:
        raise GateError("sanitized source coverage count mismatch")
    expected_keys = {(task, arm) for task in TASKS for arm in ARMS}
    actual_keys = [(item.get("task_id"), item.get("arm")) for item in records if isinstance(item, dict)]
    if len(actual_keys) != 24 or set(actual_keys) != expected_keys or len(set(actual_keys)) != 24:
        raise GateError("sanitized source duplicate or coverage mismatch")
    for item in records:
        if set(item) != {
            "arm", "eligibility", "partition", "receipt_sha256", "record_id",
            "schema_version", "stratum", "task_id", "validation_outcome",
        }:
            raise GateError("invalid sanitized source record key")
        mapping = TASK_MAPPING[item["task_id"]]
        if (item["partition"], item["stratum"]) != mapping:
            raise GateError("task partition/stratum mapping mismatch")
        core = {key: item[key] for key in (
            "arm", "eligibility", "partition", "receipt_sha256", "schema_version",
            "stratum", "task_id", "validation_outcome",
        )}
        expected_id = sha256(b"contextguard.g4-source-record/v1\x00" + canonical(core))
        if item["record_id"] != expected_id:
            raise GateError("sanitized source record identity mismatch")
        if item["eligibility"] is not True or item["validation_outcome"] != "full_g2_local_contract_validated":
            raise GateError("sanitized source is not eligible")
    return records


def _source_export(task_results: dict) -> dict:
    records = []
    for item in task_results["records"]:
        if item.get("scorer_validation") != G3_VALIDATION:
            raise GateError("G3 bounded validation outcome mismatch")
        receipt = item.get("receipt")
        if not isinstance(receipt, dict) or any(
            item.get(key) != receipt.get(key) for key in ("task_id", "arm", "stratum")
        ):
            raise GateError("G3 outer/receipt task, arm, or stratum identity mismatch")
        task_id, arm = item["task_id"], item["arm"]
        partition, stratum = TASK_MAPPING.get(task_id, (None, None))
        if item["stratum"] != stratum:
            raise GateError("G3 authenticated task stratum mapping mismatch")
        core = {
            "arm": arm, "eligibility": True, "partition": partition,
            "receipt_sha256": item["receipt_sha256"],
            "schema_version": "contextguard.g4-source-record/v1", "stratum": stratum,
            "task_id": task_id, "validation_outcome": "full_g2_local_contract_validated",
        }
        records.append(dict(core, record_id=sha256(b"contextguard.g4-source-record/v1\x00" + canonical(core))))
    value = {"record_count": len(records), "records": records, "schema_version": "contextguard.g4-source-records/v1"}
    _validate_source_records(value)
    return value


def _build_report(source: dict, boundary: dict) -> dict:
    records = _validate_source_records(source)
    rows = []
    for partition in PARTITIONS:
        for stratum in STRATA:
            for arm in ARMS:
                selected = [item for item in records if (item["partition"], item["stratum"], item["arm"]) == (partition, stratum, arm)]
                rows.append({
                    "arm": arm, "eligible_count": sum(item["eligibility"] for item in selected),
                    "partition": partition, "record_count": len(selected), "stratum": stratum,
                })
    report = {
        "boundary": boundary,
        "claims": _validate_claim_request(list(CLAIMS)),
        "combined_count_only": {
            "eligible_count": 24, "record_count": 24,
            "scope": "descriptive_count_only_no_pooled_inference", "task_count": 6,
        },
        "conservation": {
            "by_arm": {arm: sum(item["arm"] == arm for item in records) for arm in ARMS},
            "by_partition": {part: sum(item["partition"] == part for item in records) for part in PARTITIONS},
            "by_stratum": {name: sum(item["stratum"] == name for item in records) for name in STRATA},
            "total_records": len(records),
        },
        "rows": rows,
        "schema_version": "contextguard.g4-claim-report/v1",
        "source_records_sha256": sha256(canonical(source)),
    }
    reject_private(report, "G4 report")
    if sum(row["record_count"] for row in rows) != 24 or any(row["record_count"] != 1 for row in rows):
        raise GateError("G4 row conservation mismatch")
    return report


def _validate_report(report: dict, source: dict) -> None:
    reject_private(report, "G4 report")
    boundary = report.get("boundary")
    if not isinstance(boundary, dict):
        raise GateError("G4 report boundary is missing")
    expected = _build_report(source, boundary)
    if report != expected:
        raise GateError("G4 report semantic or claim-policy mismatch")


def _validate_public_artifact_schemas(
    artifacts: Mapping[str, bytes], schema_bytes: Mapping[str, bytes], g2_verifier_bytes: bytes,
) -> None:
    g2 = load_module(g2_verifier_bytes, G2_VERIFIER_SHA256, "captured_g4_schema_validator")
    mapping = {"source-records.json": "source-records.schema.json", "claim-report.json": "claim-report.schema.json"}
    if set(artifacts) != set(mapping):
        raise GateError("G4 public artifact inventory mismatch")
    if set(schema_bytes) != set(mapping.values()) | {"claim-policy.schema.json"}:
        raise GateError("G4 schema set mismatch")
    values = {}
    for artifact_name, schema_name in mapping.items():
        value = parse(artifacts[artifact_name], artifact_name)
        values[artifact_name] = value
        reject_private(value, artifact_name)
        schema = parse(schema_bytes[schema_name], schema_name)
        g2.assert_supported_schema(schema, schema_name)
        g2.assert_closed_schema(schema, schema_name)
        g2.validate_schema(value, schema, schema, artifact_name)
    _validate_source_records(values["source-records.json"])
    _validate_report(values["claim-report.json"], values["source-records.json"])
    policy_schema = parse(schema_bytes["claim-policy.schema.json"], "claim policy schema")
    g2.assert_supported_schema(policy_schema, "claim-policy.schema.json")
    g2.assert_closed_schema(policy_schema, "claim-policy.schema.json")


def load_g3(g3_runner_bytes: bytes):
    return load_module(g3_runner_bytes, G3_RUNNER_SHA256, "captured_g4_g3_runner")


def derive_from_verified_g3(
    g3_output: Path, *, g3_lock_bytes: bytes, g3_runner_bytes: bytes,
    g3_manifest_bytes: bytes, g3_cost_model_bytes: bytes,
    g3_schema_bytes: Mapping[str, bytes], g2_verifier_bytes: bytes,
    g2_lock_bytes: bytes, g4_schema_bytes: Mapping[str, bytes],
) -> dict:
    validate_upstream(
        g3_lock_bytes=g3_lock_bytes, g3_runner_bytes=g3_runner_bytes,
        g3_manifest_bytes=g3_manifest_bytes, g3_cost_model_bytes=g3_cost_model_bytes,
        g3_schema_bytes=g3_schema_bytes, g2_verifier_bytes=g2_verifier_bytes,
        g2_lock_bytes=g2_lock_bytes,
    )
    g3 = load_g3(g3_runner_bytes)
    g3.verify_output(
        Path(g3_output), dict(g3_schema_bytes), expected_manifest_bytes=g3_manifest_bytes,
        expected_manifest_sha256=G3_MANIFEST_SHA256,
    )
    task_results = parse((Path(g3_output) / "task-arm-results.json").read_bytes(), "verified G3 task results")
    return _source_export(task_results)


def verify_public_artifacts(
    g3_output: Path, artifacts: Mapping[str, bytes], *, g3_lock_bytes: bytes,
    g3_runner_bytes: bytes, g3_manifest_bytes: bytes, g3_cost_model_bytes: bytes,
    g3_schema_bytes: Mapping[str, bytes], g2_verifier_bytes: bytes,
    g2_lock_bytes: bytes, g4_schema_bytes: Mapping[str, bytes],
) -> None:
    authenticated_source = derive_from_verified_g3(
        g3_output, g3_lock_bytes=g3_lock_bytes, g3_runner_bytes=g3_runner_bytes,
        g3_manifest_bytes=g3_manifest_bytes, g3_cost_model_bytes=g3_cost_model_bytes,
        g3_schema_bytes=g3_schema_bytes, g2_verifier_bytes=g2_verifier_bytes,
        g2_lock_bytes=g2_lock_bytes, g4_schema_bytes=g4_schema_bytes,
    )
    if artifacts.get("source-records.json") != canonical(authenticated_source):
        raise GateError("G4 public source differs from authenticated G3 root")
    _validate_public_artifact_schemas(artifacts, g4_schema_bytes, g2_verifier_bytes)


def source_export(*args: object, **kwargs: object) -> dict:
    del args, kwargs
    raise GateError("authenticated G3 root required; use derive_from_verified_g3")


def build_report(*args: object, **kwargs: object) -> dict:
    del args, kwargs
    raise GateError("authenticated G3 root required; use run_authenticated")


def validate_public_artifacts(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise GateError("authenticated G3 root required; use verify_public_artifacts")


def make_private_root(root: Path) -> None:
    try:
        root.lstat()
    except FileNotFoundError:
        root.mkdir(mode=0o700)
    else:
        raise GateError("preexisting G4 private root is prohibited")
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise GateError("G4 private root mode mismatch")


def write_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_authenticated(
    repository_root: Path, private_root: Path, *, g3_lock_bytes: bytes,
    g3_runner_bytes: bytes, g3_manifest_bytes: bytes, g3_cost_model_bytes: bytes,
    g3_schema_bytes: Mapping[str, bytes], g2_verifier_bytes: bytes,
    g2_lock_bytes: bytes, claim_policy_bytes: bytes, g4_schema_bytes: Mapping[str, bytes],
) -> dict:
    repository_root = Path(repository_root).resolve(strict=True)
    private_root = Path(private_root)
    make_private_root(private_root)
    validate_upstream(
        g3_lock_bytes=g3_lock_bytes, g3_runner_bytes=g3_runner_bytes,
        g3_manifest_bytes=g3_manifest_bytes, g3_cost_model_bytes=g3_cost_model_bytes,
        g3_schema_bytes=g3_schema_bytes, g2_verifier_bytes=g2_verifier_bytes,
        g2_lock_bytes=g2_lock_bytes,
    )
    policy = parse(claim_policy_bytes, "captured G4 claim policy")
    policy_schema = parse(g4_schema_bytes["claim-policy.schema.json"], "claim policy schema")
    g2 = load_module(g2_verifier_bytes, G2_VERIFIER_SHA256, "captured_g4_policy_validator")
    g2.assert_supported_schema(policy_schema, "claim-policy.schema.json")
    g2.assert_closed_schema(policy_schema, "claim-policy.schema.json")
    g2.validate_schema(policy, policy_schema, policy_schema, "claim policy")
    if policy.get("allowed_claims") != list(ALLOWED_CLAIMS) or policy.get("forbidden_claims") != list(FORBIDDEN_CLAIMS):
        raise GateError("changed closed G4 claim policy")
    g3_output = private_root / "g3"
    g3_runner = load_g3(g3_runner_bytes)
    g3_runner.run_captured(
        repository_root, g3_output, manifest_bytes=g3_manifest_bytes,
        cost_model_bytes=g3_cost_model_bytes, schema_bytes=dict(g3_schema_bytes),
        g2_verifier_bytes=g2_verifier_bytes, g2_lock_bytes=g2_lock_bytes,
        expected_g2_lock_sha256=G2_LOCK_SHA256, expected_g2_tree_root=G2_TREE_SHA256,
        expected_g2_verifier_sha256=G2_VERIFIER_SHA256,
    )
    source = derive_from_verified_g3(
        g3_output, g3_lock_bytes=g3_lock_bytes, g3_runner_bytes=g3_runner_bytes,
        g3_manifest_bytes=g3_manifest_bytes, g3_cost_model_bytes=g3_cost_model_bytes,
        g3_schema_bytes=g3_schema_bytes, g2_verifier_bytes=g2_verifier_bytes,
        g2_lock_bytes=g2_lock_bytes, g4_schema_bytes=g4_schema_bytes,
    )
    report = _build_report(source, audited_probes(private_root))
    artifacts = {"claim-report.json": canonical(report), "source-records.json": canonical(source)}
    verify_public_artifacts(
        g3_output, artifacts, g3_lock_bytes=g3_lock_bytes,
        g3_runner_bytes=g3_runner_bytes, g3_manifest_bytes=g3_manifest_bytes,
        g3_cost_model_bytes=g3_cost_model_bytes, g3_schema_bytes=g3_schema_bytes,
        g2_verifier_bytes=g2_verifier_bytes, g2_lock_bytes=g2_lock_bytes,
        g4_schema_bytes=g4_schema_bytes,
    )
    output = private_root / "g4"
    output.mkdir(mode=0o700)
    for name, raw in artifacts.items():
        write_private(output / name, raw)
    return {
        "deterministic_report_sha256": sha256(artifacts["claim-report.json"]),
        "record_count": 24, "status": "authenticated_g3_claim_gate_verified",
    }


def main(argv: list[str] | None = None) -> int:
    del argv
    print("direct mutable G4 verifier is unavailable; use the independently pinned G4 profile", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
