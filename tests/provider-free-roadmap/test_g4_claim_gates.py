from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
G4 = ROOT / "research/provider-free-roadmap/g4"
V1 = G4 / "v1"
VERIFIER = V1 / "verify.py"
POLICY = V1 / "claim-policy.json"
SCHEMAS = V1 / "schemas"
G3 = ROOT / "research/provider-free-roadmap/g3"
G3_V1 = G3 / "v1"
G2 = ROOT / "research/provider-free-roadmap/g2"


def captured(name: str, path: Path) -> bytes:
    value = globals().get(name)
    if value is None:
        return path.read_bytes()
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be captured bytes")
    return value


def captured_map(name: str, paths: list[Path]) -> dict[str, bytes]:
    value = globals().get(name)
    if value is None:
        return {path.name: path.read_bytes() for path in paths}
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(raw, bytes) for key, raw in value.items()
    ):
        raise TypeError(f"{name} must be a captured byte map")
    return value


def load_verifier() -> types.ModuleType:
    raw = captured("__G4_CAPTURED_VERIFIER_BYTES__", VERIFIER)
    module = types.ModuleType("captured_g4_verifier")
    module.__file__ = str(VERIFIER)
    sys.modules[module.__name__] = module
    exec(compile(raw, str(VERIFIER), "exec"), module.__dict__, module.__dict__)
    return module


class G4ClaimGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = load_verifier()
        cls.g3_inputs = {
            "g3_lock_bytes": captured("__G4_CAPTURED_G3_LOCK_BYTES__", G3 / "freeze-lock.json"),
            "g3_runner_bytes": captured(
                "__G4_CAPTURED_G3_RUNNER_BYTES__", G3_V1 / "rehearse.py"
            ),
            "g3_manifest_bytes": captured(
                "__G4_CAPTURED_G3_MANIFEST_BYTES__", G3_V1 / "manifest.json"
            ),
            "g3_cost_model_bytes": captured(
                "__G4_CAPTURED_G3_COST_MODEL_BYTES__", G3_V1 / "cost-model.json"
            ),
            "g3_schema_bytes": captured_map(
                "__G4_CAPTURED_G3_SCHEMA_BYTES__", sorted((G3_V1 / "schemas").glob("*.json"))
            ),
            "g2_verifier_bytes": captured(
                "__G4_CAPTURED_G2_VERIFIER_BYTES__", G2 / "v1/verify.py"
            ),
            "g2_lock_bytes": captured("__G4_CAPTURED_G2_LOCK_BYTES__", G2 / "freeze-lock.json"),
        }
        cls.g4_inputs = {
            "claim_policy_bytes": captured("__G4_CAPTURED_POLICY_BYTES__", POLICY),
            "g4_schema_bytes": captured_map(
                "__G4_CAPTURED_SCHEMA_BYTES__", sorted(SCHEMAS.glob("*.json"))
            ),
        }
        cls.temporary = tempfile.TemporaryDirectory(prefix="contextguard-g4-test-")
        cls.private_root = Path(cls.temporary.name) / "authenticated"
        cls.result = cls.gate.run_authenticated(
            ROOT, cls.private_root, **cls.g3_inputs, **cls.g4_inputs
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def artifacts(self) -> dict[str, bytes]:
        output = self.private_root / "g4"
        return {path.name: path.read_bytes() for path in output.iterdir()}

    def test_source_is_fresh_authenticated_g3_and_exact_24(self) -> None:
        self.assertEqual(self.result["status"], "authenticated_g3_claim_gate_verified")
        records = json.loads(self.artifacts()["source-records.json"])["records"]
        self.assertEqual(len(records), 24)
        self.assertEqual(
            {(item["task_id"], item["arm"]) for item in records},
            {(task, arm) for task in self.gate.TASKS for arm in self.gate.ARMS},
        )
        self.assertTrue(all(item["eligibility"] is True for item in records))
        self.assertTrue(all(item["validation_outcome"] == "full_g2_local_contract_validated" for item in records))

    def test_arbitrary_synthetic_evidence_has_no_entrypoint(self) -> None:
        self.assertFalse(hasattr(self.gate, "validate_and_report"))
        with self.assertRaises(TypeError):
            self.gate.run_authenticated(ROOT, self.private_root, evidence={"records": []})

    def test_fabricated_24_record_helper_chain_requires_authenticated_g3_root(self) -> None:
        fabricated = {"records": [
            {
                "arm": arm,
                "receipt_sha256": "0" * 64,
                "scorer_validation": self.gate.G3_VALIDATION,
                "task_id": task,
            }
            for task in self.gate.TASKS for arm in self.gate.ARMS
        ]}
        boundary = {
            "claim": "audited_cpython_process_boundary_not_os_sandbox",
            "dns_denials": 1, "network_denials": 1,
            "process_denials": 1, "write_denials": 1,
        }
        with self.assertRaisesRegex(Exception, "authenticated G3|authenticated.*root"):
            source = self.gate.source_export(fabricated)
            report = self.gate.build_report(source, boundary)
            self.gate.validate_public_artifacts(
                {
                    "claim-report.json": self.gate.canonical(report),
                    "source-records.json": self.gate.canonical(source),
                },
                self.g4_inputs["g4_schema_bytes"],
                self.g3_inputs["g2_verifier_bytes"],
            )

    def test_source_export_rejects_outer_receipt_identity_mismatch(self) -> None:
        task_results = json.loads(
            (self.private_root / "g3/task-arm-results.json").read_bytes()
        )
        export = getattr(self.gate, "_source_export", self.gate.source_export)
        mutations = {
            "task": lambda item: item["receipt"].update(task_id="evaluation_graph"),
            "arm": lambda item: item["receipt"].update(arm="combined"),
            "stratum": lambda item: item["receipt"].update(stratum="realistic_fallback"),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(task_results)
                mutation(changed["records"][0])
                with self.assertRaisesRegex(Exception, "outer|receipt|identity|stratum"):
                    export(changed)

    def test_rows_are_exact_partition_stratum_arm_cells_and_conserve(self) -> None:
        report = json.loads(self.artifacts()["claim-report.json"])
        rows = report["rows"]
        self.assertEqual(len(rows), 24)
        self.assertEqual(
            {(row["partition"], row["stratum"], row["arm"]) for row in rows},
            {(partition, stratum, arm) for partition in self.gate.PARTITIONS
             for stratum in self.gate.STRATA for arm in self.gate.ARMS},
        )
        self.assertTrue(all(row["record_count"] == row["eligible_count"] == 1 for row in rows))
        self.assertEqual(report["combined_count_only"], {
            "eligible_count": 24, "record_count": 24,
            "scope": "descriptive_count_only_no_pooled_inference", "task_count": 6,
        })
        self.assertEqual(report["conservation"]["total_records"], 24)
        self.assertEqual(set(report["conservation"]["by_arm"].values()), {6})
        self.assertEqual(set(report["conservation"]["by_partition"].values()), {8})
        self.assertEqual(set(report["conservation"]["by_stratum"].values()), {12})
        self.assertNotIn("interval", json.dumps(report).lower())

    def test_claim_policy_is_closed_and_forbidden_claims_are_permanently_false(self) -> None:
        report = json.loads(self.artifacts()["claim-report.json"])
        verdicts = {item["claim"]: item["claim_allowed"] for item in report["claims"]}
        self.assertEqual(set(verdicts), set(self.gate.CLAIMS))
        for claim in self.gate.FORBIDDEN_CLAIMS:
            self.assertIs(verdicts[claim], False)
        for claim in self.gate.ALLOWED_CLAIMS:
            self.assertIs(verdicts[claim], True)
        for synonym in ("savings", "fast", "production-ready", "works generally"):
            with self.subTest(synonym=synonym), self.assertRaisesRegex(Exception, "claim"):
                self.gate._validate_claim_request([synonym])

    def test_public_artifacts_exclude_private_and_sealed_representations(self) -> None:
        keys = set()
        def visit(value):
            if isinstance(value, dict):
                keys.update(value)
                for item in value.values(): visit(item)
            elif isinstance(value, list):
                for item in value: visit(item)
        for raw in self.artifacts().values():
            visit(json.loads(raw))
        self.assertFalse(keys & self.gate.FORBIDDEN_PUBLIC_KEYS)
        self.assertFalse({"canonical_base64", "sealed_fields"} & keys)
        for forbidden in ("prompt", "cost", "latency", "timing", "required_paths", "required_symbols"):
            self.assertNotIn(forbidden, " ".join(keys).lower())

    def test_all_schemas_are_recursively_closed_and_actually_validate(self) -> None:
        self.gate.verify_public_artifacts(
            self.private_root / "g3", self.artifacts(), **self.g3_inputs,
            g4_schema_bytes=self.g4_inputs["g4_schema_bytes"],
        )

    def test_public_validation_byte_compares_authenticated_derived_source(self) -> None:
        artifacts = self.artifacts()
        source = json.loads(artifacts["source-records.json"])
        source["records"][0]["receipt_sha256"] = "0" * 64
        core = {key: source["records"][0][key] for key in (
            "arm", "eligibility", "partition", "receipt_sha256", "schema_version",
            "stratum", "task_id", "validation_outcome",
        )}
        source["records"][0]["record_id"] = hashlib.sha256(
            b"contextguard.g4-source-record/v1\x00" + self.gate.canonical(core)
        ).hexdigest()
        report = json.loads(artifacts["claim-report.json"])
        report = self.gate._build_report(source, report["boundary"])
        changed = {
            "claim-report.json": self.gate.canonical(report),
            "source-records.json": self.gate.canonical(source),
        }
        with self.assertRaisesRegex(Exception, "authenticated G3 root"):
            self.gate.verify_public_artifacts(
                self.private_root / "g3", changed, **self.g3_inputs,
                g4_schema_bytes=self.g4_inputs["g4_schema_bytes"],
            )

    def test_sanitized_mutations_omit_duplicate_or_misclassify_hard_fail(self) -> None:
        source = json.loads(self.artifacts()["source-records.json"])
        mutations = {
            "omission": lambda value: value["records"].pop(),
            "duplicate": lambda value: value["records"].append(copy.deepcopy(value["records"][0])),
            "partition": lambda value: value["records"][0].update(partition="evaluation"),
            "stratum": lambda value: value["records"][0].update(stratum="realistic_fallback"),
            "arm": lambda value: value["records"][0].update(arm="combined"),
            "task": lambda value: value["records"][0].update(task_id="evaluation_graph"),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(source); mutation(changed)
                with self.assertRaisesRegex(Exception, "coverage|mapping|duplicate|identity"):
                    self.gate._validate_source_records(changed)

    def test_private_or_sealed_key_in_sanitized_export_hard_fails(self) -> None:
        source = json.loads(self.artifacts()["source-records.json"])
        for key, value in (
            ("oracle", {}), ("required_symbols", []),
            ("canonical_base64", "e30K"), ("scorer_private", True),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(source); changed["records"][0][key] = value
                with self.assertRaisesRegex(Exception, "private|sealed|schema|key"):
                    self.gate._validate_source_records(changed)

    def test_g3_accounting_cost_timing_interval_tamper_is_rejected(self) -> None:
        cases = {
            "authenticated-root": ("resolved-manifest.json", lambda value: value.update(schema_version="contextguard.g3-rehearsal-manifest/forged")),
            "returned-byte": ("events.jsonl", lambda value: value.update(returned_bytes=999)),
            "cost": ("task-arm-results.json", lambda value: value["records"][0]["cost"].update(total=999)),
            "timing": ("timing-summary.json", lambda value: value.update(observation_count=23)),
            "interval": ("aggregate-results.json", lambda value: value["cost_inference"].update(enumeration_count=1)),
        }
        for label, (name, mutation) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "g3"
                shutil.copytree(self.private_root / "g3", copied)
                path = copied / name
                if name.endswith(".jsonl"):
                    lines = path.read_bytes().splitlines(); value = json.loads(lines[1]); mutation(value)
                    lines[1] = self.gate.canonical(value).rstrip(b"\n"); path.write_bytes(b"\n".join(lines) + b"\n")
                else:
                    value = json.loads(path.read_bytes()); mutation(value); path.write_bytes(self.gate.canonical(value))
                inventory_path = copied / "artifact-inventory.json"
                inventory = json.loads(inventory_path.read_bytes())
                entry = next(item for item in inventory["artifacts"] if item["path"] == name)
                raw = path.read_bytes(); entry.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                inventory_path.write_bytes(self.gate.canonical(inventory))
                with self.assertRaisesRegex(Exception, "drift|mismatch|evidence|timing|enumeration|event"):
                    self.gate.derive_from_verified_g3(
                        copied, **self.g3_inputs, g4_schema_bytes=self.g4_inputs["g4_schema_bytes"],
                    )

    def test_deterministic_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            second = self.gate.run_authenticated(
                ROOT, Path(temporary) / "authenticated", **self.g3_inputs, **self.g4_inputs
            )
            self.assertEqual(
                self.result["deterministic_report_sha256"],
                second["deterministic_report_sha256"],
            )

    def test_audited_negative_probes_and_private_modes(self) -> None:
        report = json.loads(self.artifacts()["claim-report.json"])
        self.assertEqual(report["boundary"], {
            "claim": "audited_cpython_process_boundary_not_os_sandbox",
            "dns_denials": 1, "network_denials": 1,
            "process_denials": 1, "write_denials": 1,
        })
        for directory in (self.private_root, self.private_root / "g3", self.private_root / "g4"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in (self.private_root / "g4").iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_bound_profile_environment_and_direct_runner_refusal(self) -> None:
        if "__G4_CAPTURED_VERIFIER_BYTES__" in globals():
            self.assertEqual(sys.flags.isolated, 1)
            self.assertEqual(sys.flags.dont_write_bytecode, 1)
            self.assertEqual(os.environ.get("LANG"), "C.UTF-8")
            self.assertTrue(set(os.environ) <= {"LANG", "__CF_USER_TEXT_ENCODING"})
        self.assertEqual(self.gate.main([]), 2)


if __name__ == "__main__":
    unittest.main()
