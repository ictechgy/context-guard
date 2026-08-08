from __future__ import annotations

import copy
import json
import stat
import unittest
from pathlib import Path

from tests.test_contextguard_stage2_verification_schema import validate
from tests.test_contextguard_stage2_protected_surfaces import (
    APPROVED_POST_STAGE2_PROTECTED_PATHS,
    CSV_COLUMNS_SHA256,
    EXPECTED_PATHS,
    MANIFEST_PATH,
    csv_columns_digest,
    portable_regular_mode,
    sha256,
    tracked_paths,
    validate_manifest_shape,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
STAGE2_ROOT = REPO_ROOT / "research/contextguard-stage2"
RECORD_PATH = STAGE2_ROOT / "verification-record.json"
SCHEMA_PATH = STAGE2_ROOT / "verification-record.schema.json"

EXPECTED_BLOCKERS = [
    "EXACT_FRAMING_UNPROVEN",
    "EXTERNAL_GATES_INCOMPLETE",
    "HOST_OBSERVER_CONTRACT_UNSUPPORTED",
    "INERT_RESPONSE_UNPROVEN",
    "PROVIDER_JOIN_MISSING",
    "REAL_HOST_PERMISSION_OUTCOME_UNPROVEN",
]
EXPECTED_CHARTER_IDENTITY = {
    "charter_id": "S3D-ARF",
    "charter_sha256": "f4a40efd4b526c15a44de97a2619d39c1a2db748704806fe0e0f6e882ced5a43",
    "schema_version": "contextguard-stage2-s3d-arf-charter/v1",
    "status": "inactive_provider_free",
}
EXPECTED_EXTERNAL_GATES = {
    "production_activation": "incomplete",
    "provider_join": "incomplete",
    "real_host_validation": "incomplete",
    "spend_authorization": "incomplete",
}
FROZEN_AUTHORIZATIONS = [
    "artifact_root_reuse",
    "efficacy_claim",
    "fixture_derived_claims",
    "hook_registration",
    "installed_settings_mutation",
    "multi_file_redirection",
    "package_helper_entry",
    "packaging",
    "provider_call",
    "r9_reinterpretation",
    "runtime_implementation",
    "settings_default_plugin_change",
    "spend",
    "updated_input_mutation",
]
FROZEN_SURFACES = [
    "hook_registrations",
    "package_helper_entries",
    "runtime_files",
    "settings_default_plugin_changes",
]


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"


class ContextGuardStage2CompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = RECORD_PATH.read_bytes()
        cls.record = json.loads(cls.raw)
        cls.schema = json.loads(SCHEMA_PATH.read_bytes())

    def assert_invalid(self, candidate: object) -> None:
        with self.assertRaises(AssertionError):
            validate(candidate, self.schema)

    def test_record_is_canonical_schema_valid_and_byte_stable(self) -> None:
        self.assertEqual(self.raw, canonical_bytes(self.record))
        validate(self.record, self.schema)
        regenerated = canonical_bytes(json.loads(self.raw))
        self.assertEqual(regenerated, self.raw)
        self.assertEqual(self.raw.count(b"\n"), 1)
        self.assertTrue(self.raw.endswith(b"\n"))

    def test_record_closes_unsupported_branch_and_retains_external_blockers(self) -> None:
        self.assertEqual(self.record["selected_branch"], "S2-UNSUPPORTED")
        self.assertEqual(self.record["selected_transport"], "NONE")
        self.assertIs(self.record["runtime_observer_present"], False)
        self.assertEqual(self.record["provider_join_status"], "missing")
        self.assertIs(self.record["claim_allowed"], False)
        self.assertEqual(self.record["blockers"], EXPECTED_BLOCKERS)
        self.assertEqual(self.record["external_gates"], EXPECTED_EXTERNAL_GATES)
        self.assertEqual(self.record["charter_identity"], EXPECTED_CHARTER_IDENTITY)

    def test_rejects_blocker_and_external_gate_drift(self) -> None:
        blocker_mutations = [
            EXPECTED_BLOCKERS[:-1],
            EXPECTED_BLOCKERS + ["UNDECLARED_BLOCKER"],
            EXPECTED_BLOCKERS[:-1] + [EXPECTED_BLOCKERS[0]],
            list(reversed(EXPECTED_BLOCKERS)),
        ]
        for blockers in blocker_mutations:
            candidate = copy.deepcopy(self.record)
            candidate["blockers"] = blockers
            with self.subTest(blockers=blockers):
                self.assert_invalid(candidate)

        gate_mutations = [
            {**EXPECTED_EXTERNAL_GATES, "provider_join": "complete"},
            {**EXPECTED_EXTERNAL_GATES, "invented_gate": "incomplete"},
        ]
        for gates in gate_mutations:
            candidate = copy.deepcopy(self.record)
            candidate["external_gates"] = gates
            with self.subTest(gates=gates):
                self.assert_invalid(candidate)

    def test_rejects_runtime_transport_provider_and_claim_activation(self) -> None:
        mutations = [
            ("runtime_observer_present", True),
            ("selected_transport", "EVENT"),
            ("selected_transport", "PATH"),
            ("provider_join_status", "attributed"),
            ("claim_allowed", True),
        ]
        for field, value in mutations:
            candidate = copy.deepcopy(self.record)
            candidate[field] = value
            with self.subTest(field=field, value=value):
                self.assert_invalid(candidate)

        forbidden_claim = copy.deepcopy(self.record)
        forbidden_claim["token_savings"] = 1
        self.assert_invalid(forbidden_claim)

    def test_rejects_stage1_r9_csv_settings_defaults_and_plugin_drift(self) -> None:
        self.assertEqual(list(self.record["authorizations"]), FROZEN_AUTHORIZATIONS)
        self.assertEqual(list(self.record["surface_changes"]), FROZEN_SURFACES)

        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        validate_manifest_shape(manifest)
        entries = manifest["entries"]
        self.assertEqual([entry["path"] for entry in entries], sorted(EXPECTED_PATHS))
        tracked = tracked_paths(EXPECTED_PATHS)
        for entry in entries:
            path = REPO_ROOT / entry["path"]
            metadata = path.lstat()
            with self.subTest(protected_path=entry["path"]):
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(entry["file_type"], "regular")
                self.assertEqual(entry["mode"], portable_regular_mode(metadata.st_mode))
                if entry["path"] not in APPROVED_POST_STAGE2_PROTECTED_PATHS:
                    self.assertEqual(entry["sha256"], sha256(path))
                self.assertIs(entry["tracked"], entry["path"] in tracked)

        invariants = manifest["invariants"]
        self.assertEqual(invariants["csv_columns"]["sha256"], CSV_COLUMNS_SHA256)
        self.assertEqual(
            csv_columns_digest(REPO_ROOT / invariants["csv_columns"]["source_path"]),
            CSV_COLUMNS_SHA256,
        )
        self.assertEqual(invariants["artifact_transport"]["status"], "transport_rejected")
        self.assertEqual(invariants["r9"]["verdict"], "inconclusive")
        self.assertIs(invariants["r9"]["claim_allowed"], False)

        for field in FROZEN_AUTHORIZATIONS:
            candidate = copy.deepcopy(self.record)
            candidate["authorizations"][field] = True
            with self.subTest(authorization=field):
                self.assert_invalid(candidate)

        for field in FROZEN_SURFACES:
            candidate = copy.deepcopy(self.record)
            candidate["surface_changes"][field] = ["drift"]
            with self.subTest(surface=field):
                self.assert_invalid(candidate)


if __name__ == "__main__":
    unittest.main()
