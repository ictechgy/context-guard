from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STAGE2_ROOT = REPO_ROOT / "research/contextguard-stage2"
SCHEMA_PATH = STAGE2_ROOT / "verification-record.schema.json"
CHARTER_PATH = STAGE2_ROOT / "S3D-ARF-charter.json"

BLOCKERS = [
    "EXACT_FRAMING_UNPROVEN",
    "EXTERNAL_GATES_INCOMPLETE",
    "HOST_OBSERVER_CONTRACT_UNSUPPORTED",
    "INERT_RESPONSE_UNPROVEN",
    "PROVIDER_JOIN_MISSING",
    "REAL_HOST_PERMISSION_OUTCOME_UNPROVEN",
]
CHARTER_SHA256 = "f4a40efd4b526c15a44de97a2619d39c1a2db748704806fe0e0f6e882ced5a43"
EXTERNAL_GATES = {
    "production_activation": "incomplete",
    "provider_join": "incomplete",
    "real_host_validation": "incomplete",
    "spend_authorization": "incomplete",
}
PROHIBITED_CAPABILITIES = [
    "artifact_root_reuse",
    "fixture_derived_claims",
    "installed_settings_mutation",
    "multi_file_redirection",
    "packaging",
    "r9_reinterpretation",
    "registration",
    "runtime_implementation",
    "updated_input_mutation",
]
AUTHORIZATION_FIELDS = [
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
EMPTY_SURFACE_FIELDS = [
    "hook_registrations",
    "package_helper_entries",
    "runtime_files",
    "settings_default_plugin_changes",
]


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def validate(instance: object, schema: dict[str, object], location: str = "$") -> None:
    expected_type = schema.get("type")
    type_matches = {
        "array": isinstance(instance, list),
        "boolean": type(instance) is bool,
        "object": isinstance(instance, dict),
        "string": isinstance(instance, str),
    }
    if expected_type is not None and not type_matches[expected_type]:
        raise AssertionError(f"{location} has wrong type")
    if "const" in schema and instance != schema["const"]:
        raise AssertionError(f"{location} violates const")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if any(field not in instance for field in required):
            raise AssertionError(f"{location} lacks a required property")
        if schema.get("additionalProperties") is False and set(instance) - set(properties):
            raise AssertionError(f"{location} has an additional property")
        for field, value in instance.items():
            if field in properties:
                validate(value, properties[field], f"{location}.{field}")

    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            raise AssertionError(f"{location} has too few items")
        if len(instance) > schema.get("maxItems", len(instance)):
            raise AssertionError(f"{location} has too many items")
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in instance}) != len(instance):
            raise AssertionError(f"{location} has duplicate items")
        prefix_items = schema.get("prefixItems", [])
        for index, item_schema in enumerate(prefix_items):
            if index < len(instance):
                validate(instance[index], item_schema, f"{location}[{index}]")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                validate(item, item_schema, f"{location}[{index}]")
        elif item_schema is False and len(instance) > len(prefix_items):
            raise AssertionError(f"{location} has undeclared items")


def completion_record() -> dict[str, object]:
    return {
        "authorizations": {field: False for field in AUTHORIZATION_FIELDS},
        "blockers": list(BLOCKERS),
        "charter_identity": {
            "charter_id": "S3D-ARF",
            "charter_sha256": CHARTER_SHA256,
            "schema_version": "contextguard-stage2-s3d-arf-charter/v1",
            "status": "inactive_provider_free",
        },
        "claim_allowed": False,
        "external_gates": dict(EXTERNAL_GATES),
        "provider_join_status": "missing",
        "runtime_observer_present": False,
        "schema_version": "contextguard-stage2-verification-record/v1",
        "selected_branch": "S2-UNSUPPORTED",
        "selected_transport": "NONE",
        "surface_changes": {field: [] for field in EMPTY_SURFACE_FIELDS},
    }


class ContextGuardStage2VerificationSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_raw = SCHEMA_PATH.read_bytes()
        cls.schema = json.loads(cls.schema_raw)
        cls.charter_raw = CHARTER_PATH.read_bytes()
        cls.charter = json.loads(cls.charter_raw)

    def assert_invalid(self, candidate: object) -> None:
        with self.assertRaises(AssertionError):
            validate(candidate, self.schema)

    def test_completion_record_collections_are_isolated(self) -> None:
        expected_blockers = [
            "EXACT_FRAMING_UNPROVEN",
            "EXTERNAL_GATES_INCOMPLETE",
            "HOST_OBSERVER_CONTRACT_UNSUPPORTED",
            "INERT_RESPONSE_UNPROVEN",
            "PROVIDER_JOIN_MISSING",
            "REAL_HOST_PERMISSION_OUTCOME_UNPROVEN",
        ]
        expected_gates = {
            "production_activation": "incomplete",
            "provider_join": "incomplete",
            "real_host_validation": "incomplete",
            "spend_authorization": "incomplete",
        }
        first = completion_record()
        first["blockers"].append("MUTATED")
        first["external_gates"]["provider_join"] = "complete"

        second = completion_record()
        self.assertEqual(second["blockers"], expected_blockers)
        self.assertEqual(second["external_gates"], expected_gates)
        self.assertEqual(BLOCKERS, expected_blockers)
        self.assertEqual(EXTERNAL_GATES, expected_gates)

    def test_schema_is_canonical_closed_and_accepts_only_unsupported_baseline(self) -> None:
        self.assertEqual(self.schema_raw, canonical_bytes(self.schema))
        self.assertEqual(self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(self.schema["additionalProperties"], False)
        validate(completion_record(), self.schema)

        nested_objects = [
            node
            for node in self.schema["properties"].values()
            if isinstance(node, dict) and node.get("type") == "object"
        ]
        self.assertTrue(nested_objects)
        self.assertTrue(all(node.get("additionalProperties") is False for node in nested_objects))

    def test_schema_rejects_open_runtime_provider_and_claim_surfaces(self) -> None:
        scalar_mutations = {
            "supported branch": ("selected_branch", "S2-FRAMED"),
            "transport": ("selected_transport", "PATH"),
            "observer": ("runtime_observer_present", True),
            "provider join": ("provider_join_status", "complete"),
            "efficacy claim": ("claim_allowed", True),
        }
        for label, (field, value) in scalar_mutations.items():
            candidate = completion_record()
            candidate[field] = value
            with self.subTest(label=label):
                self.assert_invalid(candidate)

        for field in AUTHORIZATION_FIELDS:
            candidate = completion_record()
            candidate["authorizations"][field] = True
            with self.subTest(authorization=field):
                self.assert_invalid(candidate)

        for field in EMPTY_SURFACE_FIELDS:
            candidate = completion_record()
            candidate["surface_changes"][field] = ["invented-entry"]
            with self.subTest(surface=field):
                self.assert_invalid(candidate)

    def test_schema_rejects_extra_duplicate_or_unsorted_blockers_and_gates(self) -> None:
        mutations = [
            BLOCKERS + ["UNDECLARED_BLOCKER"],
            BLOCKERS + [BLOCKERS[-1]],
            list(reversed(BLOCKERS)),
        ]
        for blockers in mutations:
            candidate = completion_record()
            candidate["blockers"] = blockers
            with self.subTest(blockers=blockers):
                self.assert_invalid(candidate)

        candidate = completion_record()
        candidate["external_gates"]["provider_join"] = "complete"
        self.assert_invalid(candidate)
        candidate = completion_record()
        candidate["external_gates"]["invented_gate"] = "incomplete"
        self.assert_invalid(candidate)

    def test_schema_is_closed_recursively_and_collections_are_bounded(self) -> None:
        extra_top = completion_record()
        extra_top["runtime_runner"] = "stage2-runner.py"
        self.assert_invalid(extra_top)

        for field in ("authorizations", "external_gates", "surface_changes"):
            candidate = completion_record()
            candidate[field]["invented"] = False
            with self.subTest(field=field):
                self.assert_invalid(candidate)

        candidate = completion_record()
        candidate["charter_identity"]["status"] = "active"
        self.assert_invalid(candidate)

        arrays = [
            node
            for node in self.schema["properties"].values()
            if isinstance(node, dict) and node.get("type") == "array"
        ]
        arrays.extend(self.schema["properties"]["surface_changes"]["properties"].values())
        self.assertTrue(all("maxItems" in node for node in arrays))

    def test_charter_is_canonical_inactive_exact_and_denies_every_authorization(self) -> None:
        self.assertEqual(self.charter_raw, canonical_bytes(self.charter))
        self.assertEqual(hashlib.sha256(self.charter_raw).hexdigest(), CHARTER_SHA256)
        self.assertEqual(
            set(self.charter),
            {"artifact_root_free", "authorizations", "charter_id", "prohibited_capabilities", "scope", "schema_version", "status"},
        )
        self.assertEqual(self.charter["schema_version"], "contextguard-stage2-s3d-arf-charter/v1")
        self.assertEqual(self.charter["charter_id"], "S3D-ARF")
        self.assertEqual(self.charter["status"], "inactive_provider_free")
        self.assertEqual(self.charter["scope"], "same_file_narrowing")
        self.assertIs(self.charter["artifact_root_free"], True)
        self.assertEqual(self.charter["prohibited_capabilities"], PROHIBITED_CAPABILITIES)
        self.assertEqual(list(self.charter["authorizations"]), AUTHORIZATION_FIELDS)
        self.assertTrue(all(value is False for value in self.charter["authorizations"].values()))

        for field in AUTHORIZATION_FIELDS:
            candidate = copy.deepcopy(self.charter)
            candidate["authorizations"][field] = True
            with self.subTest(charter_authorization=field):
                self.assertFalse(all(value is False for value in candidate["authorizations"].values()))


if __name__ == "__main__":
    unittest.main()
