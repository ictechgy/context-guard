from __future__ import annotations

import json
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"

EVIDENCE_BOUNDARY = {
    "evidence_class": "companion_local_receipt_only",
    "host_request_owned": False,
    "provider_claim_authority": False,
    "provider_join_status": "missing",
    "runtime_observer_present": False,
    "schema_version": "contextguard-receipt-evidence-boundary/v1",
    "selected_branch": "S2-UNSUPPORTED",
    "selected_transport": "NONE",
    "stage1_evidence": False,
    "stage2_evidence": False,
}

EXPECTED = {
    "assembly-receipt.schema.json": (
        "assembly_receipt",
        "contextguard-receipt-assembly-receipt/v1",
    ),
    "evidence-reference.schema.json": (
        "evidence_reference",
        "contextguard-receipt-evidence-reference/v1",
    ),
    "evidence-pack.schema.json": (
        "evidence_pack",
        "contextguard-receipt-evidence-pack/v1",
    ),
    "typed-blueprint.schema.json": (
        "typed_blueprint",
        "contextguard-receipt-typed-blueprint/v1",
    ),
    "expansion-envelope.schema.json": (
        "expansion_envelope",
        "contextguard-receipt-expansion-envelope/v1",
    ),
    "expansion-refusal.schema.json": (
        "expansion_refusal",
        "contextguard-receipt-expansion-refusal/v1",
    ),
}

DESCRIPTOR_VERSIONS = {
    "evidence-descriptor.schema.json": {
        "contextguard-receipt-evidence-descriptor/v1",
        "contextguard-receipt-evidence-pack-descriptor/v1",
    },
    "blueprint-descriptor.schema.json": {
        "contextguard-receipt-blueprint-descriptor/v1",
    },
}


class G005SchemaTests(unittest.TestCase):
    def test_artifact_schemas_are_recursively_closed_and_preserve_the_boundary(self) -> None:
        """Break caught: an artifact admits arbitrary nested claims or weakens the boundary."""

        for filename, (artifact_kind, version) in EXPECTED.items():
            with self.subTest(filename=filename):
                path = SCHEMA_ROOT / filename
                self.assertTrue(path.is_file(), f"missing G005 schema: {filename}")
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                top = schema["properties"]
                self.assertEqual(top["artifact_kind"]["const"], artifact_kind)
                self.assertEqual(top["schema_version"]["const"], version)

                object_nodes: list[dict[str, object]] = []

                def visit(value: object) -> None:
                    if isinstance(value, dict):
                        if value.get("type") == "object":
                            object_nodes.append(value)
                        for child in value.values():
                            visit(child)
                    elif isinstance(value, list):
                        for child in value:
                            visit(child)

                visit(schema)
                self.assertGreaterEqual(len(object_nodes), 2)
                for node in object_nodes:
                    self.assertIs(node.get("additionalProperties"), False)
                boundary = schema["$defs"]["evidence_boundary"]
                self.assertEqual(boundary["required"], list(EVIDENCE_BOUNDARY))
                for key, expected in EVIDENCE_BOUNDARY.items():
                    self.assertEqual(boundary["properties"][key]["const"], expected)

    def test_private_symbol_recipe_schema_has_no_open_evidence_object(self) -> None:
        """Break caught: symbol revalidation metadata accepts arbitrary authority fields."""

        schema = json.loads(
            (SCHEMA_ROOT / "expansion-envelope.schema.json").read_text(encoding="utf-8")
        )
        symbol = schema["$defs"]["selection"]["oneOf"][2]
        evidence = symbol["properties"]["evidence"]
        self.assertIn("properties", evidence)
        self.assertIn("required", evidence)
        expected = {
            "candidates",
            "capped",
            "complete",
            "deterministic",
            "end_byte",
            "evidence_kind",
            "fallback_used",
            "language_id",
            "occurrence",
            "parser_error",
            "producer_id",
            "qualified_name",
            "raw_range_sha256",
            "scan_complete",
            "schema_version",
            "source_sha256",
            "start_byte",
        }
        self.assertEqual(set(evidence["properties"]), expected)
        self.assertEqual(set(evidence["required"]), expected)
        self.assertIs(evidence["additionalProperties"], False)

    def test_input_descriptor_schemas_are_closed_for_every_object_branch(self) -> None:
        """Break caught: runtime-closed descriptors have no distributable contract."""

        for filename, expected_versions in DESCRIPTOR_VERSIONS.items():
            with self.subTest(filename=filename):
                path = SCHEMA_ROOT / filename
                self.assertTrue(path.is_file(), f"missing G005 schema: {filename}")
                schema = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(
                    schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                object_nodes: list[dict[str, object]] = []
                versions: set[str] = set()

                def visit(value: object) -> None:
                    if isinstance(value, dict):
                        if value.get("type") == "object":
                            object_nodes.append(value)
                        schema_version = value.get("schema_version")
                        if (
                            isinstance(schema_version, dict)
                            and isinstance(schema_version.get("const"), str)
                            and "descriptor/v1" in schema_version["const"]
                        ):
                            versions.add(schema_version["const"])
                        for child in value.values():
                            visit(child)
                    elif isinstance(value, list):
                        for child in value:
                            visit(child)

                visit(schema)
                self.assertTrue(object_nodes)
                for node in object_nodes:
                    self.assertTrue(
                        node.get("additionalProperties") is False
                        or node.get("unevaluatedProperties") is False
                    )
                self.assertEqual(versions, expected_versions)

    def test_progressive_pack_segments_and_binding_dispatch_are_closed(self) -> None:
        """Break caught: public segments or future binding modes accept arbitrary claims."""

        pack = json.loads(
            (SCHEMA_ROOT / "evidence-pack.schema.json").read_text(encoding="utf-8")
        )
        retained = pack["$defs"]["retained_segment"]
        deferred = pack["$defs"]["deferred_segment"]
        self.assertEqual(
            set(retained["properties"]),
            {"end_byte", "kind", "payload_b64u", "start_byte"},
        )
        self.assertEqual(set(retained["required"]), set(retained["properties"]))
        self.assertEqual(
            set(deferred["properties"]),
            {
                "binding_kind",
                "byte_length",
                "capability",
                "content_sha256",
                "end_byte",
                "kind",
                "start_byte",
                "subject_identity_sha256",
            },
        )
        self.assertEqual(set(deferred["required"]), set(deferred["properties"]))
        envelope = json.loads(
            (SCHEMA_ROOT / "expansion-envelope.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(envelope["properties"]["binding_kind"], {"const": "source_current"})


if __name__ == "__main__":
    unittest.main()
