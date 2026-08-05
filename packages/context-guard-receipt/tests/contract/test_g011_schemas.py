from __future__ import annotations

import json
import unittest
from pathlib import Path


SCHEMA_ROOT = Path(__file__).resolve().parents[2] / "schemas"
EXPECTED = {
    "reference-expiry-inspection.schema.json": "contextguard-receipt-reference-expiry-inspection/v1",
    "reference-expiry-metadata.schema.json": "contextguard-receipt-reference-expiry-metadata/v1",
    "reference-expiry-record.schema.json": "contextguard-receipt-reference-expiry-record/v1",
    "reference-expiry-request.schema.json": "contextguard-receipt-reference-expiry-request/v1",
    "reference-expiry-result.schema.json": "contextguard-receipt-reference-expiry-result/v1",
}


class G011ReferenceExpirySchemaTests(unittest.TestCase):
    def test_reference_expiry_schemas_exist_and_are_closed(self) -> None:
        """Break caught: a persisted or public expiry artifact is unversioned/open."""

        for filename, version in EXPECTED.items():
            with self.subTest(filename=filename):
                path = SCHEMA_ROOT / filename
                self.assertTrue(path.is_file(), f"missing G011 schema: {filename}")
                raw = path.read_bytes()
                self.assertTrue(raw.endswith(b"\n"))
                schema = json.loads(raw)
                self.assertEqual(
                    schema["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertEqual(
                    schema["properties"]["schema_version"]["const"], version
                )
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
                self.assertTrue(object_nodes)
                for node in object_nodes:
                    self.assertIs(node.get("additionalProperties"), False)

    def test_schema_contract_freezes_variants_bounds_and_private_fields(self) -> None:
        """Break caught: schemas broaden authority, clocks, quotas, or path disclosure."""

        schemas = {
            filename: json.loads((SCHEMA_ROOT / filename).read_bytes())
            for filename in EXPECTED
        }
        request = schemas["reference-expiry-request.schema.json"]
        self.assertEqual(
            [branch["properties"]["operation"]["const"] for branch in request["oneOf"]],
            ["register", "revoke"],
        )
        self.assertEqual(
            request["properties"]["expires_at_unix_ms"],
            {"maximum": 4_102_444_800_000, "minimum": 0, "type": "integer"},
        )
        self.assertEqual(
            request["properties"]["expected_generation"],
            {"maximum": 2_147_483_647, "minimum": 1, "type": "integer"},
        )
        metadata = schemas["reference-expiry-metadata.schema.json"]
        limits = metadata["properties"]["limits"]["properties"]
        self.assertEqual(limits["max_references"]["maximum"], 1024)
        self.assertEqual(limits["max_total_record_bytes"]["maximum"], 4 * 1024 * 1024)
        self.assertEqual(limits["max_record_bytes"]["maximum"], 4096)
        forbidden = {"artifact_path", "capability", "content_sha256", "payload", "state_dir"}
        for filename in (
            "reference-expiry-record.schema.json",
            "reference-expiry-result.schema.json",
            "reference-expiry-inspection.schema.json",
        ):
            with self.subTest(privacy=filename):
                properties = schemas[filename]["properties"]
                self.assertFalse(forbidden.intersection(properties))
                boundary = properties["evidence_boundary"]["const"]
                self.assertEqual(boundary["selected_branch"], "S2-UNSUPPORTED")
                self.assertEqual(boundary["selected_transport"], "NONE")
                self.assertIs(boundary["provider_claim_authority"], False)


if __name__ == "__main__":
    unittest.main()
