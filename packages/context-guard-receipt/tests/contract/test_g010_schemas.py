from __future__ import annotations

import json
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"

EXPECTED = {
    "twin-event.schema.json": "contextguard-receipt-twin-event/v1",
    "twin-metadata.schema.json": "contextguard-receipt-twin-metadata/v1",
    "twin-request.schema.json": "contextguard-receipt-twin-request/v1",
    "twin-result.schema.json": "contextguard-receipt-twin-result/v1",
    "twin-snapshot.schema.json": "contextguard-receipt-twin-snapshot/v1",
}


class G010SchemaTests(unittest.TestCase):
    def test_twin_schemas_exist_parse_and_are_recursively_closed(self) -> None:
        """Break caught: a twin artifact lacks a distributable closed contract."""

        for filename, version in EXPECTED.items():
            with self.subTest(filename=filename):
                path = SCHEMA_ROOT / filename
                self.assertTrue(path.is_file(), f"missing G010 schema: {filename}")
                raw = path.read_bytes()
                self.assertTrue(raw.endswith(b"\n"))
                schema = json.loads(raw)
                self.assertEqual(
                    schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                self.assertEqual(schema["properties"]["schema_version"]["const"], version)

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

    def test_request_variants_and_authority_constants_are_explicit(self) -> None:
        """Break caught: variants are open or result/snapshot authority can become true."""

        request = json.loads((SCHEMA_ROOT / "twin-request.schema.json").read_bytes())
        predicate = request["properties"]["predicates"]["items"]
        self.assertEqual(len(predicate["oneOf"]), 4)
        self.assertEqual(
            {
                branch["properties"]["kind"]["const"]
                for branch in predicate["oneOf"]
            },
            {
                "path_absent",
                "regular_file_equals",
                "repository_instance_equals",
                "git_logical_state_equals",
            },
        )
        for filename in ("twin-result.schema.json", "twin-snapshot.schema.json"):
            schema = json.loads((SCHEMA_ROOT / filename).read_bytes())
            for field in (
                "applied",
                "execution_authority",
                "global_completeness_authority",
                "provider_claim_authority",
            ):
                self.assertEqual(schema["properties"][field], {"const": False})

        for branch in predicate["oneOf"]:
            relative_path = branch["properties"].get("relative_path")
            if relative_path is not None:
                self.assertEqual(relative_path["maxLength"], 4096)
                self.assertEqual(relative_path["x-contextguard-maxUtf8Bytes"], 4096)

        for filename in ("twin-event.schema.json", "twin-result.schema.json"):
            schema = json.loads((SCHEMA_ROOT / filename).read_bytes())
            result_schema = schema["$defs"]["predicate_result"]
            self.assertEqual(
                set(result_schema["properties"]),
                {"kind", "matched", "observation_hmac_sha256", "ordinal"},
            )
            self.assertEqual(
                set(result_schema["required"]),
                {"kind", "matched", "observation_hmac_sha256", "ordinal"},
            )


if __name__ == "__main__":
    unittest.main()
