from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"

EXPECTED = {
    "tool-schema-descriptor.schema.json": "contextguard-receipt-tool-schema-descriptor/v1",
    "tool-schema-bundle.schema.json": "contextguard-receipt-tool-schema-bundle/v1",
    "tool-schema-catalog-reference.schema.json": "contextguard-receipt-tool-schema-catalog-reference/v1",
    "tool-schema-reference.schema.json": "contextguard-receipt-tool-schema-reference/v1",
    "tool-schema-receipt.schema.json": "contextguard-receipt-tool-schema-receipt/v1",
    "tool-schema-expansion-envelope.schema.json": "contextguard-receipt-tool-schema-envelope/v1",
    "tool-schema-expansion-refusal.schema.json": "contextguard-receipt-tool-schema-expansion-refusal/v1",
    "tool-schema-expansion-request.schema.json": "contextguard-receipt-tool-schema-expansion-request/v1",
}

NON_OBJECT_JSON_VALUES = (
    None,
    False,
    True,
    -1,
    0,
    1,
    1.5,
    "",
    "value",
    [],
    ["value"],
)


def accepts_schema(
    root: dict[str, object], schema: dict[str, object], value: object
) -> bool:
    """Evaluate the closed JSON Schema subset used by native inline tools."""

    reference = schema.get("$ref")
    if isinstance(reference, str):
        prefix = "#/$defs/"
        if not reference.startswith(prefix):
            raise AssertionError("test evaluator accepts only local definitions")
        definitions = root.get("$defs")
        if not isinstance(definitions, dict):
            raise AssertionError("schema definitions are unavailable")
        resolved = definitions.get(reference.removeprefix(prefix))
        if not isinstance(resolved, dict):
            raise AssertionError("schema definition is unavailable")
        return accepts_schema(root, resolved, value)

    expected_type = schema.get("type")
    if expected_type == "object":
        if type(value) is not dict:
            return False
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise AssertionError("object schema shape is unsupported")
        if not set(required).issubset(value):
            return False
        if schema.get("additionalProperties") is False and not set(value).issubset(
            properties
        ):
            return False
        return all(
            key not in value
            or (
                isinstance(child_schema, dict)
                and accepts_schema(root, child_schema, value[key])
            )
            for key, child_schema in properties.items()
        )
    if expected_type == "string":
        if type(value) is not str:
            return False
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        pattern = schema.get("pattern")
        return (
            (not isinstance(minimum, int) or len(value) >= minimum)
            and (not isinstance(maximum, int) or len(value) <= maximum)
            and (not isinstance(pattern, str) or re.fullmatch(pattern, value) is not None)
        )
    raise AssertionError(f"unsupported test schema type: {expected_type!r}")


def bundle_branch_accepts(
    schema: dict[str, object],
    *,
    root_format: str,
    reference_format: str,
    inline: object,
) -> bool:
    branches = schema.get("allOf")
    if not isinstance(branches, list):
        return False
    for branch in branches:
        if not isinstance(branch, dict):
            continue
        try:
            branch_format = branch["if"]["properties"]["catalog_format"]["const"]
            constraints = branch["then"]["properties"]
        except (KeyError, TypeError):
            continue
        if branch_format != root_format or not isinstance(constraints, dict):
            continue
        try:
            required_reference_format = constraints["catalog_reference"]["properties"][
                "catalog_format"
            ]["const"]
            inline_schema = constraints["inline"]["items"]
        except (KeyError, TypeError):
            return False
        return (
            required_reference_format == reference_format
            and isinstance(inline_schema, dict)
            and accepts_schema(schema, inline_schema, inline)
        )
    return False


class G006SchemaTests(unittest.TestCase):
    def test_all_g006_schemas_exist_parse_and_are_recursively_closed(self) -> None:
        """Break caught: a runtime artifact has no distributable closed contract."""

        for filename, version in EXPECTED.items():
            with self.subTest(filename=filename):
                path = SCHEMA_ROOT / filename
                self.assertTrue(path.is_file(), f"missing G006 schema: {filename}")
                raw = path.read_bytes()
                self.assertTrue(raw.endswith(b"\n"))
                self.assertEqual(raw.rstrip(b"\n"), raw[:-1])
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
                opaque = schema.get("$defs", {}).get("opaque_json_object")
                for node in object_nodes:
                    expected_closure = node is not opaque
                    self.assertIs(
                        node.get("additionalProperties"),
                        False if expected_closure else True,
                    )

    def test_bundle_schema_closes_native_shapes_with_one_opaque_object_boundary(self) -> None:
        """Break caught: arbitrary inline values escape the two native tool shapes."""

        bundle = json.loads(
            (SCHEMA_ROOT / "tool-schema-bundle.schema.json").read_text(encoding="utf-8")
        )
        definitions = bundle["$defs"]
        expected_native_definitions = {
            "anthropic_tool": {
                "additionalProperties": False,
                "properties": {
                    "description": {"type": "string"},
                    "input_schema": {"$ref": "#/$defs/opaque_json_object"},
                    "name": {"maxLength": 256, "minLength": 1, "type": "string"},
                },
                "required": ["input_schema", "name"],
                "type": "object",
            },
            "opaque_json_object": {
                "additionalProperties": True,
                "type": "object",
            },
            "openai_function": {
                "additionalProperties": False,
                "properties": {
                    "description": {"type": "string"},
                    "name": {"maxLength": 256, "minLength": 1, "type": "string"},
                    "parameters": {"$ref": "#/$defs/opaque_json_object"},
                },
                "required": ["name", "parameters"],
                "type": "object",
            },
        }
        for name, expected in expected_native_definitions.items():
            self.assertEqual(definitions.get(name), expected)

        anthropic = definitions["anthropic_tool"]
        openai = definitions["openai_function"]
        valid_anthropic = {
            "description": "lookup",
            "input_schema": {
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "type": "object",
            },
            "name": "lookup",
        }
        valid_openai = {
            "description": "lookup",
            "name": "lookup",
            "parameters": {
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "type": "object",
            },
        }
        self.assertTrue(accepts_schema(bundle, anthropic, valid_anthropic))
        self.assertTrue(accepts_schema(bundle, openai, valid_openai))
        for scalar_or_array in NON_OBJECT_JSON_VALUES:
            with self.subTest(inline=scalar_or_array):
                self.assertFalse(accepts_schema(bundle, anthropic, scalar_or_array))
                self.assertFalse(accepts_schema(bundle, openai, scalar_or_array))
            with self.subTest(opaque=scalar_or_array):
                self.assertFalse(
                    accepts_schema(
                        bundle,
                        anthropic,
                        {"input_schema": scalar_or_array, "name": "lookup"},
                    )
                )
                self.assertFalse(
                    accepts_schema(
                        bundle,
                        openai,
                        {"name": "lookup", "parameters": scalar_or_array},
                    )
                )
        self.assertFalse(
            accepts_schema(bundle, anthropic, {**valid_anthropic, "extra": None})
        )
        self.assertFalse(accepts_schema(bundle, openai, {**valid_openai, "extra": None}))
        self.assertFalse(
            accepts_schema(
                bundle,
                anthropic,
                {"name": "lookup", "parameters": {"type": "object"}},
            )
        )
        self.assertFalse(
            accepts_schema(
                bundle,
                openai,
                {"input_schema": {"type": "object"}, "name": "lookup"},
            )
        )

    def test_bundle_schema_couples_root_reference_and_inline_formats(self) -> None:
        """Break caught: one format label authorizes another format's reference or tool."""

        bundle = json.loads(
            (SCHEMA_ROOT / "tool-schema-bundle.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            bundle.get("allOf"),
            [
                {
                    "if": {
                        "properties": {
                            "catalog_format": {"const": "anthropic_tools/v1"}
                        },
                        "required": ["catalog_format"],
                    },
                    "then": {
                        "properties": {
                            "catalog_reference": {
                                "properties": {
                                    "catalog_format": {
                                        "const": "anthropic_tools/v1"
                                    }
                                }
                            },
                            "inline": {
                                "items": {"$ref": "#/$defs/anthropic_tool"}
                            },
                        }
                    },
                },
                {
                    "if": {
                        "properties": {
                            "catalog_format": {"const": "openai_functions/v1"}
                        },
                        "required": ["catalog_format"],
                    },
                    "then": {
                        "properties": {
                            "catalog_reference": {
                                "properties": {
                                    "catalog_format": {
                                        "const": "openai_functions/v1"
                                    }
                                }
                            },
                            "inline": {
                                "items": {"$ref": "#/$defs/openai_function"}
                            },
                        }
                    },
                },
            ],
        )
        anthropic_tool = {
            "input_schema": {"type": "object"},
            "name": "lookup",
        }
        openai_function = {
            "name": "lookup",
            "parameters": {"type": "object"},
        }
        self.assertTrue(
            bundle_branch_accepts(
                bundle,
                root_format="anthropic_tools/v1",
                reference_format="anthropic_tools/v1",
                inline=anthropic_tool,
            )
        )
        self.assertTrue(
            bundle_branch_accepts(
                bundle,
                root_format="openai_functions/v1",
                reference_format="openai_functions/v1",
                inline=openai_function,
            )
        )
        rejected = (
            ("anthropic_tools/v1", "openai_functions/v1", anthropic_tool),
            ("openai_functions/v1", "anthropic_tools/v1", openai_function),
            ("anthropic_tools/v1", "anthropic_tools/v1", openai_function),
            ("openai_functions/v1", "openai_functions/v1", anthropic_tool),
        )
        for root_format, reference_format, inline in rejected:
            with self.subTest(
                root_format=root_format,
                reference_format=reference_format,
                inline=inline,
            ):
                self.assertFalse(
                    bundle_branch_accepts(
                        bundle,
                        root_format=root_format,
                        reference_format=reference_format,
                        inline=inline,
                    )
                )

    def test_descriptor_and_envelope_keep_format_and_snapshot_authority_closed(self) -> None:
        """Break caught: a third-party parser or live-current authority enters G006."""

        descriptor = json.loads(
            (SCHEMA_ROOT / "tool-schema-descriptor.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            descriptor["properties"]["catalog_format"]["enum"],
            ["anthropic_tools/v1", "openai_functions/v1"],
        )
        self.assertEqual(
            set(descriptor["properties"]),
            {"catalog_format", "items", "payload_b64u", "retain_count", "schema_version"},
        )
        envelope = json.loads(
            (SCHEMA_ROOT / "tool-schema-expansion-envelope.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(envelope["properties"]["binding_kind"], {"const": "catalog_snapshot"})
        self.assertNotIn("source", json.dumps(envelope, sort_keys=True).lower())
        request = json.loads(
            (SCHEMA_ROOT / "tool-schema-expansion-request.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            set(request["properties"]),
            {"catalog_reference", "item_reference", "schema_version"},
        )
        self.assertEqual(set(request["required"]), set(request["properties"]))

    def test_receipt_shifted_bytes_has_no_provider_token_or_percent_claim(self) -> None:
        """Break caught: deterministic byte accounting is presented as provider savings."""

        receipt = json.loads(
            (SCHEMA_ROOT / "tool-schema-receipt.schema.json").read_text(encoding="utf-8")
        )
        shifted = receipt["properties"]["shifted_bytes"]
        self.assertEqual(
            set(shifted["properties"]),
            {
                "all_expansion_upper_bound_bytes",
                "catalog_stored_envelope_bytes",
                "deferred_raw_bytes",
                "deferred_stored_envelope_bytes",
                "single_expansion_upper_bound_bytes",
            },
        )
        keys: set[str] = set()

        def collect_keys(value: object) -> None:
            if isinstance(value, dict):
                keys.update(key.lower() for key in value)
                for child in value.values():
                    collect_keys(child)
            elif isinstance(value, list):
                for child in value:
                    collect_keys(child)

        collect_keys(receipt)
        for forbidden in ("provider", "token", "percent", "basis_points", "savings"):
            self.assertFalse(any(forbidden in key for key in keys))


if __name__ == "__main__":
    unittest.main()
