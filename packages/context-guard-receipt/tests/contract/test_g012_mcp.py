from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def rpc(request_id: object, method: str, params: object) -> bytes:
    return (
        json.dumps(
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def initialize_params() -> dict[str, object]:
    return {
        "capabilities": {},
        "clientInfo": {"name": "g012", "version": "1"},
        "protocolVersion": "2025-11-25",
    }


class G012McpCoreTests(unittest.TestCase):
    @staticmethod
    def _ready(server: object) -> None:
        server.handle(  # type: ignore[attr-defined]
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "g012", "version": "1"},
                    "protocolVersion": "2025-11-25",
                },
            }
        )
        server.handle(  # type: ignore[attr-defined]
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

    def test_initialize_and_tools_list_expose_only_the_four_provider_free_tools(self) -> None:
        """Break caught: the MCP surface is absent, open-ended, or provider-coupled."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            server = MCPServer(str(root))
            initialized = server.handle(
                json.loads(rpc(1, "initialize", initialize_params()).decode("ascii"))
            )
            self.assertIsNone(
                server.handle(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    }
                )
            )
            listed = server.handle(
                json.loads(rpc(2, "tools/list", {}).decode("ascii"))
            )
            server.close()

        self.assertEqual(initialized["jsonrpc"], "2.0")
        self.assertEqual(initialized["id"], 1)
        self.assertEqual(
            {tool["name"] for tool in listed["result"]["tools"]},
            {
                "receipt_assemble",
                "receipt_expand",
                "receipt_inspect",
                "receipt_tool_select",
            },
        )
        self.assertNotIn(str(root), json.dumps((initialized, listed)))

    def test_in_memory_capabilities_expire_monotonically_and_are_process_local(self) -> None:
        """Break caught: MCP handles persist, cross namespaces, or use wall-clock expiry."""

        from context_guard_receipt.mcp import InMemoryCapabilityStore
        from context_guard_receipt.store import ArtifactRequest, ArtifactType, StoreError

        request = ArtifactRequest(
            payload=b"private-bytes",
            root_identity_sha256="a" * 64,
            subject_identity_sha256="b" * 64,
            artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
        )
        observed = [10.0]
        first = InMemoryCapabilityStore(clock=lambda: observed[0])
        issued = first.issue_batch((request,))[0]
        external = first.externalize_handle(issued.handle)
        self.assertTrue(external.startswith("cgr1m_"))
        self.assertNotIn(b"private-bytes", external.encode("ascii"))
        observed[0] += 300.0
        with self.assertRaises(StoreError):
            first.resolve(external, expected_root_identity_sha256="a" * 64)
        second = InMemoryCapabilityStore()
        with self.assertRaises(StoreError):
            second.resolve(external, expected_root_identity_sha256="a" * 64)

    def test_tools_call_rejects_caller_state_and_returns_bounded_base64_output(self) -> None:
        """Break caught: callers inject roots/state/receipts or binary bytes into JSON-RPC."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = b"small exact evidence"
            (root / "evidence.bin").write_bytes(payload)
            descriptor = {
                "caller_classification": "eligible",
                "detector_signals": [],
                "payload_b64u": base64.urlsafe_b64encode(payload)
                .rstrip(b"=")
                .decode("ascii"),
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {
                    "relative_path": "evidence.bin",
                    "selection": {"kind": "file"},
                },
            }
            server = MCPServer(str(root))
            server.handle(
                json.loads(rpc(1, "initialize", initialize_params()).decode())
            )
            server.handle(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
            )
            rejected = server.handle(
                json.loads(
                    rpc(
                        2,
                        "tools/call",
                        {
                            "arguments": {
                                "descriptor": descriptor,
                                "kind": "evidence",
                                "state_dir": "/tmp/forbidden",
                            },
                            "name": "receipt_assemble",
                        },
                    ).decode()
                )
            )
            accepted = server.handle(
                json.loads(
                    rpc(
                        3,
                        "tools/call",
                        {
                            "arguments": {
                                "descriptor": descriptor,
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    ).decode()
                )
            )
            server.close()

        self.assertIs(rejected["result"]["isError"], True)
        self.assertIs(accepted["result"]["isError"], False)
        content = accepted["result"]["content"]
        self.assertEqual(len(content), 1)
        inner = json.loads(content[0]["text"])
        self.assertEqual(
            base64.urlsafe_b64decode(inner["output_b64u"] + "=" * 3), payload
        )
        self.assertNotIn(str(root), json.dumps(accepted))

    def test_large_deferred_evidence_uses_only_cgr1m_on_wire_and_expands_exactly(self) -> None:
        """Break caught: the compatibility alias leaks or deferred MCP bytes cannot expand."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = b"deferred exact bytes\n" * 30_000
            (root / "large.bin").write_bytes(payload)
            descriptor = {
                "caller_classification": "eligible",
                "detector_signals": [],
                "payload_b64u": b64url(payload),
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {
                    "relative_path": "large.bin",
                    "selection": {"kind": "file"},
                },
            }
            server = MCPServer(str(root))
            self._ready(server)
            assembled = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"descriptor": descriptor, "kind": "evidence"},
                        "name": "receipt_assemble",
                    },
                }
            )
            self.assertIsNotNone(assembled)
            assembled_result = assembled["result"]  # type: ignore[index]
            self.assertIs(assembled_result["isError"], False)
            wire = json.dumps(assembled_result)
            self.assertNotIn("cgr1p_", wire)
            structured = assembled_result["structuredContent"]
            reference = json.loads(
                base64.urlsafe_b64decode(
                    structured["output_b64u"] + "=" * 3
                )
            )
            capability = reference["capability"]
            self.assertTrue(capability.startswith("cgr1m_"))
            expanded = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"capability": capability},
                        "name": "receipt_expand",
                    },
                }
            )
            server.close()

        self.assertIsNotNone(expanded)
        expanded_result = expanded["result"]  # type: ignore[index]
        self.assertIs(expanded_result["isError"], False)
        expansion = expanded_result["structuredContent"]
        self.assertEqual(
            base64.urlsafe_b64decode(expansion["output_b64u"] + "=" * 3),
            payload,
        )

    def test_tool_catalog_and_item_expand_only_from_server_owned_references(self) -> None:
        """Break caught: tool references stay cgr1p, accept caller metadata, or cannot expand."""

        from context_guard_receipt.mcp import MCPServer

        catalog = [
            {
                "description": "inline" * 900,
                "input_schema": {"type": "object"},
                "name": "inline",
            },
            {
                "description": "deferred" * 900,
                "input_schema": {"type": "object"},
                "name": "deferred",
            },
        ]
        catalog_bytes = canonical_json(catalog)
        descriptor = {
            "catalog_format": "anthropic_tools/v1",
            "items": [
                {
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "priority": 2 - index,
                    "required": False,
                }
                for index in range(2)
            ],
            "payload_b64u": b64url(catalog_bytes),
            "retain_count": 1,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            server = MCPServer(str(root))
            self._ready(server)
            selected = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"descriptor": descriptor},
                        "name": "receipt_tool_select",
                    },
                }
            )
            self.assertIsNotNone(selected)
            selection = selected["result"]["structuredContent"]  # type: ignore[index]
            bundle = json.loads(
                base64.urlsafe_b64decode(selection["output_b64u"] + "=" * 3)
            )
            catalog_capability = bundle["catalog_reference"]["capability"]
            item_capability = bundle["deferred"][0]["capability"]
            self.assertTrue(catalog_capability.startswith("cgr1m_"))
            self.assertTrue(item_capability.startswith("cgr1m_"))

            def expand(request_id: int, capability: str) -> bytes:
                response = server.handle(
                    {
                        "id": request_id,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {"capability": capability},
                            "name": "receipt_expand",
                        },
                    }
                )
                self.assertIsNotNone(response)
                result = response["result"]  # type: ignore[index]
                self.assertIs(result["isError"], False)
                return base64.urlsafe_b64decode(
                    result["structuredContent"]["output_b64u"] + "=" * 3
                )

            expanded_catalog = expand(3, catalog_capability)
            expanded_item = expand(4, item_capability)
            forged = server.handle(
                {
                    "id": 5,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "capability": item_capability,
                            "catalog_reference": bundle["catalog_reference"],
                        },
                        "name": "receipt_expand",
                    },
                }
            )
            server.close()

        self.assertEqual(expanded_catalog, catalog_bytes)
        self.assertEqual(expanded_item, canonical_json(catalog[1])[:-1])
        self.assertIs(forged["result"]["isError"], True)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
