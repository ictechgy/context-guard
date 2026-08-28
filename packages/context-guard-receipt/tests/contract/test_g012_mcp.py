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

    def test_initialize_and_tools_list_expose_only_the_eight_provider_free_tools(self) -> None:
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
        self.assertEqual(initialized["result"]["serverInfo"]["version"], "1.3.0")
        self.assertEqual(
            {tool["name"] for tool in listed["result"]["tools"]},
            {
                "receipt_assemble",
                "receipt_context",
                "receipt_diagnose",
                "receipt_expand",
                "receipt_inspect",
                "receipt_pack",
                "receipt_tool_select",
                "receipt_twin",
            },
        )
        self.assertNotIn(str(root), json.dumps((initialized, listed)))

    def test_context_store_reads_one_local_path_without_resending_its_payload(self) -> None:
        """Break caught: explicit context storage still requires bytes in the MCP request."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = b"bounded repeated build output\n" * 20_000
            (root / "build.log").write_bytes(payload)
            server = MCPServer(str(root))
            self._ready(server)
            response = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "store",
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "relative_path": "build.log",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            server.close()

        self.assertIn("result", response)
        self.assertIs(response["result"]["isError"], False)
        result = response["result"]["structuredContent"]
        self.assertEqual(result["disposition"], "deferred")
        self.assertIn("reference", result)
        self.assertTrue(result["reference"]["capability"].startswith("cgr1m_"))
        self.assertNotIn("output_b64u", result)
        self.assertNotIn("payload_b64u", json.dumps(response))
        self.assertNotIn(payload[:64].decode("ascii"), json.dumps(response))
        self.assertLess(len(json.dumps(response).encode("utf-8")), 8_192)

    def test_context_store_reuses_one_live_capability_for_repeated_file_reads(self) -> None:
        """Break caught: repeated unchanged context creates duplicate stored artifacts."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "repeat.log").write_bytes(b"same repeated output\n" * 24_000)
            server = MCPServer(str(root))
            self._ready(server)
            params = {
                "arguments": {
                    "action": "store",
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "relative_path": "repeat.log",
                },
                "name": "receipt_context",
            }
            first = server.handle(
                {"id": 2, "jsonrpc": "2.0", "method": "tools/call", "params": params}
            )
            second = server.handle(
                {"id": 3, "jsonrpc": "2.0", "method": "tools/call", "params": params}
            )
            inspected = server.handle(
                {
                    "id": 4,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            server.close()

        self.assertEqual(
            first["result"]["structuredContent"]["reference"],
            second["result"]["structuredContent"]["reference"],
        )
        counters = inspected["result"]["structuredContent"]
        self.assertEqual(counters["artifact_count"], 1)
        self.assertEqual(counters["context_cache_hits"], 1)

    def test_context_read_returns_only_the_requested_exact_slice(self) -> None:
        """Break caught: progressive retrieval expands the entire stored file every time."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = bytes(range(256)) * 2_000
            (root / "trace.bin").write_bytes(payload)
            server = MCPServer(str(root))
            self._ready(server)
            stored = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "store",
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "relative_path": "trace.bin",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            stored_payload = stored["result"]["structuredContent"]
            reference = stored_payload["reference"]
            response = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "read",
                            "capability": reference["capability"],
                            "max_bytes": 17,
                            "offset": 101,
                        },
                        "name": "receipt_context",
                    },
                }
            )
            server.close()

        result = response["result"]["structuredContent"]
        self.assertIs(response["result"]["isError"], False)
        self.assertEqual(
            base64.urlsafe_b64decode(result["output_b64u"] + "=" * 3),
            payload[101:118],
        )
        self.assertEqual(
            result["receipt"],
            {
                "complete": False,
                "end_byte": 118,
                "start_byte": 101,
                "total_bytes": len(payload),
            },
        )

    def test_context_task_scope_release_and_history_are_closed(self) -> None:
        """Break caught: one task can reuse another task's lease or released bytes."""

        from context_guard_receipt.mcp import MCPServer

        marker = "SYNTHETIC_TASK_SCOPE_MARKER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "scoped.log").write_text(marker * 24_000, encoding="ascii")
            server = MCPServer(str(root))
            self._ready(server)

            def context(request_id: int, arguments: dict[str, object]) -> dict[str, object]:
                response = server.handle(
                    {
                        "id": request_id,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {"arguments": arguments, "name": "receipt_context"},
                    }
                )
                self.assertIsNotNone(response)
                return response  # type: ignore[return-value]

            stored = context(
                2,
                {
                    "action": "store",
                    "caller_classification": "eligible",
                    "detector_signals": [],
                    "relative_path": "scoped.log",
                    "task_scope": "task-a",
                },
            )
            capability = stored["result"]["structuredContent"]["reference"]["capability"]
            wrong_scope = context(
                3,
                {
                    "action": "read",
                    "capability": capability,
                    "max_bytes": 16,
                    "offset": 0,
                    "task_scope": "task-b",
                },
            )
            exact = context(
                4,
                {
                    "action": "read",
                    "capability": capability,
                    "max_bytes": 16,
                    "offset": 0,
                    "task_scope": "task-a",
                },
            )
            released = context(
                5,
                {
                    "action": "release",
                    "capability": capability,
                    "task_scope": "task-a",
                },
            )
            after_release = context(
                6,
                {
                    "action": "read",
                    "capability": capability,
                    "max_bytes": 16,
                    "offset": 0,
                    "task_scope": "task-a",
                },
            )
            history = context(7, {"action": "history", "limit": 16})
            server.close()

        self.assertIs(wrong_scope["result"]["isError"], True)
        self.assertIs(exact["result"]["isError"], False)
        self.assertEqual(
            base64.urlsafe_b64decode(
                exact["result"]["structuredContent"]["output_b64u"] + "=" * 3
            ),
            marker.encode("ascii")[:16],
        )
        self.assertEqual(
            released["result"]["structuredContent"]["released"], True
        )
        self.assertIs(after_release["result"]["isError"], True)
        history_payload = history["result"]["structuredContent"]
        self.assertEqual(
            history_payload["schema_version"],
            "contextguard-receipt-mcp-context-history/v1",
        )
        self.assertTrue(history_payload["advisory_only"])
        self.assertGreaterEqual(len(history_payload["events"]), 4)
        for event in history_payload["events"]:
            for field in ("capability_hmac_sha256", "path_hmac_sha256", "task_scope_hmac_sha256"):
                if event.get(field) is not None:
                    self.assertRegex(event[field], r"^[0-9a-f]{64}$")
        history_wire = json.dumps(history_payload)
        self.assertNotIn("scoped.log", history_wire)
        self.assertNotIn("task-a", history_wire)
        self.assertNotIn(marker, history_wire)

    def test_context_diagnostics_exposes_only_shadow_advice(self) -> None:
        """Break caught: the scout/surgeon path resends file bytes or applies a route."""

        from context_guard_receipt.mcp import MCPServer

        marker = "SYNTHETIC_DIAGNOSTIC_MARKER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "stable.log").write_text(marker * 24_000, encoding="ascii")
            server = MCPServer(str(root))
            self._ready(server)
            stored = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "store",
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "relative_path": "stable.log",
                            "task_scope": "diagnostic-task",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            capability = stored["result"]["structuredContent"]["reference"]["capability"]
            diagnosed = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "previous_capability": capability,
                            "relative_path": "stable.log",
                            "task_scope": "diagnostic-task",
                        },
                        "name": "receipt_diagnose",
                    },
                }
            )
            server.close()

        report = diagnosed["result"]["structuredContent"]
        self.assertIs(diagnosed["result"]["isError"], False)
        self.assertEqual(report["advisory"], {
            "lane": "surgeon",
            "only": True,
            "reason": "bounded_stable_benefit",
        })
        self.assertFalse(report["firewall"]["applied"])
        self.assertFalse(report["firewall"]["would_block"])
        self.assertFalse(report["provider_routing_authority"])
        self.assertNotIn(marker, json.dumps(report))
        self.assertNotIn("stable.log", json.dumps(report))

    def test_execution_twin_is_server_owned_advisory_state(self) -> None:
        """Break caught: MCP callers inject state paths or twin evidence applies actions."""

        from context_guard_receipt.identity import snapshot_repository
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            root = parent / "root"
            state = parent / "state"
            root.mkdir()
            (root / "tracked.txt").write_text("stable\n", encoding="ascii")
            snapshot = snapshot_repository(str(root))
            request = {
                "declared_next_action_sha256": "a" * 64,
                "expected_tail": None,
                "predicates": [
                    {
                        "expected_sha256": snapshot["instance"]["identity_sha256"],
                        "kind": "repository_instance_equals",
                    }
                ],
                "schema_version": "contextguard-receipt-twin-request/v1",
            }
            server = MCPServer(str(root), state_dir=str(state))
            self._ready(server)
            appended = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "append",
                            "observed_at_unix_ms": 1_800_000_000_000,
                            "request": request,
                        },
                        "name": "receipt_twin",
                    },
                }
            )
            inspected = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"action": "inspect", "limit": 8},
                        "name": "receipt_twin",
                    },
                }
            )
            injected = server.handle(
                {
                    "id": 4,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "inspect",
                            "limit": 8,
                            "state_dir": str(parent / "caller-state"),
                        },
                        "name": "receipt_twin",
                    },
                }
            )
            server.close()

        append_payload = appended["result"]["structuredContent"]
        inspect_payload = inspected["result"]["structuredContent"]
        self.assertTrue(append_payload["verified"])
        self.assertTrue(append_payload["advisory_only"])
        self.assertFalse(append_payload["applied"])
        self.assertEqual(inspect_payload["committed_event_count"], 1)
        self.assertFalse(inspect_payload["execution_authority"])
        self.assertIs(injected["result"]["isError"], True)

    def test_context_store_never_emits_noneligible_local_file_bytes(self) -> None:
        """Break caught: a protected path-only request reflects file bytes as fallback."""

        from context_guard_receipt.mcp import MCPServer

        marker = "SYNTHETIC_PRIVATE_CONTEXT_MARKER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "private.log").write_text(marker * 1_000, encoding="ascii")
            server = MCPServer(str(root))
            self._ready(server)
            response = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "store",
                            "caller_classification": "protected",
                            "detector_signals": [],
                            "relative_path": "private.log",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            server.close()

        self.assertIs(response["result"]["isError"], True)
        self.assertEqual(
            response["result"]["structuredContent"]["code"],
            "context_not_eligible",
        )
        self.assertNotIn(marker, json.dumps(response))

    def test_context_read_rejects_capabilities_created_by_other_tools(self) -> None:
        """Break caught: progressive context reads accept unrelated capability types."""

        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = b"ordinary assembly bytes\n" * 24_000
            (root / "assembled.bin").write_bytes(payload)
            server = MCPServer(str(root))
            self._ready(server)
            assembled = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "descriptor": {
                                "caller_classification": "eligible",
                                "detector_signals": [],
                                "payload_b64u": b64url(payload),
                                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                "source": {
                                    "relative_path": "assembled.bin",
                                    "selection": {"kind": "file"},
                                },
                            },
                            "kind": "evidence",
                        },
                        "name": "receipt_assemble",
                    },
                }
            )
            assembly = assembled["result"]["structuredContent"]
            reference = json.loads(
                base64.urlsafe_b64decode(assembly["output_b64u"] + "=" * 3)
            )
            response = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "read",
                            "capability": reference["capability"],
                            "max_bytes": 32,
                            "offset": 0,
                        },
                        "name": "receipt_context",
                    },
                }
            )
            server.close()

        self.assertIs(response["result"]["isError"], True)
        self.assertEqual(
            response["result"]["structuredContent"]["code"],
            "capability_rejected",
        )

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
