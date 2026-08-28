from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


class ReceiptPackMCPTests(unittest.TestCase):
    @staticmethod
    def ready(server: object) -> None:
        server.handle(  # type: ignore[attr-defined]
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "pack-test", "version": "1"},
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

    @staticmethod
    def decode_payload(response: dict[str, object]) -> dict[str, object]:
        structured = response["result"]["structuredContent"]  # type: ignore[index]
        encoded = structured["output_b64u"]  # type: ignore[index]
        raw = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
        return json.loads(raw)

    def test_pack_retains_budgeted_source_and_scopes_deferred_expansion(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            small = b"small exact source\n" * 4
            large = b"large exact source\n" * 2_000
            (root / "small.txt").write_bytes(small)
            (root / "large.txt").write_bytes(large)
            server = MCPServer(str(root))
            self.ready(server)
            stored = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "relative_paths": ["small.txt", "large.txt"],
                            "retained_budget_bytes": len(small),
                            "task_scope": "issue-123",
                        },
                        "name": "receipt_pack",
                    },
                }
            )
            self.assertIn("result", stored)
            pack = self.decode_payload(stored)
            deferred = [
                segment
                for segment in pack["segments"]
                if segment["kind"] == "deferred"
            ]
            retained = [
                segment
                for segment in pack["segments"]
                if segment["kind"] == "retained"
            ]
            capability = deferred[0]["capability"]
            expanded = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "capability": capability,
                            "task_scope": "issue-123",
                        },
                        "name": "receipt_expand",
                    },
                }
            )
            refused = server.handle(
                {
                    "id": 4,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "capability": capability,
                            "task_scope": "different-task",
                        },
                        "name": "receipt_expand",
                    },
                }
            )
            server.close()

        self.assertIs(stored["result"]["isError"], False)
        self.assertEqual(len(retained), 1)
        self.assertEqual(len(deferred), 1)
        self.assertEqual(
            base64.urlsafe_b64decode(retained[0]["payload_b64u"] + "=" * 3),
            small,
        )
        expanded_payload = expanded["result"]["structuredContent"]
        self.assertEqual(
            base64.urlsafe_b64decode(expanded_payload["output_b64u"] + "=" * 3),
            large,
        )
        self.assertIs(refused["result"]["isError"], True)
        serialized = json.dumps(stored)
        self.assertNotIn("small.txt", serialized)
        self.assertNotIn("large.txt", serialized)
        self.assertNotIn(large[:64].decode("ascii"), serialized)

    def test_tools_list_declares_pack_as_closed_provider_free_surface(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            self.ready(server)
            listed = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                }
            )
            server.close()

        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("receipt_pack", tools)
        schema = tools["receipt_pack"]["inputSchema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {"relative_paths", "retained_budget_bytes", "task_scope"},
        )
        self.assertFalse(tools["receipt_pack"]["annotations"]["openWorldHint"])

    def test_pack_root_revalidation_count_does_not_scale_with_file_count(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            relative_paths = []
            for index in range(16):
                relative_path = f"source-{index}.txt"
                (root / relative_path).write_bytes(b"bounded\n")
                relative_paths.append(relative_path)
            server = MCPServer(str(root))
            self.ready(server)
            original = server._revalidate_root
            calls = [0]

            def counted_revalidation() -> None:
                calls[0] += 1
                original()

            server._revalidate_root = counted_revalidation  # type: ignore[method-assign]
            response = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "relative_paths": relative_paths,
                            "retained_budget_bytes": 900_000,
                            "task_scope": "bounded-revalidation",
                        },
                        "name": "receipt_pack",
                    },
                }
            )
            server.close()

        self.assertIs(response["result"]["isError"], False)
        self.assertLessEqual(calls[0], 6)


if __name__ == "__main__":
    unittest.main()
