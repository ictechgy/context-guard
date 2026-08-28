from __future__ import annotations

import base64
from pathlib import Path
import sys
import tempfile
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


class ReceiptBatchMCPTests(unittest.TestCase):
    @staticmethod
    def ready(server: object) -> None:
        server.handle(  # type: ignore[attr-defined]
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "batch-test", "version": "1"},
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
    def call(
        server: object, request_id: int, name: str, arguments: dict[str, object]
    ) -> dict[str, object]:
        return server.handle(  # type: ignore[attr-defined,return-value]
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"arguments": arguments, "name": name},
            }
        )

    def store(
        self, server: object, request_id: int, path: str, task_scope: str
    ) -> str:
        response = self.call(
            server,
            request_id,
            "receipt_context",
            {
                "action": "store",
                "caller_classification": "eligible",
                "detector_signals": [],
                "relative_path": path,
                "task_scope": task_scope,
            },
        )
        return response["result"]["structuredContent"]["reference"]["capability"]

    def test_batch_returns_multiple_exact_slices_in_one_task_scoped_call(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = b"first payload\n" * 1_000
            second = b"second payload\n" * 1_000
            (root / "first.log").write_bytes(first)
            (root / "second.log").write_bytes(second)
            server = MCPServer(str(root))
            self.ready(server)
            first_capability = self.store(server, 2, "first.log", "issue-123")
            second_capability = self.store(server, 3, "second.log", "issue-123")

            response = self.call(
                server,
                4,
                "receipt_batch",
                {
                    "queries": [
                        {
                            "capability": first_capability,
                            "max_bytes": 17,
                            "offset": 3,
                        },
                        {
                            "capability": second_capability,
                            "max_bytes": 23,
                            "offset": 5,
                        },
                    ],
                    "task_scope": "issue-123",
                },
            )
            server.close()

        self.assertIs(response["result"]["isError"], False)
        result = response["result"]["structuredContent"]
        self.assertEqual(result["schema_version"], "contextguard-receipt-mcp-batch/v1")
        self.assertEqual(result["query_count"], 2)
        self.assertEqual(result["total_returned_bytes"], 40)
        decoded = [
            base64.urlsafe_b64decode(item["output_b64u"] + "=" * 3)
            for item in result["results"]
        ]
        self.assertEqual(decoded, [first[3:20], second[5:28]])
        self.assertEqual(result["results"][0]["start_byte"], 3)
        self.assertEqual(result["results"][0]["end_byte"], 20)
        self.assertFalse(result["provider_claim_authority"])
        self.assertFalse(result["network_authority"])

    def test_batch_rejects_one_wrong_scope_atomically_without_returning_bytes(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        marker = "SYNTHETIC_BATCH_SECRET_MARKER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "secret.log").write_text(marker * 1_000, encoding="ascii")
            server = MCPServer(str(root))
            self.ready(server)
            capability = self.store(server, 2, "secret.log", "task-a")
            response = self.call(
                server,
                3,
                "receipt_batch",
                {
                    "queries": [
                        {"capability": capability, "max_bytes": 64, "offset": 0}
                    ],
                    "task_scope": "task-b",
                },
            )
            server.close()

        self.assertIs(response["result"]["isError"], True)
        self.assertEqual(
            response["result"]["structuredContent"]["code"],
            "capability_rejected",
        )
        self.assertNotIn(marker, str(response))

    def test_batch_schema_is_closed_read_only_and_bounded(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            self.ready(server)
            listed = server.handle(  # type: ignore[attr-defined]
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                }
            )
            server.close()

        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        batch = tools["receipt_batch"]
        self.assertTrue(batch["annotations"]["readOnlyHint"])
        self.assertFalse(batch["annotations"]["openWorldHint"])
        self.assertFalse(batch["inputSchema"]["additionalProperties"])
        self.assertEqual(batch["inputSchema"]["properties"]["queries"]["maxItems"], 16)


if __name__ == "__main__":
    unittest.main()
