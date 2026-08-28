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


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class StableToolProfileTests(unittest.TestCase):
    @staticmethod
    def ready(server: object) -> None:
        server.handle(  # type: ignore[attr-defined]
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "profile-test", "version": "1"},
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
    def descriptor(suffix: str = "") -> dict[str, object]:
        catalog = [
            {
                "description": "inline" * 900,
                "input_schema": {"type": "object"},
                "name": "inline",
            },
            {
                "description": "deferred" * 900 + suffix,
                "input_schema": {"type": "object"},
                "name": "deferred",
            },
        ]
        return {
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
            "payload_b64u": b64url(canonical_json(catalog)),
            "retain_count": 1,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
        }

    @staticmethod
    def select(server: object, request_id: int, descriptor: object) -> dict[str, object]:
        return server.handle(  # type: ignore[attr-defined]
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "arguments": {
                        "descriptor": descriptor,
                        "profile_id": "coding-core",
                        "task_scope": "issue-123",
                    },
                    "name": "receipt_tool_select",
                },
            }
        )

    def test_same_profile_reuses_exact_bundle_and_rejects_catalog_drift(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            self.ready(server)
            first = self.select(server, 2, self.descriptor())
            second = self.select(server, 3, self.descriptor())
            drifted = self.select(server, 4, self.descriptor("changed"))
            inspected = server.handle(
                {
                    "id": 5,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            server.close()

        self.assertIs(first["result"]["isError"], False)
        self.assertEqual(first["result"], second["result"])
        self.assertIs(drifted["result"]["isError"], True)
        self.assertEqual(
            drifted["result"]["structuredContent"]["code"], "profile_drift"
        )
        self.assertNotIn("coding-core", json.dumps(drifted))
        self.assertEqual(
            inspected["result"]["structuredContent"]["tool_profile_cache_hits"], 1
        )

    def test_profile_deferred_schema_expands_only_with_matching_task_scope(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            self.ready(server)
            selected = self.select(server, 2, self.descriptor())
            self.assertIs(selected["result"]["isError"], False)
            payload = selected["result"]["structuredContent"]
            bundle = json.loads(
                base64.urlsafe_b64decode(payload["output_b64u"] + "=" * 3)
            )
            capability = bundle["deferred"][0]["capability"]

            def expand(request_id: int, task_scope: str) -> dict[str, object]:
                return server.handle(
                    {
                        "id": request_id,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "capability": capability,
                                "task_scope": task_scope,
                            },
                            "name": "receipt_expand",
                        },
                    }
                )

            matching = expand(3, "issue-123")
            mismatching = expand(4, "other-task")
            server.close()

        self.assertIs(matching["result"]["isError"], False)
        self.assertIs(mismatching["result"]["isError"], True)

    def test_expired_profile_is_refused_without_silent_rebuild(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        now = [0.0]
        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()), clock=lambda: now[0])
            self.ready(server)
            first = self.select(server, 2, self.descriptor())
            now[0] = 301.0
            expired = self.select(server, 3, self.descriptor())
            server.close()

        self.assertIs(first["result"]["isError"], False)
        self.assertIs(expired["result"]["isError"], True)
        self.assertEqual(
            expired["result"]["structuredContent"]["code"], "profile_expired"
        )

    def test_small_pass_through_catalog_is_still_profiled_and_reused(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        descriptor = self.descriptor()
        descriptor["payload_b64u"] = b64url(
            canonical_json(
                [
                    {
                        "description": "small",
                        "input_schema": {"type": "object"},
                        "name": "inline",
                    }
                ]
            )
        )
        descriptor["items"] = [
            {
                "caller_classification": "eligible",
                "detector_signals": [],
                "priority": 1,
                "required": False,
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            self.ready(server)
            first = self.select(server, 2, descriptor)
            second = self.select(server, 3, descriptor)
            server.close()

        self.assertIs(first["result"]["isError"], False)
        self.assertEqual(first["result"], second["result"])
        self.assertEqual(
            first["result"]["structuredContent"]["disposition"], "pass_through"
        )


if __name__ == "__main__":
    unittest.main()
