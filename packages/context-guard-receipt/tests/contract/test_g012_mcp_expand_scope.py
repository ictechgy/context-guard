"""Focused acceptance for optional task_scope binding on receipt_expand.

Prior to this change, `receipt_context` bound its capabilities to an optional
caller-declared `task_scope` (HMAC-compared, mcp.py `_lease_matches`), but
`receipt_expand` had no equivalent binding at all: any caller holding a valid,
unexpired `cgr1m_...` handle could expand it regardless of task context. This
is a structural asymmetry between the two capability lifecycles, not an
observed exploit.

This test pins the following acceptance criteria for `receipt_expand`:

1. Existing behavior is unchanged for capabilities issued without a scope
   commitment and expanded without a `task_scope` argument (the only shape
   every current issuer - `receipt_assemble`, `receipt_tool_select` - uses
   today).
2. Supplying a `task_scope` argument against a capability that was issued
   WITHOUT a scope commitment is rejected (`capability_rejected`). A caller
   must not be able to claim an arbitrary scope on an unscoped capability.
3. A capability issued WITH a scope commitment (`ArtifactRequest.scope_hmac_sha256`,
   computed the same way `receipt_context`'s "store" action does via
   `MCPServer._task_scope_hmac`) expands successfully only when the supplied
   `task_scope` matches; a missing or mismatched `task_scope` is rejected.
4. The `receipt_expand` tool's JSON schema declares `task_scope` as an
   OPTIONAL string property (not in `required`), so existing callers that
   omit it remain schema-valid.

No production issuer needs to start setting a scope for this PR; the field
default keeps 100% of existing capability issuance untouched.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def _ready(server: object) -> None:
    server.handle(  # type: ignore[attr-defined]
        {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {"name": "g012-expand-scope", "version": "1"},
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


class ReceiptExpandTaskScopeTests(unittest.TestCase):
    def _server_and_root(self, directory: str):
        from context_guard_receipt.mcp import MCPServer

        root = Path(directory).resolve()
        server = MCPServer(str(root))
        _ready(server)
        return server, root

    def _issue_capability(self, server: object, *, scope_hmac_sha256: object = None) -> str:
        from context_guard_receipt.canonical import framed_sha256_hex
        from context_guard_receipt.expansion import _COMMAND_CAPTURE_SUBJECT_DOMAIN
        from context_guard_receipt.runner import frame_sanitized_capture
        from context_guard_receipt.store import ArtifactRequest, ArtifactType

        payload = frame_sanitized_capture(b"exact stdout for expand-scope test", b"")
        subject_identity = framed_sha256_hex(_COMMAND_CAPTURE_SUBJECT_DOMAIN, payload)
        kwargs = dict(
            payload=payload,
            root_identity_sha256=server._root_identity,  # type: ignore[attr-defined]
            subject_identity_sha256=subject_identity,
            artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
        )
        if scope_hmac_sha256 is not None:
            request = ArtifactRequest(scope_hmac_sha256=scope_hmac_sha256, **kwargs)
        else:
            request = ArtifactRequest(**kwargs)
        issued = server._store.issue_batch((request,))[0]  # type: ignore[attr-defined]
        return server._store.externalize_handle(issued.handle)  # type: ignore[attr-defined]

    _next_id = 1

    def _expand(self, server: object, capability: str, task_scope: object = None) -> dict:
        arguments: dict[str, object] = {"capability": capability}
        if task_scope is not None:
            arguments["task_scope"] = task_scope
        self.__class__._next_id += 1
        return server.handle(  # type: ignore[attr-defined]
            {
                "id": self.__class__._next_id,
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"arguments": arguments, "name": "receipt_expand"},
            }
        )

    def test_unscoped_capability_expands_without_task_scope_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server, _ = self._server_and_root(directory)
            capability = self._issue_capability(server)
            response = self._expand(server, capability)
            self.assertIsNot(response["result"].get("isError"), True)

    def test_unscoped_capability_rejects_a_supplied_task_scope(self) -> None:
        """Break caught: a caller claims an arbitrary scope on an unscoped capability."""

        with tempfile.TemporaryDirectory() as directory:
            server, _ = self._server_and_root(directory)
            capability = self._issue_capability(server)
            response = self._expand(server, capability, task_scope="anything")
            self.assertIs(response["result"]["isError"], True)
            self.assertEqual(
                response["result"]["structuredContent"]["code"], "capability_rejected"
            )

    def test_scoped_capability_expands_only_with_matching_task_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            server, _ = self._server_and_root(directory)
            expected_hmac = server._task_scope_hmac("build-fix-42")  # type: ignore[attr-defined]
            capability = self._issue_capability(server, scope_hmac_sha256=expected_hmac)

            missing = self._expand(server, capability)
            self.assertIs(missing["result"]["isError"], True)
            self.assertEqual(
                missing["result"]["structuredContent"]["code"], "capability_rejected"
            )

            wrong = self._expand(server, capability, task_scope="different-task")
            self.assertIs(wrong["result"]["isError"], True)
            self.assertEqual(
                wrong["result"]["structuredContent"]["code"], "capability_rejected"
            )

            matched = self._expand(server, capability, task_scope="build-fix-42")
            self.assertIsNot(matched["result"].get("isError"), True)

    def test_receipt_expand_schema_declares_task_scope_as_optional(self) -> None:
        from context_guard_receipt.mcp import MCPServer

        with tempfile.TemporaryDirectory() as directory:
            server, _ = self._server_and_root(directory)
            listing = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                }
            )
            tools = {tool["name"]: tool for tool in listing["result"]["tools"]}
            schema = tools["receipt_expand"]["inputSchema"]
            self.assertIn("task_scope", schema["properties"])
            self.assertEqual(schema["properties"]["task_scope"]["type"], "string")
            self.assertNotIn("task_scope", schema["required"])
            self.assertIn("capability", schema["required"])


if __name__ == "__main__":
    unittest.main()
