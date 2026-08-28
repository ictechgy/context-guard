"""Adversarial G012 MCP quota, wire, and authority-boundary contracts."""

from __future__ import annotations

import base64
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.mcp import (  # noqa: E402
    MAX_FRAME_BYTES,
    MAX_SINGLE_ARTIFACT_BYTES,
    MAX_TOTAL_ARTIFACT_BYTES,
    InMemoryCapabilityStore,
    MCPServer,
)
from context_guard_receipt.store import (  # noqa: E402
    ArtifactRequest,
    ArtifactType,
    StoreError,
    StoreErrorCode,
)


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def ready(server: MCPServer) -> None:
    response = server.handle(
        {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {"name": "g012-limits", "version": "1"},
                "protocolVersion": "2025-11-25",
            },
        }
    )
    if response is None or "result" not in response:
        raise AssertionError("MCP initialization failed")
    server.handle(
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
    )


def call(server: MCPServer, request_id: int, name: str, arguments: dict[str, object]) -> dict[str, object]:
    response = server.handle(
        {
            "id": request_id,
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"arguments": arguments, "name": name},
        }
    )
    if response is None:
        raise AssertionError("tools/call unexpectedly returned no response")
    return response


def evidence_descriptor(payload: bytes, relative_path: str) -> dict[str, object]:
    return {
        "caller_classification": "eligible",
        "detector_signals": [],
        "payload_b64u": b64url(payload),
        "schema_version": "contextguard-receipt-evidence-descriptor/v1",
        "source": {
            "relative_path": relative_path,
            "selection": {"kind": "file"},
        },
    }


def artifact_request(payload: bytes) -> ArtifactRequest:
    return ArtifactRequest(
        payload=payload,
        root_identity_sha256="a" * 64,
        subject_identity_sha256="b" * 64,
        artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
    )


def tool_error_code(response: dict[str, object]) -> str:
    result = response["result"]
    if not isinstance(result, dict) or result.get("isError") is not True:
        raise AssertionError("expected a closed MCP tool error")
    structured = result.get("structuredContent")
    if not isinstance(structured, dict) or not isinstance(structured.get("code"), str):
        raise AssertionError("expected a stable MCP tool-error payload")
    return structured["code"]


class G012McpLimitTests(unittest.TestCase):
    def test_forged_cross_root_and_cross_process_capabilities_share_one_closed_error(self) -> None:
        """Break caught: invalid handles reveal scope, path, or process membership."""

        payload = b"deferred capability bytes\n" * 25_000
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            first_root = base / "first"
            second_root = base / "second"
            first_root.mkdir()
            second_root.mkdir()
            (first_root / "source.bin").write_bytes(payload)
            first = MCPServer(str(first_root))
            ready(first)
            assembled = call(
                first,
                2,
                "receipt_assemble",
                {"descriptor": evidence_descriptor(payload, "source.bin"), "kind": "evidence"},
            )
            structured = assembled["result"]["structuredContent"]  # type: ignore[index]
            reference = json.loads(
                base64.urlsafe_b64decode(
                    structured["output_b64u"] + "=" * 3  # type: ignore[index]
                )
            )
            capability = reference["capability"]
            self.assertIsInstance(capability, str)

            forged = call(
                first,
                3,
                "receipt_expand",
                {"capability": "cgr1m_" + "A" * 43},
            )
            same_root_new_process = MCPServer(str(first_root))
            ready(same_root_new_process)
            cross_process = call(
                same_root_new_process,
                2,
                "receipt_expand",
                {"capability": capability},
            )
            cross_root_server = MCPServer(str(second_root))
            ready(cross_root_server)
            cross_root = call(
                cross_root_server,
                2,
                "receipt_expand",
                {"capability": capability},
            )
            first.close()
            same_root_new_process.close()
            cross_root_server.close()

        errors = [
            forged["result"]["structuredContent"],  # type: ignore[index]
            cross_process["result"]["structuredContent"],  # type: ignore[index]
            cross_root["result"]["structuredContent"],  # type: ignore[index]
        ]
        self.assertEqual(errors[0], errors[1])
        self.assertEqual(errors[1], errors[2])
        rendered = json.dumps(errors, sort_keys=True)
        self.assertNotIn(str(first_root), rendered)
        self.assertNotIn(str(second_root), rendered)
        self.assertNotIn(str(base), rendered)

    def test_total_byte_quota_rejection_is_atomic(self) -> None:
        """Break caught: failed byte quota batches partially publish authority."""

        store = InMemoryCapabilityStore()
        payload = b"x" * MAX_SINGLE_ARTIFACT_BYTES
        fitting_count = MAX_TOTAL_ARTIFACT_BYTES // MAX_SINGLE_ARTIFACT_BYTES - 1
        store.issue_batch(tuple(artifact_request(payload) for _index in range(fitting_count)))
        before = store.inspect_counts()
        with self.assertRaises(StoreError) as caught:
            store.issue_batch((artifact_request(payload), artifact_request(payload)))
        self.assertEqual(caught.exception.code, StoreErrorCode.ARTIFACT_BYTES_QUOTA_EXCEEDED)
        self.assertEqual(store.inspect_counts(), before)
        self.assertEqual(before, (fitting_count, fitting_count * MAX_SINGLE_ARTIFACT_BYTES))

    def test_stdio_enforces_exact_frame_crlf_utf8_and_depth_boundaries(self) -> None:
        """Break caught: line framing or nested request limits accept ambiguous wire input."""

        initialize = json.dumps(
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "wire", "version": "1"},
                    "protocolVersion": "2025-11-25",
                },
            },
            separators=(",", ":"),
        ).encode("ascii")
        exact_frame = b" " * (MAX_FRAME_BYTES - len(initialize)) + initialize + b"\n"
        oversized_frame = b" " + exact_frame

        with tempfile.TemporaryDirectory() as directory:
            root = str(Path(directory).resolve())
            server = MCPServer(root)
            exact_output = io.BytesIO()
            self.assertEqual(server.serve(io.BytesIO(exact_frame), exact_output), 0)
            server.close()
            self.assertIn(b'"result"', exact_output.getvalue())

            for invalid_wire in (oversized_frame, initialize + b"\r\n"):
                server = MCPServer(root)
                self.assertEqual(server.serve(io.BytesIO(invalid_wire), io.BytesIO()), 1)
                server.close()

            server = MCPServer(root)
            invalid_utf8_output = io.BytesIO()
            self.assertEqual(server.serve(io.BytesIO(b"\xff\n"), invalid_utf8_output), 0)
            server.close()
            self.assertEqual(
                json.loads(invalid_utf8_output.getvalue())["error"]["code"], -32700
            )

            def nested_meta(depth: int) -> dict[str, object]:
                value: dict[str, object] = {}
                for _index in range(depth):
                    value = {"x": value}
                return value

            def wire_for_depth(depth: int) -> bytes:
                initialized = initialize + b"\n"
                notification = (
                    b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
                )
                listed = json.dumps(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/list",
                        "params": {"_meta": nested_meta(depth)},
                    },
                    separators=(",", ":"),
                ).encode("ascii") + b"\n"
                return initialized + notification + listed

            server = MCPServer(root)
            accepted_depth_output = io.BytesIO()
            self.assertEqual(server.serve(io.BytesIO(wire_for_depth(38)), accepted_depth_output), 0)
            server.close()
            accepted = [json.loads(line) for line in accepted_depth_output.getvalue().splitlines()]
            self.assertIn("result", accepted[-1])

            server = MCPServer(root)
            rejected_depth_output = io.BytesIO()
            self.assertEqual(server.serve(io.BytesIO(wire_for_depth(39)), rejected_depth_output), 0)
            server.close()
            rejected = [json.loads(line) for line in rejected_depth_output.getvalue().splitlines()]
            self.assertEqual(rejected[-1]["error"]["code"], -32600)

    def test_concurrent_tool_call_fails_closed_while_another_call_holds_lock(self) -> None:
        """Break caught: a second request can execute concurrently with shared capability state."""

        with tempfile.TemporaryDirectory() as directory:
            server = MCPServer(str(Path(directory).resolve()))
            ready(server)
            entered = threading.Event()
            release = threading.Event()
            original_inspect = server._inspect

            def blocked_inspect(arguments: object) -> dict[str, object]:
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("concurrent test did not release")
                return original_inspect(arguments)

            with mock.patch.object(server, "_inspect", side_effect=blocked_inspect):
                first_result: list[dict[str, object]] = []

                def first_call() -> None:
                    first_result.append(call(server, 2, "receipt_inspect", {}))

                worker = threading.Thread(target=first_call)
                worker.start()
                self.assertTrue(entered.wait(timeout=5))
                contended = call(server, 3, "receipt_inspect", {})
                release.set()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
            server.close()

        self.assertEqual(tool_error_code(contended), "concurrency_limit_reached")
        self.assertFalse(first_result[0]["result"]["isError"])  # type: ignore[index]

    def test_every_tool_rejects_every_caller_authority_field_without_reflection(self) -> None:
        """Break caught: caller-supplied state, execution, or receipt authority reaches a tool."""

        forbidden = {
            "root": "/private-root-not-reflected",
            "state_dir": "/private-root-not-reflected",
            "receipt": {"forged": True},
            "artifact_id": "forged-artifact",
            "command": ["not", "run"],
            "run": True,
            "twin": {"forged": True},
            "reference_expiry": {"forged": True},
            "config": {"forged": True},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            payload = b"authority boundary"
            (root / "source.bin").write_bytes(payload)
            server = MCPServer(str(root))
            ready(server)
            request_id = 2
            for tool_name, baseline in (
                (
                    "receipt_assemble",
                    {"descriptor": evidence_descriptor(payload, "source.bin"), "kind": "evidence"},
                ),
                ("receipt_expand", {"capability": "cgr1m_" + "A" * 43}),
                ("receipt_inspect", {}),
                (
                    "receipt_pack",
                    {
                        "sources": [
                            {
                                "capability": "cgr1m_" + "A" * 43,
                                "relative_path": "source.bin",
                            }
                        ],
                        "retained_budget_bytes": 0,
                        "task_scope": "scope",
                    },
                ),
                ("receipt_tool_select", {"descriptor": {}}),
            ):
                for field, value in forbidden.items():
                    arguments = {**baseline, field: value}
                    response = call(server, request_id, tool_name, arguments)
                    request_id += 1
                    self.assertEqual(tool_error_code(response), "invalid_arguments")
                    self.assertNotIn("private-root-not-reflected", json.dumps(response))
            server.close()

    def test_blueprint_assembly_and_inspection_are_provider_free_and_process_scoped(self) -> None:
        """Break caught: valid blueprint assembly lacks bounded MCP inspection evidence."""

        payload = b"blueprint deferred payload\n" * 2_000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "blueprint.bin").write_bytes(payload)
            server = MCPServer(str(root))
            ready(server)
            descriptor = {
                "items": [
                    {
                        "caller_classification": "eligible",
                        "detector_signals": [],
                        "payload_end_byte": len(payload),
                        "payload_start_byte": 0,
                        "source": {
                            "relative_path": "blueprint.bin",
                            "selection": {"kind": "file"},
                        },
                    }
                ],
                "obligations": [{"item_index": 0, "phase": "optional_evidence"}],
                "payload_b64u": b64url(payload),
                "schema_version": "contextguard-receipt-blueprint-descriptor/v1",
            }
            assembled = call(
                server,
                2,
                "receipt_assemble",
                {"descriptor": descriptor, "kind": "blueprint"},
            )
            inspected = call(server, 3, "receipt_inspect", {})
            server.close()

        assembled_payload = assembled["result"]["structuredContent"]  # type: ignore[index]
        inspection = inspected["result"]["structuredContent"]  # type: ignore[index]
        self.assertFalse(assembled["result"]["isError"])  # type: ignore[index]
        self.assertEqual(assembled_payload["artifact_kind"], "mcp_assembly_result")  # type: ignore[index]
        self.assertEqual(inspection["scope"], "process")  # type: ignore[index]
        self.assertFalse(inspection["network_authority"])  # type: ignore[index]
        self.assertFalse(inspection["provider_claim_authority"])  # type: ignore[index]
        self.assertNotIn(str(root), json.dumps((assembled, inspected)))


if __name__ == "__main__":
    unittest.main()
