"""Adversarial G012 root, capability, and wire-boundary contracts."""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.mcp import (  # noqa: E402
    MAX_ARTIFACTS,
    InMemoryCapabilityStore,
    MCPServer,
)
from context_guard_receipt.store import (  # noqa: E402
    ArtifactRequest,
    ArtifactType,
    StoreError,
)


def request() -> ArtifactRequest:
    return ArtifactRequest(
        payload=b"bounded-artifact",
        root_identity_sha256="a" * 64,
        subject_identity_sha256="b" * 64,
        artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
    )


def ready(server: MCPServer) -> None:
    initialized = server.handle(
        {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {"name": "adversarial", "version": "1"},
                "protocolVersion": "2025-11-25",
            },
        }
    )
    if initialized is None or "result" not in initialized:
        raise AssertionError("MCP initialization failed")
    server.handle(
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
    )


class G012CapabilityAdversarialTests(unittest.TestCase):
    def test_unrecognized_nested_paths_do_not_amplify_preflight_work(self) -> None:
        """Break caught: schema-invalid nested fields trigger repeated directory scans."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            (root / "source.bin").write_bytes(b"exact")
            server = MCPServer(str(root))
            ready(server)
            original_validation = server._validate_relative_path
            descriptor = {
                "attacker": [
                    {"relative_path": "source.bin"} for _index in range(1_000)
                ],
                "caller_classification": "eligible",
                "detector_signals": [],
                "payload_b64u": "ZXhhY3Q",
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {
                    "relative_path": "source.bin",
                    "selection": {"kind": "file"},
                },
            }
            with mock.patch.object(
                server, "_validate_relative_path", wraps=original_validation
            ) as validation:
                response = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": descriptor,
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertLessEqual(validation.call_count, 1)

    def test_backslash_and_non_normalized_relative_paths_are_tool_errors(self) -> None:
        """Break caught: platform-specific aliases are reported as successful bypasses."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            (root / "dir\\file").write_bytes(b"exact")
            server = MCPServer(str(root))
            ready(server)
            responses = []
            for request_id, relative_path in enumerate(
                ("dir\\file", "e\N{COMBINING ACUTE ACCENT}.txt"), start=2
            ):
                responses.append(
                    server.handle(
                        {
                            "id": request_id,
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "arguments": {
                                    "descriptor": {
                                        "caller_classification": "eligible",
                                        "detector_signals": [],
                                        "payload_b64u": "ZXhhY3Q",
                                        "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                        "source": {
                                            "relative_path": relative_path,
                                            "selection": {"kind": "file"},
                                        },
                                    },
                                    "kind": "evidence",
                                },
                                "name": "receipt_assemble",
                            },
                        }
                    )
                )
            server.close()
        self.assertTrue(
            all(response["result"]["isError"] for response in responses)  # type: ignore[index]
        )

    def test_source_symlink_swap_after_preflight_is_a_tool_error(self) -> None:
        """Break caught: a no-follow source refusal is mislabeled as successful pass-through."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory).resolve()
            root = base / "root"
            root.mkdir()
            source = root / "source.bin"
            source.write_bytes(b"expected")
            outside = base / "outside.bin"
            outside.write_bytes(b"outside-private")
            server = MCPServer(str(root))
            ready(server)
            original_validation = server._validate_descriptor_paths

            def swap_after_validation(descriptor: object) -> None:
                original_validation(descriptor)
                source.unlink()
                source.symlink_to(outside)

            with mock.patch.object(
                server, "_validate_descriptor_paths", side_effect=swap_after_validation
            ):
                response = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "eligible",
                                    "detector_signals": [],
                                    "payload_b64u": "ZXhwZWN0ZWQ",
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "source.bin",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertNotIn(str(outside), json.dumps(response))
        self.assertNotIn("outside-private", json.dumps(response))

    def test_pass_through_payload_is_never_rewritten_as_a_capability(self) -> None:
        """Break caught: MCP alias translation mutates caller-owned exact bytes."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            seed_payload = b"seed deferred bytes\n" * 25_000
            capability_bytes = b"C" * 32
            internal_alias = "cgr1p_" + base64.urlsafe_b64encode(
                capability_bytes
            ).rstrip(b"=").decode("ascii")
            exact_payload = (
                json.dumps(
                    {"capability": internal_alias, "kind": "caller-owned"},
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("ascii")
            (root / "seed.bin").write_bytes(seed_payload)
            (root / "pass-through.json").write_bytes(exact_payload)
            with mock.patch(
                "context_guard_receipt.mcp.secrets.token_bytes",
                side_effect=(b"N" * 32, capability_bytes),
            ):
                server = MCPServer(str(root))
                ready(server)
                seeded = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "eligible",
                                    "detector_signals": [],
                                    "payload_b64u": base64.urlsafe_b64encode(
                                        seed_payload
                                    )
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "seed.bin",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
                seed_reference = json.loads(
                    base64.urlsafe_b64decode(
                        seeded["result"]["structuredContent"]["output_b64u"] + "=" * 3  # type: ignore[index]
                    )
                )
                self.assertEqual(
                    seed_reference["capability"].replace("cgr1m_", "cgr1p_", 1),
                    internal_alias,
                )
                passed = server.handle(
                    {
                        "id": 3,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "protected",
                                    "detector_signals": [],
                                    "payload_b64u": base64.urlsafe_b64encode(
                                        exact_payload
                                    )
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "pass-through.json",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
                server.close()
        returned = base64.urlsafe_b64decode(
            passed["result"]["structuredContent"]["output_b64u"] + "=" * 3  # type: ignore[index]
        )
        self.assertEqual(returned, exact_payload)

    def test_clock_rollback_terminally_invalidates_existing_handles(self) -> None:
        """Break caught: a regressed injected clock lengthens capability authority."""

        observed = [100.0]
        store = InMemoryCapabilityStore(clock=lambda: observed[0])
        internal = store.issue_batch((request(),))[0].handle
        external = store.externalize_handle(internal)
        observed[0] = 99.0
        with self.assertRaises(StoreError):
            store.resolve(external, expected_root_identity_sha256="a" * 64)
        observed[0] = 101.0
        with self.assertRaises(StoreError):
            store.resolve(external, expected_root_identity_sha256="a" * 64)

    def test_batch_exhaustion_is_atomic_and_never_evicts_live_records(self) -> None:
        """Break caught: quota pressure partially publishes or evicts capabilities."""

        store = InMemoryCapabilityStore()
        issued = store.issue_batch((request(),) * (MAX_ARTIFACTS - 1))
        self.assertEqual(len(issued), MAX_ARTIFACTS - 1)
        before = store.inspect_counts()
        with self.assertRaises(StoreError):
            store.issue_batch((request(), request()))
        self.assertEqual(store.inspect_counts(), before)
        self.assertEqual(before[0], MAX_ARTIFACTS - 1)

    def test_symlinked_root_ancestor_is_rejected(self) -> None:
        """Break caught: the startup path aliases an unpinned directory ancestor."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory).resolve()
            real_parent = base / "real-parent"
            root = real_parent / "root"
            root.mkdir(parents=True)
            alias_parent = base / "alias-parent"
            try:
                alias_parent.symlink_to(real_parent, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaises(ValueError):
                MCPServer(str(alias_parent / "root"))

    def test_root_replacement_poisoning_is_terminal_even_after_restore(self) -> None:
        """Break caught: a renamed/replaced startup root can silently regain authority."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory).resolve()
            root = base / "root"
            original = base / "original"
            root.mkdir()
            server = MCPServer(str(root))
            ready(server)
            root.rename(original)
            root.mkdir()
            first = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            root.rmdir()
            original.rename(root)
            second = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            server.close()
        self.assertIs(first["result"]["isError"], True)  # type: ignore[index]
        self.assertIs(second["result"]["isError"], True)  # type: ignore[index]

    def test_root_replacement_during_assembly_never_issues_a_capability(self) -> None:
        """Break caught: transient replacement-root bytes receive startup-root authority."""

        payload = b"deferred exact bytes\n" * 30_000
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory).resolve()
            root = base / "root"
            original = base / "original"
            root.mkdir()
            (root / "source.bin").write_bytes(payload)
            server = MCPServer(str(root))
            ready(server)

            from context_guard_receipt import mcp as mcp_module

            real_assemble = mcp_module.assemble_evidence

            def swap_while_assembling(
                descriptor_raw: bytes, *, root: object, store: object
            ) -> object:
                Path(root).rename(original)
                Path(root).mkdir()
                (Path(root) / "source.bin").write_bytes(payload)
                try:
                    return real_assemble(descriptor_raw, root=root, store=store)
                finally:
                    (Path(root) / "source.bin").unlink()
                    Path(root).rmdir()
                    original.rename(Path(root))

            with mock.patch.object(
                mcp_module, "assemble_evidence", side_effect=swap_while_assembling
            ):
                response = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "eligible",
                                    "detector_signals": [],
                                    "payload_b64u": base64.urlsafe_b64encode(payload)
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "source.bin",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
            inspected = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            artifact_count, total_bytes = server._store.inspect_counts()
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertIs(inspected["result"]["isError"], True)  # type: ignore[index]
        self.assertEqual((artifact_count, total_bytes), (0, 0))

    def test_git_logical_state_drift_terminally_requires_restart(self) -> None:
        """Break caught: one MCP process silently spans different repository states."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            subprocess.run(
                ["git", "init", "--quiet", str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / "tracked.txt").write_text("initial\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", "tracked.txt"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server = MCPServer(str(root))
            ready(server)
            drift = root / "untracked.txt"
            drift.write_text("drift\n", encoding="utf-8")
            first = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            drift.unlink()
            second = server.handle(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            server.close()
        self.assertIs(first["result"]["isError"], True)  # type: ignore[index]
        self.assertIs(second["result"]["isError"], True)  # type: ignore[index]

    def test_ignored_source_creation_terminally_requires_restart(self) -> None:
        """Break caught: Git-ignored bytes bypass the startup root-state freeze."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            subprocess.run(
                ["git", "init", "--quiet", str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (root / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitignore"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=G012",
                    "-c",
                    "user.email=g012@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server = MCPServer(str(root))
            ready(server)
            (root / "ignored.bin").write_bytes(b"ignored bytes")
            response = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"arguments": {}, "name": "receipt_inspect"},
                }
            )
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]

    def test_git_metadata_sources_are_always_tool_errors(self) -> None:
        """Break caught: excluded Git-internal bytes receive source capability authority."""

        payload = b"git internal bytes\n" * 30_000
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            subprocess.run(
                ["git", "init", "--quiet", str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            source = root / ".git/hooks/frozen.bin"
            source.write_bytes(payload)
            server = MCPServer(str(root))
            ready(server)
            response = server.handle(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "descriptor": {
                                "caller_classification": "eligible",
                                "detector_signals": [],
                                "payload_b64u": base64.urlsafe_b64encode(payload)
                                .rstrip(b"=")
                                .decode("ascii"),
                                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                "source": {
                                    "relative_path": ".git/hooks/frozen.bin",
                                    "selection": {"kind": "file"},
                                },
                            },
                            "kind": "evidence",
                        },
                        "name": "receipt_assemble",
                    },
                }
            )
            artifact_count, total_bytes = server._store.inspect_counts()
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertEqual((artifact_count, total_bytes), (0, 0))

    def test_tracked_source_change_restored_during_assembly_is_terminal(self) -> None:
        """Break caught: transient tracked bytes receive authority after exact restore."""

        original_payload = b"original tracked bytes\n" * 30_000
        transient_payload = b"transient caller bytes\n" * 30_000
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            subprocess.run(
                ["git", "init", "--quiet", str(root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            source = root / "source.bin"
            source.write_bytes(original_payload)
            subprocess.run(
                ["git", "-C", str(root), "add", "source.bin"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=G012",
                    "-c",
                    "user.email=g012@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            server = MCPServer(str(root))
            ready(server)

            from context_guard_receipt import mcp as mcp_module

            real_assemble = mcp_module.assemble_evidence

            def transient_assembly(
                descriptor_raw: bytes, *, root: object, store: object
            ) -> object:
                source.write_bytes(transient_payload)
                try:
                    return real_assemble(descriptor_raw, root=root, store=store)
                finally:
                    source.write_bytes(original_payload)

            with mock.patch.object(
                mcp_module, "assemble_evidence", side_effect=transient_assembly
            ):
                response = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "eligible",
                                    "detector_signals": [],
                                    "payload_b64u": base64.urlsafe_b64encode(
                                        transient_payload
                                    )
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "source.bin",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
            artifact_count, total_bytes = server._store.inspect_counts()
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertEqual((artifact_count, total_bytes), (0, 0))

    def test_non_git_same_size_change_restored_during_assembly_is_terminal(self) -> None:
        """Break caught: non-Git metadata races issue transient source authority."""

        original_payload = b"A" * 600_000
        transient_payload = b"B" * 600_000
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            source = root / "source.bin"
            source.write_bytes(original_payload)
            server = MCPServer(str(root))
            ready(server)

            from context_guard_receipt import mcp as mcp_module

            real_assemble = mcp_module.assemble_evidence

            def transient_assembly(
                descriptor_raw: bytes, *, root: object, store: object
            ) -> object:
                source.write_bytes(transient_payload)
                try:
                    return real_assemble(descriptor_raw, root=root, store=store)
                finally:
                    source.write_bytes(original_payload)

            with mock.patch.object(
                mcp_module, "assemble_evidence", side_effect=transient_assembly
            ):
                response = server.handle(
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/call",
                        "params": {
                            "arguments": {
                                "descriptor": {
                                    "caller_classification": "eligible",
                                    "detector_signals": [],
                                    "payload_b64u": base64.urlsafe_b64encode(
                                        transient_payload
                                    )
                                    .rstrip(b"=")
                                    .decode("ascii"),
                                    "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                                    "source": {
                                        "relative_path": "source.bin",
                                        "selection": {"kind": "file"},
                                    },
                                },
                                "kind": "evidence",
                            },
                            "name": "receipt_assemble",
                        },
                    }
                )
            artifact_count, total_bytes = server._store.inspect_counts()
            server.close()
        self.assertIs(response["result"]["isError"], True)  # type: ignore[index]
        self.assertEqual((artifact_count, total_bytes), (0, 0))

    def test_unresolved_repository_snapshot_is_rejected_at_startup(self) -> None:
        """Break caught: an unobservable Git state is treated as a frozen identity."""

        unresolved = {
            "instance": {"identity_sha256": "a" * 64},
            "logical_state": {
                "kind": "unresolved",
                "reason": "git_output_limit",
                "state_sha256": "b" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as temporary_directory, mock.patch(
            "context_guard_receipt.mcp.snapshot_repository", return_value=unresolved
        ):
            with self.assertRaises(ValueError):
                MCPServer(str(Path(temporary_directory).resolve()))

    def test_wire_accepts_noncanonical_json_but_rejects_duplicate_keys_and_ids(self) -> None:
        """Break caught: valid MCP JSON is over-restricted or ambiguous IDs are replayed."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            server = MCPServer(str(Path(temporary_directory).resolve()))
            wire = (
                b'{ "method" : "initialize", "params" : '
                b'{"clientInfo":{"version":"1","name":"wire"},'
                b'"protocolVersion":"2025-11-25","capabilities":{}},'
                b'"jsonrpc":"2.0", "id":7}\n'
                b'{"jsonrpc":"2.0","method":"ping","id":8,"id":9}\n'
                b'{"jsonrpc":"2.0","id":7,"method":"initialize",'
                b'"params":{"protocolVersion":"2025-11-25",'
                b'"capabilities":{},"clientInfo":{"name":"wire","version":"1"}}}\n'
            )
            output = io.BytesIO()
            self.assertEqual(server.serve(io.BytesIO(wire), output), 0)
            server.close()
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[0]["id"], 7)
        self.assertIn("result", responses[0])
        self.assertEqual(responses[1]["error"]["code"], -32600)
        self.assertEqual(responses[2]["error"]["code"], -32600)

    def test_large_tool_bundle_never_leaks_internal_capability_syntax(self) -> None:
        """Break caught: the default canonical parser cap leaves cgr1p_ in a large bundle."""

        catalog = [
            {
                "description": "safe-a" * 45_000,
                "input_schema": {"type": "object"},
                "name": "inline",
            },
            {
                "description": "safe-b" * 45_000,
                "input_schema": {"type": "object"},
                "name": "deferred",
            },
        ]
        catalog_bytes = (
            json.dumps(catalog, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
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
            "payload_b64u": base64.urlsafe_b64encode(catalog_bytes)
            .rstrip(b"=")
            .decode("ascii"),
            "retain_count": 1,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            server = MCPServer(str(Path(temporary_directory).resolve()))
            ready(server)
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
            server.close()
        self.assertIsNotNone(selected)
        result = selected["result"]  # type: ignore[index]
        self.assertIs(result["isError"], False)
        bundle = base64.urlsafe_b64decode(
            result["structuredContent"]["output_b64u"] + "=" * 3
        )
        self.assertGreater(len(bundle), 256 * 1024)
        self.assertNotIn(b"cgr1p_", bundle)
        self.assertIn(b"cgr1m_", bundle)


if __name__ == "__main__":
    unittest.main()
