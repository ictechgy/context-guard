"""Installed-tarball G012 stdio lifecycle and restart invalidation."""

from __future__ import annotations

import base64
import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
NPM = shutil.which("npm")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class InstalledMCPProcess:
    def __init__(
        self, executable: Path, root: Path, cwd: Path, *, state_dir: Path | None = None
    ) -> None:
        environment = {
            "CONTEXT_GUARD_RECEIPT_PYTHON": str(Path(sys.executable).resolve()),
            "LANG": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        arguments = [str(Path(NODE).resolve()), str(executable), "--root", str(root)]
        if state_dir is not None:
            arguments.extend(("--state-dir", str(state_dir)))
        self.process = subprocess.Popen(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def notify(self, message: dict[str, object]) -> None:
        if self.process.stdin is None:
            raise AssertionError("MCP stdin is unavailable")
        self.process.stdin.write(
            json.dumps(message, ensure_ascii=True, separators=(",", ":")) + "\n"
        )
        self.process.stdin.flush()

    def request(self, message: dict[str, object]) -> dict[str, object]:
        self.notify(message)
        if self.process.stdout is None:
            raise AssertionError("MCP stdout is unavailable")
        readable, _, _ = select.select([self.process.stdout], [], [], 10.0)
        if not readable:
            raise AssertionError("installed MCP did not flush a response")
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError("installed MCP exited before responding")
        return json.loads(line)

    def initialize(self) -> None:
        response = self.request(
            {
                "id": 1,
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "installed-e2e", "version": "1"},
                    "protocolVersion": "2025-11-25",
                },
            }
        )
        if response.get("id") != 1 or "result" not in response:
            raise AssertionError("installed MCP initialization failed")
        self.notify(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

    def close(self) -> str:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        self.process.wait(timeout=20)
        stderr = self.process.stderr.read() if self.process.stderr is not None else ""
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()
        if self.process.returncode != 0:
            raise AssertionError(f"installed MCP exited {self.process.returncode}")
        return stderr


@unittest.skipIf(NODE is None or NPM is None, "Node.js and npm are required")
class G012InstalledMCPTests(unittest.TestCase):
    def test_installed_assemble_expand_and_restart_invalidation(self) -> None:
        """Break caught: tarball MCP buffers, persists handles, or omits its runtime."""

        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory).resolve()
            pack_directory = base / "pack"
            install_directory = base / "install"
            repository_root = base / "repository"
            state_directory = base / "state"
            pack_directory.mkdir()
            install_directory.mkdir()
            repository_root.mkdir()
            packed = subprocess.run(
                [
                    str(Path(NPM).resolve()),
                    "pack",
                    "--json",
                    "--offline",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    "--pack-destination",
                    str(pack_directory),
                    str(PACKAGE_ROOT),
                ],
                cwd=pack_directory,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(packed.returncode, 0, packed.stderr)
            tarball = pack_directory / json.loads(packed.stdout)[0]["filename"]
            installed = subprocess.run(
                [
                    str(Path(NPM).resolve()),
                    "install",
                    "--offline",
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    str(tarball),
                ],
                cwd=install_directory,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            executable = (
                install_directory
                / "node_modules/@ictechgy/context-guard-receipt/bin/context-guard-receipt-mcp.cjs"
            ).resolve()

            payload = b"installed exact MCP bytes\n" * 24_000
            (repository_root / "evidence.bin").write_bytes(payload)
            descriptor = {
                "caller_classification": "eligible",
                "detector_signals": [],
                "payload_b64u": b64url(payload),
                "schema_version": "contextguard-receipt-evidence-descriptor/v1",
                "source": {
                    "relative_path": "evidence.bin",
                    "selection": {"kind": "file"},
                },
            }

            first = InstalledMCPProcess(
                executable,
                repository_root,
                install_directory,
                state_dir=state_directory,
            )
            first.initialize()
            listed = first.request(
                {"id": 2, "jsonrpc": "2.0", "method": "tools/list", "params": {}}
            )
            self.assertEqual(
                [tool["name"] for tool in listed["result"]["tools"]],
                [
                    "receipt_assemble",
                    "receipt_batch",
                    "receipt_context",
                    "receipt_diagnose",
                    "receipt_expand",
                    "receipt_inspect",
                    "receipt_pack",
                    "receipt_tool_select",
                    "receipt_twin",
                ],
            )
            assembled = first.request(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"descriptor": descriptor, "kind": "evidence"},
                        "name": "receipt_assemble",
                    },
                }
            )
            assembly = assembled["result"]["structuredContent"]
            reference = json.loads(
                base64.urlsafe_b64decode(assembly["output_b64u"] + "=" * 3)
            )
            capability = reference["capability"]
            self.assertTrue(capability.startswith("cgr1m_"))
            expanded = first.request(
                {
                    "id": 4,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"capability": capability},
                        "name": "receipt_expand",
                    },
                }
            )
            self.assertEqual(
                base64.urlsafe_b64decode(
                    expanded["result"]["structuredContent"]["output_b64u"] + "=" * 3
                ),
                payload,
            )
            context_stored = first.request(
                {
                    "id": 5,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "store",
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "relative_path": "evidence.bin",
                            "task_scope": "installed-task",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            context_reference = context_stored["result"]["structuredContent"][
                "reference"
            ]
            context_slice = first.request(
                {
                    "id": 6,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "read",
                            "capability": context_reference["capability"],
                            "max_bytes": 31,
                            "offset": 7,
                            "task_scope": "installed-task",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            self.assertEqual(
                base64.urlsafe_b64decode(
                    context_slice["result"]["structuredContent"]["output_b64u"]
                    + "=" * 3
                ),
                payload[7:38],
            )
            diagnosed = first.request(
                {
                    "id": 7,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "caller_classification": "eligible",
                            "detector_signals": [],
                            "previous_capability": context_reference["capability"],
                            "relative_path": "evidence.bin",
                            "task_scope": "installed-task",
                        },
                        "name": "receipt_diagnose",
                    },
                }
            )
            self.assertEqual(
                diagnosed["result"]["structuredContent"]["advisory"]["lane"],
                "surgeon",
            )
            twin_request = {
                "declared_next_action_sha256": "a" * 64,
                "expected_tail": None,
                "predicates": [
                    {"kind": "path_absent", "relative_path": "not-created.txt"}
                ],
                "schema_version": "contextguard-receipt-twin-request/v1",
            }
            appended = first.request(
                {
                    "id": 8,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "append",
                            "observed_at_unix_ms": 1_800_000_000_000,
                            "request": twin_request,
                        },
                        "name": "receipt_twin",
                    },
                }
            )
            self.assertTrue(appended["result"]["structuredContent"]["verified"])
            released = first.request(
                {
                    "id": 9,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "action": "release",
                            "capability": context_reference["capability"],
                            "task_scope": "installed-task",
                        },
                        "name": "receipt_context",
                    },
                }
            )
            self.assertTrue(released["result"]["structuredContent"]["released"])
            self.assertEqual(first.close(), "")

            restarted = InstalledMCPProcess(executable, repository_root, install_directory)
            restarted.initialize()
            rejected = restarted.request(
                {
                    "id": 2,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {"capability": capability},
                        "name": "receipt_expand",
                    },
                }
            )
            self.assertIs(rejected["result"]["isError"], True)
            self.assertNotIn(str(repository_root), json.dumps(rejected))
            self.assertEqual(restarted.close(), "")
            self.assertEqual(
                sorted(path.name for path in repository_root.iterdir()),
                ["evidence.bin"],
            )


if __name__ == "__main__":
    unittest.main()
