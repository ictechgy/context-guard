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
    def __init__(self, executable: Path, root: Path, cwd: Path) -> None:
        environment = {
            "CONTEXT_GUARD_RECEIPT_PYTHON": str(Path(sys.executable).resolve()),
            "LANG": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.process = subprocess.Popen(
            [str(Path(NODE).resolve()), str(executable), "--root", str(root)],
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

            first = InstalledMCPProcess(executable, repository_root, install_directory)
            first.initialize()
            listed = first.request(
                {"id": 2, "jsonrpc": "2.0", "method": "tools/list", "params": {}}
            )
            self.assertEqual(
                [tool["name"] for tool in listed["result"]["tools"]],
                [
                    "receipt_assemble",
                    "receipt_expand",
                    "receipt_inspect",
                    "receipt_tool_select",
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
