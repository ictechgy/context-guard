"""G012 launcher and CLI contracts for the opt-in stdio MCP surface."""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
NODE = shutil.which("node")

if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt import cli  # noqa: E402


class MCPCLIContractTests(unittest.TestCase):
    def test_cli_accepts_only_server_owned_absolute_root_and_optional_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = str(Path(temporary_directory).resolve())
            state = str((Path(temporary_directory) / "state").resolve())
            with mock.patch(
                "context_guard_receipt.mcp.serve_stdio", return_value=17
            ) as serve_stdio:
                self.assertEqual(cli.mcp_main(("--root", root)), 17)
            serve_stdio.assert_called_once_with(root)
            with mock.patch(
                "context_guard_receipt.mcp.serve_stdio", return_value=19
            ) as serve_stdio:
                self.assertEqual(
                    cli.mcp_main(("--root", root, "--state-dir", state)), 19
                )
            serve_stdio.assert_called_once_with(root, state_dir=state)

        for arguments in (
            (),
            ("--root", "."),
            ("--state-dir", "/tmp/state", "--root", "/tmp"),
            ("--root", "/tmp", "--state-dir", "relative"),
            ("--namespace", "caller-chosen"),
        ):
            with self.subTest(arguments=arguments):
                with mock.patch(
                    "context_guard_receipt.mcp.serve_stdio"
                ) as serve_stdio, mock.patch.object(cli.sys, "stderr"):
                    self.assertEqual(cli.mcp_main(arguments), 64)
                serve_stdio.assert_not_called()

    @unittest.skipIf(NODE is None, "Node.js is required")
    def test_node_launcher_flushes_initialize_response_before_stdin_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = str(Path(temporary_directory).resolve())
            environment = {
                "LANG": "C",
                "PATH": os.defpath,
                "PYTHONDONTWRITEBYTECODE": "1",
                "CONTEXT_GUARD_RECEIPT_PYTHON": str(Path(sys.executable).resolve()),
            }
            process = subprocess.Popen(
                [
                    str(Path(NODE).resolve()),
                    str(PACKAGE_ROOT / "bin/context-guard-receipt-mcp.cjs"),
                    "--root",
                    root,
                ],
                cwd=temporary_directory,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            try:
                assert process.stdin is not None
                assert process.stdout is not None
                process.stdin.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2025-11-25",
                                "capabilities": {},
                                "clientInfo": {"name": "g012", "version": "1"},
                            },
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                process.stdin.flush()
                readable, _, _ = select.select([process.stdout], [], [], 3.0)
                self.assertTrue(readable, "MCP response was buffered until process exit")
                response_line = process.stdout.readline()
                self.assertTrue(response_line, "MCP process exited before its response")
                response = json.loads(response_line)
                self.assertEqual(response["id"], 1)
                self.assertEqual(response["result"]["serverInfo"]["name"], "context-guard-receipt")
                self.assertIsNone(process.poll())
            finally:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                process.wait(timeout=20)
                stderr = process.stderr.read() if process.stderr is not None else ""
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
