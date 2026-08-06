from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from contract.test_g001_distribution_contract import (
    EVIDENCE_BOUNDARY,
    EXPECTED_BOUNDARY_RESPONSE,
    EXPECTED_RUNTIME_MODES,
    NODE,
    PACKAGE_ROOT,
    PYTHON_ENV,
    canonical_json,
    process_exists,
    read_child_record,
    wait_for_process_exit,
)


NPM = shutil.which("npm")
GIT = shutil.which("git")


def run_command(
    command: list[str], *, cwd: Path, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_binary_command(
    command: list[str], *, cwd: Path, environment: dict[str, str], input_bytes: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def capture_frame(sequence: int, channel: int, payload: bytes) -> bytes:
    return (
        sequence.to_bytes(8, "big")
        + channel.to_bytes(1, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


def twin_request(private_relative_path: str) -> bytes:
    return canonical_json(
        {
            "declared_next_action_sha256": "a" * 64,
            "expected_tail": None,
            "predicates": [
                {"kind": "path_absent", "relative_path": private_relative_path}
            ],
            "schema_version": "contextguard-receipt-twin-request/v1",
        }
    ).encode("ascii")


class G001OfflineDistributionTests(unittest.TestCase):
    def test_tarball_installs_offline_and_ignores_poisoned_contextguard_helpers(self) -> None:
        """Break caught: checkout imports, registry/helper dependence, or unsafe tar contents."""
        if not (PACKAGE_ROOT / "package.json").is_file():
            raise AssertionError(f"G001 distribution is missing: {PACKAGE_ROOT / 'package.json'}")
        if NODE is None or NPM is None or GIT is None:
            raise AssertionError(
                "Node.js, npm, and Git are required for offline distribution verification"
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            pack_directory = temporary_root / "pack"
            install_directory = temporary_root / "install"
            poisoned_bin = temporary_root / "poisoned-bin"
            pack_directory.mkdir()
            install_directory.mkdir()
            poisoned_bin.mkdir()

            packed = run_command(
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
            )
            self.assertEqual(packed.returncode, 0, packed.stderr)
            records = json.loads(packed.stdout)
            self.assertIsInstance(records, list)
            self.assertEqual(len(records), 1)
            tarball = pack_directory / records[0]["filename"]
            self.assertTrue(tarball.is_file())

            expected_tar_modes = {
                f"package/{path}": mode for path, mode in EXPECTED_RUNTIME_MODES.items()
            }
            with tarfile.open(tarball, "r:gz") as archive:
                members = [member for member in archive.getmembers() if member.isfile() or member.issym()]
                self.assertFalse(any(member.issym() for member in members))
                actual_tar_modes = {
                    member.name: stat.S_IMODE(member.mode)
                    for member in members
                    if member.isfile()
                }
            self.assertEqual(actual_tar_modes, expected_tar_modes)

            installed = run_command(
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
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            installed_root = (
                install_directory / "node_modules/@ictechgy/context-guard-receipt"
            )
            self.assertFalse(installed_root.is_symlink())
            installed_root = installed_root.resolve()
            receipt_bin = installed_root / "bin/context-guard-receipt.cjs"
            mcp_bin = installed_root / "bin/context-guard-receipt-mcp.cjs"
            self.assertTrue(receipt_bin.is_file())
            self.assertTrue(mcp_bin.is_file())

            foundation_smoke = run_command(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import sys; sys.path.insert(0, sys.argv[1]); "
                        "from context_guard_receipt.canonical import canonical_json_bytes; "
                        "from context_guard_receipt.identity import IdentityLimits; "
                        "from context_guard_receipt.protection import decide_protection; "
                        "from context_guard_receipt.store import predicted_capability_bytes; "
                        "assert canonical_json_bytes({'b': 2, 'a': 1}) == "
                        "b'{\"a\":1,\"b\":2}\\n'; "
                        "decision = decide_protection(b'raw\\x00\\xff', 'protected'); "
                        "assert decision.exact_bytes == b'raw\\x00\\xff'; "
                        "assert IdentityLimits().max_file_bytes == 1048576; "
                        "assert predicted_capability_bytes(2) == 98"
                    ),
                    str(installed_root / "python"),
                ],
                cwd=install_directory,
                environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(foundation_smoke.returncode, 0, foundation_smoke.stderr)
            self.assertEqual(foundation_smoke.stdout, "")

            sanitizer_smoke = run_command(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import sys\n"
                        "from pathlib import Path\n"
                        "installed = Path(sys.argv[1]).resolve()\n"
                        "sys.path.insert(0, str(installed))\n"
                        "from context_guard_receipt import sanitizer\n"
                        "candidate = b'api_key=synthetic-test-value'\n"
                        "whole = sanitizer.sanitize_bytes(candidate)\n"
                        "stream = sanitizer.StreamingSanitizer()\n"
                        "stream.feed(candidate[:7])\n"
                        "stream.feed(candidate[7:])\n"
                        "split = stream.finish()\n"
                        "bytewise = sanitizer.StreamingSanitizer()\n"
                        "for byte in candidate:\n"
                        " bytewise.feed(bytes((byte,)))\n"
                        "assert whole.payload == split.payload == bytewise.finish().payload == b'[REDACTED SECRET]'\n"
                        "try:\n"
                        " sanitizer.sanitize_bytes(b'opaque-probe', limits=sanitizer.SanitizerLimits(max_input_bytes=0))\n"
                        "except sanitizer.SanitizationError as error:\n"
                        " assert error.code is sanitizer.SanitizationErrorCode.INPUT_LIMIT_EXCEEDED\n"
                        " assert 'opaque-probe' not in str(error)\n"
                        " assert 'opaque-probe' not in repr(error)\n"
                        "else:\n"
                        " raise AssertionError('expected sanitizer input failure')\n"
                        "assert Path(sanitizer.__file__).resolve().is_relative_to(installed)"
                    ),
                    str(installed_root / "python"),
                ],
                cwd=install_directory,
                environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(sanitizer_smoke.returncode, 0, sanitizer_smoke.stderr)
            self.assertEqual(sanitizer_smoke.stdout, "")

            sentinel = temporary_root / "helper-was-executed"
            for helper_name in (
                "context-guard",
                "context-guard-mcp",
                "context-guard-pack",
                "context-guard-read-symbol",
                "context-guard-tool-prune",
                "python",
                "python3",
            ):
                helper = poisoned_bin / helper_name
                helper.write_text(
                    f"#!/bin/sh\ntouch '{sentinel}'\nexit 99\n",
                    encoding="utf-8",
                )
                helper.chmod(0o755)

            environment = {
                "LANG": "C",
                "PATH": os.pathsep.join(
                    (str(poisoned_bin), str(Path(GIT).resolve().parent))
                ),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                PYTHON_ENV: str(Path(sys.executable).resolve()),
            }
            response = run_command(
                [str(Path(NODE).resolve()), str(receipt_bin), "inspect", "boundary"],
                cwd=install_directory,
                environment=environment,
            )
            self.assertEqual(response.returncode, 0, response.stderr)
            self.assertEqual(response.stdout, canonical_json(EXPECTED_BOUNDARY_RESPONSE))
            self.assertEqual(response.stderr, "")
            self.assertFalse(sentinel.exists())

            repository_root = (temporary_root / "repository").resolve()
            repository_root.mkdir(mode=0o700)
            payload = (b"expand\x00\xff" * 2_048) + b"done"
            (repository_root / "source.bin").write_bytes(payload)
            state_directory = (temporary_root / "private-state").resolve()

            command_repository_root = (temporary_root / "command-repository").resolve()
            command_repository_root.mkdir(mode=0o700)
            initialized = run_command(
                [str(Path(GIT).resolve()), "init", "--quiet", str(command_repository_root)],
                cwd=temporary_root,
                environment={
                    "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "LANG": "C",
                    "PATH": os.defpath,
                },
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            command_state_directory = (temporary_root / "command-state").resolve()
            command_stdout = b"SAFE_OUTPUT\n"
            private_arguments = (
                b"synthetic-private-secret-g008",
                b"synthetic-private-argv-g008",
                b"synthetic-private-path-g008",
            )
            command_program = (
                "import os,sys; "
                "os.write(1,bytes.fromhex('534146455f4f55545055540a')); "
                "os.write(2,sys.argv[1].encode('ascii'))"
            )
            captured = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "run",
                    "--escrow",
                    "--root",
                    str(command_repository_root),
                    "--state-dir",
                    str(command_state_directory),
                    "--",
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    command_program,
                    *(value.decode("ascii") for value in private_arguments),
                ],
                cwd=install_directory,
                environment=environment,
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
            self.assertEqual(captured.stderr, b"")
            receipt = json.loads(captured.stdout)
            self.assertEqual(captured.stdout, canonical_json(receipt).encode("ascii"))
            self.assertRegex(receipt["handle"], r"^cgr1p_[A-Za-z0-9_-]{43}$")
            self.assertEqual(
                set(receipt["observation"]),
                {"after_sha256", "before_sha256", "scope"},
            )
            self.assertEqual(receipt["observation"]["scope"], "worktree")
            self.assertEqual(
                receipt["stderr"],
                {
                    "argument_derived_output_redacted": True,
                    "excerpt": "",
                    "frame_count": 0,
                    "sanitized_bytes": 0,
                },
            )
            self.assertTrue(
                all(value not in captured.stdout for value in private_arguments),
                "receipt reflected a private test input",
            )
            private_paths = (
                str(command_repository_root).encode(),
                str(command_state_directory).encode(),
            )
            self.assertTrue(
                all(value not in captured.stdout for value in private_paths),
                "receipt reflected a private test path",
            )

            receipt_validator = run_binary_command(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import json,sys\n"
                        "from pathlib import Path\n"
                        "installed = Path(sys.argv[1]).resolve()\n"
                        "sys.path.insert(0, str(installed))\n"
                        "from context_guard_receipt import runner\n"
                        "receipt = json.loads(sys.stdin.buffer.read())\n"
                        "assert runner.validate_command_capture_receipt(receipt)\n"
                        "assert Path(runner.__file__).resolve().is_relative_to(installed)\n"
                    ),
                    str(installed_root / "python"),
                ],
                cwd=install_directory,
                environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                input_bytes=captured.stdout,
            )
            self.assertEqual(receipt_validator.returncode, 0, receipt_validator.stderr)
            self.assertEqual(receipt_validator.stdout, b"")

            (command_repository_root / "after-capture.txt").write_text(
                "worktree drift after capture\n", encoding="utf-8"
            )
            command_expanded = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "expand",
                    receipt["handle"],
                    "--root",
                    str(command_repository_root),
                    "--state-dir",
                    str(command_state_directory),
                    "--emit",
                    "bytes",
                ],
                cwd=install_directory,
                environment=environment,
            )
            expected_capture = (
                b"CGRF1\x00"
                + capture_frame(0, 1, command_stdout)
            )
            self.assertEqual(command_expanded.returncode, 0, command_expanded.stderr)
            self.assertEqual(command_expanded.stderr, b"")
            self.assertEqual(command_expanded.stdout, expected_capture)
            self.assertTrue(
                all(value not in command_expanded.stdout for value in private_arguments),
                "expanded capture reflected a private test input",
            )
            self.assertFalse(sentinel.exists())

            frame_validator = run_binary_command(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import sys\n"
                        "from pathlib import Path\n"
                        "installed = Path(sys.argv[1]).resolve()\n"
                        "sys.path.insert(0, str(installed))\n"
                        "from context_guard_receipt.runner import validate_framed_capture\n"
                        "frames = validate_framed_capture(sys.stdin.buffer.read())\n"
                        "assert tuple(frame.channel for frame in frames) == (1,)\n"
                    ),
                    str(installed_root / "python"),
                ],
                cwd=install_directory,
                environment={"LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"},
                input_bytes=command_expanded.stdout,
            )
            self.assertEqual(frame_validator.returncode, 0, frame_validator.stderr)
            self.assertEqual(frame_validator.stdout, b"")

            delivery_marker = "synthetic-private-installed-delivery-g008"
            delivery_state = (temporary_root / "delivery-state").resolve()
            delivery_process = subprocess.Popen(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "run",
                    "--escrow",
                    "--root",
                    str(command_repository_root),
                    "--state-dir",
                    str(delivery_state),
                    "--",
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    "import time; time.sleep(0.2)",
                    delivery_marker,
                ],
                cwd=install_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertIsNotNone(delivery_process.stdout)
            self.assertIsNotNone(delivery_process.stderr)
            delivery_process.stdout.close()
            delivery_process.stdout = None
            delivery_stderr = delivery_process.stderr.read()
            delivery_process.stderr.close()
            self.assertEqual(delivery_process.wait(timeout=8), 74, delivery_stderr)
            expected_delivery_failure = canonical_json(
                {
                    "evidence_boundary": EVIDENCE_BOUNDARY,
                    "operation": "launcher",
                    "reason": "delivery_failure",
                    "schema_version": "contextguard-receipt-cli-response/v1",
                    "status": "error",
                }
            ).encode("ascii")
            self.assertEqual(delivery_stderr, expected_delivery_failure)
            self.assertNotIn(delivery_marker.encode("ascii"), delivery_stderr)
            self.assertNotIn(b"cgr1p_", delivery_stderr)

            interrupt_record = temporary_root / "installed-interrupt-child"
            interrupt_state = (temporary_root / "installed-interrupt-state").resolve()
            interrupted = subprocess.Popen(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "run",
                    "--escrow",
                    "--root",
                    str(command_repository_root),
                    "--state-dir",
                    str(interrupt_state),
                    "--",
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    (
                        "import os,time; "
                        f"open({str(interrupt_record)!r},'w',encoding='ascii').write("
                        "f'{os.getpid()}:{os.getppid()}'); "
                        "time.sleep(60)"
                    ),
                ],
                cwd=install_directory,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            child_pid = 0
            python_pid = 0
            try:
                child_pid, python_pid = read_child_record(interrupt_record)
                interrupted.send_signal(signal.SIGTERM)
                interrupted_stdout, interrupted_stderr = interrupted.communicate(timeout=8)
                self.assertEqual(interrupted.returncode, 128 + signal.SIGTERM)
                self.assertEqual(interrupted_stdout, b"")
                self.assertEqual(interrupted_stderr, b"")
                self.assertTrue(wait_for_process_exit(child_pid))
                self.assertFalse(interrupt_state.exists())
            finally:
                if interrupted.poll() is None:
                    interrupted.kill()
                    interrupted.wait(timeout=3)
                for pid in (child_pid, python_pid):
                    if pid > 0 and process_exists(pid):
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

            descriptor = json.dumps(
                {
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
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            assembled = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "assemble",
                    "--kind",
                    "evidence",
                    "--descriptor",
                    "-",
                    "--root",
                    str(repository_root),
                    "--state-dir",
                    str(state_directory),
                    "--persist",
                    "--emit",
                    "bytes",
                ],
                cwd=install_directory,
                environment=environment,
                input_bytes=descriptor,
            )
            self.assertEqual(assembled.returncode, 0, assembled.stderr)
            self.assertEqual(assembled.stderr, b"")
            artifact = json.loads(assembled.stdout)
            self.assertEqual(artifact["artifact_kind"], "evidence_reference")
            expanded = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "expand",
                    artifact["capability"],
                    "--root",
                    str(repository_root),
                    "--state-dir",
                    str(state_directory),
                    "--emit",
                    "bytes",
                ],
                cwd=install_directory,
                environment=environment,
            )
            self.assertEqual(expanded.returncode, 0, expanded.stderr)
            self.assertEqual(expanded.stdout, payload)
            self.assertEqual(expanded.stderr, b"")
            self.assertFalse(sentinel.exists())

            tool_catalog = [
                {
                    "description": "inline" * 800,
                    "input_schema": {"type": "object"},
                    "name": "inline",
                },
                {
                    "description": "deferred" * 800,
                    "input_schema": {"type": "object"},
                    "name": "deferred",
                },
            ]
            tool_payload = json.dumps(
                tool_catalog,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            tool_descriptor = json.dumps(
                {
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
                    "payload_b64u": base64.urlsafe_b64encode(tool_payload)
                    .rstrip(b"=")
                    .decode("ascii"),
                    "retain_count": 1,
                    "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            tool_assembled = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "assemble",
                    "--kind",
                    "tool-schemas",
                    "--descriptor",
                    "-",
                    "--root",
                    str(repository_root),
                    "--state-dir",
                    str(state_directory),
                    "--persist",
                    "--emit",
                    "bytes",
                ],
                cwd=install_directory,
                environment=environment,
                input_bytes=tool_descriptor,
            )
            self.assertEqual(tool_assembled.returncode, 0, tool_assembled.stderr)
            tool_bundle = json.loads(tool_assembled.stdout)
            self.assertEqual(tool_bundle["artifact_kind"], "tool_schema_bundle")

            def expand_tool(item_reference: object) -> subprocess.CompletedProcess[bytes]:
                request = json.dumps(
                    {
                        "catalog_reference": tool_bundle["catalog_reference"],
                        "item_reference": item_reference,
                        "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8") + b"\n"
                return run_binary_command(
                    [
                        str(Path(NODE).resolve()),
                        str(receipt_bin),
                        "expand",
                        "tool-schema",
                        "--request",
                        "-",
                        "--root",
                        str(repository_root),
                        "--state-dir",
                        str(state_directory),
                        "--emit",
                        "bytes",
                    ],
                    cwd=install_directory,
                    environment=environment,
                    input_bytes=request,
                )

            whole_catalog = expand_tool(None)
            deferred_schema = expand_tool(tool_bundle["deferred"][0])
            expected_schema = json.dumps(
                tool_catalog[1],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self.assertEqual(whole_catalog.returncode, 0, whole_catalog.stderr)
            self.assertEqual(whole_catalog.stdout, tool_payload)
            self.assertEqual(deferred_schema.returncode, 0, deferred_schema.stderr)
            self.assertEqual(deferred_schema.stdout, expected_schema)
            self.assertFalse(sentinel.exists())

            mcp_help = run_command(
                [str(Path(NODE).resolve()), str(mcp_bin), "--help"],
                cwd=install_directory,
                environment=environment,
            )
            self.assertEqual(mcp_help.returncode, 0, mcp_help.stderr)
            self.assertIn("--root", mcp_help.stdout)
            self.assertEqual(mcp_help.stderr, "")

            twin_directories_before_mcp = tuple(temporary_root.rglob("twin-v1"))
            self.assertEqual(
                twin_directories_before_mcp,
                (),
                "an ordinary installed surface created twin state",
            )
            mcp_input = b"".join(
                canonical_json(message).encode("ascii")
                for message in (
                    {
                        "id": 1,
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {
                            "capabilities": {},
                            "clientInfo": {"name": "g001-e2e", "version": "1"},
                            "protocolVersion": "2025-11-25",
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                    {
                        "id": 2,
                        "jsonrpc": "2.0",
                        "method": "tools/list",
                        "params": {},
                    },
                )
            )
            mcp_started = run_binary_command(
                [str(Path(NODE).resolve()), str(mcp_bin), "--root", str(repository_root)],
                cwd=install_directory,
                environment=environment,
                input_bytes=mcp_input,
            )
            self.assertEqual(mcp_started.returncode, 0, mcp_started.stderr)
            self.assertEqual(mcp_started.stderr, b"")
            mcp_responses = [json.loads(line) for line in mcp_started.stdout.splitlines()]
            self.assertEqual([response["id"] for response in mcp_responses], [1, 2])
            self.assertEqual(
                [tool["name"] for tool in mcp_responses[1]["result"]["tools"]],
                [
                    "receipt_assemble",
                    "receipt_expand",
                    "receipt_inspect",
                    "receipt_tool_select",
                ],
            )
            self.assertEqual(
                tuple(temporary_root.rglob("twin-v1")),
                twin_directories_before_mcp,
                "ordinary MCP startup created twin state",
            )
            self.assertFalse(sentinel.exists())

            twin_repository_root = (temporary_root / "twin-repository").resolve()
            twin_state_directory = (temporary_root / "twin-state").resolve()
            twin_repository_root.mkdir(mode=0o700)
            private_relative_path = "synthetic-private-installed-twin-g010.txt"
            twin_appended = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "inspect",
                    "twin",
                    "--experimental-twin",
                    "--input",
                    "-",
                    "--root",
                    str(twin_repository_root),
                    "--state-dir",
                    str(twin_state_directory),
                ],
                cwd=install_directory,
                environment=environment,
                input_bytes=twin_request(private_relative_path),
            )
            self.assertEqual(twin_appended.returncode, 0, twin_appended.stderr)
            self.assertEqual(twin_appended.stderr, b"")
            twin_result = json.loads(twin_appended.stdout)
            self.assertEqual(
                twin_appended.stdout, canonical_json(twin_result).encode("ascii")
            )
            self.assertEqual(twin_result["event_sequence"], 1)

            twin_inspected = run_binary_command(
                [
                    str(Path(NODE).resolve()),
                    str(receipt_bin),
                    "inspect",
                    "twin",
                    "--experimental-twin",
                    "--root",
                    str(twin_repository_root),
                    "--state-dir",
                    str(twin_state_directory),
                    "--limit",
                    "1",
                ],
                cwd=install_directory,
                environment=environment,
            )
            self.assertEqual(twin_inspected.returncode, 0, twin_inspected.stderr)
            self.assertEqual(twin_inspected.stderr, b"")
            twin_snapshot = json.loads(twin_inspected.stdout)
            self.assertEqual(
                twin_inspected.stdout, canonical_json(twin_snapshot).encode("ascii")
            )
            self.assertEqual(twin_snapshot["committed_event_count"], 1)
            self.assertEqual(len(twin_snapshot["latest_events"]), 1)
            for payload in (twin_result, twin_snapshot):
                self.assertEqual(payload["evidence_boundary"], EVIDENCE_BOUNDARY)
                for authority_field in (
                    "applied",
                    "execution_authority",
                    "global_completeness_authority",
                    "provider_claim_authority",
                ):
                    self.assertIs(payload[authority_field], False)
            for private_value in (
                private_relative_path.encode("ascii"),
                str(twin_repository_root).encode(),
                str(twin_state_directory).encode(),
            ):
                self.assertNotIn(private_value, twin_appended.stdout)
                self.assertNotIn(private_value, twin_inspected.stdout)
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
