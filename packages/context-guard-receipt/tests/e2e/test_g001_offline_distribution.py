from __future__ import annotations

import base64
import json
import os
import shutil
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
)


NPM = shutil.which("npm")


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


class G001OfflineDistributionTests(unittest.TestCase):
    def test_tarball_installs_offline_and_ignores_poisoned_contextguard_helpers(self) -> None:
        """Break caught: checkout imports, registry/helper dependence, or unsafe tar contents."""
        if not (PACKAGE_ROOT / "package.json").is_file():
            raise AssertionError(f"G001 distribution is missing: {PACKAGE_ROOT / 'package.json'}")
        if NODE is None or NPM is None:
            raise AssertionError("Node.js and npm are required for offline distribution verification")

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
                "PATH": str(poisoned_bin),
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

            mcp_unavailable = run_command(
                [str(Path(NODE).resolve()), str(mcp_bin), "--root", str(install_directory)],
                cwd=install_directory,
                environment=environment,
            )
            expected_mcp = {
                "evidence_boundary": EVIDENCE_BOUNDARY,
                "operation": "mcp",
                "reason": "feature_not_available",
                "schema_version": "contextguard-receipt-cli-response/v1",
                "status": "unavailable",
            }
            self.assertEqual(mcp_unavailable.returncode, 69, mcp_unavailable.stderr)
            self.assertEqual(mcp_unavailable.stdout, "")
            self.assertEqual(mcp_unavailable.stderr, canonical_json(expected_mcp))
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
