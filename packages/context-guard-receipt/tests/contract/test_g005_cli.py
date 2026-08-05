from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
NODE = shutil.which("node")
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import canonical_json_bytes, parse_canonical_json_bytes
from context_guard_receipt.assembly import DESCRIPTOR_LIMITS
from context_guard_receipt import cli as cli_module
from context_guard_receipt import contracts
from context_guard_receipt.cli_io import CliIOError, write_receipt


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def evidence_descriptor(
    payload: bytes,
    relative_path: str,
    *,
    classification: str = "eligible",
    detector_signals: tuple[str, ...] = (),
) -> bytes:
    return canonical_json_bytes(
        {
            "caller_classification": classification,
            "detector_signals": list(detector_signals),
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": relative_path,
                "selection": {"kind": "file"},
            },
        },
        limits=DESCRIPTOR_LIMITS,
    )


def run_cli(*arguments: str, input_bytes: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    environment = {
        "LANG": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    return subprocess.run(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-B",
            str(BOOTSTRAP),
            "receipt",
            *arguments,
        ],
        cwd=PACKAGE_ROOT,
        env=environment,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_node_cli(*arguments: str, input_bytes: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    if NODE is None:
        raise AssertionError("Node.js is required to exercise the package entrypoint")
    environment = {
        "LANG": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "CONTEXT_GUARD_RECEIPT_PYTHON": str(Path(sys.executable).resolve()),
    }
    return subprocess.run(
        [str(Path(NODE).resolve()), str(PACKAGE_ROOT / "bin/context-guard-receipt.cjs"), *arguments],
        cwd=PACKAGE_ROOT,
        env=environment,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class G005CliTests(unittest.TestCase):
    def test_json_output_uses_a_fresh_immutable_evidence_boundary(self) -> None:
        """Break caught: a mutated compatibility export forges CLI evidence authority."""

        original = dict(contracts.EVIDENCE_BOUNDARY)
        captured: list[bytes] = []
        try:
            contracts.EVIDENCE_BOUNDARY["provider_claim_authority"] = True
            contracts.EVIDENCE_BOUNDARY["stage2_evidence"] = True
            with mock.patch.object(cli_module, "write_stdout", side_effect=captured.append):
                cli_module._emit_payload(
                    b"value", operation="assemble", emit="json", receipt=None
                )
        finally:
            contracts.EVIDENCE_BOUNDARY.clear()
            contracts.EVIDENCE_BOUNDARY.update(original)

        self.assertEqual(len(captured), 1)
        envelope = parse_canonical_json_bytes(captured[0], limits=DESCRIPTOR_LIMITS)
        self.assertEqual(envelope["evidence_boundary"], contracts.evidence_boundary())

    def test_node_entrypoint_forwards_binary_stdin_and_stdout_exactly(self) -> None:
        """Break caught: the Node launcher text-decodes a binary descriptor or output."""

        payload = (b"node-stdin\x00\xff\r\n" * 1_024) + b"tail"
        with tempfile.TemporaryDirectory() as directory:
            root = (Path(directory) / "repository").resolve()
            root.mkdir(mode=0o700)
            (root / "source.bin").write_bytes(payload)
            response = run_node_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--emit",
                "bytes",
                input_bytes=evidence_descriptor(payload, "source.bin"),
            )

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stdout, payload)
        self.assertEqual(response.stderr, b"")

    def test_nonpersistent_stdin_assembly_is_exact_binary_pass_through(self) -> None:
        """Break caught: the CLI corrupts bytes or creates state without opt-in."""

        payload = (b"raw\x00\xff\r\n" * 1_024) + b"tail"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            (root / "source.bin").write_bytes(payload)
            state_dir = base / "private-state"
            response = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--emit",
                "bytes",
                input_bytes=evidence_descriptor(payload, "source.bin"),
            )

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stdout, payload)
        self.assertEqual(response.stderr, b"")
        self.assertFalse(state_dir.exists())

    def test_persistent_assembly_and_capability_only_expansion_round_trip_exact_bytes(self) -> None:
        """Break caught: persisted references cannot rehydrate through the public CLI."""

        payload = (b"expand\x00\xff" * 2_048) + b"done"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            (root / "source.bin").write_bytes(payload)
            state_dir = base / "private-state"
            assembled = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--persist",
                "--emit",
                "bytes",
                input_bytes=evidence_descriptor(payload, "source.bin"),
            )
            self.assertEqual(assembled.returncode, 0, assembled.stderr)
            artifact = parse_canonical_json_bytes(assembled.stdout)
            expanded = run_cli(
                "expand",
                artifact["capability"],
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--emit",
                "bytes",
            )

        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        self.assertEqual(assembled.stderr, b"")
        self.assertEqual(artifact["artifact_kind"], "evidence_reference")
        self.assertEqual(expanded.returncode, 0, expanded.stderr)
        self.assertEqual(expanded.stdout, payload)
        self.assertEqual(expanded.stderr, b"")

    def test_persist_flag_creates_no_state_when_a_pre_store_gate_bypasses(self) -> None:
        """Break caught: CLI setup mutates disk before threshold/protection decisions."""

        cases = ((b"s" * 511, "eligible"), (b"p" * 8_192, "protected"))
        for payload, classification in cases:
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = base / "repository"
                root.mkdir(mode=0o700)
                (root / "source.bin").write_bytes(payload)
                state_dir = base / "private-state"
                response = run_cli(
                    "assemble",
                    "--kind",
                    "evidence",
                    "--descriptor",
                    "-",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state_dir),
                    "--persist",
                    "--emit",
                    "bytes",
                    input_bytes=evidence_descriptor(
                        payload, "source.bin", classification=classification
                    ),
                )

                self.assertEqual(response.returncode, 0, response.stderr)
                self.assertEqual(response.stdout, payload)
                self.assertFalse(state_dir.exists())

    def test_receipt_failure_preserves_the_complete_persistent_artifact_on_stdout(self) -> None:
        """Break caught: a failed sidecar write strands an undisclosed capability."""

        payload = b"persist" * 2_048
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            (root / "source.bin").write_bytes(payload)
            state_dir = base / "private-state"
            receipt_path = base / "receipt.json"
            receipt_path.write_bytes(b"existing")
            response = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--persist",
                "--emit",
                "bytes",
                "--receipt-out",
                str(receipt_path),
                input_bytes=evidence_descriptor(payload, "source.bin"),
            )

            self.assertEqual(response.returncode, 74, response.stderr)
            artifact = parse_canonical_json_bytes(response.stdout)
            self.assertEqual(artifact["artifact_kind"], "evidence_reference")
            self.assertEqual(receipt_path.read_bytes(), b"existing")
            error = json.loads(response.stderr)
            self.assertEqual(error["reason"], "receipt_unwritable")
            expanded = run_cli(
                "expand",
                artifact["capability"],
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--emit",
                "bytes",
            )
            self.assertEqual(expanded.returncode, 0, expanded.stderr)
            self.assertEqual(expanded.stdout, payload)

    def test_receipt_write_failure_removes_only_the_new_partial_file(self) -> None:
        """Break caught: a failed private receipt blocks safe retry with partial bytes."""

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "receipt.json"
            with mock.patch(
                "context_guard_receipt.cli_io.os.fsync",
                side_effect=OSError("injected"),
            ):
                with self.assertRaises(CliIOError) as caught:
                    write_receipt(str(target), b'{"safe":true}\n')
            self.assertEqual(caught.exception.code, "receipt_unwritable")
            self.assertFalse(target.exists())

            write_receipt(str(target), b'{"safe":true}\n')
            self.assertEqual(target.read_bytes(), b'{"safe":true}\n')

    def test_secret_refusal_and_stale_expansion_never_write_payload_to_stdout(self) -> None:
        """Break caught: a closed refusal leaks secret or stale source bytes."""

        payload = b"secret material" * 1_024
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            source = root / "source.bin"
            source.write_bytes(payload)
            state_dir = base / "private-state"
            secret = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--emit",
                "bytes",
                input_bytes=evidence_descriptor(
                    payload, "source.bin", detector_signals=("secret",)
                ),
            )
            issued = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--persist",
                "--emit",
                "bytes",
                input_bytes=evidence_descriptor(payload, "source.bin"),
            )
            self.assertEqual(issued.returncode, 0, issued.stderr)
            capability = parse_canonical_json_bytes(issued.stdout)["capability"]
            source.write_bytes(b"changed" * 2_048)
            stale = run_cli(
                "expand",
                capability,
                "--root",
                str(root),
                "--state-dir",
                str(state_dir),
                "--emit",
                "bytes",
            )

        for response in (secret, stale):
            self.assertNotEqual(response.returncode, 0)
            self.assertEqual(response.stdout, b"")
            error = json.loads(response.stderr)
            self.assertIn(error["status"], {"refused", "stale"})
            self.assertNotIn(payload, response.stderr)
            self.assertNotIn(b"source.bin", response.stderr)

    def test_named_descriptor_is_bounded_regular_nonsymlink_and_errors_are_nonreflective(self) -> None:
        """Break caught: descriptor I/O follows links or reflects private caller data."""

        marker = b"DO-NOT-REFLECT-PRIVATE-MARKER"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            target = base / "descriptor.json"
            target.write_bytes(marker)
            linked = base / "linked.json"
            linked.symlink_to(target)
            response = run_cli(
                "assemble",
                "--kind",
                "evidence",
                "--descriptor",
                str(linked),
                "--root",
                str(root),
                "--emit",
                "bytes",
            )

        self.assertNotEqual(response.returncode, 0)
        self.assertEqual(response.stdout, b"")
        self.assertNotIn(marker, response.stderr)
        self.assertNotIn(os.fsencode(str(linked)), response.stderr)
        error = json.loads(response.stderr)
        self.assertEqual(error["operation"], "assemble")


if __name__ == "__main__":
    unittest.main()
