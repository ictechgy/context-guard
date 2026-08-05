from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
NODE = shutil.which("node")
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.canonical import canonical_json_bytes
from context_guard_receipt import cli as cli_module
from context_guard_receipt.contracts import EVIDENCE_BOUNDARY
from context_guard_receipt.diagnostic_ledger import DiagnosticLedger
from context_guard_receipt.store import ArtifactType, CapabilityStore, StoreError


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def diagnostic_request(
    payload: bytes = b"x" * 4096,
    *,
    current_prefix: bytes = b"stable-prefix" * 64,
    previous_prefix: bytes | None = b"stable-prefix" * 64,
) -> bytes:
    return canonical_json_bytes(
        {
            "blueprint_b64u": "",
            "caller_classification": "eligible",
            "current_prefix_b64u": b64url(current_prefix),
            "detector_signals": [],
            "handle_b64u": b64url(b"h" * 49),
            "input_b64u": b64url(payload),
            "mandatory_expansion_b64u": "",
            "previous_prefix_b64u": (
                None if previous_prefix is None else b64url(previous_prefix)
            ),
            "retained_wire_b64u": "",
            "schema_version": "contextguard-receipt-diagnostics-request/v1",
            "subject_kind": "evidence",
            "wrapper_b64u": b64url(b"w" * 128),
        }
    )


def run_cli(
    *arguments: str,
    input_bytes: bytes = b"",
    cwd: Path = PACKAGE_ROOT,
) -> subprocess.CompletedProcess[bytes]:
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
        cwd=cwd,
        env={
            "LANG": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_node_cli(
    *arguments: str,
    input_bytes: bytes = b"",
    cwd: Path = PACKAGE_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    if NODE is None:
        raise unittest.SkipTest("Node.js is required for distribution coverage")
    return subprocess.run(
        [
            str(Path(NODE).resolve()),
            str(PACKAGE_ROOT / "bin/context-guard-receipt.cjs"),
            *arguments,
        ],
        cwd=cwd,
        env={
            "CONTEXT_GUARD_RECEIPT_PYTHON": str(Path(sys.executable).resolve()),
            "LANG": "C",
            "PATH": os.defpath,
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class G009CliContractTests(unittest.TestCase):
    def test_packaged_node_entrypoint_runs_process_diagnostics_and_firewall(self) -> None:
        """Break caught: the launcher trust set omits the active diagnostics files."""

        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            diagnostics = run_node_cli(
                "inspect", "diagnostics", "--input", "-",
                input_bytes=diagnostic_request(), cwd=cwd,
            )
            firewall = run_node_cli(
                "inspect", "firewall", "--input", "-",
                input_bytes=diagnostic_request(), cwd=cwd,
            )
            self.assertEqual(list(cwd.iterdir()), [])

        self.assertEqual(diagnostics.returncode, 0, diagnostics.stderr)
        self.assertEqual(firewall.returncode, 0, firewall.stderr)
        self.assertEqual(
            json.loads(diagnostics.stdout)["schema_version"],
            "contextguard-receipt-diagnostics-report/v1",
        )
        self.assertEqual(
            json.loads(firewall.stdout)["schema_version"],
            "contextguard-receipt-shadow-firewall-finding/v1",
        )

    def test_process_diagnostics_are_canonical_unlinkable_and_state_free(self) -> None:
        """Break caught: advisory diagnostics remain reserved or create durable state."""

        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            first = run_cli(
                "inspect", "diagnostics", "--input", "-",
                input_bytes=diagnostic_request(), cwd=cwd,
            )
            second = run_cli(
                "inspect", "diagnostics", "--input", "-",
                input_bytes=diagnostic_request(), cwd=cwd,
            )
            self.assertEqual(list(cwd.iterdir()), [])

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stderr, b"")
        self.assertEqual(second.stderr, b"")
        first_report = json.loads(first.stdout)
        second_report = json.loads(second.stdout)
        self.assertEqual(first.stdout, canonical_json_bytes(first_report))
        self.assertEqual(first_report["schema_version"], "contextguard-receipt-diagnostics-report/v1")
        self.assertEqual(first_report["evidence_boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(first_report["state_scope"], "process")
        self.assertFalse(first_report["firewall"]["applied"])
        for field in (
            "provider_claim_authority",
            "provider_routing_authority",
            "live_observation_authority",
            "efficacy_claim_authority",
        ):
            self.assertIs(first_report[field], False)
        self.assertNotEqual(
            first_report["firewall"]["evidence_hmac_sha256"],
            second_report["firewall"]["evidence_hmac_sha256"],
        )

    def test_firewall_is_a_non_applying_process_local_projection(self) -> None:
        """Break caught: firewall diagnostics apply a route or expose durable options."""

        with tempfile.TemporaryDirectory() as directory:
            cwd = Path(directory).resolve()
            response = run_cli(
                "inspect", "firewall", "--input", "-",
                input_bytes=diagnostic_request(), cwd=cwd,
            )
            self.assertEqual(list(cwd.iterdir()), [])

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stderr, b"")
        finding = json.loads(response.stdout)
        self.assertEqual(response.stdout, canonical_json_bytes(finding))
        self.assertEqual(finding["evidence_boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(
            finding["schema_version"],
            "contextguard-receipt-shadow-firewall-finding/v1",
        )
        self.assertIs(finding["applied"], False)
        self.assertEqual(finding["subject_kind"], "evidence")

    def test_durable_grammar_is_all_or_nothing_and_firewall_rejects_state(self) -> None:
        """Break caught: partial opt-in silently creates or links diagnostic state."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state = base / "state"
            cases = (
                ("inspect", "diagnostics", "--input", "-", "--state-scope", "durable"),
                ("inspect", "diagnostics", "--input", "-", "--root", str(root), "--state-dir", str(state)),
                ("inspect", "firewall", "--input", "-", "--state-scope", "durable", "--root", str(root), "--state-dir", str(state)),
                ("inspect", "diagnostic-ledger", "--input", "-", "--state-scope", "durable", "--root", str(root), "--state-dir", str(state)),
            )
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    response = run_cli(*arguments, input_bytes=diagnostic_request())
                    self.assertEqual(response.returncode, 64)
                    self.assertEqual(response.stdout, b"")
                    self.assertNotIn(str(state).encode(), response.stderr)
                    self.assertFalse(state.exists())

    def test_invalid_input_is_nonreflective_and_creates_no_state(self) -> None:
        """Break caught: malformed diagnostics echo caller bytes or open state."""

        marker = b"synthetic-private-diagnostic-input"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state = base / "state"
            response = run_cli(
                "inspect", "diagnostics", "--input", "-",
                "--state-scope", "durable", "--root", str(root),
                "--state-dir", str(state), input_bytes=marker,
            )

        self.assertEqual(response.returncode, 65)
        self.assertEqual(response.stdout, b"")
        self.assertNotIn(marker, response.stderr)
        self.assertNotIn(str(state).encode(), response.stderr)
        self.assertFalse(state.exists())

    def test_descriptor_io_failures_are_not_misclassified_as_invalid_data(self) -> None:
        """Break caught: missing or oversized input is reported as malformed JSON."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            missing = run_cli(
                "inspect", "diagnostics", "--input", str(base / "missing.json"),
                "--state-scope", "durable", "--root", str(root),
                "--state-dir", str(state),
            )
            oversized = run_cli(
                "inspect", "diagnostics", "--input", "-",
                "--state-scope", "durable", "--root", str(root),
                "--state-dir", str(state), input_bytes=b"x" * (2 * 1024 * 1024 + 1),
            )

        for response in (missing, oversized):
            self.assertEqual(response.returncode, 74)
            self.assertEqual(response.stdout, b"")
            self.assertIn(b'"reason":"diagnostic_input_unavailable"', response.stderr)
            self.assertNotIn(str(state).encode(), response.stderr)
        self.assertFalse(state.exists())

    def test_durable_diagnostics_append_and_ledger_inspection_are_bounded(self) -> None:
        """Break caught: explicit durable advice cannot be inspected as a closed chain."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state = base / "state"
            analyzed = run_cli(
                "inspect", "diagnostics", "--input", "-",
                "--state-scope", "durable", "--root", str(root),
                "--state-dir", str(state), input_bytes=diagnostic_request(),
            )
            inspected = run_cli(
                "inspect", "diagnostic-ledger", "--state-scope", "durable",
                "--root", str(root), "--state-dir", str(state), "--limit", "1",
            )

        self.assertEqual(analyzed.returncode, 0, analyzed.stderr)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        report = json.loads(analyzed.stdout)
        ledger = json.loads(inspected.stdout)
        self.assertEqual(report["state_scope"], "durable")
        self.assertEqual(ledger["schema_version"], "contextguard-receipt-diagnostic-ledger-inspection/v1")
        self.assertEqual(ledger["entry_count"], 1)
        self.assertEqual(len(ledger["entries"]), 1)
        self.assertIs(ledger["recovery_required"], False)

    def test_uninitialized_ledger_inspection_does_not_create_state(self) -> None:
        """Break caught: read-only state discovery initializes a durable compartment."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state = base / "state"
            response = run_cli(
                "inspect", "diagnostic-ledger", "--state-scope", "durable",
                "--root", str(root), "--state-dir", str(state), "--limit", "1",
            )
            self.assertFalse(state.exists())

        self.assertEqual(response.returncode, 69)
        self.assertEqual(response.stdout, b"")
        self.assertNotIn(str(state).encode(), response.stderr)

    def test_raw_secret_never_appears_in_report_error_or_durable_files(self) -> None:
        """Break caught: diagnostic payload bytes leak into the report or ledger."""

        marker = b"synthetic-secret-diagnostic-marker"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            state = base / "state"
            response = run_cli(
                "inspect", "diagnostics", "--input", "-",
                "--state-scope", "durable", "--root", str(root),
                "--state-dir", str(state),
                input_bytes=diagnostic_request(marker * 128),
            )
            persisted = b"".join(
                path.read_bytes()
                for path in state.rglob("*")
                if path.is_file() and not path.is_symlink()
            ) if state.exists() else b""

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertNotIn(marker, response.stdout)
        self.assertNotIn(marker, response.stderr)
        self.assertNotIn(marker, persisted)
        self.assertNotIn(b64url(marker).encode("ascii"), persisted)

    def test_capability_store_roundtrips_while_known_auxiliary_is_present(self) -> None:
        """Break caught: the removable advisory axis makes store-v1 unavailable."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)

            with DiagnosticLedger.open(
                state_dir=str(state), repository_root=str(root), create=True
            ):
                pass
            capability = CapabilityStore.open(
                state_dir=str(state), repository_root=str(root), create=True
            )
            issued = capability.issue(
                payload=b"independent-store-payload",
                root_identity_sha256="1" * 64,
                subject_identity_sha256="2" * 64,
                artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            )
            capability.close()

            # Known diagnostics corruption belongs to the removable advisory axis.
            (state / "auxiliary-v1/diagnostics-v1/key").write_bytes(b"broken")
            reopened = CapabilityStore.open(
                state_dir=str(state), repository_root=str(root)
            )
            retrieved = reopened.retrieve(
                issued.handle,
                expected_namespace_id=issued.namespace_id,
                expected_root_identity_sha256="1" * 64,
                expected_subject_identity_sha256="2" * 64,
                expected_artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            )
            reopened.close()

            self.assertEqual(retrieved.payload, b"independent-store-payload")

    def test_capability_store_rejects_unknown_or_drifted_auxiliary_boundary(self) -> None:
        """Break caught: an unknown auxiliary version is silently trusted."""

        mutations = {
            "metadata": lambda state: (
                state / "auxiliary-v1/metadata.json"
            ).write_bytes(canonical_json_bytes({"schema_version": "unknown/v1"})),
            "sibling": lambda state: (
                state / "auxiliary-v1/unknown-v1"
            ).mkdir(mode=0o700),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = base / "repository"
                state = base / "state"
                root.mkdir(mode=0o700)
                with DiagnosticLedger.open(
                    state_dir=str(state), repository_root=str(root), create=True
                ):
                    pass
                capability = CapabilityStore.open(
                    state_dir=str(state), repository_root=str(root), create=True
                )
                capability.close()
                mutate(state)

                with self.assertRaises(StoreError):
                    CapabilityStore.open(
                        state_dir=str(state), repository_root=str(root)
                    )

    def test_removing_auxiliary_preserves_capability_store_roundtrip(self) -> None:
        """Break caught: store-v1 depends on auxiliary keys or namespaces."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            capability = CapabilityStore.open(
                state_dir=str(state), repository_root=str(root), create=True
            )
            issued = capability.issue(
                payload=b"survives-removal",
                root_identity_sha256="1" * 64,
                subject_identity_sha256="2" * 64,
                artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            )
            capability.close()
            with DiagnosticLedger.open(
                state_dir=str(state), repository_root=str(root), create=True
            ):
                pass
            shutil.rmtree(state / "auxiliary-v1")

            reopened = CapabilityStore.open(
                state_dir=str(state), repository_root=str(root)
            )
            retrieved = reopened.retrieve(
                issued.handle,
                expected_namespace_id=issued.namespace_id,
                expected_root_identity_sha256="1" * 64,
                expected_subject_identity_sha256="2" * 64,
                expected_artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            )
            reopened.close()

            self.assertEqual(retrieved.payload, b"survives-removal")

    def test_durable_append_survives_stdout_delivery_failure(self) -> None:
        """Break caught: a committed advisory row is rolled back or duplicated on EPIPE."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            request_path = base / "request.json"
            root.mkdir(mode=0o700)
            request_path.write_bytes(diagnostic_request())
            stderr = io.StringIO()
            with mock.patch.object(
                cli_module, "write_stdout", side_effect=BrokenPipeError
            ), contextlib.redirect_stderr(stderr):
                exit_code = cli_module.receipt_main(
                    (
                        "inspect",
                        "diagnostics",
                        "--input",
                        str(request_path),
                        "--state-scope",
                        "durable",
                        "--root",
                        str(root),
                        "--state-dir",
                        str(state),
                    )
                )
            with DiagnosticLedger.open(
                state_dir=str(state), repository_root=str(root)
            ) as ledger:
                inspection = ledger.inspect(limit=1)

        self.assertEqual(exit_code, 74)
        self.assertEqual(inspection["entry_count"], 1)
        self.assertIn('"operation":"inspect_diagnostics"', stderr.getvalue())

    def test_firewall_delivery_failure_reports_the_exact_operation(self) -> None:
        """Break caught: process firewall errors are mislabeled as diagnostics."""

        with tempfile.TemporaryDirectory() as directory:
            request_path = Path(directory).resolve() / "request.json"
            request_path.write_bytes(diagnostic_request())
            stderr = io.StringIO()
            with mock.patch.object(
                cli_module, "write_stdout", side_effect=BrokenPipeError
            ), contextlib.redirect_stderr(stderr):
                exit_code = cli_module.receipt_main(
                    ("inspect", "firewall", "--input", str(request_path))
                )

        self.assertEqual(exit_code, 74)
        self.assertIn('"operation":"inspect_firewall"', stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
