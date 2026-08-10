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
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
NODE = shutil.which("node")
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt import cli as cli_module
from context_guard_receipt.canonical import canonical_json_bytes
from context_guard_receipt.contracts import EVIDENCE_BOUNDARY
from context_guard_receipt.diagnostic_ledger import DiagnosticLedger
from context_guard_receipt.diagnostics import DIAGNOSTICS_POLICY_SHA256
from context_guard_receipt.store import ArtifactType, CapabilityStore


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def twin_request(*, expected_tail: object = None) -> bytes:
    return canonical_json_bytes(
        {
            "declared_next_action_sha256": "a" * 64,
            "expected_tail": expected_tail,
            "predicates": [
                {
                    "kind": "path_absent",
                    "relative_path": "private-input-must-not-appear.txt",
                }
            ],
            "schema_version": "contextguard-receipt-twin-request/v1",
        }
    )


def diagnostic_request() -> bytes:
    return canonical_json_bytes(
        {
            "blueprint_b64u": "",
            "caller_classification": "eligible",
            "current_prefix_b64u": b64url(b"stable-prefix" * 64),
            "detector_signals": [],
            "handle_b64u": b64url(b"h" * 49),
            "input_b64u": b64url(b"x" * 4096),
            "mandatory_expansion_b64u": "",
            "previous_prefix_b64u": b64url(b"stable-prefix" * 64),
            "retained_wire_b64u": "",
            "schema_version": "contextguard-receipt-diagnostics-request/v1",
            "subject_kind": "evidence",
            "wrapper_b64u": b64url(b"w" * 128),
        }
    )


def tool_schema_descriptor() -> bytes:
    catalog = [
        {
            "description": ("inline" if index == 0 else "deferred") * 800,
            "input_schema": {"type": "object"},
            "name": "inline" if index == 0 else "deferred",
        }
        for index in range(2)
    ]
    return canonical_json_bytes(
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
            "payload_b64u": b64url(canonical_json_bytes(catalog)),
            "retain_count": 1,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
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
        env={"LANG": "C", "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_node_cli(
    *arguments: str, input_bytes: bytes = b"", cwd: Path = PACKAGE_ROOT
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


def run_mcp(*arguments: str, cwd: Path = PACKAGE_ROOT) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-B",
            str(BOOTSTRAP),
            "mcp",
            *arguments,
        ],
        cwd=cwd,
        env={"LANG": "C", "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def twin_dir(state_dir: Path) -> Path:
    return state_dir / "auxiliary-v1" / "twin-v1"


class G010TwinCliContractTests(unittest.TestCase):
    def assert_authority_boundary(self, payload: dict[str, object]) -> None:
        self.assertEqual(payload["evidence_boundary"], EVIDENCE_BOUNDARY)
        for field in (
            "applied",
            "execution_authority",
            "global_completeness_authority",
            "provider_claim_authority",
        ):
            self.assertIs(payload[field], False)

    def test_experimental_tuple_appends_then_reads_a_bounded_provider_free_twin(self) -> None:
        """Break caught: the explicit twin command omits/overclaims an event or snapshot."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            appended = run_cli(
                "inspect", "twin", "--experimental-twin", "--input", "-",
                "--root", str(root), "--state-dir", str(state),
                input_bytes=twin_request(),
            )
            inspected = run_cli(
                "inspect", "twin", "--experimental-twin", "--root", str(root),
                "--state-dir", str(state), "--limit", "1",
            )

        self.assertEqual(appended.returncode, 0, appended.stderr)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        result = json.loads(appended.stdout)
        snapshot = json.loads(inspected.stdout)
        self.assertEqual(appended.stdout, canonical_json_bytes(result))
        self.assertEqual(inspected.stdout, canonical_json_bytes(snapshot))
        self.assertEqual(result["schema_version"], "contextguard-receipt-twin-result/v1")
        self.assertEqual(result["result_kind"], "revalidated_declared_next_action_delta")
        self.assertEqual(result["declared_next_action_sha256"], "a" * 64)
        self.assertEqual(result["predicate_count"], 1)
        self.assertEqual(result["matched_predicate_count"], 1)
        self.assertIs(result["verified"], True)
        self.assertIs(result["advisory_only"], True)
        self.assertEqual(result["event_sequence"], 1)
        self.assertIsNone(result["previous_event_hmac_sha256"])
        for field in ("namespace_id", "event_id", "event_hmac_sha256"):
            self.assertIsInstance(result[field], str)
        self.assert_authority_boundary(result)
        self.assertEqual(
            set(result["predicate_results"][0]),
            {"kind", "matched", "observation_hmac_sha256", "ordinal"},
        )
        self.assertNotIn(b"private-input-must-not-appear", appended.stdout)
        self.assertEqual(snapshot["schema_version"], "contextguard-receipt-twin-snapshot/v1")
        self.assertEqual(snapshot["committed_event_count"], 1)
        self.assertEqual(len(snapshot["latest_events"]), 1)
        self.assertIs(snapshot["recovery_required"], False)
        self.assert_authority_boundary(snapshot)

    def test_twin_grammar_is_all_or_nothing_and_uninitialized_read_is_unavailable(self) -> None:
        """Break caught: partial, reordered, or extended opt-in opens a twin compartment."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            bare = run_cli("inspect", "twin")
            invalid = (
                ("inspect", "twin", "--experimental-twin"),
                ("inspect", "twin", "--input", "-", "--root", str(root), "--state-dir", str(state)),
                ("inspect", "twin", "--experimental-twin", "--input", "-", "--state-dir", str(state), "--root", str(root)),
                ("inspect", "twin", "--experimental-twin", "--root", str(root), "--state-dir", str(state), "--input", "-"),
                ("inspect", "twin", "--experimental-twin", "--root", str(root), "--state-dir", str(state), "--limit", "0"),
                ("inspect", "twin", "--experimental-twin", "--root", str(root), "--state-dir", str(state), "--limit", "257"),
                ("inspect", "twin", "--experimental-twin", "--root", str(root), "--state-dir", str(state), "--limit", "01"),
                ("inspect", "twin", "--experimental-twin", "--root", str(root), "--state-dir", str(state), "--unknown"),
            )
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    response = run_cli(*arguments, input_bytes=twin_request())
                    self.assertEqual(response.returncode, 64, response.stderr)
                    self.assertEqual(response.stdout, b"")
                    self.assertFalse(state.exists())
            uninitialized = run_cli(
                "inspect", "twin", "--experimental-twin", "--root", str(root),
                "--state-dir", str(state),
            )
            self.assertFalse(state.exists())

        self.assertEqual(bare.returncode, 69, bare.stderr)
        self.assertEqual(uninitialized.returncode, 69, uninitialized.stderr)
        self.assertEqual(uninitialized.stdout, b"")

    def test_twin_rejects_bad_input_before_creating_state(self) -> None:
        """Break caught: malformed, oversized, or noncanonical twin input creates durable state."""

        noncanonical = json.dumps(
            json.loads(twin_request()), sort_keys=False, indent=2
        ).encode("utf-8")
        invalid_inputs = (b"{", noncanonical, b"x" * (2 * 1024 * 1024 + 1))
        for raw in invalid_inputs:
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root = base / "repository"
                state = base / "state"
                root.mkdir(mode=0o700)
                response = run_cli(
                    "inspect", "twin", "--experimental-twin", "--input", "-",
                    "--root", str(root), "--state-dir", str(state), input_bytes=raw,
                )
                self.assertEqual(response.stdout, b"")
                self.assertIn(response.returncode, {65, 74}, response.stderr)
                self.assertFalse(state.exists())

    def test_ordinary_surfaces_never_create_twin_state(self) -> None:
        """Break caught: unrelated receipt, diagnostics, or MCP commands initialize twin-v1."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = PACKAGE_ROOT.resolve()
            state = base / "state"
            assembled = run_cli(
                "assemble", "--kind", "evidence", "--descriptor", "-", "--root",
                str(root), input_bytes=b"{}\n",
            )
            captured = run_cli(
                "run", "--escrow", "--root", str(root), "--state-dir", str(state),
                "--", str(Path(sys.executable).resolve()), "-c",
                "import os,time; os.write(1,b'x'); time.sleep(0.2)",
            )
            self.assertEqual(captured.returncode, 0, captured.stderr)
            capture_receipt = json.loads(captured.stdout)
            expanded = run_cli(
                "expand", capture_receipt["handle"], "--root", str(root),
                "--state-dir", str(state), "--emit", "bytes",
            )
            tool_assembled = run_cli(
                "assemble", "--kind", "tool-schemas", "--descriptor", "-", "--root",
                str(root), "--state-dir", str(state), "--persist", "--emit", "bytes",
                input_bytes=tool_schema_descriptor(),
            )
            self.assertEqual(tool_assembled.returncode, 0, tool_assembled.stderr)
            tool_bundle = json.loads(tool_assembled.stdout)
            tool_expanded = run_cli(
                "expand", "tool-schema", "--request", "-", "--root", str(root),
                "--state-dir", str(state), "--emit", "bytes",
                input_bytes=canonical_json_bytes(
                    {
                        "catalog_reference": tool_bundle["catalog_reference"],
                        "item_reference": None,
                        "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
                    }
                ),
            )
            firewall = run_cli(
                "inspect", "firewall", "--input", "-", input_bytes=diagnostic_request()
            )
            calls = (
                assembled,
                captured,
                expanded,
                tool_assembled,
                tool_expanded,
                firewall,
                run_cli("inspect", "boundary"),
                run_cli("inspect", "diagnostics", "--input", "-", "--state-scope", "durable", "--root", str(root), "--state-dir", str(state), input_bytes=diagnostic_request()),
                run_cli("inspect", "diagnostic-ledger", "--state-scope", "durable", "--root", str(root), "--state-dir", str(state)),
                run_mcp("--root", str(root)),
            )
            self.assertFalse(twin_dir(state).exists())

        for call in calls[1:6]:
            self.assertEqual(call.returncode, 0, call.stderr)
        self.assertEqual(calls[7].returncode, 0, calls[7].stderr)

    def test_stdout_failure_preserves_committed_twin_event_and_labels_operation(self) -> None:
        """Break caught: delivery failure rolls back a committed twin event or mislabels it."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            request_path = base / "request.json"
            root.mkdir(mode=0o700)
            request_path.write_bytes(twin_request())
            stderr = io.StringIO()
            with mock.patch.object(cli_module, "write_stdout", side_effect=BrokenPipeError), contextlib.redirect_stderr(stderr):
                exit_code = cli_module.receipt_main(
                    ("inspect", "twin", "--experimental-twin", "--input", str(request_path), "--root", str(root), "--state-dir", str(state))
                )
            inspection = run_cli(
                "inspect", "twin", "--experimental-twin", "--root", str(root),
                "--state-dir", str(state), "--limit", "1",
            )

        self.assertEqual(exit_code, 74)
        self.assertIn('"operation":"inspect_twin"', stderr.getvalue())
        self.assertEqual(inspection.returncode, 0, inspection.stderr)
        self.assertEqual(json.loads(inspection.stdout)["committed_event_count"], 1)

    def test_twin_auxiliary_is_removable_without_breaking_store_or_diagnostics(self) -> None:
        """Break caught: twin state shares keys or couples store/diagnostic recovery to twin-v1."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            appended = run_cli(
                "inspect", "twin", "--experimental-twin", "--input", "-",
                "--root", str(root), "--state-dir", str(state), input_bytes=twin_request(),
            )
            self.assertEqual(appended.returncode, 0, appended.stderr)
            with DiagnosticLedger.open(state_dir=str(state), repository_root=str(root), create=True) as ledger:
                ledger.append({
                    "advisory_lane": "none", "advisory_only": True, "advisory_reason": "exact_path_required", "applied": False,
                    "blueprint_bytes": 0, "current_prefix_bytes": 0, "current_prefix_hmac_sha256": "1" * 64, "current_reuse_basis_points": 0, "current_sample_bytes": 0, "current_truncated": False, "current_window_count": 0,
                    "efficacy_claim_authority": False, "evidence_hmac_sha256": "2" * 64, "firewall_reason": "protected", "handle_bytes": 0, "input_bytes": 0,
                    "live_observation_authority": False, "mandatory_expansion_bytes": 0, "matched_window_count": 0, "policy_sha256": DIAGNOSTICS_POLICY_SHA256, "predicted_cost_bytes": 0, "predicted_savings_bytes": 0,
                    "previous_prefix_bytes": 0, "previous_prefix_hmac_sha256": "4" * 64, "previous_prefix_present": False, "previous_retention_basis_points": 0, "previous_sample_bytes": 0, "previous_truncated": False, "previous_window_count": 0,
                    "provider_claim_authority": False, "provider_routing_authority": False, "retained_wire_bytes": 0, "rolling_status": "unavailable", "savings_basis_points": 0, "subject_kind": "evidence", "prefix_delta_bytes": 0, "would_block": True, "wrapper_bytes": 0,
                }, observed_at_unix_ms=1)
            with CapabilityStore.open(state_dir=str(state), repository_root=str(root), create=True) as store:
                issued = store.issue(payload=b"store-survives-twin-removal", root_identity_sha256="1" * 64, subject_identity_sha256="2" * 64, artifact_type=ArtifactType.RAW_EVIDENCE_BYTES)
            shutil.rmtree(twin_dir(state))
            with CapabilityStore.open(state_dir=str(state), repository_root=str(root)) as store:
                retrieved = store.retrieve(issued.handle, expected_namespace_id=issued.namespace_id, expected_root_identity_sha256="1" * 64, expected_subject_identity_sha256="2" * 64, expected_artifact_type=ArtifactType.RAW_EVIDENCE_BYTES)
            with DiagnosticLedger.open(state_dir=str(state), repository_root=str(root)) as ledger:
                entry_count = ledger.inspect(limit=1)["entry_count"]

        self.assertEqual(retrieved.payload, b"store-survives-twin-removal")
        self.assertEqual(entry_count, 1)

    def test_packaged_node_entrypoint_executes_the_twin_runtime_and_schema_trust_set(self) -> None:
        """Break caught: package trust data omits the runtime or schemas needed by twin CLI."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            response = run_node_cli(
                "inspect", "twin", "--experimental-twin", "--input", "-",
                "--root", str(root), "--state-dir", str(state), input_bytes=twin_request(),
            )

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(json.loads(response.stdout)["schema_version"], "contextguard-receipt-twin-result/v1")


if __name__ == "__main__":
    unittest.main()
