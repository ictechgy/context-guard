from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = PACKAGE_ROOT / "python/context_guard_receipt/bootstrap.py"
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt.identity import snapshot_repository  # noqa: E402
from context_guard_receipt.store import (  # noqa: E402
    ArtifactType,
    CapabilityStore,
)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def evidence_descriptor(payload: bytes, relative_path: str) -> bytes:
    return canonical_json(
        {
            "caller_classification": "eligible",
            "detector_signals": [],
            "payload_b64u": b64url(payload),
            "schema_version": "contextguard-receipt-evidence-descriptor/v1",
            "source": {
                "relative_path": relative_path,
                "selection": {"kind": "file"},
            },
        }
    )


def tool_descriptor() -> bytes:
    catalog = [
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
    payload = canonical_json(catalog)
    return canonical_json(
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
            "payload_b64u": b64url(payload),
            "retain_count": 1,
            "schema_version": "contextguard-receipt-tool-schema-descriptor/v1",
        }
    )


def tool_expansion_request(
    catalog_reference: object, item_reference: object = None
) -> bytes:
    return canonical_json(
        {
            "catalog_reference": catalog_reference,
            "item_reference": item_reference,
            "schema_version": "contextguard-receipt-tool-schema-expansion-request/v1",
        }
    )


def diagnostic_request() -> bytes:
    return canonical_json(
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


def twin_request() -> bytes:
    return canonical_json(
        {
            "declared_next_action_sha256": "a" * 64,
            "expected_tail": None,
            "predicates": [
                {
                    "kind": "path_absent",
                    "relative_path": "must-remain-absent.txt",
                }
            ],
            "schema_version": "contextguard-receipt-twin-request/v1",
        }
    )


def request(operation: str, capability: str, value: int) -> bytes:
    document: dict[str, object] = {
        "capability": capability,
        "operation": operation,
        "schema_version": "contextguard-receipt-reference-expiry-request/v1",
    }
    if operation == "register":
        document["expires_at_unix_ms"] = value
    else:
        document["expected_generation"] = value
    return canonical_json(document)


def run_cli(*arguments: str, input_bytes: bytes = b"") -> subprocess.CompletedProcess[bytes]:
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
        env={"LANG": "C", "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_bootstrap(
    bootstrap: Path, *arguments: str, input_bytes: bytes = b""
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-S",
            "-B",
            str(bootstrap),
            "receipt",
            *arguments,
        ],
        cwd=bootstrap.parents[2],
        env={"LANG": "C", "PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def store_snapshot(state: Path) -> dict[str, tuple[str, int, str]]:
    root = state / "store-v1"
    result: dict[str, tuple[str, int, str]] = {}
    for path in sorted((root, *root.rglob("*"))):
        relative = path.relative_to(root).as_posix() or "."
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            result[relative] = ("directory", mode, "")
        elif stat.S_ISREG(metadata.st_mode):
            result[relative] = (
                "regular",
                mode,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        else:
            result[relative] = ("other", mode, "")
    return result


def tree_snapshot(root: Path) -> dict[str, tuple[int, str]]:
    return {
        path.relative_to(root).as_posix(): (
            stat.S_IMODE(path.lstat().st_mode),
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


class G011ReferenceExpiryCliTests(unittest.TestCase):
    def _issue(
        self, root: Path, state: Path, name: str, payload: bytes
    ) -> str:
        (root / name).write_bytes(payload)
        issued = run_cli(
            "assemble",
            "--kind",
            "evidence",
            "--descriptor",
            "-",
            "--root",
            str(root),
            "--state-dir",
            str(state),
            "--persist",
            "--emit",
            "bytes",
            input_bytes=evidence_descriptor(payload, name),
        )
        self.assertEqual(issued.returncode, 0, issued.stderr)
        return json.loads(issued.stdout)["capability"]

    def test_explicit_register_revoke_blocks_expansion_but_retains_store(self) -> None:
        """Break caught: revocation deletes artifacts, leaks authority, or is bypassed."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            payload = b"retained-reference-bytes" * 1024
            capability = self._issue(root, state, "source.bin", payload)
            before = store_snapshot(state)
            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 4_102_444_800_000),
            )
            self.assertEqual(registered.returncode, 0, registered.stderr)
            result = json.loads(registered.stdout)
            self.assertNotIn(capability, registered.stdout.decode("ascii"))
            self.assertIs(result["retained_artifacts"], True)
            self.assertIs(result["artifact_cleanup_performed"], False)

            still_exact = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(still_exact.returncode, 0, still_exact.stderr)
            self.assertEqual(still_exact.stdout, payload)
            revoked = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("revoke", capability, 1),
            )
            self.assertEqual(revoked.returncode, 0, revoked.stderr)
            denied = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(denied.returncode, 65)
            self.assertEqual(denied.stdout, b"")
            self.assertEqual(json.loads(denied.stderr)["reason"], "capability_rejected")
            self.assertEqual(store_snapshot(state), before)

    def test_expiry_mutates_no_source_store_output_ledger_twin_or_transcript(self) -> None:
        """Break caught: the compact denial overlay acquires artifact ownership."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            source_payload = b"coexistence-source" * 1024
            capability = self._issue(root, state, "source.bin", source_payload)
            root_identity = snapshot_repository(str(root))["instance"][
                "identity_sha256"
            ]
            with CapabilityStore.open(
                state_dir=str(state), repository_root=str(root)
            ) as store:
                store.issue(
                    payload=b"retained-command-output",
                    root_identity_sha256=root_identity,
                    subject_identity_sha256="d" * 64,
                    artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                )
            diagnosed = run_cli(
                "inspect",
                "diagnostics",
                "--input",
                "-",
                "--state-scope",
                "durable",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=diagnostic_request(),
            )
            twinned = run_cli(
                "inspect",
                "twin",
                "--experimental-twin",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=twin_request(),
            )
            for response in (diagnosed, twinned):
                self.assertEqual(response.returncode, 0, response.stderr)
            transcript = base / "transcript.log"
            transcript.write_bytes(b"user-owned transcript")
            source = root / "source.bin"
            diagnostics_dir = state / "auxiliary-v1/diagnostics-v1"
            twin_dir = state / "auxiliary-v1/twin-v1"
            before = {
                "diagnostics": tree_snapshot(diagnostics_dir),
                "source": source.read_bytes(),
                "store": store_snapshot(state),
                "transcript": transcript.read_bytes(),
                "twin": tree_snapshot(twin_dir),
            }

            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 4_102_444_800_000),
            )
            revoked = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("revoke", capability, 1),
            )
            self.assertEqual(registered.returncode, 0, registered.stderr)
            self.assertEqual(revoked.returncode, 0, revoked.stderr)
            after = {
                "diagnostics": tree_snapshot(diagnostics_dir),
                "source": source.read_bytes(),
                "store": store_snapshot(state),
                "transcript": transcript.read_bytes(),
                "twin": tree_snapshot(twin_dir),
            }
            self.assertEqual(after, before)
            ledger = run_cli(
                "inspect",
                "diagnostic-ledger",
                "--state-scope",
                "durable",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--limit",
                "1",
            )
            twin = run_cli(
                "inspect",
                "twin",
                "--experimental-twin",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--limit",
                "1",
            )
            self.assertEqual(ledger.returncode, 0, ledger.stderr)
            self.assertEqual(twin.returncode, 0, twin.stderr)
            self.assertEqual(json.loads(ledger.stdout)["entry_count"], 1)
            self.assertEqual(json.loads(twin.stdout)["committed_event_count"], 1)

    def test_due_reference_is_irreversibly_expired_and_inspection_is_path_free(self) -> None:
        """Break caught: deadline access re-enables or exposes local locations."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            payload = b"expired-retained" * 1024
            capability = self._issue(root, state, "due.bin", payload)
            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 0),
            )
            self.assertEqual(registered.returncode, 0, registered.stderr)
            denied = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(denied.returncode, 65)

            inspected = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--limit",
                "1",
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            snapshot = json.loads(inspected.stdout)
            self.assertEqual(
                snapshot["state_location"],
                {
                    "compartment": "auxiliary-v1/reference-expiry-v1",
                    "scope": "explicit_state_dir",
                },
            )
            for secret in (capability, str(root), str(state), "due.bin"):
                self.assertNotIn(secret, inspected.stdout.decode("ascii"))
            raw_registry = b"".join(
                path.read_bytes()
                for path in (state / "auxiliary-v1/reference-expiry-v1").rglob("*")
                if path.is_file()
            )
            self.assertNotIn(capability.encode("ascii"), raw_registry)
            self.assertNotIn(payload, raw_registry)

    def test_registration_rejects_a_source_stale_capability_without_a_record(self) -> None:
        """Break caught: an already stale source reference is registered as active."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            source = root / "stale.bin"
            capability = self._issue(
                root, state, source.name, b"original bytes" * 1024
            )
            source.write_bytes(b"changed bytes")

            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 4_102_444_800_000),
            )

            self.assertEqual(registered.returncode, 65)
            self.assertEqual(registered.stdout, b"")
            self.assertEqual(
                json.loads(registered.stderr)["reason"],
                "reference_expiry_input_rejected",
            )
            inspected = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--root",
                str(root),
                "--state-dir",
                str(state),
            )
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(json.loads(inspected.stdout)["registered_reference_count"], 0)

    def test_stale_source_can_still_be_revoked_and_cannot_reactivate_on_restore(self) -> None:
        """Break caught: freshness failure prevents durable revocation."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            original = b"revocation survives restoration" * 1024
            source = root / "restored.bin"
            capability = self._issue(root, state, source.name, original)
            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 4_102_444_800_000),
            )
            self.assertEqual(registered.returncode, 0, registered.stderr)
            source.write_bytes(b"temporarily stale")
            revoked = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("revoke", capability, 1),
            )
            self.assertEqual(revoked.returncode, 0, revoked.stderr)
            source.write_bytes(original)
            denied = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(denied.returncode, 65)
            self.assertEqual(json.loads(denied.stderr)["reason"], "capability_rejected")

    def test_tool_schema_capabilities_can_be_registered_and_revoked(self) -> None:
        """Break caught: generic expiry rejects valid snapshot-bound tool references."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            assembled = run_cli(
                "assemble",
                "--kind",
                "tool-schemas",
                "--descriptor",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--persist",
                "--emit",
                "bytes",
                input_bytes=tool_descriptor(),
            )
            self.assertEqual(assembled.returncode, 0, assembled.stderr)
            bundle = json.loads(assembled.stdout)
            catalog = bundle["catalog_reference"]
            item = bundle["deferred"][0]
            for reference in (catalog, item):
                registered = run_cli(
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--input",
                    "-",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    input_bytes=request(
                        "register", reference["capability"], 4_102_444_800_000
                    ),
                )
                self.assertEqual(registered.returncode, 0, registered.stderr)
            revoked = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("revoke", item["capability"], 1),
            )
            self.assertEqual(revoked.returncode, 0, revoked.stderr)
            whole = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
                input_bytes=tool_expansion_request(catalog),
            )
            selected = run_cli(
                "expand",
                "tool-schema",
                "--request",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
                input_bytes=tool_expansion_request(catalog, item),
            )
            self.assertEqual(whole.returncode, 0, whole.stderr)
            self.assertEqual(selected.returncode, 65)
            self.assertEqual(json.loads(selected.stderr)["reason"], "artifact_invalid")

    def test_feature_is_inert_without_exact_opt_in_and_ordinary_flows_do_not_create_it(self) -> None:
        """Break caught: expiry state or authority appears without the explicit flag."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            capability = self._issue(root, state, "ordinary.bin", b"x" * 8192)
            expanded = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(expanded.returncode, 0, expanded.stderr)
            self.assertFalse((state / "auxiliary-v1/reference-expiry-v1").exists())
            unavailable = run_cli("inspect", "reference-expiry")
            self.assertEqual(unavailable.returncode, 69)
            relative = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--root",
                ".",
                "--state-dir",
                str(state),
            )
            self.assertEqual(relative.returncode, 64)

    def test_experimental_cli_tuple_is_exact_ordered_and_bounded(self) -> None:
        """Break caught: reordered, duplicate, or ambiguous opt-in enables expiry."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            invalid = (
                (
                    "inspect",
                    "reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--state-dir",
                    str(state),
                    "--root",
                    str(root),
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--experimental-reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    "--limit",
                    "0",
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    "--limit",
                    "257",
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    "--limit",
                    "01",
                ),
                (
                    "inspect",
                    "reference-expiry",
                    "--experimental-reference-expiry",
                    "--root",
                    str(root),
                    "--state-dir",
                    str(state),
                    "--unknown",
                ),
            )
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    response = run_cli(*arguments)
                    self.assertEqual(response.returncode, 64)
                    self.assertEqual(response.stdout, b"")
            self.assertFalse(state.exists())

    def test_corrupt_registry_fails_closed_and_user_removal_restores_retained_artifact(self) -> None:
        """Break caught: tamper fails open or the optional axis owns artifact lifetime."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            payload = b"independently-retained" * 1024
            capability = self._issue(root, state, "retained.bin", payload)
            registered = run_cli(
                "inspect",
                "reference-expiry",
                "--experimental-reference-expiry",
                "--input",
                "-",
                "--root",
                str(root),
                "--state-dir",
                str(state),
                input_bytes=request("register", capability, 4_102_444_800_000),
            )
            self.assertEqual(registered.returncode, 0, registered.stderr)
            registry = state / "auxiliary-v1/reference-expiry-v1"
            key = registry / "key"
            key.write_bytes(b"z" * 32)
            os.chmod(key, 0o600)
            denied = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(denied.returncode, 65)
            self.assertEqual(json.loads(denied.stderr)["reason"], "capability_rejected")

            shutil.rmtree(registry)
            restored = run_cli(
                "expand", capability, "--root", str(root), "--state-dir", str(state)
            )
            self.assertEqual(restored.returncode, 0, restored.stderr)
            self.assertEqual(restored.stdout, payload)

    def test_removing_optional_module_leaves_preexisting_exact_expansion_green(self) -> None:
        """Break caught: an ordinary flow imports the removable axis eagerly."""

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state = base / "state"
            root.mkdir(mode=0o700)
            payload = b"module-removal-independent" * 1024
            capability = self._issue(root, state, "independent.bin", payload)
            copied_python = base / "runtime/python"
            shutil.copytree(PACKAGE_ROOT / "python", copied_python)
            (copied_python / "context_guard_receipt/reference_expiry.py").unlink()
            copied_bootstrap = copied_python / "context_guard_receipt/bootstrap.py"
            expanded = run_bootstrap(
                copied_bootstrap,
                "expand",
                capability,
                "--root",
                str(root),
                "--state-dir",
                str(state),
                "--emit",
                "bytes",
            )
            self.assertEqual(expanded.returncode, 0, expanded.stderr)
            self.assertEqual(expanded.stdout, payload)


if __name__ == "__main__":
    unittest.main()
