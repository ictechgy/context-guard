from __future__ import annotations

import importlib
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

from context_guard_receipt import expansion
from context_guard_receipt.canonical import framed_sha256_hex
from context_guard_receipt.identity import snapshot_repository
from context_guard_receipt.store import ArtifactType, CapabilityStore, StoredArtifact


MERGED_SUBJECT_DOMAIN = (
    "contextguard-receipt/command-capture-merged-sanitized/v1"
)
STORE_PAYLOAD_DOMAIN = "contextguard-receipt/store-payload/v1"
LEGACY_SUBJECT_DOMAIN = "contextguard-receipt/command-capture-subject/v1"
HANDLE = "cgr1p_" + "H" * 43
BOOTSTRAP = PYTHON_ROOT / "context_guard_receipt/bootstrap.py"
REFERENCE_QUERY_SCHEMA = "contextguard-receipt-bash-reference-query/v1"


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


def frame(sequence: int, channel: int, payload: bytes) -> bytes:
    return (
        sequence.to_bytes(8, "big")
        + channel.to_bytes(1, "big")
        + len(payload).to_bytes(4, "big")
        + payload
    )


def canonical_legacy_capture() -> bytes:
    return b"CGRF1\x00" + frame(0, 1, b"legacy\n")


def deterministic_state_directory(root: Path) -> Path:
    status = root.lstat()
    selector = hashlib.sha256()
    selector.update(b"contextguard/bash-reference-state-selector/v1\0")
    for field in (
        os.fsencode(str(root)),
        str(status.st_dev).encode("ascii"),
        str(status.st_ino).encode("ascii"),
    ):
        selector.update(len(field).to_bytes(8, "big"))
        selector.update(field)
    return root.parent / f".context-guard-receipt-state-{selector.hexdigest()}"


def run_cli(*arguments: str) -> subprocess.CompletedProcess[bytes]:
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class Fixture:
    def __init__(self, testcase: unittest.TestCase) -> None:
        self.testcase = testcase
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repository"
        self.state = self.base / "private-state"
        self.spool = self.base / "merged-output.txt"
        self.root.mkdir(mode=0o700)
        self.write_spool(b"stdout line\nstderr line\n")

    def write_spool(self, payload: bytes) -> None:
        self.spool.write_bytes(payload)
        self.spool.chmod(0o600)

    @property
    def root_identity(self) -> str:
        return snapshot_repository(
            str(self.root), git_executable=git_executable()
        )["instance"]["identity_sha256"]

    def close(self) -> None:
        self.temporary.cleanup()

    def __enter__(self) -> "Fixture":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class G014MergedCaptureTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module("context_guard_receipt.merged_capture")
        except ModuleNotFoundError as error:
            raise AssertionError("merged capture import implementation is missing") from error

    def assert_import_error(self, code: str, operation) -> None:
        module = self.module()
        with self.assertRaises(module.MergedCaptureError) as caught:
            operation()
        self.assertEqual(caught.exception.code.value, code)

    def publish(
        self,
        fixture: Fixture,
        transaction_id: str,
        *,
        observed_at: int = 1_000,
    ) -> dict[str, object]:
        module = self.module()
        with mock.patch.object(
            module.time, "time_ns", return_value=observed_at * 1_000_000
        ):
            return module.publish(
                spool_path=str(fixture.spool),
                transaction_id=transaction_id,
                repository_root=str(fixture.root),
                state_dir=str(fixture.state),
                disclosure_days=7,
            )

    def test_publish_uses_fixed_absolute_seven_day_deadline_and_is_idempotent(self) -> None:
        """Break caught: retry mints again or recomputes and extends the TTL."""

        with Fixture(self) as fixture:
            first = self.publish(fixture, "1" * 64, observed_at=1_000)
            retried = self.publish(fixture, "1" * 64, observed_at=90_000)

            self.assertEqual(first["status"], "registered")
            self.assertEqual(first["expires_at_unix_ms"], 604_801_000)
            self.assertEqual(retried["expires_at_unix_ms"], 604_801_000)
            self.assertEqual(retried["reference"], first["reference"])
            self.assertIs(first["actionable"], True)
            self.assertIsNone(first["reason"])
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                summary = store.inspect_counts()
            self.assertEqual(summary.artifact_count, 1)
            self.assertEqual(summary.capability_count, 1)

    def test_existing_default_store_upgrades_for_large_merged_capture(self) -> None:
        """Break caught: enabling merged capture strands an existing default store."""

        store_module = importlib.import_module("context_guard_receipt.store")
        with Fixture(self) as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as store:
                original_namespace = store.namespace_id
                legacy = store.issue(
                    payload=b"existing artifact",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="a" * 64,
                    artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                )
                self.assertEqual(
                    store.limits.max_single_artifact_bytes,
                    1024 * 1024,
                )

            payload = b"x" * (1024 * 1024 + 1)
            fixture.write_spool(payload)
            published = self.publish(fixture, "2" * 64)

            self.assertEqual(published["status"], "registered")
            with CapabilityStore.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
            ) as store:
                self.assertEqual(store.namespace_id, original_namespace)
                self.assertEqual(
                    store.limits,
                    store_module.StoreLimits(max_single_artifact_bytes=10_000_000),
                )
                self.assertEqual(
                    store.resolve(
                        legacy.handle,
                        expected_root_identity_sha256=fixture.root_identity,
                    ).payload,
                    b"existing artifact",
                )
                self.assertEqual(
                    store.resolve(
                        published["reference"],
                        expected_root_identity_sha256=fixture.root_identity,
                    ).payload,
                    payload,
                )

    def test_merged_capture_refuses_nondefault_store_limit_mismatch(self) -> None:
        """Break caught: migration blesses an arbitrary persisted limit profile."""

        store_module = importlib.import_module("context_guard_receipt.store")
        custom_limits = store_module.StoreLimits(
            max_single_artifact_bytes=2 * 1024 * 1024
        )
        with Fixture(self) as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
                limits=custom_limits,
            ):
                pass

            self.assert_import_error(
                "state_unavailable",
                lambda: self.publish(fixture, "3" * 64),
            )
            with CapabilityStore.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
            ) as store:
                self.assertEqual(store.limits, custom_limits)

    def test_recovery_refuses_expired_reference_without_redisclosing_authority(self) -> None:
        """Break caught: an expired transaction is returned as an actionable handle."""

        module = self.module()
        with Fixture(self) as fixture:
            published = self.publish(fixture, "e" * 64, observed_at=1_000)
            with mock.patch.object(
                module.time,
                "time_ns",
                return_value=published["expires_at_unix_ms"] * 1_000_000,
            ):
                with self.assertRaises(module.MergedCaptureError) as caught:
                    module.recover(
                        transaction_id="e" * 64,
                        repository_root=str(fixture.root),
                        state_dir=str(fixture.state),
                    )

            self.assertEqual(caught.exception.code.value, "reference_inaccessible")
            rendered = str(caught.exception) + repr(caught.exception)
            self.assertNotIn(str(published["reference"]), rendered)

    def test_prepared_broker_commits_anonymous_fd_without_post_ready_reopen(self) -> None:
        """Break caught: COMMIT reopens Git, store, or registry after READY."""

        module = self.module()
        store_module = importlib.import_module("context_guard_receipt.store")
        expiry_module = importlib.import_module(
            "context_guard_receipt.reference_expiry"
        )
        with Fixture(self) as fixture, tempfile.TemporaryFile("w+b") as capture:
            os.fchmod(capture.fileno(), 0o600)
            prepared = module.prepare_broker(
                capture_fd=capture.fileno(),
                transaction_id="7" * 64,
                repository_root=str(fixture.root),
                state_dir=str(fixture.state),
                disclosure_days=7,
            )
            try:
                capture.write(b"prepared anonymous bytes\n")
                capture.flush()
                with (
                    mock.patch.object(
                        module,
                        "snapshot_repository",
                        side_effect=AssertionError("Git reopened after READY"),
                    ),
                    mock.patch.object(
                        store_module.CapabilityStore,
                        "open",
                        side_effect=AssertionError("store reopened after READY"),
                    ),
                    mock.patch.object(
                        expiry_module.ReferenceExpiryRegistry,
                        "open",
                        side_effect=AssertionError("registry reopened after READY"),
                    ),
                ):
                    result = prepared.commit()
            finally:
                prepared.close()

            self.assertEqual(result["status"], "registered")
            self.assertEqual(result["transaction_id"], "7" * 64)
            self.assertIs(result["actionable"], True)

    def test_prepared_broker_rejects_named_capture(self) -> None:
        """Break caught: a pathname-backed spool crosses the private broker boundary."""

        module = self.module()
        with Fixture(self) as fixture:
            descriptor = os.open(
                fixture.spool,
                os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                self.assert_import_error(
                    "unsafe_spool",
                    lambda: module.prepare_broker(
                        capture_fd=descriptor,
                        transaction_id="8" * 64,
                        repository_root=str(fixture.root),
                        state_dir=str(fixture.state),
                        disclosure_days=7,
                    ),
                )
            finally:
                os.close(descriptor)

    def test_prepared_broker_recovers_phase_uncertainty_in_same_instance(self) -> None:
        """Break caught: phase uncertainty requires a second CLI/process recovery."""

        module = self.module()
        with Fixture(self) as fixture, tempfile.TemporaryFile("w+b") as capture:
            os.fchmod(capture.fileno(), 0o600)
            prepared = module.prepare_broker(
                capture_fd=capture.fileno(),
                transaction_id="9" * 64,
                repository_root=str(fixture.root),
                state_dir=str(fixture.state),
                disclosure_days=7,
            )
            capture.write(b"recover in one loaded process\n")
            capture.flush()
            original_advance = prepared._journal.advance
            faulted = False

            def uncertain(transaction_id, state, *, observed_at_unix_ms):
                nonlocal faulted
                result = original_advance(
                    transaction_id,
                    state,
                    observed_at_unix_ms=observed_at_unix_ms,
                )
                if state == "issued" and not faulted:
                    faulted = True
                    raise module.MergedCaptureError(
                        module.MergedCaptureErrorCode.COMMIT_UNCERTAIN
                    )
                return result

            prepared._journal.advance = uncertain
            try:
                result = prepared.commit()
            finally:
                prepared.close()

            self.assertTrue(faulted)
            self.assertEqual(result["status"], "registered")

    def test_private_broker_protocol_is_exact_and_bounded(self) -> None:
        """Break caught: broker accepts extra commands or emits noncanonical framing."""

        cli = importlib.import_module("context_guard_receipt.cli")
        with Fixture(self) as fixture, tempfile.TemporaryFile("w+b") as capture:
            os.fchmod(capture.fileno(), 0o600)
            capture.write(b"broker protocol bytes\n")
            capture.flush()
            # Preparation requires the capture to start empty; feed bytes after
            # the READY boundary from a controlled flush callback.
            capture.seek(0)
            capture.truncate(0)

            class Control(io.BytesIO):
                def readline(self, size: int = -1) -> bytes:
                    capture.write(b"broker protocol bytes\n")
                    capture.flush()
                    return super().readline(size)

            output = io.BytesIO()
            result = cli._run_bash_reference_broker(
                (
                    "--transaction-id",
                    "a" * 64,
                    "--root",
                    str(fixture.root),
                    "--state-dir",
                    str(fixture.state),
                    "--disclosure-days",
                    "7",
                ),
                capture_fd=capture.fileno(),
                control=Control(b"COMMIT\n"),
                output=output,
            )

            self.assertEqual(result, 0)
            ready, final, empty = output.getvalue().split(b"\n")
            self.assertEqual(
                ready, b"READY contextguard-bash-reference-broker/v1"
            )
            self.assertTrue(final.startswith(b"FINAL "))
            payload = json.loads(final[len(b"FINAL ") :])
            self.assertEqual(payload["transaction_id"], "a" * 64)
            self.assertIs(payload["actionable"], True)
            self.assertEqual(empty, b"")

            rejected = cli._run_bash_reference_broker(
                (),
                capture_fd=capture.fileno(),
                control=io.BytesIO(b"COMMIT extra\n"),
                output=io.BytesIO(),
            )
            self.assertNotEqual(rejected, 0)

    def test_private_reference_query_returns_one_utf8_bounded_exact_page(self) -> None:
        """Break caught: a reference query emits the complete multi-page artifact."""

        module = self.module()
        with Fixture(self) as fixture:
            fixture.state = deterministic_state_directory(fixture.root)
            payload = b"a" * 19_999 + "π".encode("utf-8") + b"tail\n"
            fixture.write_spool(payload)
            published = module.publish(
                spool_path=str(fixture.spool),
                transaction_id="b" * 64,
                repository_root=str(fixture.root),
                state_dir=str(fixture.state),
                disclosure_days=7,
            )

            first = run_cli(
                "--private-bash-reference-query-v1",
                str(published["reference"]),
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
                "0",
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertLess(len(first.stdout), 28_000)
            response = json.loads(first.stdout)
            first_page = base64.urlsafe_b64decode(
                response["payload_b64u"] + "=" * (-len(response["payload_b64u"]) % 4)
            )
            self.assertEqual(response["schema_version"], REFERENCE_QUERY_SCHEMA)
            self.assertEqual(response["status"], "exact")
            self.assertEqual(
                response["request"],
                {"offset": 0, "reference": published["reference"]},
            )
            self.assertEqual(first_page, b"a" * 19_999)
            self.assertEqual(response["next_offset"], 19_999)
            self.assertEqual(response["total_bytes"], len(payload))

            second = run_cli(
                "--private-bash-reference-query-v1",
                str(published["reference"]),
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
                "19999",
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            response = json.loads(second.stdout)
            second_page = base64.urlsafe_b64decode(
                response["payload_b64u"] + "=" * (-len(response["payload_b64u"]) % 4)
            )
            self.assertEqual(second_page, "πtail\n".encode("utf-8"))
            self.assertEqual(response["next_offset"], len(payload))

    def test_private_reference_query_rejects_nonboundary_and_oversize_offsets(self) -> None:
        """Break caught: offsets can split UTF-8 or seek beyond the artifact."""

        module = self.module()
        with Fixture(self) as fixture:
            fixture.state = deterministic_state_directory(fixture.root)
            fixture.write_spool("aπz".encode("utf-8"))
            published = module.publish(
                spool_path=str(fixture.spool),
                transaction_id="c" * 64,
                repository_root=str(fixture.root),
                state_dir=str(fixture.state),
                disclosure_days=7,
            )
            common = (
                "--private-bash-reference-query-v1",
                str(published["reference"]),
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
            )
            split = run_cli(*common, "2")
            beyond = run_cli(*common, "999")

        for refused in (split, beyond):
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"")
            self.assertNotIn(str(published["reference"]).encode(), refused.stderr)
            self.assertNotIn(b"payload", refused.stderr)
            diagnostic = json.loads(refused.stderr)
            self.assertEqual(diagnostic["operation"], "query_bash_reference")
            self.assertEqual(diagnostic["reason"], "offset_rejected")

    def test_private_reference_query_enforces_root_and_active_registry(self) -> None:
        """Break caught: a capability survives its root or seven-day registry binding."""

        module = self.module()
        with Fixture(self) as fixture:
            fixture.state = deterministic_state_directory(fixture.root)
            current = int(importlib.import_module("time").time_ns() // 1_000_000)
            published = self.publish(
                fixture,
                "d" * 64,
                observed_at=current - 604_800_001,
            )
            expired = run_cli(
                "--private-bash-reference-query-v1",
                str(published["reference"]),
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
                "0",
            )
            wrong_root = fixture.base / "other-repository"
            wrong_root.mkdir(mode=0o700)
            wrong = run_cli(
                "--private-bash-reference-query-v1",
                str(published["reference"]),
                "--root",
                str(wrong_root),
                "--state-dir",
                str(deterministic_state_directory(wrong_root)),
                "--offset",
                "0",
            )

        for refused in (expired, wrong):
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"")
            self.assertNotIn(str(published["reference"]).encode(), refused.stderr)
            self.assertNotIn(b"payload", refused.stderr)
            diagnostic = json.loads(refused.stderr)
            self.assertEqual(diagnostic["operation"], "query_bash_reference")
            self.assertEqual(diagnostic["reason"], "capability_rejected")

    def test_private_reference_query_rejects_generic_registered_legacy_capability(self) -> None:
        """Break caught: generic expiry registration grants merged-query provenance."""

        with Fixture(self) as fixture:
            fixture.state = deterministic_state_directory(fixture.root)
            current = int(importlib.import_module("time").time_ns() // 1_000_000)
            fixture.write_spool(b"real merged capture\n")
            merged = self.publish(fixture, "a" * 64, observed_at=current)
            payload = canonical_legacy_capture()
            fixture.write_spool(payload)
            descriptor = os.open(
                fixture.spool, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
            try:
                with CapabilityStore.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    create=True,
                ) as store:
                    issued = store.ensure_issued_file(
                        source_fd=descriptor,
                        byte_length=len(payload),
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256=framed_sha256_hex(
                            LEGACY_SUBJECT_DOMAIN, payload
                        ),
                        subject_identity_domain=LEGACY_SUBJECT_DOMAIN,
                        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                        idempotency_key="f" * 64,
                    )
                    namespace = store.namespace_id
            finally:
                os.close(descriptor)
            expiry = importlib.import_module("context_guard_receipt.reference_expiry")
            with expiry.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=namespace,
                create=True,
            ) as registry:
                registered = registry.register(
                    issued.handle,
                    expires_at_unix_ms=current + 60_000,
                    observed_at_unix_ms=current,
                )
            self.assertEqual(registered["status"], "active")

            refused = run_cli(
                "--private-bash-reference-query-v1",
                issued.handle,
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
                "0",
            )
            accepted = run_cli(
                "--private-bash-reference-query-v1",
                str(merged["reference"]),
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--offset",
                "0",
            )

        self.assertEqual(refused.returncode, 65)
        self.assertEqual(refused.stdout, b"")
        self.assertEqual(json.loads(refused.stderr)["reason"], "capability_rejected")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        response = json.loads(accepted.stdout)
        decoded = base64.urlsafe_b64decode(
            response["payload_b64u"] + "=" * (-len(response["payload_b64u"]) % 4)
        )
        self.assertEqual(decoded, b"real merged capture\n")

    def test_disclosure_days_and_deadline_overflow_are_rejected_before_commit(self) -> None:
        """Break caught: caller-selected metadata changes the fixed protocol TTL."""

        module = self.module()
        with Fixture(self) as fixture:
            self.assert_import_error(
                "invalid_argument",
                lambda: module.publish(
                    spool_path=str(fixture.spool),
                    transaction_id="2" * 64,
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                    disclosure_days=8,
                ),
            )
            with mock.patch.object(
                module.time,
                "time_ns",
                return_value=4_102_444_800_000 * 1_000_000,
            ):
                self.assert_import_error(
                    "deadline_overflow",
                    lambda: module.publish(
                        spool_path=str(fixture.spool),
                        transaction_id="3" * 64,
                        repository_root=str(fixture.root),
                        state_dir=str(fixture.state),
                        disclosure_days=7,
                    ),
                )
            self.assertFalse(fixture.state.exists())

    def test_registry_ensure_registered_is_noop_only_for_equal_deadline(self) -> None:
        """Break caught: recovery either refuses its own retry or silently changes expiry."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with Fixture(self) as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as store:
                issued = store.issue(
                    payload=b"plain",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="a" * 64,
                    artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                )
                namespace = store.namespace_id
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=namespace,
                create=True,
            ) as registry:
                first = registry.ensure_registered(
                    issued.handle,
                    expires_at_unix_ms=900,
                    observed_at_unix_ms=100,
                )
                same = registry.ensure_registered(
                    issued.handle,
                    expires_at_unix_ms=900,
                    observed_at_unix_ms=700,
                )
                self.assertEqual(first["generation"], 1)
                self.assertEqual(same["generation"], 1)
                self.assertEqual(same["expires_at_unix_ms"], 900)
                self.assertEqual(same["status"], "active")
                with self.assertRaises(module.ReferenceExpiryError) as caught:
                    registry.ensure_registered(
                        issued.handle,
                        expires_at_unix_ms=901,
                        observed_at_unix_ms=700,
                    )
                self.assertEqual(
                    caught.exception.code.value, "reference_already_registered"
                )

    def test_store_file_issuance_streams_one_idempotent_capability(self) -> None:
        """Break caught: import must materialize a second full spool for byte-only issue."""

        with Fixture(self) as fixture:
            payload = fixture.spool.read_bytes()
            subject = framed_sha256_hex(MERGED_SUBJECT_DOMAIN, payload)
            descriptor = os.open(
                fixture.spool,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                with CapabilityStore.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    create=True,
                ) as store:
                    first = store.ensure_issued_file(
                        source_fd=descriptor,
                        byte_length=len(payload),
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256=subject,
                        subject_identity_domain=MERGED_SUBJECT_DOMAIN,
                        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                        idempotency_key="e" * 64,
                    )
                    retried = store.ensure_issued_file(
                        source_fd=descriptor,
                        byte_length=len(payload),
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256=subject,
                        subject_identity_domain=MERGED_SUBJECT_DOMAIN,
                        artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                        idempotency_key="e" * 64,
                    )
                    summary = store.inspect_counts()
                    stored = store.resolve(
                        first.handle,
                        expected_root_identity_sha256=fixture.root_identity,
                    )
            finally:
                os.close(descriptor)
            self.assertEqual(retried.handle, first.handle)
            self.assertEqual(stored.payload, payload)
            self.assertEqual(summary.artifact_count, 1)

    def test_imported_merged_bytes_expand_only_while_registry_is_active(self) -> None:
        """Break caught: merged bytes bypass expiry or are mistaken for legacy CGRF."""

        module = self.module()
        cli = importlib.import_module("context_guard_receipt.cli")
        expiry = importlib.import_module("context_guard_receipt.reference_expiry")
        with Fixture(self) as fixture:
            published = self.publish(fixture, "4" * 64, observed_at=1_000)
            backend = cli._LazyResolutionStore(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            )
            with mock.patch.object(
                expansion.time if hasattr(expansion, "time") else module.time,
                "time_ns",
                return_value=604_800_999 * 1_000_000,
            ):
                exact = expansion.expand_capability(
                    published["reference"],
                    root=str(fixture.root),
                    store=backend,
                    git_executable=git_executable(),
                )
            self.assertEqual(exact.disposition, expansion.ExpansionDisposition.EXACT)
            self.assertEqual(exact.output_bytes, fixture.spool.read_bytes())

            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                namespace = store.namespace_id
            with expiry.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=namespace,
            ) as registry:
                registry.revoke(
                    published["reference"],
                    expected_generation=1,
                    observed_at_unix_ms=2_000,
                )
            refused = expansion.expand_capability(
                published["reference"],
                root=str(fixture.root),
                store=backend,
                git_executable=git_executable(),
            )
            self.assertEqual(refused.disposition, expansion.ExpansionDisposition.REFUSED)
            self.assertEqual(refused.refusal["reason"], "capability_rejected")

    def test_merged_without_registry_refuses_while_legacy_remains_readable(self) -> None:
        """Break caught: the new active-registration rule retroactively breaks CGRF."""

        with Fixture(self) as fixture:
            root_identity = fixture.root_identity
            merged = fixture.spool.read_bytes()
            legacy = canonical_legacy_capture()

            class Backend:
                def __init__(self, artifact: StoredArtifact) -> None:
                    self.artifact = artifact

                def resolve(self, _handle: str, *, expected_root_identity_sha256: str):
                    if expected_root_identity_sha256 != root_identity:
                        raise AssertionError("unexpected root")
                    return self.artifact

            def stored(payload: bytes, domain: str) -> StoredArtifact:
                return StoredArtifact(
                    artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                    byte_length=len(payload),
                    namespace_id="a" * 64,
                    payload=payload,
                    payload_sha256=framed_sha256_hex(STORE_PAYLOAD_DOMAIN, payload),
                    root_identity_sha256=root_identity,
                    subject_identity_sha256=framed_sha256_hex(domain, payload),
                )

            merged_result = expansion.expand_capability(
                HANDLE,
                root=str(fixture.root),
                store=Backend(stored(merged, MERGED_SUBJECT_DOMAIN)),
                git_executable=git_executable(),
            )
            legacy_result = expansion.expand_capability(
                HANDLE,
                root=str(fixture.root),
                store=Backend(stored(legacy, LEGACY_SUBJECT_DOMAIN)),
                git_executable=git_executable(),
            )

        self.assertEqual(
            merged_result.disposition, expansion.ExpansionDisposition.REFUSED
        )
        self.assertEqual(legacy_result.disposition, expansion.ExpansionDisposition.EXACT)
        self.assertEqual(legacy_result.output_bytes, legacy)

    def test_malformed_symlink_and_public_spools_do_not_commit(self) -> None:
        """Break caught: untrusted or noncanonical spool bytes reach durable storage."""

        module = self.module()
        with Fixture(self) as fixture:
            variants: list[tuple[str, Path, str]] = []
            invalid_utf8 = fixture.base / "invalid.txt"
            invalid_utf8.write_bytes(b"bad\xff")
            invalid_utf8.chmod(0o600)
            variants.append(("invalid_utf8", invalid_utf8, "noncanonical_spool"))
            public = fixture.base / "public.txt"
            public.write_bytes(b"public\n")
            public.chmod(0o644)
            variants.append(("permissions", public, "unsafe_spool"))
            symlink = fixture.base / "symlink.txt"
            symlink.symlink_to(fixture.spool)
            variants.append(("symlink", symlink, "unsafe_spool"))
            for index, (name, path, reason) in enumerate(variants):
                with self.subTest(name=name):
                    self.assert_import_error(
                        reason,
                        lambda path=path, index=index: module.publish(
                            spool_path=str(path),
                            transaction_id=f"{index + 5:x}" * 64,
                            repository_root=str(fixture.root),
                            state_dir=str(fixture.state),
                            disclosure_days=7,
                        ),
                    )

            self.assertFalse(fixture.state.exists())

    def test_frozen_ten_million_byte_boundary_is_accepted_and_one_more_is_rejected(self) -> None:
        """Break caught: root and companion disagree on the frozen spool cap."""

        boundary = b"x" * 10_000_000
        with Fixture(self) as fixture:
            fixture.write_spool(boundary)
            published = self.publish(fixture, "5" * 64, observed_at=1_000)
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                stored = store.resolve(
                    published["reference"],
                    expected_root_identity_sha256=fixture.root_identity,
                )
            self.assertEqual(stored.byte_length, 10_000_000)
            self.assertEqual(stored.payload, boundary)

        module = self.module()
        with Fixture(self) as fixture:
            fixture.write_spool(boundary + b"x")
            self.assert_import_error(
                "spool_too_large",
                lambda: module.publish(
                    spool_path=str(fixture.spool),
                    transaction_id="6" * 64,
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                    disclosure_days=7,
                ),
            )
            self.assertFalse(fixture.state.exists())

    def test_canonical_cr_lf_and_crlf_are_preserved_exactly(self) -> None:
        """Break caught: producer-preserved carriage returns are rejected or normalized."""

        with Fixture(self) as fixture:
            expected = b"carriage\rline-feed\npaired\r\n"
            fixture.write_spool(expected)
            published = self.publish(fixture, "8" * 64, observed_at=1_000)
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                stored = store.resolve(
                    published["reference"],
                    expected_root_identity_sha256=fixture.root_identity,
                )
            self.assertEqual(stored.payload, expected)

    def test_commit_uncertainty_and_phase_recovery_keep_exactly_one_capability(self) -> None:
        """Break caught: recovery mints a replacement or exposes a pre-registration handle."""

        module = self.module()
        store_module = importlib.import_module("context_guard_receipt.store")
        with Fixture(self) as fixture:
            original = store_module.CapabilityStore.ensure_issued_file
            raised = False

            def uncertain(opened_store, **kwargs):
                nonlocal raised
                result = original(opened_store, **kwargs)
                if not raised:
                    raised = True
                    raise store_module.StoreError(
                        store_module.StoreErrorCode.COMMIT_UNCERTAIN
                    )
                return result

            with mock.patch.object(
                store_module.CapabilityStore, "ensure_issued_file", uncertain
            ):
                result = self.publish(fixture, "a" * 64, observed_at=1_000)
            with mock.patch.object(module.time, "time_ns", return_value=2_000_000_000):
                recovered = module.recover(
                    transaction_id="a" * 64,
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                )
            self.assertEqual(recovered["reference"], result["reference"])
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                summary = store.inspect_counts()
            self.assertEqual(summary.artifact_count, 1)
            self.assertEqual(summary.capability_count, 1)

    def test_aggregate_inspection_contains_no_transaction_reference_or_path(self) -> None:
        """Break caught: aggregate operations leak planted transaction metadata."""

        module = self.module()
        with Fixture(self) as fixture:
            result = self.publish(fixture, "b" * 64)
            aggregate = module.inspect(
                repository_root=str(fixture.root), state_dir=str(fixture.state)
            )
            rendered = repr(aggregate)
            self.assertEqual(aggregate["registered_transaction_count"], 1)
            self.assertEqual(aggregate["pending_transaction_count"], 0)
            self.assertNotIn("b" * 64, rendered)
            self.assertNotIn(result["reference"], rendered)
            self.assertNotIn(str(fixture.spool), rendered)

    def test_public_cli_emits_closed_adapter_shape_and_recovers_by_transaction(self) -> None:
        """Break caught: root adapter must scrape prose or receive pre-registration data."""

        with Fixture(self) as fixture:
            imported = run_cli(
                "import",
                "merged-capture",
                "--spool",
                str(fixture.spool),
                "--transaction-id",
                "c" * 64,
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--disclosure-days",
                "7",
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(imported.stderr, b"")
            payload = json.loads(imported.stdout)
            self.assertEqual(
                set(payload),
                {
                    "evidence_boundary",
                    "import_result",
                    "operation",
                    "schema_version",
                    "status",
                },
            )
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["operation"], "import_merged_capture")
            result = payload["import_result"]
            self.assertEqual(
                set(result),
                {
                    "actionable",
                    "expires_at_unix_ms",
                    "reason",
                    "reference",
                    "status",
                    "transaction_id",
                },
            )
            self.assertEqual(result["status"], "registered")
            self.assertEqual(result["transaction_id"], "c" * 64)
            self.assertIs(result["actionable"], True)

            recovered = run_cli(
                "recover",
                "merged-capture",
                "--transaction-id",
                "c" * 64,
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            recovered_result = json.loads(recovered.stdout)["import_result"]
            self.assertEqual(recovered_result["reference"], result["reference"])

    def test_public_cli_failure_never_echoes_spool_transaction_or_reference(self) -> None:
        """Break caught: closed CLI errors reflect attacker-planted authority or paths."""

        with Fixture(self) as fixture:
            planted = "d" * 64
            fixture.spool.chmod(0o644)
            refused = run_cli(
                "import",
                "merged-capture",
                "--spool",
                str(fixture.spool),
                "--transaction-id",
                planted,
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
                "--disclosure-days",
                "7",
            )
            self.assertEqual(refused.returncode, 65)
            self.assertEqual(refused.stdout, b"")
            self.assertNotIn(str(fixture.spool).encode(), refused.stderr)
            self.assertNotIn(planted.encode(), refused.stderr)
            error = json.loads(refused.stderr)
            self.assertEqual(error["operation"], "import_merged_capture")
            self.assertEqual(error["reason"], "unsafe_spool")

    def test_public_cli_inspect_failure_uses_inspect_operation(self) -> None:
        with Fixture(self) as fixture:
            response = run_cli(
                "inspect",
                "merged-capture-import",
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
            )
            self.assertEqual(response.returncode, 74)
            self.assertEqual(response.stdout, b"")
            error = json.loads(response.stderr)
            self.assertEqual(error["operation"], "inspect_merged_capture_import")

    def test_exact_expiry_boundary_clock_rollback_and_revoke_retain_artifact(self) -> None:
        """Break caught: boundary is off by one, rollback reopens, or denial deletes bytes."""

        expiry = importlib.import_module("context_guard_receipt.reference_expiry")
        with Fixture(self) as fixture:
            published = self.publish(fixture, "f" * 64, observed_at=1_000)
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                namespace = store.namespace_id
            with expiry.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=namespace,
            ) as registry:
                self.assertTrue(
                    registry.is_registered_and_accessible(
                        published["reference"], observed_at_unix_ms=604_800_999
                    )
                )
                self.assertFalse(
                    registry.is_registered_and_accessible(
                        published["reference"], observed_at_unix_ms=604_801_000
                    )
                )
                snapshot = registry.inspect(
                    observed_at_unix_ms=604_801_000, limit=1
                )
                self.assertEqual(
                    snapshot["reference_summaries"][0]["expires_at_unix_ms"],
                    604_801_000,
                )
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                retained = store.inspect_counts()
            self.assertEqual(retained.artifact_count, 1)

        with Fixture(self) as fixture:
            published = self.publish(fixture, "0" * 64, observed_at=10_000)
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                namespace = store.namespace_id
            with expiry.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=namespace,
            ) as registry:
                self.assertTrue(
                    registry.is_registered_and_accessible(
                        published["reference"], observed_at_unix_ms=20_000
                    )
                )
                self.assertFalse(
                    registry.is_registered_and_accessible(
                        published["reference"], observed_at_unix_ms=19_999
                    )
                )
                snapshot = registry.inspect(observed_at_unix_ms=20_000, limit=1)
                self.assertEqual(
                    snapshot["reference_summaries"][0]["expires_at_unix_ms"],
                    604_810_000,
                )

    def test_crash_recovery_at_each_journal_phase_never_mints_twice(self) -> None:
        """Break caught: phase uncertainty exposes early authority or creates replacement."""

        module = self.module()
        store_module = importlib.import_module("context_guard_receipt.store")

        with Fixture(self) as fixture:
            with mock.patch.object(
                store_module.CapabilityStore,
                "ensure_issued_file",
                side_effect=store_module.StoreError(
                    store_module.StoreErrorCode.WRITE_FAILED
                ),
            ):
                self.assert_import_error(
                    "state_unavailable",
                    lambda: self.publish(fixture, "1" * 64),
                )
            self.assert_import_error(
                "transaction_abandoned",
                lambda: module.recover(
                    transaction_id="1" * 64,
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                ),
            )
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                self.assertEqual(store.inspect_counts().artifact_count, 0)

        for index, phase in enumerate(("issued", "validated", "registered"), 2):
            with self.subTest(phase=phase), Fixture(self) as fixture:
                original_advance = module._Journal.advance
                faulted = False

                def crash_after(journal, transaction_id, state, *, observed_at_unix_ms):
                    nonlocal faulted
                    result = original_advance(
                        journal,
                        transaction_id,
                        state,
                        observed_at_unix_ms=observed_at_unix_ms,
                    )
                    if state == phase and not faulted:
                        faulted = True
                        raise module.MergedCaptureError(
                            module.MergedCaptureErrorCode.COMMIT_UNCERTAIN
                        )
                    return result

                with mock.patch.object(module._Journal, "advance", crash_after):
                    self.assert_import_error(
                        "commit_uncertain",
                        lambda: self.publish(fixture, f"{index}" * 64),
                    )
                with mock.patch.object(
                    module.time, "time_ns", return_value=2_000_000_000
                ):
                    recovered = module.recover(
                        transaction_id=f"{index}" * 64,
                        repository_root=str(fixture.root),
                        state_dir=str(fixture.state),
                    )
                with CapabilityStore.open(
                    state_dir=str(fixture.state), repository_root=str(fixture.root)
                ) as store:
                    summary = store.inspect_counts()
                    expected_handle = store.idempotent_handle(f"{index}" * 64)
                self.assertEqual(recovered["reference"], expected_handle)
                self.assertEqual(summary.artifact_count, 1)
                self.assertEqual(summary.capability_count, 1)

    def test_pending_transaction_limit_is_hard_and_aggregate_only(self) -> None:
        """Break caught: crashed imports grow unbounded or inspection leaks identifiers."""

        module = self.module()
        store_module = importlib.import_module("context_guard_receipt.store")
        with Fixture(self) as fixture, mock.patch.object(
            store_module.CapabilityStore,
            "ensure_issued_file",
            side_effect=store_module.StoreError(
                store_module.StoreErrorCode.WRITE_FAILED
            ),
        ):
            for index in range(32):
                self.assert_import_error(
                    "state_unavailable",
                    lambda index=index: module.publish(
                        spool_path=str(fixture.spool),
                        transaction_id=f"{index:064x}",
                        repository_root=str(fixture.root),
                        state_dir=str(fixture.state),
                        disclosure_days=7,
                    ),
                )
            self.assert_import_error(
                "pending_quota_exceeded",
                lambda: module.publish(
                    spool_path=str(fixture.spool),
                    transaction_id=f"{32:064x}",
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                    disclosure_days=7,
                ),
            )
            aggregate = module.inspect(
                repository_root=str(fixture.root), state_dir=str(fixture.state)
            )
            self.assertEqual(aggregate["pending_transaction_count"], 32)
            self.assertEqual(
                aggregate["pending_artifact_bytes"],
                32 * len(fixture.spool.read_bytes()),
            )
            rendered = repr(aggregate)
            self.assertNotIn(f"{31:064x}", rendered)
            self.assertNotIn(str(fixture.spool), rendered)

    def test_concurrent_same_transaction_returns_one_registered_capability(self) -> None:
        """Break caught: concurrent old/new access publishes duplicate store records."""

        module = self.module()
        with Fixture(self) as fixture:
            barrier = threading.Barrier(2)

            def import_once(_value: int) -> dict[str, object]:
                barrier.wait()
                return module.publish(
                    spool_path=str(fixture.spool),
                    transaction_id="9" * 64,
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                    disclosure_days=7,
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(import_once, range(2)))
            self.assertEqual(results[0]["reference"], results[1]["reference"])
            self.assertEqual(
                results[0]["expires_at_unix_ms"],
                results[1]["expires_at_unix_ms"],
            )
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                summary = store.inspect_counts()
            self.assertEqual(summary.artifact_count, 1)
            self.assertEqual(summary.capability_count, 1)

    def test_authenticated_journal_and_errors_never_contain_planted_authority_or_path(self) -> None:
        """Break caught: recovery metadata becomes a handle/path disclosure channel."""

        module = self.module()
        with Fixture(self) as fixture:
            result = self.publish(fixture, "a" * 64)
            record_path = (
                fixture.state
                / "auxiliary-v1"
                / "reference-expiry-v1"
                / "import-transactions-v1"
                / "records"
                / ("a" * 64)
            )
            raw = record_path.read_bytes()
            self.assertNotIn(result["reference"].encode("ascii"), raw)
            self.assertNotIn(str(fixture.spool).encode("utf-8"), raw)
            planted = b"/private/planted/path-cgr1p_HOSTILE"
            record_path.write_bytes(raw + planted)
            with self.assertRaises(module.MergedCaptureError) as caught:
                module.inspect(
                    repository_root=str(fixture.root),
                    state_dir=str(fixture.state),
                )
            self.assertEqual(caught.exception.code.value, "state_corrupt")
            rendered = str(caught.exception) + repr(caught.exception)
            self.assertNotIn(planted.decode("ascii"), rendered)

    def test_corrupt_merged_payload_is_refused_even_with_positive_active_backend(self) -> None:
        """Break caught: active registry status bypasses canonical UTF-8 validation."""

        with Fixture(self) as fixture:
            payload = b"not-canonical\xff"
            artifact = StoredArtifact(
                artifact_type=ArtifactType.COMMAND_CAPTURE_BYTES,
                byte_length=len(payload),
                namespace_id="a" * 64,
                payload=payload,
                payload_sha256=framed_sha256_hex(STORE_PAYLOAD_DOMAIN, payload),
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256=framed_sha256_hex(
                    MERGED_SUBJECT_DOMAIN, payload
                ),
            )

            class ActiveBackend:
                def resolve(
                    self, _handle: str, *, expected_root_identity_sha256: str
                ) -> StoredArtifact:
                    self_expected = artifact.root_identity_sha256
                    if expected_root_identity_sha256 != self_expected:
                        raise AssertionError("unexpected root")
                    return artifact

                def is_reference_active(self, _handle: str) -> bool:
                    return True

            result = expansion.expand_capability(
                HANDLE,
                root=str(fixture.root),
                store=ActiveBackend(),
                git_executable=git_executable(),
            )
            self.assertEqual(result.disposition, expansion.ExpansionDisposition.REFUSED)
            self.assertEqual(result.refusal["reason"], "artifact_invalid")


if __name__ == "__main__":
    unittest.main()
