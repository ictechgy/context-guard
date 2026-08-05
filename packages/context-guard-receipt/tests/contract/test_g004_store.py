from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from multiprocessing import get_context
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
METADATA_SCHEMA_PATH = PACKAGE_ROOT / "schemas/store-metadata.schema.json"
RECORD_SCHEMA_PATH = PACKAGE_ROOT / "schemas/capability-record.schema.json"
COMMIT_SCHEMA_PATH = PACKAGE_ROOT / "schemas/store-commit.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


def store_module():
    try:
        return importlib.import_module("context_guard_receipt.store")
    except ModuleNotFoundError as error:
        raise AssertionError("G004 capability store implementation is missing") from error


def identity_module():
    return importlib.import_module("context_guard_receipt.identity")


def git_executable() -> str:
    candidate = shutil.which("git")
    if candidate is None:
        raise unittest.SkipTest("git is unavailable")
    return str(Path(candidate).resolve())


EVIDENCE_BOUNDARY = {
    "evidence_class": "companion_local_receipt_only",
    "host_request_owned": False,
    "provider_claim_authority": False,
    "provider_join_status": "missing",
    "runtime_observer_present": False,
    "schema_version": "contextguard-receipt-evidence-boundary/v1",
    "selected_branch": "S2-UNSUPPORTED",
    "selected_transport": "NONE",
    "stage1_evidence": False,
    "stage2_evidence": False,
}


def issue_in_process(arguments: tuple[str, str, str, str]) -> str:
    python_root, state_dir, repository_root, root_identity = arguments
    if python_root not in sys.path:
        sys.path.insert(0, python_root)
    store = importlib.import_module("context_guard_receipt.store")
    try:
        opened = store.CapabilityStore.open(
            state_dir=state_dir,
            repository_root=repository_root,
            git_executable=git_executable(),
        )
        try:
            opened.issue(
                payload=b"x",
                root_identity_sha256=root_identity,
                subject_identity_sha256="9" * 64,
                artifact_type=store.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            return "issued"
        finally:
            opened.close()
    except store.StoreError as error:
        return error.code.value


class StoreFixture:
    def __init__(self, testcase: unittest.TestCase, *, limits=None) -> None:
        self.testcase = testcase
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "repository"
        self.state_dir = self.base / "private-state"
        self.root.mkdir(mode=0o700)
        identity = identity_module()
        self.git = git_executable()
        self.root_identity = identity.snapshot_repository(
            self.root, git_executable=self.git
        )["instance"]["identity_sha256"]
        self.store = store_module().CapabilityStore.open(
            state_dir=str(self.state_dir),
            repository_root=str(self.root),
            git_executable=self.git,
            create=True,
            limits=limits,
        )

    def close(self) -> None:
        self.store.close()
        self.temporary_directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        self.close()


class G004CapabilityStoreTests(unittest.TestCase):
    def assert_store_error(self, code: str, operation) -> None:
        module = store_module()
        with self.assertRaises(module.StoreError) as caught:
            operation()
        self.assertEqual(caught.exception.code.value, code)

    def test_issue_survives_restart_and_retrieves_only_with_exact_bindings(self) -> None:
        """Break caught: issued authority is not durable or retrieval skips a binding."""

        module = store_module()
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            root_identity = identity.snapshot_repository(
                root, git_executable=git_executable()
            )["instance"]["identity_sha256"]
            subject_identity = "2" * 64
            payload = b"exact\x00payload\xff\n"
            limits = module.StoreLimits(
                max_artifacts=4,
                max_total_artifact_bytes=128,
                max_capabilities=4,
                max_single_artifact_bytes=64,
            )

            first = module.CapabilityStore.open(
                state_dir=str(state_dir),
                repository_root=str(root),
                git_executable=git_executable(),
                create=True,
                limits=limits,
            )
            issued = first.issue(
                payload=payload,
                root_identity_sha256=root_identity,
                subject_identity_sha256=subject_identity,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            first.close()

            reopened = module.CapabilityStore.open(
                state_dir=str(state_dir),
                repository_root=str(root),
                git_executable=git_executable(),
            )
            stored = reopened.retrieve(
                issued.handle,
                expected_namespace_id=issued.namespace_id,
                expected_root_identity_sha256=root_identity,
                expected_subject_identity_sha256=subject_identity,
                expected_artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            self.assertEqual(stored.payload, payload)
            self.assertEqual(stored.byte_length, len(payload))
            self.assertEqual(stored.namespace_id, issued.namespace_id)
            self.assertEqual(stored.root_identity_sha256, root_identity)
            self.assertEqual(stored.subject_identity_sha256, subject_identity)
            reopened.close()

    def test_resolve_reveals_sealed_bindings_from_capability_and_exact_root(self) -> None:
        """Break caught: expansion must guess sealed subject/type before opening its envelope."""

        module = store_module()
        with StoreFixture(self) as fixture:
            issued = fixture.store.issue(
                payload=b"sealed-expansion",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="a" * 64,
                artifact_type=module.ArtifactType.BLUEPRINT_ITEM_BYTES,
            )
            self.assertTrue(
                hasattr(fixture.store, "resolve"),
                "CapabilityStore.resolve is required for non-oracular expansion",
            )
            stored = fixture.store.resolve(
                issued.handle,
                expected_root_identity_sha256=fixture.root_identity,
            )
            self.assertEqual(stored.payload, b"sealed-expansion")
            self.assertEqual(stored.artifact_type, module.ArtifactType.BLUEPRINT_ITEM_BYTES)
            self.assertEqual(stored.subject_identity_sha256, "a" * 64)
            self.assertEqual(stored.root_identity_sha256, fixture.root_identity)
            self.assertEqual(stored.namespace_id, issued.namespace_id)

    def test_resolve_collapses_malformed_forged_cross_root_and_cross_namespace_authority(
        self,
    ) -> None:
        """Break caught: resolve becomes an oracle for roots, namespaces, or handle contents."""

        module = store_module()
        with StoreFixture(self) as fixture:
            issued = fixture.store.issue(
                payload=b"non-oracular",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="b" * 64,
                artifact_type=module.ArtifactType.TOOL_SCHEMA_SET_BYTES,
            )
            cases = (
                ("cgr1p_HOSTILE-/private/path", fixture.root_identity),
                ("cgr1p_" + "A" * 43, fixture.root_identity),
                (issued.handle, "f" * 64),
            )
            for handle, expected_root in cases:
                with self.subTest(handle_length=len(handle), root=expected_root[:1]):
                    with self.assertRaises(module.StoreError) as caught:
                        fixture.store.resolve(
                            handle,
                            expected_root_identity_sha256=expected_root,
                        )
                    self.assertEqual(caught.exception.code.value, "capability_rejected")
                    rendered = str(caught.exception) + repr(caught.exception)
                    self.assertNotIn(handle, rendered)
                    self.assertNotIn(expected_root, rendered)
                    self.assertNotIn(str(fixture.state_dir), rendered)

            other = module.CapabilityStore.open(
                state_dir=str(fixture.base / "other-private-state"),
                repository_root=str(fixture.root),
                git_executable=fixture.git,
                create=True,
            )
            try:
                with self.assertRaises(module.StoreError) as caught:
                    other.resolve(
                        issued.handle,
                        expected_root_identity_sha256=fixture.root_identity,
                    )
                self.assertEqual(caught.exception.code.value, "capability_rejected")
                self.assertNotIn(issued.handle, repr(caught.exception))
            finally:
                other.close()

    def test_resolve_validates_record_hmac_before_revealing_sealed_content(self) -> None:
        """Break caught: resolve returns metadata whose authenticated record was modified."""

        module = store_module()
        with StoreFixture(self) as fixture:
            issued = fixture.store.issue(
                payload=b"authenticated",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="c" * 64,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            record_path = next(fixture.state_dir.rglob("record.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["subject_identity_sha256"] = "d" * 64
            canonical_record = json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            record_path.write_bytes(
                (canonical_record + "\n").encode("utf-8")
            )
            record_path.chmod(0o600)
            self.assert_store_error(
                "store_tampered",
                lambda: fixture.store.resolve(
                    issued.handle,
                    expected_root_identity_sha256=fixture.root_identity,
                ),
            )

    def test_capabilities_are_256_bit_opaque_unique_and_never_persisted_or_reflected(self) -> None:
        """Break caught: authority is predictable, path/content-derived, or leaks at rest."""

        module = store_module()
        with StoreFixture(self) as fixture:
            issued = [
                fixture.store.issue(
                    payload=b"same-payload",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="3" * 64,
                    artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                )
                for _ in range(2)
            ]
            self.assertNotEqual(issued[0].handle, issued[1].handle)
            for item in issued:
                self.assertRegex(item.handle, r"^cgr1p_[A-Za-z0-9_-]{43}$")
                self.assertNotIn(item.handle, repr(item))
                stored_bytes = b"".join(
                    path.read_bytes()
                    for path in fixture.state_dir.rglob("*")
                    if path.is_file()
                )
                self.assertNotIn(item.handle.encode("ascii"), stored_bytes)
            hostile = "cgr1p_HOSTILE-/private/path"
            with self.assertRaises(module.StoreError) as caught:
                fixture.store.retrieve(
                    hostile,
                    expected_namespace_id=issued[0].namespace_id,
                    expected_root_identity_sha256=fixture.root_identity,
                    expected_subject_identity_sha256="3" * 64,
                    expected_artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                )
            self.assertEqual(caught.exception.code.value, "capability_rejected")
            self.assertNotIn("HOSTILE", str(caught.exception))
            self.assertNotIn("private", repr(caught.exception))

    def test_batch_is_one_atomic_publication_and_capability_byte_prediction_is_exact(self) -> None:
        """Break caught: a batch exposes a strict subset or benefit math guesses handle size."""

        module = store_module()
        with StoreFixture(self) as fixture:
            requests = (
                module.ArtifactRequest(
                    payload=b"whole",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="4" * 64,
                    artifact_type=module.ArtifactType.BLUEPRINT_WHOLE_BYTES,
                ),
                module.ArtifactRequest(
                    payload=b"item",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="5" * 64,
                    artifact_type=module.ArtifactType.BLUEPRINT_ITEM_BYTES,
                ),
            )
            issued = fixture.store.issue_batch(requests)
            self.assertEqual(len(issued), 2)
            self.assertEqual(module.predicted_capability_bytes(2), 98)
            summary = fixture.store.inspect_counts()
            self.assertEqual(
                (summary.artifact_count, summary.capability_count, summary.total_artifact_bytes),
                (2, 2, 9),
            )
            commits = list((fixture.state_dir / "store-v1/commits").iterdir())
            self.assertEqual(len(commits), 1)
            self.assertEqual(len(list(commits[0].glob("*/payload.bin"))), 2)

    def test_wrong_namespace_root_subject_and_type_all_reject_without_bytes(self) -> None:
        """Break caught: possession bypasses one of the four mandatory bindings."""

        module = store_module()
        with StoreFixture(self) as fixture:
            issued = fixture.store.issue(
                payload=b"bound",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="6" * 64,
                artifact_type=module.ArtifactType.TOOL_SCHEMA_BYTES,
            )
            cases = (
                ("0" * 64, fixture.root_identity, "6" * 64, module.ArtifactType.TOOL_SCHEMA_BYTES),
                (issued.namespace_id, "1" * 64, "6" * 64, module.ArtifactType.TOOL_SCHEMA_BYTES),
                (issued.namespace_id, fixture.root_identity, "7" * 64, module.ArtifactType.TOOL_SCHEMA_BYTES),
                (issued.namespace_id, fixture.root_identity, "6" * 64, module.ArtifactType.TOOL_SCHEMA_SET_BYTES),
            )
            for namespace, root, subject, artifact_type in cases:
                with self.subTest(artifact_type=artifact_type, subject=subject[:1]):
                    self.assert_store_error(
                        "capability_rejected",
                        lambda namespace=namespace, root=root, subject=subject, artifact_type=artifact_type: fixture.store.retrieve(
                            issued.handle,
                            expected_namespace_id=namespace,
                            expected_root_identity_sha256=root,
                            expected_subject_identity_sha256=subject,
                            expected_artifact_type=artifact_type,
                        ),
                    )

    def test_state_dir_must_be_normalized_absolute_private_and_outside_repository(self) -> None:
        """Break caught: durable state falls back into a repository or follows a symlink."""

        module = store_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            root.mkdir(mode=0o700)
            git = git_executable()
            common = {
                "repository_root": str(root),
                "git_executable": git,
                "create": True,
            }
            self.assert_store_error(
                "state_dir_not_absolute",
                lambda: module.CapabilityStore.open(state_dir="relative", **common),
            )
            self.assert_store_error(
                "state_dir_not_normalized",
                lambda: module.CapabilityStore.open(
                    state_dir=str(base / "x/../state"), **common
                ),
            )
            self.assert_store_error(
                "state_dir_forbidden",
                lambda: module.CapabilityStore.open(
                    state_dir=str(root / "state"), **common
                ),
            )
            actual_parent = base / "actual"
            actual_parent.mkdir(mode=0o700)
            linked_parent = base / "linked"
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
            self.assert_store_error(
                "unsafe_state",
                lambda: module.CapabilityStore.open(
                    state_dir=str(linked_parent / "state"), **common
                ),
            )

    def test_existing_unsafe_hardlinked_lock_is_refused_without_mode_repair(self) -> None:
        """Break caught: opening a store mutates an unsafe pre-existing lock inode."""

        module = store_module()
        with StoreFixture(self) as fixture:
            state_dir = fixture.state_dir
            root = fixture.root
            git = fixture.git
            fixture.store.close()
            lock_path = state_dir / "lock"
            alias_path = state_dir / "lock-alias"
            lock_path.chmod(0o640)
            os.link(lock_path, alias_path)
            self.assert_store_error(
                "unsafe_state",
                lambda: module.CapabilityStore.open(
                    state_dir=str(state_dir),
                    repository_root=str(root),
                    git_executable=git,
                    create=True,
                ),
            )
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(alias_path.stat().st_mode & 0o777, 0o640)

    def test_state_directory_replacement_is_detected_before_detached_commit(self) -> None:
        """Break caught: a held fd publishes into a renamed store and returns a dead handle."""

        module = store_module()
        with StoreFixture(self) as fixture:
            detached = fixture.base / "detached-state"
            os.rename(fixture.state_dir, detached)
            fixture.state_dir.mkdir(mode=0o700)
            self.assert_store_error(
                "unsafe_state",
                lambda: fixture.store.issue(
                    payload=b"must-not-commit",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="d" * 64,
                    artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                ),
            )
            self.assertEqual(list((detached / "store-v1/commits").iterdir()), [])

    def test_exact_count_byte_and_capability_quotas_refuse_without_eviction(self) -> None:
        """Break caught: quota checks are off by one, race-prone, or evict old entries."""

        module = store_module()
        quota_cases = (
            (
                module.StoreLimits(
                    max_artifacts=1,
                    max_total_artifact_bytes=8,
                    max_capabilities=2,
                    max_single_artifact_bytes=8,
                ),
                "artifact_count_quota_exceeded",
            ),
            (
                module.StoreLimits(
                    max_artifacts=2,
                    max_total_artifact_bytes=1,
                    max_capabilities=2,
                    max_single_artifact_bytes=1,
                ),
                "artifact_bytes_quota_exceeded",
            ),
            (
                module.StoreLimits(
                    max_artifacts=2,
                    max_total_artifact_bytes=8,
                    max_capabilities=1,
                    max_single_artifact_bytes=8,
                ),
                "capability_count_quota_exceeded",
            ),
        )
        for limits, expected in quota_cases:
            with self.subTest(expected=expected), StoreFixture(self, limits=limits) as fixture:
                first = fixture.store.issue(
                    payload=b"x",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="8" * 64,
                    artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                )
                before = fixture.store.inspect_counts()
                self.assert_store_error(
                    expected,
                    lambda: fixture.store.issue(
                        payload=b"x",
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256="8" * 64,
                        artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                    ),
                )
                self.assertEqual(fixture.store.inspect_counts(), before)
                recovered = fixture.store.retrieve(
                    first.handle,
                    expected_namespace_id=first.namespace_id,
                    expected_root_identity_sha256=fixture.root_identity,
                    expected_subject_identity_sha256="8" * 64,
                    expected_artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                )
                self.assertEqual(recovered.payload, b"x")

    def test_oversized_batch_is_refused_before_inspecting_hostile_items(self) -> None:
        """Break caught: an over-quota batch performs attacker-controlled item work first."""

        module = store_module()
        limits = module.StoreLimits(
            max_artifacts=2,
            max_total_artifact_bytes=8,
            max_capabilities=1,
            max_single_artifact_bytes=8,
        )
        with StoreFixture(self, limits=limits) as fixture:
            valid = module.ArtifactRequest(
                payload=b"x",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="e" * 64,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            hostile = module.ArtifactRequest(
                payload=bytearray(b"not-exact-bytes"),
                root_identity_sha256="not-a-hash",
                subject_identity_sha256="not-a-hash",
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            self.assert_store_error(
                "capability_count_quota_exceeded",
                lambda: fixture.store.issue_batch((valid, hostile)),
            )
            self.assertEqual(fixture.store.inspect_counts().artifact_count, 0)

    def test_exact_hard_maximum_batch_has_one_bounded_atomic_manifest(self) -> None:
        """Break caught: default canonical JSON bounds make the documented hard cap unusable."""

        module = store_module()
        with StoreFixture(self) as fixture:
            request = module.ArtifactRequest(
                payload=b"",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="f" * 64,
                artifact_type=module.ArtifactType.TOOL_SCHEMA_BYTES,
            )
            issued = fixture.store.issue_batch((request,) * 1024)
            self.assertEqual(len(issued), 1024)
            summary = fixture.store.inspect_counts()
            self.assertEqual(
                (summary.artifact_count, summary.capability_count, summary.total_artifact_bytes),
                (1024, 1024, 0),
            )
            commits = list((fixture.state_dir / "store-v1/commits").iterdir())
            self.assertEqual(len(commits), 1)
            self.assertLessEqual((commits[0] / "manifest.json").stat().st_size, 128 * 1024)

    def test_payload_and_record_tampering_fail_closed(self) -> None:
        """Break caught: modified bytes or metadata are returned as issued authority."""

        module = store_module()
        for target_name, expected in (("payload.bin", "store_tampered"), ("record.json", "store_corrupt")):
            with self.subTest(target=target_name), StoreFixture(self) as fixture:
                issued = fixture.store.issue(
                    payload=b"original",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="a" * 64,
                    artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                )
                target = next(fixture.state_dir.rglob(target_name))
                raw = target.read_bytes()
                target.write_bytes((b"X" + raw[1:]) if raw else b"X")
                target.chmod(0o600)
                self.assert_store_error(
                    expected,
                    lambda: fixture.store.retrieve(
                        issued.handle,
                        expected_namespace_id=issued.namespace_id,
                        expected_root_identity_sha256=fixture.root_identity,
                        expected_subject_identity_sha256="a" * 64,
                        expected_artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                    ),
                )

    def test_authenticated_malformed_manifest_fails_with_stable_store_error(self) -> None:
        """Break caught: hostile manifest element types escape as a raw TypeError."""

        module = store_module()
        with StoreFixture(self) as fixture:
            fixture.store.issue(
                payload=b"manifest-shape",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="0" * 64,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            manifest_path = next(fixture.state_dir.rglob("manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["capability_lookup_sha256"].append(1)
            manifest_path.write_bytes(
                module._mac_document(
                    fixture.store._key,
                    b"contextguard-receipt/store-commit-mac/v1",
                    manifest,
                    limits=module._COMMIT_JSON_LIMITS,
                )
            )
            manifest_path.chmod(0o600)
            self.assert_store_error("store_corrupt", fixture.store.inspect_counts)

    def test_initialization_failure_closes_temporary_store_descriptor(self) -> None:
        """Break caught: failed first-time initialization leaks its temporary directory fd."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        module = store_module()
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            git = git_executable()
            identity.snapshot_repository(root, git_executable=git)
            before = len(os.listdir("/dev/fd"))
            real_fsync = module.os.fsync
            calls = 0

            def fail_key_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 4:
                    raise OSError("HOSTILE-initialization-fsync")
                real_fsync(descriptor)

            with mock.patch.object(module.os, "fsync", side_effect=fail_key_fsync):
                self.assert_store_error(
                    "write_failed",
                    lambda: module.CapabilityStore.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        git_executable=git,
                        create=True,
                    ),
                )
            self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_state_directory_creation_failure_closes_new_descriptor(self) -> None:
        """Break caught: a parent fsync failure leaks the newly created state directory fd."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        module = store_module()
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            git = git_executable()
            identity.snapshot_repository(root, git_executable=git)
            before = len(os.listdir("/dev/fd"))

            with mock.patch.object(
                module.os,
                "fsync",
                side_effect=OSError("HOSTILE-state-parent-fsync"),
            ):
                self.assert_store_error(
                    "write_failed",
                    lambda: module.CapabilityStore.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        git_executable=git,
                        create=True,
                    ),
                )
            self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_lock_creation_failure_closes_new_descriptor(self) -> None:
        """Break caught: a lock chmod failure leaks its newly created regular-file fd."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        module = store_module()
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "repository"
            state_dir = base / "private-state"
            root.mkdir(mode=0o700)
            git = git_executable()
            identity.snapshot_repository(root, git_executable=git)
            before = len(os.listdir("/dev/fd"))
            real_fchmod = module.os.fchmod

            def fail_regular_file(descriptor: int, mode: int) -> None:
                if stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("HOSTILE-lock-chmod")
                real_fchmod(descriptor, mode)

            with mock.patch.object(module.os, "fchmod", side_effect=fail_regular_file):
                self.assert_store_error(
                    "write_failed",
                    lambda: module.CapabilityStore.open(
                        state_dir=str(state_dir),
                        repository_root=str(root),
                        git_executable=git,
                        create=True,
                    ),
                )
            self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_prepublication_fsync_failure_exposes_nothing_and_requires_recovery(self) -> None:
        """Break caught: failed batches leak a partial committed capability."""

        module = store_module()
        with StoreFixture(self) as fixture:
            real_fsync = module.os.fsync
            calls = 0

            def fail_early(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("HOSTILE-disk-failure")
                real_fsync(descriptor)

            with mock.patch.object(module.os, "fsync", side_effect=fail_early):
                self.assert_store_error(
                    "write_failed",
                    lambda: fixture.store.issue_batch(
                        (
                            module.ArtifactRequest(
                                payload=b"one",
                                root_identity_sha256=fixture.root_identity,
                                subject_identity_sha256="b" * 64,
                                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                            ),
                            module.ArtifactRequest(
                                payload=b"two",
                                root_identity_sha256=fixture.root_identity,
                                subject_identity_sha256="c" * 64,
                                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                            ),
                        )
                    ),
                )
            summary = fixture.store.inspect_counts()
            self.assertEqual(summary.artifact_count, 0)
            self.assertTrue(summary.recovery_required)

    def test_prepublication_failure_closes_unpublished_descriptors(self) -> None:
        """Break caught: repeated storage failures leak entry and batch descriptors."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        module = store_module()
        before = len(os.listdir("/dev/fd"))
        fixture = StoreFixture(self)
        try:
            real_fsync = module.os.fsync
            calls = 0

            def fail_record(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("HOSTILE-record-fsync")
                real_fsync(descriptor)

            with mock.patch.object(module.os, "fsync", side_effect=fail_record):
                self.assert_store_error(
                    "write_failed",
                    lambda: fixture.store.issue(
                        payload=b"descriptor-check",
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256="2" * 64,
                        artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                    ),
                )
        finally:
            fixture.close()
        self.assertEqual(len(os.listdir("/dev/fd")), before)

    def test_postrename_fsync_failure_is_commit_uncertain_but_never_partial(self) -> None:
        """Break caught: post-publication durability failure is reported as ordinary write loss."""

        module = store_module()
        with StoreFixture(self) as fixture:
            real_fsync = module.os.fsync

            def fail_commit_directory(descriptor: int) -> None:
                if descriptor == fixture.store._commits_fd:
                    raise OSError("HOSTILE-post-rename-failure")
                real_fsync(descriptor)

            with mock.patch.object(
                module.os, "fsync", side_effect=fail_commit_directory
            ):
                self.assert_store_error(
                    "commit_uncertain",
                    lambda: fixture.store.issue(
                        payload=b"published-whole",
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256="1" * 64,
                        artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                    ),
                )
            summary = fixture.store.inspect_counts()
            self.assertEqual(
                (summary.artifact_count, summary.capability_count, summary.total_artifact_bytes),
                (1, 1, len(b"published-whole")),
            )
            self.assertFalse(summary.recovery_required)

    def test_concurrent_issuance_serializes_quota_without_duplicate_or_lost_commits(self) -> None:
        """Break caught: separate processes overrun quota or overwrite each other's commit."""

        module = store_module()
        limits = module.StoreLimits(
            max_artifacts=4,
            max_total_artifact_bytes=16,
            max_capabilities=4,
            max_single_artifact_bytes=4,
        )
        with StoreFixture(self, limits=limits) as fixture:
            arguments = (
                str(PYTHON_ROOT),
                str(fixture.state_dir),
                str(fixture.root),
                fixture.root_identity,
            )
            with ProcessPoolExecutor(
                max_workers=4, mp_context=get_context("spawn")
            ) as executor:
                results = list(executor.map(issue_in_process, [arguments] * 8))
            self.assertEqual(results.count("issued"), 4)
            self.assertEqual(results.count("artifact_count_quota_exceeded"), 4)
            summary = fixture.store.inspect_counts()
            self.assertEqual((summary.artifact_count, summary.capability_count), (4, 4))

    def test_same_instance_threads_serialize_the_entire_quota_transaction(self) -> None:
        """Break caught: threads share one flock description and both spend one capability."""

        module = store_module()
        barrier = threading.Barrier(2)
        seen_threads: set[int] = set()
        seen_guard = threading.Lock()

        class SynchronizedStore(module.CapabilityStore):
            def _scan(self, *, return_payload_for=None):
                usage = super()._scan(return_payload_for=return_payload_for)
                thread_id = threading.get_ident()
                with seen_guard:
                    first_scan = thread_id not in seen_threads
                    seen_threads.add(thread_id)
                if return_payload_for is None and first_scan:
                    try:
                        barrier.wait(timeout=0.5)
                    except threading.BrokenBarrierError:
                        pass
                return usage

        limits = module.StoreLimits(
            max_artifacts=2,
            max_total_artifact_bytes=2,
            max_capabilities=1,
            max_single_artifact_bytes=1,
        )
        with StoreFixture(self, limits=limits) as fixture:
            fixture.store.close()
            fixture.store = SynchronizedStore.open(
                state_dir=str(fixture.state_dir),
                repository_root=str(fixture.root),
                git_executable=fixture.git,
            )

            def issue_one(subject: str) -> str:
                try:
                    fixture.store.issue(
                        payload=b"x",
                        root_identity_sha256=fixture.root_identity,
                        subject_identity_sha256=subject * 64,
                        artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
                    )
                    return "issued"
                except module.StoreError as error:
                    return error.code.value

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(issue_one, ("1", "2")))
            self.assertEqual(results.count("issued"), 1)
            self.assertEqual(results.count("capability_count_quota_exceeded"), 1)
            summary = fixture.store.inspect_counts()
            self.assertEqual((summary.artifact_count, summary.capability_count), (1, 1))

    def test_fork_inherited_store_instance_is_rejected_and_parent_remains_usable(self) -> None:
        """Break caught: a child reuses the parent's mutex and flock open-file description."""

        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable")
        module = store_module()
        with StoreFixture(self) as fixture:
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:
                os.close(read_fd)
                try:
                    try:
                        fixture.store.inspect_counts()
                        result = b"accepted"
                    except module.StoreError as error:
                        result = error.code.value.encode("ascii")
                    os.write(write_fd, result)
                finally:
                    os.close(write_fd)
                    os._exit(0)

            os.close(write_fd)
            try:
                result = os.read(read_fd, 64)
            finally:
                os.close(read_fd)
            _waited_pid, wait_status = os.waitpid(child_pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(wait_status), 0)
            self.assertEqual(result, b"unsafe_state")
            self.assertEqual(fixture.store.inspect_counts().artifact_count, 0)

    def test_scan_rejects_legacy_state_above_capability_quota(self) -> None:
        """Break caught: a persisted over-capability race remains accepted after restart."""

        module = store_module()
        limits = module.StoreLimits(
            max_artifacts=2,
            max_total_artifact_bytes=2,
            max_capabilities=2,
            max_single_artifact_bytes=1,
        )
        with StoreFixture(self, limits=limits) as fixture:
            request = module.ArtifactRequest(
                payload=b"x",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="3" * 64,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            fixture.store.issue_batch((request,))
            fixture.store.issue_batch((request,))
            fixture.store.close()
            store_path = fixture.state_dir / "store-v1"
            key = (store_path / "integrity-key").read_bytes()
            metadata_path = store_path / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["limits"]["max_capabilities"] = 1
            metadata_path.write_bytes(
                module._mac_document(
                    key,
                    b"contextguard-receipt/store-metadata-mac/v1",
                    metadata,
                )
            )
            metadata_path.chmod(0o600)
            fixture.store = module.CapabilityStore.open(
                state_dir=str(fixture.state_dir),
                repository_root=str(fixture.root),
                git_executable=fixture.git,
            )
            self.assert_store_error("store_corrupt", fixture.store.inspect_counts)

    def test_scan_rejects_authenticated_legacy_artifact_above_single_byte_limit(self) -> None:
        """Break caught: sentinel over-read widens the persisted per-artifact quota by one."""

        module = store_module()
        limits = module.StoreLimits(
            max_artifacts=1,
            max_total_artifact_bytes=2,
            max_capabilities=1,
            max_single_artifact_bytes=2,
        )
        with StoreFixture(self, limits=limits) as fixture:
            fixture.store.issue(
                payload=b"xx",
                root_identity_sha256=fixture.root_identity,
                subject_identity_sha256="4" * 64,
                artifact_type=module.ArtifactType.RAW_EVIDENCE_BYTES,
            )
            fixture.store.close()
            store_path = fixture.state_dir / "store-v1"
            key = (store_path / "integrity-key").read_bytes()
            metadata_path = store_path / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["limits"]["max_single_artifact_bytes"] = 1
            metadata_path.write_bytes(
                module._mac_document(
                    key,
                    b"contextguard-receipt/store-metadata-mac/v1",
                    metadata,
                )
            )
            metadata_path.chmod(0o600)
            fixture.store = module.CapabilityStore.open(
                state_dir=str(fixture.state_dir),
                repository_root=str(fixture.root),
                git_executable=fixture.git,
            )
            self.assert_store_error("store_corrupt", fixture.store.inspect_counts)

    def test_store_schemas_are_closed_and_expiry_free(self) -> None:
        """Break caught: persisted records gain open/path/expiry fields or lose fixed bounds."""

        self.assertTrue(METADATA_SCHEMA_PATH.is_file())
        self.assertTrue(RECORD_SCHEMA_PATH.is_file())
        self.assertTrue(COMMIT_SCHEMA_PATH.is_file())
        metadata = json.loads(METADATA_SCHEMA_PATH.read_text(encoding="utf-8"))
        record = json.loads(RECORD_SCHEMA_PATH.read_text(encoding="utf-8"))
        commit = json.loads(COMMIT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertIs(metadata["additionalProperties"], False)
        self.assertIs(record["additionalProperties"], False)
        self.assertIs(commit["additionalProperties"], False)
        self.assertEqual(
            set(metadata["required"]),
            {
                "evidence_boundary",
                "integrity_hmac_sha256",
                "limits",
                "namespace_id",
                "schema_version",
            },
        )
        self.assertEqual(
            set(record["required"]),
            {
                "artifact_type",
                "byte_length",
                "capability_lookup_sha256",
                "evidence_boundary",
                "integrity_hmac_sha256",
                "namespace_id",
                "payload_sha256",
                "root_identity_sha256",
                "schema_version",
                "subject_identity_sha256",
            },
        )
        self.assertEqual(
            set(commit["required"]),
            {
                "capability_lookup_sha256",
                "evidence_boundary",
                "integrity_hmac_sha256",
                "schema_version",
            },
        )
        self.assertEqual(commit["properties"]["capability_lookup_sha256"]["maxItems"], 1024)
        self.assertTrue(commit["properties"]["capability_lookup_sha256"]["uniqueItems"])
        serialized = json.dumps((metadata, record, commit), sort_keys=True)
        for forbidden in ("path", "handle", "payload_b64", "expires", "expiry", "revoked"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            record["properties"]["artifact_type"]["enum"],
            [
                "raw_evidence_bytes",
                "blueprint_whole_bytes",
                "blueprint_item_bytes",
                "tool_schema_set_bytes",
                "tool_schema_bytes",
            ],
        )


if __name__ == "__main__":
    unittest.main()
