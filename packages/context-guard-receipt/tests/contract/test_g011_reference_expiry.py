from __future__ import annotations

import importlib
import base64
import json
import os
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

from context_guard_receipt.canonical import canonical_json_bytes  # noqa: E402
from context_guard_receipt.identity import snapshot_repository  # noqa: E402
from context_guard_receipt.store import ArtifactType, CapabilityStore  # noqa: E402


def request_bytes(operation: str, capability: str, value: object) -> bytes:
    request: dict[str, object] = {
        "capability": capability,
        "operation": operation,
        "schema_version": "contextguard-receipt-reference-expiry-request/v1",
    }
    request[
        "expires_at_unix_ms" if operation == "register" else "expected_generation"
    ] = value
    return canonical_json_bytes(request)


class ExpiryFixture:
    def __init__(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "repository"
        self.state = self.base / "state"
        self.root.mkdir(mode=0o700)
        snapshot = snapshot_repository(str(self.root))
        self.root_identity = snapshot["instance"]["identity_sha256"]
        with CapabilityStore.open(
            state_dir=str(self.state), repository_root=str(self.root), create=True
        ) as store:
            issued = store.issue(
                payload=b"retained artifact bytes",
                root_identity_sha256=self.root_identity,
                subject_identity_sha256="a" * 64,
                artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
            )
            self.capability = issued.handle
            self.store_namespace_id = issued.namespace_id

    @property
    def registry_dir(self) -> Path:
        return self.state / "auxiliary-v1" / "reference-expiry-v1"

    def close(self) -> None:
        self.temporary_directory.cleanup()

    def __enter__(self) -> "ExpiryFixture":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class G011ReferenceExpiryContractTests(unittest.TestCase):
    def assert_expiry_error(self, code: str, operation) -> None:
        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with self.assertRaises(module.ReferenceExpiryError) as caught:
            operation()
        self.assertEqual(caught.exception.code.value, code)
        self.assertNotIn("repository", str(caught.exception))

    def test_reference_expiry_public_contract_exists(self) -> None:
        """Break caught: the removable reference-expiry axis is absent."""

        try:
            module = importlib.import_module(
                "context_guard_receipt.reference_expiry"
            )
        except ModuleNotFoundError as error:
            self.fail(f"G011 reference expiry implementation is missing: {error}")
        for name in (
            "ReferenceExpiryError",
            "ReferenceExpiryErrorCode",
            "ReferenceExpiryLimits",
            "ReferenceExpiryRegistry",
            "parse_reference_expiry_request",
        ):
            self.assertTrue(hasattr(module, name), name)

    def test_request_parser_is_canonical_closed_and_bounds_time(self) -> None:
        """Break caught: ambiguous input, floats, or unbounded clocks gain authority."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        capability = "cgr1p_" + base64.urlsafe_b64encode(b"c" * 32).rstrip(
            b"="
        ).decode("ascii")
        registered = module.parse_reference_expiry_request(
            request_bytes("register", capability, 4_102_444_800_000)
        )
        revoked = module.parse_reference_expiry_request(
            request_bytes("revoke", capability, 1)
        )
        self.assertEqual(registered["operation"], "register")
        self.assertEqual(revoked["operation"], "revoke")
        invalid = (
            json.dumps(json.loads(request_bytes("register", capability, 1)), indent=2).encode(),
            canonical_json_bytes(
                {**json.loads(request_bytes("register", capability, 1)), "extra": False}
            ),
            request_bytes("register", capability, True),
            request_bytes("register", capability, -1),
            request_bytes("register", capability, 4_102_444_800_001),
            (
                b'{"capability":"'
                + capability.encode("ascii")
                + b'","expires_at_unix_ms":1.5,"operation":"register",'
                b'"schema_version":"contextguard-receipt-reference-expiry-request/v1"}\n'
            ),
            request_bytes("revoke", capability, 0),
            request_bytes("revoke", "cgr1p_forged", 1),
        )
        for raw in invalid:
            with self.subTest(raw=raw[:40]):
                self.assert_expiry_error(
                    "invalid_request",
                    lambda raw=raw: module.parse_reference_expiry_request(raw),
                )

    def test_deadline_transition_and_revoke_are_durable_without_artifact_deletion(self) -> None:
        """Break caught: expiry is reversible or mutates the sealed artifact store."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                result = registry.register(
                    fixture.capability,
                    expires_at_unix_ms=100,
                    observed_at_unix_ms=1,
                )
                self.assertEqual(result["generation"], 1)
                self.assertIs(
                    registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=99
                    ),
                    False,
                )
                self.assertIs(
                    registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=100
                    ),
                    True,
                )
                self.assertIs(
                    registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=2
                    ),
                    True,
                )
                snapshot = registry.inspect(observed_at_unix_ms=2, limit=1)
                self.assertEqual(snapshot["expired_reference_count"], 1)

            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                retained = store.resolve(
                    fixture.capability,
                    expected_root_identity_sha256=fixture.root_identity,
                )
            self.assertEqual(retained.payload, b"retained artifact bytes")

    def test_generation_cas_duplicate_and_namespace_binding_fail_closed(self) -> None:
        """Break caught: stale administrators or another store can revoke a reference."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=1000,
                    observed_at_unix_ms=1,
                )
                self.assert_expiry_error(
                    "reference_already_registered",
                    lambda: registry.register(
                        fixture.capability,
                        expires_at_unix_ms=2000,
                        observed_at_unix_ms=2,
                    ),
                )
                self.assert_expiry_error(
                    "cas_mismatch",
                    lambda: registry.revoke(
                        fixture.capability,
                        expected_generation=2,
                        observed_at_unix_ms=3,
                    ),
                )
                revoked = registry.revoke(
                    fixture.capability,
                    expected_generation=1,
                    observed_at_unix_ms=4,
                )
                self.assertEqual(revoked["generation"], 2)

            self.assert_expiry_error(
                "store_namespace_mismatch",
                lambda: module.ReferenceExpiryRegistry.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    store_namespace_id="b" * 64,
                ),
            )

    def test_registration_rejects_a_forged_capability_without_persisting_it(self) -> None:
        """Break caught: valid-looking random authority becomes an expiry record."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        forged = "cgr1p_" + base64.urlsafe_b64encode(os.urandom(32)).rstrip(
            b"="
        ).decode("ascii")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                self.assert_expiry_error(
                    "invalid_argument",
                    lambda: registry.register(
                        forged,
                        expires_at_unix_ms=1000,
                        observed_at_unix_ms=1,
                    ),
                )
                snapshot = registry.inspect(observed_at_unix_ms=1, limit=256)
            self.assertEqual(snapshot["registered_reference_count"], 0)

    def test_concurrent_duplicate_registration_has_one_winner_and_no_eviction(self) -> None:
        """Break caught: racing mutation publishes two generations or loses state."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            barrier = threading.Barrier(2)

            def register_once() -> str:
                barrier.wait()
                try:
                    with module.ReferenceExpiryRegistry.open(
                        state_dir=str(fixture.state),
                        repository_root=str(fixture.root),
                        store_namespace_id=fixture.store_namespace_id,
                        create=True,
                    ) as registry:
                        registry.register(
                            fixture.capability,
                            expires_at_unix_ms=1000,
                            observed_at_unix_ms=1,
                        )
                    return "ok"
                except module.ReferenceExpiryError as error:
                    return error.code.value

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = sorted(executor.map(lambda _value: register_once(), range(2)))
            self.assertEqual(outcomes, ["ok", "reference_already_registered"])
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
            ) as registry:
                snapshot = registry.inspect(observed_at_unix_ms=1, limit=256)
            self.assertEqual(snapshot["registered_reference_count"], 1)
            persisted = b"".join(
                path.read_bytes()
                for path in fixture.registry_dir.rglob("*")
                if path.is_file()
            )
            self.assertNotIn(fixture.capability.encode("ascii"), persisted)

    def test_concurrent_due_checks_make_one_irreversible_transition(self) -> None:
        """Break caught: concurrent expiry loses the denial or adds generations twice."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=10,
                    observed_at_unix_ms=1,
                )
            barrier = threading.Barrier(2)

            def expire_once() -> bool:
                barrier.wait()
                with module.ReferenceExpiryRegistry.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    store_namespace_id=fixture.store_namespace_id,
                ) as registry:
                    return registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=10
                    )

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda _value: expire_once(), range(2)))
            self.assertEqual(outcomes, [True, True])
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
            ) as registry:
                snapshot = registry.inspect(observed_at_unix_ms=0, limit=1)
            self.assertEqual(snapshot["expired_reference_count"], 1)
            self.assertEqual(snapshot["reference_summaries"][0]["generation"], 2)

    def test_active_checks_persist_a_non_decreasing_clock_high_water(self) -> None:
        """Break caught: a wall-clock rollback silently extends an active reference."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=100,
                    observed_at_unix_ms=10,
                )
                self.assertIs(
                    registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=90
                    ),
                    False,
                )
                rolled_back = registry.inspect(observed_at_unix_ms=50, limit=1)
            summary = rolled_back["reference_summaries"][0]
            self.assertEqual(summary["updated_at_unix_ms"], 90)
            self.assertEqual(summary["generation"], 2)
            self.assertEqual(summary["status"], "expired")

    def test_clock_rollback_cannot_block_explicit_revocation(self) -> None:
        """Break caught: a backward clock preserves active authority against CAS revoke."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=1000,
                    observed_at_unix_ms=100,
                )
                revoked = registry.revoke(
                    fixture.capability,
                    expected_generation=1,
                    observed_at_unix_ms=50,
                )
                snapshot = registry.inspect(observed_at_unix_ms=50, limit=1)
            self.assertEqual(revoked["status"], "revoked")
            self.assertEqual(
                snapshot["reference_summaries"][0]["updated_at_unix_ms"], 100
            )
            self.assertEqual(snapshot["revoked_reference_count"], 1)

    def test_inspection_batches_due_transitions_without_quadratic_rescans(self) -> None:
        """Break caught: one inspection rescans the whole registry per due entry."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            capabilities = [fixture.capability]
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                for index in range(3):
                    capabilities.append(
                        store.issue(
                            payload=f"retained-{index}".encode("ascii"),
                            root_identity_sha256=fixture.root_identity,
                            subject_identity_sha256=f"{index + 1:064x}",
                            artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                        ).handle
                    )
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                for capability in capabilities:
                    registry.register(
                        capability,
                        expires_at_unix_ms=10,
                        observed_at_unix_ms=1,
                    )
                with mock.patch.object(
                    registry, "_scan", wraps=registry._scan
                ) as scanned:
                    snapshot = registry.inspect(observed_at_unix_ms=10, limit=256)
            self.assertEqual(snapshot["expired_reference_count"], 4)
            self.assertLessEqual(scanned.call_count, 2)

    def test_partial_batch_publish_is_commit_uncertain_and_retains_store(self) -> None:
        """Break caught: a failed multi-expiry commit is accepted or deletes artifacts."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                other = store.issue(
                    payload=b"batch-fault-retained",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="e" * 64,
                    artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                ).handle
            store_root = fixture.state / "store-v1"
            before = {
                path.relative_to(store_root).as_posix(): path.read_bytes()
                for path in store_root.rglob("*")
                if path.is_file()
            }
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            ) as registry:
                for capability in (fixture.capability, other):
                    registry.register(
                        capability,
                        expires_at_unix_ms=10,
                        observed_at_unix_ms=1,
                    )
                real_rename = module.os.rename
                record_renames = 0

                def fail_second_record_rename(source, destination, **kwargs):
                    nonlocal record_renames
                    if kwargs.get("dst_dir_fd") == registry._records_fd:
                        record_renames += 1
                        if record_renames == 2:
                            raise OSError("injected")
                    return real_rename(source, destination, **kwargs)

                with mock.patch.object(
                    module.os, "rename", side_effect=fail_second_record_rename
                ):
                    self.assert_expiry_error(
                        "commit_uncertain",
                        lambda: registry.inspect(observed_at_unix_ms=10, limit=2),
                    )
            after = {
                path.relative_to(store_root).as_posix(): path.read_bytes()
                for path in store_root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            self.assert_expiry_error(
                "recovery_required",
                lambda: module.ReferenceExpiryRegistry.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    store_namespace_id=fixture.store_namespace_id,
                ),
            )

    def test_forked_child_rejects_use_but_can_close_inherited_descriptors(self) -> None:
        """Break caught: a forked child cannot safely release inherited authority."""

        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable")
        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            registry = module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            )
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:
                os.close(read_fd)
                try:
                    try:
                        registry.inspect(observed_at_unix_ms=1, limit=1)
                    except module.ReferenceExpiryError as error:
                        use_result = error.code.value
                    else:
                        use_result = "accepted"
                    try:
                        registry.close()
                    except Exception:
                        close_result = "close_failed"
                    else:
                        close_result = "closed"
                    os.write(
                        write_fd,
                        f"{use_result}:{close_result}".encode("ascii"),
                    )
                finally:
                    os.close(write_fd)
                    os._exit(0)
            os.close(write_fd)
            try:
                outcome = os.read(read_fd, 128)
                _waited_pid, status = os.waitpid(child_pid, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertEqual(outcome, b"unsafe_state:closed")
                self.assertEqual(
                    registry.inspect(observed_at_unix_ms=1, limit=1)[
                        "registered_reference_count"
                    ],
                    0,
                )
            finally:
                os.close(read_fd)
                registry.close()

    def test_read_only_open_without_registry_creates_nothing(self) -> None:
        """Break caught: an ordinary lookup silently opts into expiry state."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            before = sorted(path.relative_to(fixture.state) for path in fixture.state.rglob("*"))
            self.assert_expiry_error(
                "registry_uninitialized",
                lambda: module.ReferenceExpiryRegistry.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    store_namespace_id=fixture.store_namespace_id,
                    create=False,
                ),
            )
            after = sorted(path.relative_to(fixture.state) for path in fixture.state.rglob("*"))
            self.assertEqual(after, before)

    def test_exact_reference_quota_refuses_plus_one_without_evicting(self) -> None:
        """Break caught: quota pressure silently evicts an earlier reference."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        limits = module.ReferenceExpiryLimits(
            max_references=1,
            max_total_record_bytes=4096,
            max_record_bytes=4096,
        )
        with ExpiryFixture() as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                other = store.issue(
                    payload=b"another retained artifact",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="b" * 64,
                    artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                ).handle
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
                limits=limits,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=1000,
                    observed_at_unix_ms=1,
                )
                self.assert_expiry_error(
                    "reference_count_quota_exceeded",
                    lambda: registry.register(
                        other,
                        expires_at_unix_ms=1000,
                        observed_at_unix_ms=2,
                    ),
                )
                self.assertIs(
                    registry.is_inaccessible(
                        fixture.capability, observed_at_unix_ms=2
                    ),
                    False,
                )

    def test_record_and_total_byte_quotas_refuse_without_partial_records(self) -> None:
        """Break caught: byte quota overflow publishes or evicts a compact record."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            limits = module.ReferenceExpiryLimits(
                max_references=1,
                max_total_record_bytes=128,
                max_record_bytes=128,
            )
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
                limits=limits,
            ) as registry:
                self.assert_expiry_error(
                    "record_bytes_quota_exceeded",
                    lambda: registry.register(
                        fixture.capability,
                        expires_at_unix_ms=1000,
                        observed_at_unix_ms=1,
                    ),
                )
                self.assertEqual(
                    registry.inspect(observed_at_unix_ms=1, limit=1)[
                        "registered_reference_count"
                    ],
                    0,
                )

        with ExpiryFixture() as fixture:
            with CapabilityStore.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as store:
                other = store.issue(
                    payload=b"total-byte-quota",
                    root_identity_sha256=fixture.root_identity,
                    subject_identity_sha256="c" * 64,
                    artifact_type=ArtifactType.RAW_EVIDENCE_BYTES,
                ).handle
            limits = module.ReferenceExpiryLimits(
                max_references=2,
                max_total_record_bytes=1024,
                max_record_bytes=1024,
            )
            with module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
                limits=limits,
            ) as registry:
                registry.register(
                    fixture.capability,
                    expires_at_unix_ms=1000,
                    observed_at_unix_ms=1,
                )
                self.assert_expiry_error(
                    "record_bytes_quota_exceeded",
                    lambda: registry.register(
                        other,
                        expires_at_unix_ms=1000,
                        observed_at_unix_ms=1,
                    ),
                )
                snapshot = registry.inspect(observed_at_unix_ms=1, limit=2)
            self.assertEqual(snapshot["registered_reference_count"], 1)
            self.assertEqual(snapshot["active_reference_count"], 1)

    def test_store_directory_replacement_after_open_fails_closed(self) -> None:
        """Break caught: a long-lived registry silently crosses store instances."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            registry = module.ReferenceExpiryRegistry.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                store_namespace_id=fixture.store_namespace_id,
                create=True,
            )
            original = fixture.state / "store-v1"
            displaced = fixture.base / "displaced-store"
            replacement = fixture.state / "store-v1"
            os.rename(original, displaced)
            replacement.mkdir(mode=0o700)
            try:
                self.assert_expiry_error(
                    "unsafe_state",
                    lambda: registry.inspect(observed_at_unix_ms=1, limit=1),
                )
            finally:
                registry.close()

    def test_repository_open_race_is_sanitized_without_path_disclosure(self) -> None:
        """Break caught: a root replacement race leaks an absolute path in OSError."""

        module = importlib.import_module("context_guard_receipt.reference_expiry")
        with ExpiryFixture() as fixture:
            moved_root = fixture.base / "moved-repository"
            real_check = module._filesystem._check_disjoint
            check_count = 0

            def move_after_second_disjoint_check(*arguments, **kwargs):
                nonlocal check_count
                result = real_check(*arguments, **kwargs)
                check_count += 1
                if check_count == 2:
                    os.rename(fixture.root, moved_root)
                return result

            try:
                with mock.patch.object(
                    module._filesystem,
                    "_check_disjoint",
                    side_effect=move_after_second_disjoint_check,
                ):
                    with self.assertRaises(module.ReferenceExpiryError) as caught:
                        module.ReferenceExpiryRegistry.open(
                            state_dir=str(fixture.state),
                            repository_root=str(fixture.root),
                            store_namespace_id=fixture.store_namespace_id,
                            create=True,
                        )
                self.assertEqual(caught.exception.code.value, "unsafe_state")
                self.assertNotIn(str(fixture.root), str(caught.exception))
            finally:
                if moved_root.exists() and not fixture.root.exists():
                    os.rename(moved_root, fixture.root)


if __name__ == "__main__":
    unittest.main()
