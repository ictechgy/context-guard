from __future__ import annotations

import importlib
import hashlib
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

from context_guard_receipt.canonical import canonical_json_bytes  # noqa: E402
from context_guard_receipt.identity import snapshot_repository  # noqa: E402


def twin_module():
    try:
        return importlib.import_module("context_guard_receipt.execution_twin")
    except ModuleNotFoundError as error:
        raise AssertionError("G010 execution twin implementation is missing") from error


def request_bytes(
    predicates: list[dict[str, object]],
    *,
    expected_tail: object = None,
    action: str = "a" * 64,
) -> bytes:
    return canonical_json_bytes(
        {
            "declared_next_action_sha256": action,
            "expected_tail": expected_tail,
            "predicates": predicates,
            "schema_version": "contextguard-receipt-twin-request/v1",
        }
    )


class TwinFixture:
    def __init__(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name).resolve()
        self.root = self.base / "repository"
        self.state = self.base / "state"
        self.root.mkdir(mode=0o700)

    @property
    def twin_dir(self) -> Path:
        return self.state / "auxiliary-v1" / "twin-v1"

    def close(self) -> None:
        self.temporary_directory.cleanup()

    def __enter__(self) -> "TwinFixture":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class G010ExecutionTwinTests(unittest.TestCase):
    def assert_twin_error(self, code: str, operation) -> None:
        module = twin_module()
        with self.assertRaises(module.ExecutionTwinError) as caught:
            operation()
        self.assertEqual(caught.exception.code.value, code)
        self.assertNotIn("repository", str(caught.exception))

    def test_request_parser_is_canonical_closed_and_variant_exact(self) -> None:
        """Break caught: ambiguous bytes or open predicate variants gain authority."""

        module = twin_module()
        valid = request_bytes(
            [
                {
                    "expected_content_sha256": "b" * 64,
                    "expected_length_bytes": 3,
                    "expected_mode": "0644",
                    "kind": "regular_file_equals",
                    "relative_path": "src/value.txt",
                }
            ]
        )
        parsed = module.parse_twin_request(valid)
        self.assertEqual(parsed["declared_next_action_sha256"], "a" * 64)
        self.assertEqual(parsed["predicates"][0]["expected_mode"], "0644")

        invalid_values = (
            json.dumps(json.loads(valid), indent=2).encode("utf-8"),
            canonical_json_bytes({**json.loads(valid), "unexpected": False}),
            request_bytes([]),
            request_bytes([{"kind": "path_absent", "relative_path": "../escape"}]),
            request_bytes(
                [
                    {
                        "kind": "regular_file_equals",
                        "relative_path": "value.txt",
                        "expected_content_sha256": "b" * 64,
                        "expected_length_bytes": 3,
                        "expected_mode": "644",
                    }
                ]
            ),
        )
        for raw in invalid_values:
            with self.subTest(size=len(raw)):
                self.assert_twin_error(
                    "invalid_request", lambda raw=raw: module.parse_twin_request(raw)
                )

    def test_first_append_is_provider_free_path_free_and_durably_inspectable(self) -> None:
        """Break caught: first append overclaims, leaks a path, or is not durable."""

        module = twin_module()
        with TwinFixture() as fixture:
            private_name = "private-input-must-not-appear.txt"
            parsed = module.parse_twin_request(
                request_bytes([{"kind": "path_absent", "relative_path": private_name}])
            )
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                result = twin.append(parsed, observed_at_unix_ms=1_700_000_000_000)

            self.assertEqual(
                set(path.name for path in fixture.twin_dir.iterdir()),
                {"events.log", "key", "lock", "metadata.json"},
            )
            self.assertEqual(len((fixture.twin_dir / "key").read_bytes()), 32)
            self.assertEqual(result["event_sequence"], 1)
            self.assertIsNone(result["previous_event_hmac_sha256"])
            self.assertIs(result["verified"], True)
            self.assertIs(result["advisory_only"], True)
            for field in (
                "applied",
                "execution_authority",
                "global_completeness_authority",
                "provider_claim_authority",
            ):
                self.assertIs(result[field], False)
            self.assertEqual(
                set(result["predicate_results"][0]),
                {"kind", "matched", "observation_hmac_sha256", "ordinal"},
            )
            self.assertNotIn(private_name.encode(), canonical_json_bytes(result))
            self.assertNotIn(private_name.encode(), (fixture.twin_dir / "events.log").read_bytes())

            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                snapshot = twin.inspect(limit=1)
            self.assertEqual(snapshot["committed_event_count"], 1)
            self.assertEqual(len(snapshot["latest_events"]), 1)
            self.assertIs(snapshot["recovery_required"], False)

    def test_restart_requires_exact_cas_tail_and_preserves_chain(self) -> None:
        """Break caught: stale or null expected tails append after the initial event."""

        module = twin_module()
        predicate = {"kind": "path_absent", "relative_path": "still-absent"}
        with TwinFixture() as fixture:
            first_request = module.parse_twin_request(request_bytes([predicate]))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root), create=True
            ) as twin:
                first = twin.append(first_request, observed_at_unix_ms=1)

            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                self.assert_twin_error(
                    "cas_mismatch",
                    lambda: twin.append(first_request, observed_at_unix_ms=2),
                )
                expected_tail = {
                    "event_hmac_sha256": first["event_hmac_sha256"],
                    "event_sequence": first["event_sequence"],
                    "namespace_id": first["namespace_id"],
                }
                second = twin.append(
                    module.parse_twin_request(
                        request_bytes([predicate], expected_tail=expected_tail, action="c" * 64)
                    ),
                    observed_at_unix_ms=3,
                )

            self.assertEqual(second["event_sequence"], 2)
            self.assertEqual(
                second["previous_event_hmac_sha256"], first["event_hmac_sha256"]
            )
            self.assertNotEqual(second["event_id"], first["event_id"])

    def test_regular_file_checks_are_exact_and_links_fail_closed(self) -> None:
        """Break caught: content, length, mode, aliases, or symlinks bypass revalidation."""

        module = twin_module()
        with TwinFixture() as fixture:
            payload = b"exact bytes\n"
            target = fixture.root / "value.txt"
            target.write_bytes(payload)
            target.chmod(0o640)
            os.symlink("value.txt", fixture.root / "alias.txt")
            predicates = [
                {
                    "expected_content_sha256": __import__("hashlib").sha256(payload).hexdigest(),
                    "expected_length_bytes": len(payload),
                    "expected_mode": "0640",
                    "kind": "regular_file_equals",
                    "relative_path": "value.txt",
                },
                {"kind": "path_absent", "relative_path": "alias.txt"},
            ]
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root), create=True
            ) as twin:
                result = twin.append(
                    module.parse_twin_request(request_bytes(predicates)),
                    observed_at_unix_ms=4,
                )

            self.assertEqual(result["matched_predicate_count"], 1)
            self.assertIs(result["predicate_results"][0]["matched"], True)
            self.assertIs(result["predicate_results"][1]["matched"], False)
            self.assertIs(result["verified"], False)

    def test_repository_state_predicate_is_explicitly_git_logical_only(self) -> None:
        """Break caught: a content-sounding predicate verifies an incomplete state hash."""

        module = twin_module()
        self.assert_twin_error(
            "invalid_request",
            lambda: module.parse_twin_request(
                request_bytes(
                    [{"expected_sha256": "b" * 64, "kind": "repository_state_equals"}]
                )
            ),
        )
        parsed = module.parse_twin_request(
            request_bytes(
                [{"expected_sha256": "b" * 64, "kind": "git_logical_state_equals"}]
            )
        )
        self.assertEqual(parsed["predicates"][0]["kind"], "git_logical_state_equals")

        with TwinFixture() as fixture:
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                result = twin.append(parsed, observed_at_unix_ms=4)
        self.assertIs(result["predicate_results"][0]["matched"], False)
        self.assertIs(result["verified"], False)

    def test_all_predicates_run_and_untracked_bytes_require_file_equality(self) -> None:
        """Break caught: a Git metadata predicate silently claims untracked bytes."""

        git = shutil.which("git")
        if git is None:
            self.skipTest("git is required for Git logical-state coverage")
        module = twin_module()
        with TwinFixture() as fixture:
            subprocess.run(
                [git, "init", "-q"],
                cwd=fixture.root,
                env={"LANG": "C", "PATH": os.defpath},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            payload = b"first untracked bytes"
            target = fixture.root / "untracked.txt"
            target.write_bytes(payload)
            target.chmod(0o640)
            snapshot = snapshot_repository(str(fixture.root))
            predicates = [
                {
                    "expected_sha256": snapshot["instance"]["identity_sha256"],
                    "kind": "repository_instance_equals",
                },
                {
                    "expected_sha256": snapshot["logical_state"]["state_sha256"],
                    "kind": "git_logical_state_equals",
                },
                {
                    "expected_content_sha256": hashlib.sha256(payload).hexdigest(),
                    "expected_length_bytes": len(payload),
                    "expected_mode": "0640",
                    "kind": "regular_file_equals",
                    "relative_path": "untracked.txt",
                },
                {"kind": "path_absent", "relative_path": "absent.txt"},
            ]
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                first = twin.append(
                    module.parse_twin_request(request_bytes(predicates)),
                    observed_at_unix_ms=4,
                )
                target.write_bytes(b"other untracked bytes")
                second = twin.append(
                    module.parse_twin_request(
                        request_bytes(
                            predicates,
                            action="e" * 64,
                            expected_tail={
                                "event_hmac_sha256": first["event_hmac_sha256"],
                                "event_sequence": 1,
                                "namespace_id": first["namespace_id"],
                            },
                        )
                    ),
                    observed_at_unix_ms=5,
                )

        self.assertEqual(first["matched_predicate_count"], 4)
        self.assertIs(first["verified"], True)
        self.assertEqual(second["matched_predicate_count"], 3)
        self.assertIs(second["predicate_results"][1]["matched"], True)
        self.assertIs(second["predicate_results"][2]["matched"], False)
        self.assertIs(second["verified"], False)

    def test_observation_macs_are_unlinkable_across_twins_and_sequences(self) -> None:
        """Break caught: a public digest permits path guessing or cross-twin linkage."""

        module = twin_module()
        private_name = "guessable-private-path.txt"
        predicate = {"kind": "path_absent", "relative_path": private_name}
        with TwinFixture() as fixture:
            state_two = fixture.base / "state-two"
            parsed = module.parse_twin_request(request_bytes([predicate]))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as first_twin:
                first = first_twin.append(parsed, observed_at_unix_ms=5)
                second = first_twin.append(
                    module.parse_twin_request(
                        request_bytes(
                            [predicate],
                            action="c" * 64,
                            expected_tail={
                                "event_hmac_sha256": first["event_hmac_sha256"],
                                "event_sequence": 1,
                                "namespace_id": first["namespace_id"],
                            },
                        )
                    ),
                    observed_at_unix_ms=6,
                )
            with module.ExecutionTwin.open(
                state_dir=str(state_two),
                repository_root=str(fixture.root),
                create=True,
            ) as other_twin:
                other = other_twin.append(parsed, observed_at_unix_ms=5)

        field = "observation_hmac_sha256"
        first_mac = first["predicate_results"][0][field]
        self.assertNotEqual(first_mac, second["predicate_results"][0][field])
        self.assertNotEqual(first_mac, other["predicate_results"][0][field])
        for artifact in (first, second, other):
            self.assertNotIn(private_name.encode(), canonical_json_bytes(artifact))

    def test_uncommitted_tail_is_truncated_but_committed_prefix_tamper_is_refused(self) -> None:
        """Break caught: crash residue blocks forever or committed bytes are silently repaired."""

        module = twin_module()
        with TwinFixture() as fixture:
            parsed = module.parse_twin_request(
                request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
            )
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root), create=True
            ) as twin:
                twin.append(parsed, observed_at_unix_ms=5)
            committed_size = (fixture.twin_dir / "events.log").stat().st_size
            with (fixture.twin_dir / "events.log").open("ab") as stream:
                stream.write(b"crash-tail")
                stream.flush()
                os.fsync(stream.fileno())
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                snapshot = twin.inspect(limit=1)
            self.assertIs(snapshot["recovery_required"], True)
            self.assertEqual((fixture.twin_dir / "events.log").stat().st_size, committed_size)

            with (fixture.twin_dir / "events.log").open("r+b") as stream:
                stream.seek(8)
                original = stream.read(1)
                stream.seek(8)
                stream.write(bytes([original[0] ^ 1]))
                stream.flush()
                os.fsync(stream.fileno())
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                self.assert_twin_error("twin_tampered", lambda: twin.inspect(limit=1))

    def test_authenticated_metadata_rollback_never_truncates_a_valid_suffix(self) -> None:
        """Break caught: replayed old metadata silently deletes a committed event."""

        module = twin_module()
        predicate = {"kind": "path_absent", "relative_path": "absent"}
        with TwinFixture() as fixture:
            first_request = module.parse_twin_request(request_bytes([predicate]))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                first = twin.append(first_request, observed_at_unix_ms=7)
            metadata_path = fixture.twin_dir / "metadata.json"
            old_metadata = metadata_path.read_bytes()
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                twin.append(
                    module.parse_twin_request(
                        request_bytes(
                            [predicate],
                            action="d" * 64,
                            expected_tail={
                                "event_hmac_sha256": first["event_hmac_sha256"],
                                "event_sequence": 1,
                                "namespace_id": first["namespace_id"],
                            },
                        )
                    ),
                    observed_at_unix_ms=8,
                )
            current_metadata = metadata_path.read_bytes()
            log_path = fixture.twin_dir / "events.log"
            committed_log = log_path.read_bytes()

            metadata_path.write_bytes(old_metadata)
            metadata_path.chmod(0o600)
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                self.assert_twin_error("commit_uncertain", lambda: twin.inspect(limit=2))
            self.assertEqual(log_path.read_bytes(), committed_log)

            metadata_path.write_bytes(current_metadata)
            metadata_path.chmod(0o600)
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                snapshot = twin.inspect(limit=2)
            self.assertEqual(snapshot["committed_event_count"], 2)

    def test_request_path_predicate_and_file_bounds_are_exact(self) -> None:
        """Break caught: documented predicate, UTF-8 path, or file bounds drift."""

        module = twin_module()
        self.assertEqual(module._MAX_PREDICATES, 32)
        self.assertEqual(module._MAX_PATH_BYTES, 4096)
        self.assertEqual(module._MAX_FILE_BYTES, 1024 * 1024)
        predicates = [
            {"kind": "path_absent", "relative_path": f"absent-{index}"}
            for index in range(32)
        ]
        self.assertEqual(len(module.parse_twin_request(request_bytes(predicates))["predicates"]), 32)
        self.assert_twin_error(
            "invalid_request",
            lambda: module.parse_twin_request(
                request_bytes(predicates + [{"kind": "path_absent", "relative_path": "extra"}])
            ),
        )
        within_utf8_limit = "/".join(["é" * 100] * 20)
        beyond_utf8_limit = "/".join(["é" * 100] * 21)
        self.assertLessEqual(len(within_utf8_limit.encode("utf-8")), 4096)
        module.parse_twin_request(
            request_bytes([{"kind": "path_absent", "relative_path": within_utf8_limit}])
        )
        self.assert_twin_error(
            "invalid_request",
            lambda: module.parse_twin_request(
                request_bytes([{"kind": "path_absent", "relative_path": beyond_utf8_limit}])
            ),
        )

        with TwinFixture() as fixture:
            payload = b"x" * module._MAX_FILE_BYTES
            target = fixture.root / "edge.bin"
            target.write_bytes(payload)
            target.chmod(0o600)
            predicate = {
                "expected_content_sha256": hashlib.sha256(payload).hexdigest(),
                "expected_length_bytes": len(payload),
                "expected_mode": "0600",
                "kind": "regular_file_equals",
                "relative_path": "edge.bin",
            }
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                first = twin.append(
                    module.parse_twin_request(request_bytes([predicate])),
                    observed_at_unix_ms=9,
                )
                target.write_bytes(payload + b"y")
                second = twin.append(
                    module.parse_twin_request(
                        request_bytes(
                            [predicate],
                            action="f" * 64,
                            expected_tail={
                                "event_hmac_sha256": first["event_hmac_sha256"],
                                "event_sequence": 1,
                                "namespace_id": first["namespace_id"],
                            },
                        )
                    ),
                    observed_at_unix_ms=10,
                )
        self.assertIs(first["verified"], True)
        self.assertIs(second["predicate_results"][0]["matched"], False)
        self.assertIs(second["verified"], False)

    def test_event_count_log_and_event_byte_quotas_refuse_without_eviction(self) -> None:
        """Break caught: hard twin quotas drift or silently evict history."""

        module = twin_module()
        self.assertEqual(module._MAX_EVENT_COUNT, 1024)
        self.assertEqual(module._MAX_COMMITTED_LOG_BYTES, 8 * 1024 * 1024)
        self.assertEqual(module._MAX_EVENT_BYTES, 16 * 1024)
        predicate = {"kind": "path_absent", "relative_path": "absent"}

        with TwinFixture() as fixture:
            request = module.parse_twin_request(request_bytes([predicate]))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                first = twin.append(request, observed_at_unix_ms=11)
                committed_bytes = (fixture.twin_dir / "events.log").stat().st_size
                metadata = twin._read_metadata_state()
                with mock.patch.object(module, "_MAX_EVENT_COUNT", 1), mock.patch.object(
                    twin, "_read_metadata_state", return_value=metadata
                ):
                    self.assert_twin_error(
                        "count_quota_exceeded",
                        lambda: twin.append(
                            module.parse_twin_request(
                                request_bytes(
                                    [predicate],
                                    action="1" * 64,
                                    expected_tail={
                                        "event_hmac_sha256": first["event_hmac_sha256"],
                                        "event_sequence": 1,
                                        "namespace_id": first["namespace_id"],
                                    },
                                )
                            ),
                            observed_at_unix_ms=12,
                        ),
                    )
            self.assertEqual((fixture.twin_dir / "events.log").stat().st_size, committed_bytes)

        with TwinFixture() as fixture:
            request = module.parse_twin_request(request_bytes([predicate]))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                first = twin.append(request, observed_at_unix_ms=13)
                committed_bytes = (fixture.twin_dir / "events.log").stat().st_size
                metadata = twin._read_metadata_state()
                with mock.patch.object(
                    module, "_MAX_COMMITTED_LOG_BYTES", committed_bytes
                ), mock.patch.object(twin, "_read_metadata_state", return_value=metadata):
                    self.assert_twin_error(
                        "byte_quota_exceeded",
                        lambda: twin.append(
                            module.parse_twin_request(
                                request_bytes(
                                    [predicate],
                                    action="2" * 64,
                                    expected_tail={
                                        "event_hmac_sha256": first["event_hmac_sha256"],
                                        "event_sequence": 1,
                                        "namespace_id": first["namespace_id"],
                                    },
                                )
                            ),
                            observed_at_unix_ms=14,
                        ),
                    )
                self.assertEqual((fixture.twin_dir / "events.log").stat().st_size, committed_bytes)

        with TwinFixture() as fixture:
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                metadata = twin._read_metadata_state()
                with mock.patch.object(module, "_MAX_EVENT_BYTES", 1), mock.patch.object(
                    twin, "_read_metadata_state", return_value=metadata
                ):
                    self.assert_twin_error(
                        "event_too_large",
                        lambda: twin.append(
                            module.parse_twin_request(request_bytes([predicate])),
                            observed_at_unix_ms=15,
                        ),
                    )
            self.assertEqual((fixture.twin_dir / "events.log").stat().st_size, 0)

    def test_independent_threads_read_fresh_metadata_and_serialize_cas(self) -> None:
        """Break caught: cached tails let two same-CAS appends commit."""

        module = twin_module()
        request = module.parse_twin_request(
            request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
        )
        with TwinFixture() as fixture:
            module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ).close()
            first_twin = module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            )
            second_twin = module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            )
            barrier = threading.Barrier(2)

            def append(twin, timestamp):
                barrier.wait(timeout=5)
                try:
                    return ("ok", twin.append(request, observed_at_unix_ms=timestamp))
                except module.ExecutionTwinError as error:
                    return (error.code.value, None)

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(
                        pool.map(
                            lambda item: append(*item),
                            ((first_twin, 16), (second_twin, 17)),
                        )
                    )
                self.assertEqual(sorted(item[0] for item in outcomes), ["cas_mismatch", "ok"])
                winner = next(item[1] for item in outcomes if item[0] == "ok")
                followup = second_twin.append(
                    module.parse_twin_request(
                        request_bytes(
                            [{"kind": "path_absent", "relative_path": "absent"}],
                            action="3" * 64,
                            expected_tail={
                                "event_hmac_sha256": winner["event_hmac_sha256"],
                                "event_sequence": 1,
                                "namespace_id": winner["namespace_id"],
                            },
                        )
                    ),
                    observed_at_unix_ms=18,
                )
                self.assertEqual(followup["event_sequence"], 2)
            finally:
                first_twin.close()
                second_twin.close()

    def test_separate_processes_serialize_the_same_initial_cas(self) -> None:
        """Break caught: per-process locks permit duplicate first events."""

        module = twin_module()
        with TwinFixture() as fixture:
            module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ).close()
            bootstrap = PACKAGE_ROOT / "python/context_guard_receipt/bootstrap.py"
            command = [
                str(Path(sys.executable).resolve()),
                "-I",
                "-S",
                "-B",
                str(bootstrap),
                "receipt",
                "inspect",
                "twin",
                "--experimental-twin",
                "--input",
                "-",
                "--root",
                str(fixture.root),
                "--state-dir",
                str(fixture.state),
            ]
            environment = {
                "LANG": "C",
                "PATH": os.defpath,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            processes = [
                subprocess.Popen(
                    command,
                    cwd=PACKAGE_ROOT,
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _index in range(2)
            ]
            raw = request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
            with ThreadPoolExecutor(max_workers=2) as pool:
                outputs = list(pool.map(lambda process: process.communicate(raw, timeout=10), processes))
            self.assertEqual(sorted(process.returncode for process in processes), [0, 74])
            successful = [json.loads(stdout) for process, (stdout, _stderr) in zip(processes, outputs) if process.returncode == 0]
            self.assertEqual(successful[0]["event_sequence"], 1)
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as twin:
                self.assertEqual(twin.inspect(limit=2)["committed_event_count"], 1)

    def test_metadata_publication_failures_preserve_an_indeterminate_event(self) -> None:
        """Break caught: metadata faults erase or falsely acknowledge an event."""

        module = twin_module()
        request = module.parse_twin_request(
            request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
        )
        with TwinFixture() as fixture:
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                real_rename = module.os.rename

                def fail_metadata_rename(source, destination, *args, **kwargs):
                    if destination == "metadata.json" and str(source).startswith(
                        ".metadata.json.tmp-"
                    ):
                        raise OSError("injected")
                    return real_rename(source, destination, *args, **kwargs)

                with mock.patch.object(module.os, "rename", side_effect=fail_metadata_rename):
                    self.assert_twin_error(
                        "commit_uncertain",
                        lambda: twin.append(request, observed_at_unix_ms=19),
                    )
                preserved = (fixture.twin_dir / "events.log").read_bytes()
                self.assertNotEqual(preserved, b"")
                self.assert_twin_error("commit_uncertain", lambda: twin.inspect(limit=1))
                self.assertEqual((fixture.twin_dir / "events.log").read_bytes(), preserved)

        with TwinFixture() as fixture:
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            ) as twin:
                real_fsync = module.os.fsync

                def fail_directory_fsync(descriptor):
                    if descriptor == twin._twin_fd:
                        raise OSError("injected")
                    return real_fsync(descriptor)

                with mock.patch.object(module.os, "fsync", side_effect=fail_directory_fsync):
                    self.assert_twin_error(
                        "commit_uncertain",
                        lambda: twin.append(request, observed_at_unix_ms=20),
                    )
                self.assertEqual(twin.inspect(limit=1)["committed_event_count"], 1)

    def test_forked_inherited_instance_is_rejected_and_parent_remains_usable(self) -> None:
        """Break caught: a fork inherits live descriptor authority."""

        if not hasattr(os, "fork"):
            self.skipTest("fork is unavailable")
        module = twin_module()
        request = module.parse_twin_request(
            request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
        )
        with TwinFixture() as fixture:
            twin = module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            )
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:
                os.close(read_fd)
                try:
                    twin.inspect(limit=1)
                except module.ExecutionTwinError as error:
                    outcome = error.code.value.encode("ascii")
                else:
                    outcome = b"accepted"
                try:
                    os.write(write_fd, outcome)
                finally:
                    os.close(write_fd)
                    twin.close()
                    os._exit(0)
            os.close(write_fd)
            try:
                outcome = os.read(read_fd, 128)
                _waited_pid, status = os.waitpid(child_pid, 0)
                self.assertEqual(status, 0)
                self.assertEqual(outcome, b"unsafe_state")
                result = twin.append(request, observed_at_unix_ms=21)
                self.assertEqual(result["event_sequence"], 1)
            finally:
                os.close(read_fd)
                twin.close()

    def test_close_serializes_with_an_active_append(self) -> None:
        """Break caught: close invalidates descriptors while append is committing."""

        module = twin_module()
        request = module.parse_twin_request(
            request_bytes([{"kind": "path_absent", "relative_path": "absent"}])
        )
        with TwinFixture() as fixture:
            twin = module.ExecutionTwin.open(
                state_dir=str(fixture.state),
                repository_root=str(fixture.root),
                create=True,
            )
            entered = threading.Event()
            release = threading.Event()
            close_finished = threading.Event()
            original = twin._evaluate_predicates

            def blocked_evaluation(*args, **kwargs):
                if not entered.is_set():
                    entered.set()
                    self.assertTrue(release.wait(timeout=5))
                return original(*args, **kwargs)

            def close_twin():
                twin.close()
                close_finished.set()

            with mock.patch.object(twin, "_evaluate_predicates", side_effect=blocked_evaluation):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    append_future = pool.submit(twin.append, request, 22)
                    self.assertTrue(entered.wait(timeout=5))
                    close_future = pool.submit(close_twin)
                    self.assertFalse(close_finished.wait(timeout=0.1))
                    release.set()
                    result = append_future.result(timeout=10)
                    close_future.result(timeout=10)
            self.assertEqual(result["event_sequence"], 1)
            self.assert_twin_error("invalid_argument", lambda: twin.inspect(limit=1))
            with module.ExecutionTwin.open(
                state_dir=str(fixture.state), repository_root=str(fixture.root)
            ) as reopened:
                self.assertEqual(reopened.inspect(limit=1)["committed_event_count"], 1)

    def test_uninitialized_and_overlapping_state_are_rejected_without_mutation(self) -> None:
        """Break caught: reads initialize state or twin state overlaps the observed root."""

        module = twin_module()
        with TwinFixture() as fixture:
            self.assert_twin_error(
                "twin_uninitialized",
                lambda: module.ExecutionTwin.open(
                    state_dir=str(fixture.state), repository_root=str(fixture.root)
                ),
            )
            self.assertFalse(fixture.state.exists())
            overlapping = fixture.root / "state"
            self.assert_twin_error(
                "unsafe_state",
                lambda: module.ExecutionTwin.open(
                    state_dir=str(overlapping),
                    repository_root=str(fixture.root),
                    create=True,
                ),
            )
            self.assertFalse(overlapping.exists())

    def test_repository_root_must_be_explicit_absolute_and_normalized(self) -> None:
        """Break caught: the library silently resolves a caller-relative authority root."""

        module = twin_module()
        with TwinFixture() as fixture:
            relative_root = os.path.relpath(fixture.root, Path.cwd())
            self.assert_twin_error(
                "invalid_argument",
                lambda: module.ExecutionTwin.open(
                    state_dir=str(fixture.state),
                    repository_root=relative_root,
                    create=True,
                ),
            )
            self.assertFalse(fixture.state.exists())

    def test_new_lock_fchmod_failure_closes_descriptor_and_is_uncertain(self) -> None:
        """Break caught: failed lock hardening leaks an fd and understates residue."""

        module = twin_module()
        with TwinFixture() as fixture:
            real_open = module.os.open
            real_fchmod = module.os.fchmod
            created_lock_fds: list[int] = []

            def tracked_open(path, flags, *args, **kwargs):
                descriptor = real_open(path, flags, *args, **kwargs)
                if path == "lock" and flags & os.O_CREAT:
                    created_lock_fds.append(descriptor)
                return descriptor

            def injected_fchmod(descriptor, mode):
                if descriptor in created_lock_fds:
                    raise OSError("injected")
                return real_fchmod(descriptor, mode)

            with mock.patch.object(
                module, "_require_filesystem_features", return_value=None
            ), mock.patch.object(module.os, "open", side_effect=tracked_open), mock.patch.object(
                module.os, "fchmod", side_effect=injected_fchmod
            ), self.assertRaises(module.ExecutionTwinError) as caught:
                module.ExecutionTwin.open(
                    state_dir=str(fixture.state),
                    repository_root=str(fixture.root),
                    create=True,
                )

            leaked: list[int] = []
            for descriptor in created_lock_fds:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                leaked.append(descriptor)
                os.close(descriptor)
            self.assertEqual(caught.exception.code.value, "commit_uncertain")
            self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()
