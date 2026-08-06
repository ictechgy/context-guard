from __future__ import annotations

import base64
import dataclasses
import hashlib
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = PACKAGE_ROOT / "python"
SCHEMA_PATH = PACKAGE_ROOT / "schemas/source-identity.schema.json"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))


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


def identity_module():
    try:
        return importlib.import_module("context_guard_receipt.identity")
    except ModuleNotFoundError as error:
        raise AssertionError("G003 identity implementation is missing") from error


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def framed_sha256(domain: str, *parts: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\0")
    for part in parts:
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )


def complete_symbol_evidence(
    payload: bytes,
    start_byte: int,
    end_byte: int,
    **overrides: object,
) -> dict[str, object]:
    raw_range_sha256 = hashlib.sha256(payload[start_byte:end_byte]).hexdigest()
    evidence: dict[str, object] = {
        "candidates": [
            {
                "end_byte": end_byte,
                "occurrence": 0,
                "qualified_name": "module.answer",
                "raw_range_sha256": raw_range_sha256,
                "start_byte": start_byte,
            }
        ],
        "capped": False,
        "complete": True,
        "deterministic": True,
        "end_byte": end_byte,
        "evidence_kind": "caller_supplied_symbol_range",
        "fallback_used": False,
        "language_id": "python",
        "occurrence": 0,
        "parser_error": False,
        "producer_id": "test-parser/1",
        "qualified_name": "module.answer",
        "raw_range_sha256": raw_range_sha256,
        "scan_complete": True,
        "schema_version": "contextguard-receipt-caller-symbol-evidence/v1",
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "start_byte": start_byte,
    }
    evidence.update(overrides)
    return evidence


def find_git() -> str | None:
    candidate = shutil.which("git")
    return str(Path(candidate).resolve()) if candidate is not None else None


class TemporaryRepository:
    def __init__(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.git = find_git()

    def close(self) -> None:
        self.temporary_directory.cleanup()

    def run_git(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        if self.git is None:
            raise unittest.SkipTest("git is unavailable")
        return subprocess.run(
            [self.git, *arguments],
            cwd=cwd or self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )


class G003IdentityTests(unittest.TestCase):
    def assert_identity_error(self, code: str, operation) -> None:
        identity = identity_module()
        with self.assertRaises(identity.IdentityError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("0x", str(caught.exception))

    def test_limits_are_frozen_positive_integers(self) -> None:
        """Break caught: resource bounds become unbounded, mutable, or bool-compatible."""
        identity = identity_module()
        limits = identity.IdentityLimits()
        self.assertEqual(limits.max_file_bytes, 1024 * 1024)
        self.assertEqual(limits.max_git_output_bytes, 256 * 1024)
        self.assertEqual(limits.max_git_nul_fields, 4096)
        self.assertEqual(limits.max_directory_entries, 4096)
        self.assertEqual(limits.max_path_bytes, 4096)
        self.assertEqual(limits.max_symbol_evidence_bytes, 64 * 1024)
        self.assertEqual(limits.git_timeout_seconds, 5)
        self.assertRaises(dataclasses.FrozenInstanceError, setattr, limits, "max_file_bytes", 1)
        for field in dataclasses.fields(limits):
            for invalid in (0, -1, True, 1.5):
                with self.subTest(field=field.name, invalid=invalid):
                    arguments = {field.name: invalid}
                    self.assert_identity_error(
                        "invalid_limits",
                        lambda arguments=arguments: identity.IdentityLimits(**arguments),
                    )
        maximums = {
            "git_timeout_seconds": 30,
            "max_file_bytes": 1024 * 1024,
            "max_directory_entries": 4096,
            "max_git_nul_fields": 4096,
            "max_git_output_bytes": 1024 * 1024,
            "max_path_bytes": 4096,
            "max_symbol_evidence_bytes": 64 * 1024,
        }
        for field, maximum in maximums.items():
            with self.subTest(field=field, maximum=maximum):
                identity.IdentityLimits(**{field: maximum})
                self.assert_identity_error(
                    "invalid_limits",
                    lambda field=field, maximum=maximum: identity.IdentityLimits(
                        **{field: maximum + 1}
                    ),
                )
        self.assert_identity_error(
            "invalid_limits", lambda: identity.snapshot_repository(Path.cwd(), limits=object())
        )

    def test_non_git_file_identity_is_exact_raw_content_and_instance_bound(self) -> None:
        """Break caught: text decoding or a path-only digest masquerades as file identity."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "src" / "café.py"
            source.parent.mkdir()
            payload = b"a\x00b\xff\r\n"
            source.write_bytes(payload)
            source.chmod(0o640)

            result = identity.identify_source(
                root,
                "src/café.py",
                git_executable=find_git(),
            )

        self.assertEqual(result["artifact_kind"], "source_identity")
        self.assertEqual(result["schema_version"], "contextguard-receipt-source-identity/v1")
        self.assertEqual(result["disposition"], "exact_file")
        self.assertEqual(result["reason"], "raw_file_identity")
        self.assertEqual(result["path_b64u"], b64url("src/café.py".encode("utf-8")))
        self.assertNotIn("src/caf", json.dumps(result, ensure_ascii=False))
        self.assertEqual(result["source"]["byte_length"], len(payload))
        self.assertEqual(result["source"]["content_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["source"]["file_type"], "regular")
        self.assertEqual(result["source"]["mode"], "0640")
        self.assertEqual(result["source"]["git_index"], {"status": "not_applicable"})
        instance = bytes.fromhex(result["repository"]["instance"]["identity_sha256"])
        expected_file_identity = framed_sha256(
            "contextguard-receipt/raw-file/v1",
            bytes.fromhex(result["repository"]["logical_state"]["state_sha256"]),
            instance,
            "src/café.py".encode("utf-8"),
            b"regular",
            b"0640",
            canonical_bytes({"status": "not_applicable"}),
            payload,
        )
        self.assertEqual(result["source"]["identity_sha256"], expected_file_identity)
        self.assertEqual(result["selection"]["identity_sha256"], expected_file_identity)
        self.assertEqual(result["evidence_boundary"], EVIDENCE_BOUNDARY)
        self.assertEqual(result["repository"]["logical_state"]["kind"], "non_git")

    def test_raw_range_uses_half_open_bytes_and_never_claims_symbol_authority(self) -> None:
        """Break caught: character offsets, inclusive ends, or inferred parser authority."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = "AéZ".encode("utf-8")
            (root / "value.txt").write_bytes(payload)
            result = identity.identify_source(
                root,
                "value.txt",
                byte_range=(1, 3),
                git_executable=find_git(),
            )

        expected_slice = "é".encode("utf-8")
        expected_range_identity = framed_sha256(
            "contextguard-receipt/raw-byte-range/v1",
            bytes.fromhex(result["source"]["identity_sha256"]),
            b"1",
            b"3",
            expected_slice,
        )
        self.assertEqual(result["disposition"], "range_candidate")
        self.assertEqual(result["reason"], "raw_range_without_symbol_authority")
        self.assertEqual(
            result["selection"],
            {
                "byte_length": 2,
                "content_sha256": hashlib.sha256(expected_slice).hexdigest(),
                "end_byte": 3,
                "identity_sha256": expected_range_identity,
                "kind": "raw_range",
                "start_byte": 1,
            },
        )
        self.assertNotIn("symbol", result)

    def test_complete_deterministic_matching_caller_evidence_is_exact_symbol(self) -> None:
        """Break caught: caller evidence is ignored or labeled companion parser proof."""
        identity = identity_module()
        payload = b"def answer():\n    return 42\n"
        evidence = complete_symbol_evidence(payload, 0, len(payload))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "answer.py").write_bytes(payload)
            result = identity.identify_source(
                root,
                "answer.py",
                symbol_evidence=evidence,
                git_executable=find_git(),
            )

        evidence_bytes = canonical_bytes(evidence)
        expected_evidence_hash = framed_sha256(
            "contextguard-receipt/caller-symbol-evidence/v1", evidence_bytes
        )
        expected_symbol_identity = framed_sha256(
            "contextguard-receipt/caller-symbol/v1",
            bytes.fromhex(result["selection"]["identity_sha256"]),
            bytes.fromhex(expected_evidence_hash),
        )
        self.assertEqual(result["disposition"], "exact_symbol")
        self.assertEqual(result["reason"], "caller_complete_deterministic_symbol_evidence")
        self.assertEqual(
            result["symbol"],
            {
                "authority": "caller_supplied",
                "evidence_sha256": expected_evidence_hash,
                "identity_sha256": expected_symbol_identity,
            },
        )

    def test_incomplete_extra_or_mismatched_symbol_evidence_never_becomes_exact(self) -> None:
        """Break caught: truthy flags, open objects, or stale source evidence grant authority."""
        identity = identity_module()
        payload = b"abcde"
        base = complete_symbol_evidence(payload, 1, 4)
        cases = []
        for field in ("complete", "deterministic"):
            candidate = dict(base)
            candidate[field] = 1 if field == "complete" else False
            cases.append(("symbol_evidence_incomplete", candidate))
        extra = dict(base)
        extra["parser_authority"] = True
        cases.append(("symbol_evidence_incomplete", extra))
        mismatch = dict(base)
        mismatch["source_sha256"] = "0" * 64
        cases.append(("symbol_evidence_mismatch", mismatch))
        for field, invalid in (
            ("scan_complete", False),
            ("capped", True),
            ("fallback_used", True),
            ("parser_error", True),
        ):
            candidate = dict(base)
            candidate[field] = invalid
            cases.append(("symbol_evidence_incomplete", candidate))
        duplicate_candidate = dict(base)
        duplicate_candidate["candidates"] = list(base["candidates"]) * 2
        cases.append(("symbol_evidence_incomplete", duplicate_candidate))
        bad_range_hash = dict(base)
        bad_range_hash["raw_range_sha256"] = "0" * 64
        cases.append(("symbol_evidence_mismatch", bad_range_hash))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value.txt").write_bytes(payload)
            for expected_reason, evidence in cases:
                with self.subTest(expected_reason=expected_reason, evidence=evidence):
                    result = identity.identify_source(
                        root,
                        "value.txt",
                        byte_range=(1, 4),
                        symbol_evidence=evidence,
                        git_executable=find_git(),
                    )
                    self.assertEqual(result["disposition"], "range_candidate")
                    self.assertEqual(result["reason"], expected_reason)
                    self.assertNotIn("symbol", result)

    def test_symbol_occurrences_are_recomputed_by_ascending_byte_start(self) -> None:
        """Break caught: caller-chosen occurrence ranks can select the wrong duplicate."""
        identity = identity_module()
        payload = b"aa--aa"
        evidence = complete_symbol_evidence(payload, 4, 6)
        evidence["occurrence"] = 2
        evidence["candidates"] = [
            {
                "end_byte": 2,
                "occurrence": 9,
                "qualified_name": "module.answer",
                "raw_range_sha256": hashlib.sha256(payload[0:2]).hexdigest(),
                "start_byte": 0,
            },
            {
                "end_byte": 6,
                "occurrence": 2,
                "qualified_name": "module.answer",
                "raw_range_sha256": hashlib.sha256(payload[4:6]).hexdigest(),
                "start_byte": 4,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "duplicates.txt").write_bytes(payload)
            result = identity.identify_source(
                root,
                "duplicates.txt",
                symbol_evidence=evidence,
                git_executable=find_git(),
            )
        self.assertEqual(result["disposition"], "pass_through")
        self.assertEqual(result["reason"], "symbol_evidence_incomplete")
        self.assertNotIn("symbol", result)

    def test_symbol_request_without_a_trustworthy_range_passes_through(self) -> None:
        """Break caught: malformed semantic evidence silently becomes whole-file identity."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value.txt").write_bytes(b"abc")
            result = identity.identify_source(
                root,
                "value.txt",
                symbol_evidence={"complete": False},
                git_executable=find_git(),
            )
        self.assertEqual(result["disposition"], "pass_through")
        self.assertEqual(result["reason"], "symbol_evidence_incomplete")
        self.assertNotIn("selection", result)
        self.assertNotIn("symbol", result)

    def test_symbol_evidence_requires_utf8_without_bom_nonempty_boundaries(self) -> None:
        """Break caught: byte fragments or unsupported source encodings gain symbol identity."""
        identity = identity_module()
        cases = (
            (b"\xef\xbb\xbfanswer", 3, 9),
            (b"a\xffb", 0, 1),
            ("AéZ".encode("utf-8"), 2, 3),
            (b"abc", 1, 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, (payload, start_byte, end_byte) in enumerate(cases):
                relative_path = f"case-{index}.txt"
                (root / relative_path).write_bytes(payload)
                evidence = complete_symbol_evidence(payload, start_byte, end_byte)
                with self.subTest(index=index):
                    result = identity.identify_source(
                        root,
                        relative_path,
                        symbol_evidence=evidence,
                        git_executable=find_git(),
                    )
                    self.assertEqual(result["disposition"], "pass_through")
                    self.assertNotIn("symbol", result)

    def test_paths_are_canonical_bounded_regular_files_without_symlink_following(self) -> None:
        """Break caught: traversal, aliases, symlinks, or special files escape the root."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "regular").write_bytes(b"safe")
            outside = root.parent / f"{root.name}-outside"
            outside.write_bytes(b"outside")
            try:
                (root / "link").symlink_to(outside)
                (root / "linked-dir").symlink_to(root.parent, target_is_directory=True)
                path_cases = ("", ".", "../outside", "/etc/passwd", "a//b", "a/./b", "a\\b")
                for candidate in path_cases:
                    with self.subTest(candidate=candidate):
                        self.assert_identity_error(
                            "invalid_relative_path",
                            lambda candidate=candidate: identity.identify_source(
                                root, candidate, git_executable=find_git()
                            ),
                        )
                for candidate in ("link", f"linked-dir/{outside.name}"):
                    with self.subTest(candidate=candidate):
                        result = identity.identify_source(
                            root, candidate, git_executable=find_git()
                        )
                        self.assertEqual(result["disposition"], "pass_through")
                        self.assertEqual(result["reason"], "source_symlink")
                if hasattr(os, "mkfifo"):
                    os.mkfifo(root / "pipe")
                    special = identity.identify_source(
                        root, "pipe", git_executable=find_git()
                    )
                    self.assertEqual(special["disposition"], "pass_through")
                    self.assertEqual(special["reason"], "source_not_regular")
                missing = identity.identify_source(
                    root, "missing", git_executable=find_git()
                )
                self.assertEqual(missing["disposition"], "pass_through")
                self.assertEqual(missing["reason"], "source_missing")
            finally:
                outside.unlink(missing_ok=True)

    def test_opened_identity_descriptor_fstat_failures_are_stable_and_leak_free(
        self,
    ) -> None:
        """Break caught: root or source post-open fstat leaks its fd or raw OSError."""

        if not Path("/dev/fd").is_dir():
            self.skipTest("descriptor inventory is unavailable")
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "source.py").write_bytes(b"x")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

            def run_injected_failure(operation, target_name: str) -> tuple[str, int]:
                before = len(os.listdir("/dev/fd"))
                real_open = identity.os.open
                real_fstat = identity.os.fstat
                target_fds: set[int] = set()

                def observe_open(path, *args, **kwargs):
                    opened_fd = real_open(path, *args, **kwargs)
                    if os.fspath(path) == target_name:
                        target_fds.add(opened_fd)
                    return opened_fd

                def fail_target_fstat(opened_fd: int):
                    if opened_fd in target_fds:
                        raise OSError("HOSTILE-identity-fstat")
                    return real_fstat(opened_fd)

                outcome = "returned"
                with mock.patch.object(
                    identity.os, "open", side_effect=observe_open
                ), mock.patch.object(
                    identity.os, "fstat", side_effect=fail_target_fstat
                ):
                    try:
                        result = operation()
                    except identity.IdentityError:
                        outcome = "identity_error"
                    except OSError:
                        outcome = "raw_os_error"
                    else:
                        os.close(result)
                return outcome, len(os.listdir("/dev/fd")) - before

            cases = (
                ("root", lambda: identity._open_root(str(root)), str(root)),
                (
                    "regular-file",
                    lambda: identity._open_regular_file(
                        root_fd, "source.py", identity.IdentityLimits()
                    ),
                    "source.py",
                ),
            )
            try:
                for name, operation, target_name in cases:
                    with self.subTest(case=name):
                        self.assertEqual(
                            run_injected_failure(operation, target_name),
                            ("identity_error", 0),
                        )
            finally:
                os.close(root_fd)

    def test_path_enumeration_rejects_case_and_nfc_aliases(self) -> None:
        """Break caught: filesystem folding resolves a different spelling than requested."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Case.txt").write_bytes(b"case")
            self.assert_identity_error(
                "ambiguous_path",
                lambda: identity.identify_source(
                    root, "case.txt", git_executable=find_git()
                ),
            )
            (root / "e\u0301.txt").write_bytes(b"nfc")
            self.assert_identity_error(
                "ambiguous_path",
                lambda: identity.identify_source(
                    root, "é.txt", git_executable=find_git()
                ),
            )

    def test_file_range_path_and_evidence_limits_fail_closed(self) -> None:
        """Break caught: off-by-one reads or foreign limits disable bounded operation."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "value").write_bytes(b"12345")
            self.assert_identity_error(
                "file_too_large",
                lambda: identity.identify_source(
                    root,
                    "value",
                    git_executable=find_git(),
                    limits=identity.IdentityLimits(max_file_bytes=4),
                ),
            )
            for byte_range in ((-1, 1), (2, 1), (0, 6), (True, 1), [0, 1]):
                with self.subTest(byte_range=byte_range):
                    self.assert_identity_error(
                        "invalid_byte_range",
                        lambda byte_range=byte_range: identity.identify_source(
                            root,
                            "value",
                            byte_range=byte_range,
                            git_executable=find_git(),
                        ),
                    )
            self.assert_identity_error(
                "path_too_large",
                lambda: identity.identify_source(
                    root,
                    "value",
                    git_executable=find_git(),
                    limits=identity.IdentityLimits(max_path_bytes=4),
                ),
            )
            oversized = {"blob": "x" * 128}
            self.assert_identity_error(
                "symbol_evidence_too_large",
                lambda: identity.identify_source(
                    root,
                    "value",
                    byte_range=(0, 1),
                    symbol_evidence=oversized,
                    git_executable=find_git(),
                    limits=identity.IdentityLimits(max_symbol_evidence_bytes=32),
                ),
            )

    def test_git_worktree_snapshot_hashes_nul_framed_state_without_reflecting_paths(self) -> None:
        """Break caught: line parsing corrupts adversarial filenames or emits opaque Git bytes."""
        identity = identity_module()
        repository = TemporaryRepository()
        try:
            repository.run_git("init", "-q")
            weird_name = "line\nbreak.txt"
            (repository.root / weird_name).write_bytes(b"untracked")
            snapshot = identity.snapshot_repository(
                repository.root, git_executable=repository.git
            )
            raw_status = repository.run_git(
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=dirty",
            ).stdout
        finally:
            repository.close()

        logical = snapshot["logical_state"]
        self.assertEqual(snapshot["artifact_kind"], "repository_snapshot")
        self.assertEqual(
            snapshot["schema_version"], "contextguard-receipt-repository-snapshot/v1"
        )
        self.assertEqual(snapshot["disposition"], "captured")
        self.assertEqual(snapshot["reason"], "git_unborn_worktree_state")
        self.assertEqual(logical["kind"], "git_worktree")
        self.assertEqual(logical["head_state"], "unborn")
        self.assertEqual(logical["status_format"], "git-status-porcelain-v1-z")
        self.assertEqual(logical["status_sha256"], hashlib.sha256(raw_status).hexdigest())
        self.assertEqual(logical["status_nul_fields"], raw_status.count(b"\0"))
        self.assertEqual(logical["index_format"], "git-ls-files-stage-z")
        self.assertEqual(logical["index_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(logical["worktree_diff_sha256"], hashlib.sha256(b"").hexdigest())
        serialized = json.dumps(snapshot, ensure_ascii=False)
        self.assertNotIn("line", serialized)
        self.assertNotIn("break.txt", serialized)
        self.assertEqual(snapshot["evidence_boundary"], EVIDENCE_BOUNDARY)

    def test_corrupt_git_metadata_never_degrades_to_non_git_exact_identity(self) -> None:
        """Break caught: Git exit 128 is mistaken for proof that no repository exists."""
        identity = identity_module()
        repository = TemporaryRepository()
        try:
            repository.run_git("init", "-q")
            (repository.root / "source.py").write_bytes(b"print('safe')\n")
            (repository.root / ".git" / "config").write_bytes(b"[broken\n")
            snapshot = identity.snapshot_repository(
                repository.root, git_executable=repository.git
            )
            identified = identity.identify_source(
                repository.root, "source.py", git_executable=repository.git
            )
        finally:
            repository.close()

        self.assertEqual(snapshot["disposition"], "pass_through")
        self.assertEqual(snapshot["reason"], "git_command_failed")
        self.assertEqual(snapshot["logical_state"]["kind"], "unresolved")
        self.assertEqual(identified["disposition"], "pass_through")
        self.assertEqual(identified["reason"], "repository_state_unresolved")
        self.assertNotIn("source", identified)

    def test_snapshot_recheck_degrades_a_torn_multi_command_capture(self) -> None:
        """Break caught: one repository snapshot combines observations from two states."""
        identity = identity_module()
        repository = TemporaryRepository()
        try:
            repository.run_git("init", "-q")
            tracked = repository.root / "tracked"
            tracked.write_bytes(b"one")
            repository.run_git("add", "tracked")
            repository.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )
            real_snapshot_once = identity._snapshot_once
            calls = 0

            def capture_then_change(*arguments, **keyword_arguments):
                nonlocal calls
                result = real_snapshot_once(*arguments, **keyword_arguments)
                calls += 1
                if calls == 1:
                    tracked.write_bytes(b"two")
                    repository.run_git("add", "tracked")
                return result

            with mock.patch.object(
                identity, "_snapshot_once", side_effect=capture_then_change
            ):
                snapshot = identity.snapshot_repository(
                    repository.root, git_executable=repository.git
                )
        finally:
            repository.close()

        self.assertEqual(snapshot["disposition"], "pass_through")
        self.assertEqual(snapshot["reason"], "git_state_changed")
        self.assertEqual(snapshot["logical_state"]["kind"], "unresolved")

    def test_git_attached_detached_bare_and_linked_worktree_states_are_explicit(self) -> None:
        """Break caught: distinct Git topologies collapse into an invented normal worktree."""
        identity = identity_module()
        repository = TemporaryRepository()
        try:
            repository.run_git("init", "-q")
            (repository.root / "tracked").write_bytes(b"one")
            repository.run_git("add", "tracked")
            repository.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )
            attached = identity.snapshot_repository(
                repository.root, git_executable=repository.git
            )
            oid = repository.run_git("rev-parse", "--verify", "HEAD").stdout[:-1]
            repository.run_git("checkout", "--detach", "-q")
            detached = identity.snapshot_repository(
                repository.root, git_executable=repository.git
            )
            linked_root = repository.root.parent / f"{repository.root.name}-linked"
            repository.run_git("worktree", "add", "-qb", "linked-test", str(linked_root))
            try:
                linked = identity.snapshot_repository(linked_root, git_executable=repository.git)
                exclusion_paths = identity._repository_exclusion_paths(
                    linked_root, git_executable=repository.git
                )
                linked_git_directory = Path(
                    os.fsdecode(
                        repository.run_git(
                            "rev-parse", "--absolute-git-dir", cwd=linked_root
                        ).stdout[:-1]
                    )
                ).resolve()
            finally:
                repository.run_git("worktree", "remove", "--force", str(linked_root))

            bare_root = repository.root.parent / f"{repository.root.name}-bare.git"
            repository.run_git("init", "--bare", "-q", str(bare_root))
            try:
                bare = identity.snapshot_repository(bare_root, git_executable=repository.git)
                bare_source = identity.identify_source(
                    bare_root, "HEAD", git_executable=repository.git
                )
            finally:
                shutil.rmtree(bare_root)
        finally:
            repository.close()

        self.assertEqual(attached["logical_state"]["head_state"], "attached")
        self.assertTrue(attached["logical_state"]["head_ref_b64u"])
        self.assertEqual(attached["logical_state"]["head_oid_b64u"], b64url(oid))
        self.assertEqual(detached["logical_state"]["head_state"], "detached")
        self.assertNotIn("head_ref_b64u", detached["logical_state"])
        self.assertEqual(linked["instance"]["kind"], "linked_worktree")
        self.assertNotEqual(
            linked["instance"]["identity_sha256"],
            attached["instance"]["identity_sha256"],
        )
        self.assertEqual(
            exclusion_paths,
            (
                linked_root.resolve(),
                linked_git_directory,
                (repository.root / ".git").resolve(),
            ),
        )
        serialized_linked = json.dumps(linked, ensure_ascii=False)
        for private_path in exclusion_paths:
            self.assertNotIn(str(private_path), serialized_linked)
        self.assertEqual(bare["logical_state"]["kind"], "git_bare")
        self.assertEqual(bare["instance"]["kind"], "bare_repository")
        self.assertEqual(bare_source["disposition"], "pass_through")
        self.assertEqual(bare_source["reason"], "bare_repository")
        self.assertNotIn("source", bare_source)

    def test_source_binds_git_index_mode_and_rejects_repository_drift(self) -> None:
        """Break caught: HEAD/index/status or file mode changes reuse one source identity."""
        identity = identity_module()
        repository = TemporaryRepository()
        try:
            repository.run_git("init", "-q")
            source_path = repository.root / "tracked.py"
            source_path.write_bytes(b"print('one')\n")
            source_path.chmod(0o640)
            repository.run_git("add", "tracked.py")
            repository.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )
            clean = identity.identify_source(
                repository.root, "tracked.py", git_executable=repository.git
            )
            source_path.write_bytes(b"print('two')\n")
            dirty = identity.identify_source(
                repository.root, "tracked.py", git_executable=repository.git
            )
            repository.run_git("add", "tracked.py")
            staged = identity.identify_source(
                repository.root, "tracked.py", git_executable=repository.git
            )

            real_read = identity._read_stable_file

            def read_then_change(*arguments, **keyword_arguments):
                value = real_read(*arguments, **keyword_arguments)
                source_path.write_bytes(b"print('three')\n")
                repository.run_git("add", "tracked.py")
                return value

            with mock.patch.object(
                identity, "_read_stable_file", side_effect=read_then_change
            ):
                drifted = identity.identify_source(
                    repository.root, "tracked.py", git_executable=repository.git
                )

            repository.run_git("update-index", "--skip-worktree", "tracked.py")
            repository.run_git("update-index", "--assume-unchanged", "tracked.py")
            sparse_tag = repository.run_git(
                "ls-files", "-v", "--", "tracked.py"
            ).stdout
            try:
                sparse = identity.identify_source(
                    repository.root, "tracked.py", git_executable=repository.git
                )
            finally:
                repository.run_git(
                    "update-index",
                    "--no-assume-unchanged",
                    "--no-skip-worktree",
                    "tracked.py",
                )
        finally:
            repository.close()

        self.assertEqual(clean["source"]["file_type"], "regular")
        self.assertEqual(clean["source"]["mode"], "0640")
        self.assertEqual(clean["source"]["git_index"]["status"], "tracked")
        self.assertEqual(clean["source"]["git_index"]["stage"], 0)
        self.assertNotEqual(
            clean["repository"]["logical_state"]["state_sha256"],
            dirty["repository"]["logical_state"]["state_sha256"],
        )
        self.assertNotEqual(clean["source"]["identity_sha256"], dirty["source"]["identity_sha256"])
        self.assertNotEqual(dirty["source"]["identity_sha256"], staged["source"]["identity_sha256"])
        self.assertEqual(drifted["disposition"], "pass_through")
        self.assertEqual(drifted["reason"], "repository_state_changed")
        self.assertNotIn("source", drifted)
        self.assertTrue(sparse_tag.startswith(b"s "), sparse_tag)
        self.assertEqual(sparse["disposition"], "pass_through")
        self.assertEqual(sparse["reason"], "sparse_path")

    def test_git_executable_is_absolute_regular_and_output_is_bounded(self) -> None:
        """Break caught: PATH lookup, symlinked executables, shell use, or capture-all output."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assert_identity_error(
                "invalid_git_executable",
                lambda: identity.snapshot_repository(root, git_executable="git"),
            )
            executable = root / "fake-git"
            executable.write_text(
                "#!/bin/sh\n"
                "i=0\n"
                "while [ \"$i\" -lt 4096 ]; do\n"
                "  printf xxxxxxxxxxxxxxxx\n"
                "  i=$((i+1))\n"
                "done\n",
                encoding="utf-8",
            )
            executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            snapshot = identity.snapshot_repository(
                root,
                git_executable=str(executable),
                limits=identity.IdentityLimits(max_git_output_bytes=64),
            )
            linked_executable = root / "linked-git"
            linked_executable.symlink_to(executable)
            self.assert_identity_error(
                "invalid_git_executable",
                lambda: identity.snapshot_repository(
                    root, git_executable=str(linked_executable)
                ),
            )
        self.assertEqual(snapshot["disposition"], "pass_through")
        self.assertEqual(snapshot["reason"], "git_output_limit")

    def test_caller_environment_is_not_inherited_by_git(self) -> None:
        """Break caught: ambient secrets or config alter Git subprocess behavior."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-git"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ -n \"$CONTEXT_GUARD_SECRET_SENTINEL\" ]; then\n"
                "  printf leaked\n"
                "else\n"
                "  exit 128\n"
                "fi\n",
                encoding="utf-8",
            )
            executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            previous = os.environ.get("CONTEXT_GUARD_SECRET_SENTINEL")
            os.environ["CONTEXT_GUARD_SECRET_SENTINEL"] = "must-not-cross"
            try:
                snapshot = identity.snapshot_repository(root, git_executable=str(executable))
            finally:
                if previous is None:
                    os.environ.pop("CONTEXT_GUARD_SECRET_SENTINEL", None)
                else:
                    os.environ["CONTEXT_GUARD_SECRET_SENTINEL"] = previous
        self.assertEqual(snapshot["disposition"], "pass_through")
        self.assertEqual(snapshot["reason"], "non_git_directory")

    def test_repository_filter_commands_never_run_during_snapshot(self) -> None:
        """Break caught: repository-local clean or process filters execute during evidence capture."""
        identity = identity_module()
        filter_commands = {
            "clean": "sh -c 'touch .clean-filter-ran; cat'",
            "process": "sh -c 'touch .process-filter-ran; exit 1'",
        }
        for operation, command in filter_commands.items():
            with self.subTest(operation=operation):
                repository = TemporaryRepository()
                try:
                    repository.run_git("init", "-q")
                    source = repository.root / "tracked.txt"
                    source.write_bytes(b"one\n")
                    (repository.root / ".gitattributes").write_text(
                        "tracked.txt filter=hostile\n", encoding="utf-8"
                    )
                    repository.run_git("add", ".gitattributes", "tracked.txt")
                    repository.run_git(
                        "-c",
                        "user.name=Receipt Test",
                        "-c",
                        "user.email=receipt@example.invalid",
                        "commit",
                        "-qm",
                        "initial",
                    )
                    repository.run_git(
                        "config", f"filter.hostile.{operation}", command
                    )
                    repository.run_git("config", "filter.hostile.required", "true")
                    source.write_bytes(b"two\n")
                    sentinel = repository.root / f".{operation}-filter-ran"

                    snapshot = identity.snapshot_repository(
                        repository.root, git_executable=repository.git
                    )

                    self.assertFalse(sentinel.exists())
                    self.assertEqual(snapshot["disposition"], "captured")
                    self.assertEqual(snapshot["logical_state"]["kind"], "git_worktree")
                finally:
                    repository.close()

    def test_populated_submodule_filters_never_run_during_parent_snapshot(self) -> None:
        """Break caught: parent status recursively executes filters in a populated submodule."""
        identity = identity_module()
        child = TemporaryRepository()
        parent = TemporaryRepository()
        try:
            child.run_git("init", "-q")
            (child.root / "tracked.txt").write_bytes(b"one\n")
            (child.root / ".gitattributes").write_text(
                "tracked.txt filter=hostile\n", encoding="utf-8"
            )
            child.run_git("add", ".gitattributes", "tracked.txt")
            child.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )

            parent.run_git("init", "-q")
            parent.run_git(
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(child.root),
                "nested",
            )
            parent.run_git("add", ".gitmodules", "nested")
            parent.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )
            populated = parent.root / "nested"
            parent.run_git(
                "config",
                "filter.hostile.clean",
                "sh -c 'touch .submodule-filter-ran; cat'",
                cwd=populated,
            )
            (populated / "tracked.txt").write_bytes(b"two\n")
            sentinel = populated / ".submodule-filter-ran"

            snapshot = identity.snapshot_repository(
                parent.root, git_executable=parent.git
            )

            self.assertFalse(sentinel.exists())
            self.assertEqual(snapshot["disposition"], "captured")
            self.assertEqual(snapshot["logical_state"]["kind"], "git_worktree")
        finally:
            parent.close()
            child.close()

    def test_parent_snapshot_preserves_staged_gitlink_commit_evidence(self) -> None:
        """Break caught: blocking submodule dirty scans also hides a staged gitlink update."""
        identity = identity_module()
        child = TemporaryRepository()
        parent = TemporaryRepository()
        try:
            child.run_git("init", "-q")
            (child.root / "tracked.txt").write_bytes(b"one\n")
            child.run_git("add", "tracked.txt")
            child.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )

            parent.run_git("init", "-q")
            parent.run_git(
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(child.root),
                "nested",
            )
            parent.run_git("add", ".gitmodules", "nested")
            parent.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "initial",
            )
            baseline = identity.snapshot_repository(
                parent.root, git_executable=parent.git
            )

            populated = parent.root / "nested"
            (populated / "tracked.txt").write_bytes(b"two\n")
            parent.run_git("add", "tracked.txt", cwd=populated)
            parent.run_git(
                "-c",
                "user.name=Receipt Test",
                "-c",
                "user.email=receipt@example.invalid",
                "commit",
                "-qm",
                "second",
                cwd=populated,
            )
            parent.run_git("add", "nested")
            staged = identity.snapshot_repository(
                parent.root, git_executable=parent.git
            )
        finally:
            parent.close()
            child.close()

        self.assertEqual(baseline["disposition"], "captured")
        self.assertEqual(staged["disposition"], "captured")
        self.assertNotEqual(
            baseline["logical_state"]["index_sha256"],
            staged["logical_state"]["index_sha256"],
        )
        self.assertNotEqual(
            baseline["logical_state"]["state_sha256"],
            staged["logical_state"]["state_sha256"],
        )

    def test_filter_discovery_malformed_overflow_or_error_fails_closed(self) -> None:
        """Break caught: incomplete filter discovery permits later worktree commands."""
        identity = identity_module()
        cases = {
            "empty-success": ("exit 0", "git_state_malformed"),
            "malformed": (
                "printf 'filter.hostile.clean'; exit 0",
                "git_state_malformed",
            ),
            "invalid-key": (
                "printf 'filter.hostile.clean.extra\\000'; exit 0",
                "git_state_malformed",
            ),
            "overflow": (
                "i=0; while [ \"$i\" -lt 65 ]; do "
                "printf 'filter.hostile%s.clean\\000' \"$i\"; "
                "i=$((i+1)); done; exit 0",
                "git_output_limit",
            ),
            "error": ("exit 2", "git_command_failed"),
        }
        for case, (discovery_action, expected_reason) in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executable = root / "fake-git"
                executable.write_text(
                    "#!/bin/sh\n"
                    "case \"$5\" in\n"
                    f"  config) {discovery_action} ;;\n"
                    "  rev-parse)\n"
                    "    case \"$6\" in\n"
                    "      --is-inside-work-tree) printf 'true\\n' ;;\n"
                    "      --is-bare-repository) printf 'false\\n' ;;\n"
                    "      --git-dir|--git-common-dir) printf '.git\\n' ;;\n"
                    "      --verify) exit 128 ;;\n"
                    "      *) exit 2 ;;\n"
                    "    esac ;;\n"
                    "  symbolic-ref) printf 'refs/heads/main\\n' ;;\n"
                    "  status|ls-files|diff) exit 0 ;;\n"
                    "  *) exit 2 ;;\n"
                    "esac\n",
                    encoding="utf-8",
                )
                executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

                snapshot = identity.snapshot_repository(
                    root, git_executable=str(executable)
                )

                self.assertEqual(snapshot["disposition"], "pass_through")
                self.assertEqual(snapshot["reason"], expected_reason)
                self.assertEqual(snapshot["logical_state"]["kind"], "unresolved")

    def test_filter_overrides_are_normalized_deduplicated_and_child_inherited(self) -> None:
        """Break caught: unsafe or duplicate config keys escape command-scoped overrides."""
        identity = identity_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-git"
            executable.write_text(
                "#!/bin/sh\n"
                "case \"$5\" in\n"
                "  config)\n"
                "    printf 'FILTER.Hostile.CLEAN\\000'\n"
                "    printf 'filter.Hostile.clean\\000'\n"
                "    printf 'filter.Hostile.smudge\\000'\n"
                "    printf 'filter.Hostile.process\\000'\n"
                "    printf 'filter.Hostile.required\\000' ;;\n"
                "  rev-parse)\n"
                "    case \"$6\" in\n"
                "      --is-inside-work-tree) printf 'true\\n' ;;\n"
                "      --is-bare-repository) printf 'false\\n' ;;\n"
                "      --git-dir|--git-common-dir) printf '.git\\n' ;;\n"
                "      --verify) exit 128 ;;\n"
                "      *) exit 2 ;;\n"
                "    esac ;;\n"
                "  symbolic-ref) printf 'refs/heads/main\\n' ;;\n"
                "  status)\n"
                "    [ \"$GIT_CONFIG_COUNT\" = 4 ] || exit 2\n"
                "    [ \"$GIT_CONFIG_KEY_0\" = filter.Hostile.clean ] || exit 2\n"
                "    [ \"$GIT_CONFIG_VALUE_0\" = cat ] || exit 2\n"
                "    [ \"$GIT_CONFIG_KEY_1\" = filter.Hostile.smudge ] || exit 2\n"
                "    [ \"$GIT_CONFIG_VALUE_1\" = cat ] || exit 2\n"
                "    [ \"$GIT_CONFIG_KEY_2\" = filter.Hostile.process ] || exit 2\n"
                "    [ \"${GIT_CONFIG_VALUE_2+x}\" = x ] || exit 2\n"
                "    [ -z \"$GIT_CONFIG_VALUE_2\" ] || exit 2\n"
                "    [ \"$GIT_CONFIG_KEY_3\" = filter.Hostile.required ] || exit 2\n"
                "    [ \"$GIT_CONFIG_VALUE_3\" = false ] || exit 2 ;;\n"
                "  ls-files|diff) exit 0 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            snapshot = identity.snapshot_repository(
                root, git_executable=str(executable)
            )

        self.assertEqual(snapshot["disposition"], "captured")
        self.assertEqual(snapshot["logical_state"]["kind"], "git_worktree")

    def test_schema_is_recursively_closed_and_freezes_companion_boundary(self) -> None:
        """Break caught: nested extension points or weakened evidence claims enter receipts."""
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(
            schema["$id"], "https://context-guard.local/schemas/source-identity-v1.json"
        )

        object_nodes: list[dict[str, object]] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    object_nodes.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(schema)
        self.assertGreaterEqual(len(object_nodes), 8)
        for node in object_nodes:
            self.assertIs(node.get("additionalProperties"), False)

        top = schema["properties"]
        self.assertEqual(top["artifact_kind"]["const"], "source_identity")
        self.assertEqual(
            top["schema_version"]["const"], "contextguard-receipt-source-identity/v1"
        )
        boundary = schema["$defs"]["evidence_boundary"]
        self.assertEqual(boundary["required"], list(EVIDENCE_BOUNDARY))
        for key, expected in EVIDENCE_BOUNDARY.items():
            self.assertEqual(boundary["properties"][key]["const"], expected)
        source = schema["$defs"]["source"]
        self.assertEqual(
            source["required"],
            [
                "byte_length",
                "content_sha256",
                "file_type",
                "git_index",
                "identity_sha256",
                "mode",
            ],
        )
        self.assertEqual(source["properties"]["file_type"]["const"], "regular")
        logical = schema["$defs"]["logical_state"]["properties"]
        self.assertEqual(logical["index_format"]["const"], "git-ls-files-stage-z")
        self.assertIn("worktree_diff_sha256", logical)
        self.assertIn("git_state_changed", logical["reason"]["enum"])
        self.assertIn(
            "git_state_changed",
            schema["$defs"]["repository_snapshot"]["properties"]["reason"]["enum"],
        )
        self.assertEqual(
            schema["$defs"]["git_index"]["properties"]["status"]["enum"],
            ["not_applicable", "tracked", "untracked"],
        )

    def test_mutating_compatibility_boundary_cannot_change_identity_receipts(self) -> None:
        """Break caught: mutable compatibility state upgrades companion evidence."""
        identity = identity_module()
        contracts = importlib.import_module("context_guard_receipt.contracts")
        original = dict(contracts.EVIDENCE_BOUNDARY)
        try:
            contracts.EVIDENCE_BOUNDARY["provider_claim_authority"] = True
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "value").write_bytes(b"safe")
                result = identity.identify_source(
                    root, "value", git_executable=find_git()
                )
            self.assertEqual(result["evidence_boundary"], EVIDENCE_BOUNDARY)
            self.assertEqual(result["repository"]["evidence_boundary"], EVIDENCE_BOUNDARY)
        finally:
            contracts.EVIDENCE_BOUNDARY.clear()
            contracts.EVIDENCE_BOUNDARY.update(original)


if __name__ == "__main__":
    unittest.main()
