from __future__ import annotations

import json
import os
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

from context_guard_receipt import cleanup, cli


class CleanupContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _absent_plan(self) -> dict[str, object]:
        return cleanup.plan_cleanup(str(self.root))

    def _state(self) -> Path:
        plan = self._absent_plan()
        return self.root.parent / str(plan["target_name"])

    def _populate(self) -> Path:
        state = self._state()
        state.mkdir(mode=0o700)
        nested = state / "store-v1"
        nested.mkdir(mode=0o700)
        payload = nested / "payload.bin"
        payload.write_bytes(b"bounded-cleanup-fixture")
        payload.chmod(0o600)
        metadata = state / "metadata.json"
        metadata.write_text("{}\n", encoding="ascii")
        metadata.chmod(0o600)
        return state

    def test_absent_plan_is_read_only_and_deterministic(self) -> None:
        before = sorted(path.name for path in self.base.iterdir())
        first = self._absent_plan()
        second = self._absent_plan()

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "absent")
        self.assertFalse(first["requires_confirmation"])
        self.assertFalse(first["artifact_cleanup_performed"])
        self.assertEqual(first["entry_count"], 0)
        self.assertRegex(str(first["target_name"]), r"^\.context-guard-receipt-state-[0-9a-f]{64}$")
        self.assertRegex(str(first["plan_sha256"]), r"^[0-9a-f]{64}$")
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), before)

    def test_apply_requires_exact_plan_and_deletes_only_derived_state(self) -> None:
        state = self._populate()
        decoy = self.base / (".context-guard-receipt-state-" + "f" * 64)
        decoy.mkdir(mode=0o700)
        plan = cleanup.plan_cleanup(str(self.root))

        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["file_count"], 2)
        self.assertEqual(plan["directory_count"], 2)
        self.assertGreater(plan["total_bytes"], 0)
        with self.assertRaises(cleanup.CleanupError) as caught:
            cleanup.apply_cleanup(str(self.root), "0" * 64)
        self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.PLAN_MISMATCH)
        self.assertTrue(state.is_dir())

        result = cleanup.apply_cleanup(str(self.root), str(plan["plan_sha256"]))

        self.assertEqual(result["status"], "deleted")
        self.assertTrue(result["artifact_cleanup_performed"])
        self.assertEqual(result["plan_sha256"], plan["plan_sha256"])
        self.assertFalse(state.exists())
        self.assertTrue(decoy.is_dir())
        self.assertFalse(list(self.base.glob(".context-guard-receipt-cleanup-*")))

    def test_tree_drift_rejects_without_deleting(self) -> None:
        state = self._populate()
        plan = cleanup.plan_cleanup(str(self.root))
        payload = state / "store-v1" / "payload.bin"
        payload.write_bytes(b"changed")
        payload.chmod(0o600)

        with self.assertRaises(cleanup.CleanupError) as caught:
            cleanup.apply_cleanup(str(self.root), str(plan["plan_sha256"]))

        self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.PLAN_MISMATCH)
        self.assertTrue(state.is_dir())
        self.assertEqual(payload.read_bytes(), b"changed")

    def test_symlink_and_nonprivate_entries_fail_closed(self) -> None:
        state = self._state()
        state.mkdir(mode=0o700)
        outside = self.base / "outside"
        outside.write_text("keep", encoding="ascii")
        link = state / "link"
        try:
            link.symlink_to(outside)
        except OSError as error:
            self.skipTest(f"symlink unavailable: {error}")

        with self.assertRaises(cleanup.CleanupError) as caught:
            cleanup.plan_cleanup(str(self.root))

        self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.STATE_UNSAFE)
        self.assertEqual(outside.read_text(encoding="ascii"), "keep")
        self.assertTrue(link.is_symlink())

    def test_nonprivate_and_hardlinked_files_fail_closed(self) -> None:
        for kind in ("mode", "hardlink"):
            with self.subTest(kind=kind):
                state = self._populate()
                payload = state / "store-v1" / "payload.bin"
                if kind == "mode":
                    payload.chmod(0o644)
                else:
                    os.link(payload, state / "linked.bin")
                with self.assertRaises(cleanup.CleanupError) as caught:
                    cleanup.plan_cleanup(str(self.root))
                self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.STATE_UNSAFE)
                for child in sorted(state.rglob("*"), reverse=True):
                    if child.is_dir():
                        child.rmdir()
                    else:
                        child.unlink()
                state.rmdir()

    def test_cross_device_entry_fails_closed(self) -> None:
        state = self._populate()
        descriptor = os.open(state, cleanup._directory_flags())
        expected_device = os.fstat(descriptor).st_dev
        real_stat = os.stat

        def cross_device_stat(path: object, *args: object, **kwargs: object) -> object:
            status = real_stat(path, *args, **kwargs)
            if path != "payload.bin":
                return status
            return SimpleNamespace(
                st_dev=expected_device + 1,
                st_ino=status.st_ino,
                st_mode=status.st_mode,
                st_mtime_ns=status.st_mtime_ns,
                st_nlink=status.st_nlink,
                st_size=status.st_size,
                st_uid=status.st_uid,
            )

        try:
            with mock.patch.object(cleanup.os, "stat", side_effect=cross_device_stat):
                with self.assertRaises(cleanup.CleanupError) as caught:
                    cleanup._scan_directory(
                        descriptor,
                        ".",
                        0,
                        [],
                        [0],
                        expected_device,
                    )
        finally:
            os.close(descriptor)

        self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.STATE_UNSAFE)
        self.assertTrue((state / "store-v1" / "payload.bin").is_file())

    def test_partial_delete_is_reported_and_quarantine_is_preserved(self) -> None:
        state = self._populate()
        plan = cleanup.plan_cleanup(str(self.root))
        injected = cleanup.CleanupError(cleanup.CleanupErrorCode.CLEANUP_INCOMPLETE)
        with mock.patch.object(cleanup, "_delete_directory", side_effect=injected):
            with self.assertRaises(cleanup.CleanupError) as caught:
                cleanup.apply_cleanup(str(self.root), str(plan["plan_sha256"]))

        self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.CLEANUP_INCOMPLETE)
        self.assertFalse(state.exists())
        self.assertEqual(len(list(self.base.glob(".context-guard-receipt-cleanup-*"))), 1)

    def test_root_symlink_and_filesystem_root_are_rejected(self) -> None:
        alias = self.base / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink unavailable: {error}")
        for rejected in (str(alias), os.sep, "relative"):
            with self.subTest(rejected=rejected), self.assertRaises(cleanup.CleanupError) as caught:
                cleanup.plan_cleanup(rejected)
            self.assertEqual(caught.exception.code, cleanup.CleanupErrorCode.ROOT_REJECTED)

    def test_cli_plan_and_apply_are_closed_and_non_reflective(self) -> None:
        state = self._populate()
        writes: list[bytes] = []
        with mock.patch.object(cli, "write_stdout", side_effect=writes.append):
            plan_code = cli._cleanup_bash_reference_state(
                ("--bash-reference-v1", "--root", str(self.root), "--plan")
            )
        self.assertEqual(plan_code, 0)
        plan = json.loads(writes.pop())
        rendered = json.dumps(plan, sort_keys=True)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("payload.bin", rendered)

        with mock.patch.object(cli, "write_stdout", side_effect=writes.append):
            apply_code = cli._cleanup_bash_reference_state(
                (
                    "--bash-reference-v1",
                    "--root",
                    str(self.root),
                    "--yes",
                    "--confirm-plan-sha256",
                    plan["plan_sha256"],
                )
            )
        self.assertEqual(apply_code, 0)
        self.assertEqual(json.loads(writes.pop())["status"], "deleted")
        self.assertFalse(state.exists())

    def test_cli_rejects_arbitrary_state_directory_and_missing_confirmation(self) -> None:
        for arguments in (
            ("--root", str(self.root), "--plan"),
            ("--bash-reference-v1", "--state-dir", str(self.base), "--plan"),
            ("--bash-reference-v1", "--root", str(self.root), "--yes"),
        ):
            with self.subTest(arguments=arguments):
                with mock.patch.object(cli, "emit_error", return_value=65):
                    self.assertEqual(cli._cleanup_bash_reference_state(arguments), 65)


if __name__ == "__main__":
    unittest.main()
