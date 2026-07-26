#!/usr/bin/env python3
"""Focused A2 tests for exact Claude Read permission migration."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPTS = [
    ROOT / "context-guard-kit" / "setup_wizard.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-setup",
]
EXACT_ENV_READ_DENIES = {
    "Read(./.env)",
    "Read(./.env.*)",
}
USER_DENIES = [
    "Read(./custom-before/**)",
    "Read(./.env.local)",
    "Read(./.env/**)",
    "Read(./.envx)",
    " read(./.env)",
    "read(./.env)",
    {"custom": "entry"},
    7,
    "Read(./custom-after/**)",
]


def load_setup(path: Path, suffix: str):
    name = f"_a2_env_setup_{suffix}"
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def setup_argv(script: Path, root: Path, *extra: str) -> list[str]:
    return [
        sys.executable,
        str(script),
        "--root",
        str(root),
        "--no-statusline",
        "--no-bash-hook",
        "--no-model-defaults",
        "--no-failed-attempt-nudge",
        "--no-diet-scan",
        "--json",
        *extra,
    ]


def run_setup(script: Path, root: Path, *extra: str) -> dict[str, object]:
    proc = subprocess.run(
        setup_argv(script, root, *extra),
        text=True,
        capture_output=True,
        check=True,
    )
    if proc.stderr:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


def write_legacy_settings(root: Path) -> tuple[Path, bytes]:
    target = root / ".claude" / "settings.json"
    target.parent.mkdir()
    deny = [
        USER_DENIES[0],
        "Read(./.env)",
        *USER_DENIES[1:4],
        "Read(./.env.*)",
        *USER_DENIES[4:8],
        "Read(./.env)",
        USER_DENIES[8],
    ]
    original = (
        json.dumps(
            {
                "permissions": {
                    "allow": ["Read(./public/**)"],
                    "deny": deny,
                },
                "userKey": "preserve",
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    target.write_bytes(original)
    target.chmod(0o640)
    return target, original


class EnvPermissionMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules = [
            load_setup(path, f"{index}_{self._testMethodName}")
            for index, path in enumerate(SETUP_SCRIPTS)
        ]

    def test_helper_removes_only_exact_strings_and_preserves_user_order(self) -> None:
        original = [
            USER_DENIES[0],
            "Read(./.env)",
            *USER_DENIES[1:],
            "Read(./.env.*)",
        ]
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                settings = {"permissions": {"deny": list(original)}}
                actions: list[str] = []
                setup.ensure_permissions(
                    settings,
                    actions,
                    migrate_env_read_denies=True,
                )
                deny = settings["permissions"]["deny"]
                self.assertEqual(deny[: len(USER_DENIES)], USER_DENIES)
                self.assertFalse(
                    any(
                        isinstance(rule, str)
                        and rule in EXACT_ENV_READ_DENIES
                        for rule in deny
                    )
                )
                self.assertIn(
                    "removed 2 obsolete permissions.deny rules now enforced by the Claude Read hook",
                    actions,
                )

                gated = {"permissions": {"deny": list(original)}}
                setup.ensure_permissions(
                    gated,
                    [],
                    migrate_env_read_denies=False,
                )
                self.assertEqual(gated["permissions"]["deny"][: len(original)], original)

    def test_plan_apply_idempotence_and_expected_post_rollback(self) -> None:
        for index, script in enumerate(SETUP_SCRIPTS):
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target, original = write_legacy_settings(root)
                    before_stat = target.stat()
                    before_files = sorted(path.relative_to(root) for path in root.rglob("*"))

                    plan = run_setup(script, root, "--plan")
                    after_plan_stat = target.stat()
                    self.assertTrue(plan["changed"])
                    self.assertFalse(plan["applied"])
                    self.assertTrue(any("removed 3 obsolete" in action for action in plan["actions"]))
                    self.assertEqual(target.read_bytes(), original)
                    self.assertEqual(
                        (
                            after_plan_stat.st_dev,
                            after_plan_stat.st_ino,
                            after_plan_stat.st_mode,
                            after_plan_stat.st_size,
                            after_plan_stat.st_mtime_ns,
                        ),
                        (
                            before_stat.st_dev,
                            before_stat.st_ino,
                            before_stat.st_mode,
                            before_stat.st_size,
                            before_stat.st_mtime_ns,
                        ),
                    )
                    self.assertEqual(
                        sorted(path.relative_to(root) for path in root.rglob("*")),
                        before_files,
                    )

                    applied = run_setup(script, root, "--yes")
                    self.assertTrue(applied["changed"])
                    self.assertTrue(applied["applied"])
                    self.assertTrue(any("non-cooperating editor" in warning for warning in applied["warnings"]))
                    settings = json.loads(target.read_text(encoding="utf-8"))
                    deny = settings["permissions"]["deny"]
                    self.assertEqual(deny[: len(USER_DENIES)], USER_DENIES)
                    self.assertFalse(
                        any(
                            isinstance(rule, str)
                            and rule in EXACT_ENV_READ_DENIES
                            for rule in deny
                        )
                    )
                    self.assertEqual(settings["permissions"]["allow"], ["Read(./public/**)"])
                    self.assertEqual(settings["userKey"], "preserve")
                    self.assertIn("context-guard-guard-read", json.dumps(settings["hooks"]))
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

                    backup = Path(str(applied["backup_path"]))
                    self.assertEqual(backup.read_bytes(), original)
                    self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
                    backups_before_second_apply = sorted(target.parent.glob("settings.json.bak-*"))

                    again = run_setup(script, root, "--yes")
                    self.assertFalse(again["changed"])
                    self.assertFalse(again["applied"])
                    self.assertEqual(again["actions"], [])
                    self.assertEqual(
                        sorted(target.parent.glob("settings.json.bak-*")),
                        backups_before_second_apply,
                    )

                    setup = self.modules[index]
                    post = setup.read_managed_file_snapshot(target)
                    rolled_back = setup.write_managed_file(
                        target,
                        expected=post,
                        desired=backup.read_bytes(),
                        mode=0o600,
                        dir_mode=setup.PRIVATE_DIR_MODE,
                    )
                    self.assertEqual(rolled_back["status"], "applied")
                    self.assertEqual(target.read_bytes(), original)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)

    def test_expected_post_conflict_preserves_external_edit(self) -> None:
        for index, script in enumerate(SETUP_SCRIPTS):
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target, original = write_legacy_settings(root)
                    applied = run_setup(script, root, "--yes")
                    backup = Path(str(applied["backup_path"]))
                    self.assertEqual(backup.read_bytes(), original)

                    setup = self.modules[index]
                    post = setup.read_managed_file_snapshot(target)
                    external = b'{"external":"edit"}\n'
                    target.write_bytes(external)
                    conflict = setup.write_managed_file(
                        target,
                        expected=post,
                        desired=backup.read_bytes(),
                        mode=0o600,
                        dir_mode=setup.PRIVATE_DIR_MODE,
                    )
                    self.assertEqual(conflict["status"], "conflict")
                    self.assertEqual(target.read_bytes(), external)

    def test_no_read_guard_or_no_denies_keeps_legacy_entries(self) -> None:
        for script in SETUP_SCRIPTS:
            for gate in ("--no-read-guard", "--no-denies"):
                with self.subTest(script=script, gate=gate):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        target, _ = write_legacy_settings(root)
                        run_setup(script, root, "--yes", gate)
                        deny = json.loads(target.read_text(encoding="utf-8"))["permissions"]["deny"]
                        string_denies = {
                            entry for entry in deny if isinstance(entry, str)
                        }
                        self.assertTrue(EXACT_ENV_READ_DENIES.issubset(string_denies))

    def test_canonical_and_packaged_setup_are_exact_mirrors(self) -> None:
        self.assertEqual(SETUP_SCRIPTS[0].read_bytes(), SETUP_SCRIPTS[1].read_bytes())
        for setup in self.modules:
            with self.subTest(script=setup.__file__):
                self.assertTrue(
                    EXACT_ENV_READ_DENIES.isdisjoint(setup.RECOMMENDED_DENIES)
                )
                self.assertEqual(
                    set(setup.PRODUCT_OWNED_ENV_READ_DENIES),
                    EXACT_ENV_READ_DENIES,
                )


if __name__ == "__main__":
    unittest.main()
