from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETUP = ROOT / "context-guard-kit" / "setup_wizard.py"


@unittest.skipUnless(
    os.environ.get("CONTEXT_GUARD_CAMPAIGN_ACCEPTANCE") == "1",
    "prospective campaign acceptance only",
)
class HomeSettingsAliasScopeTests(unittest.TestCase):
    def run_setup(
        self, home: Path, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(home)
        return subprocess.run(
            [
                sys.executable,
                str(SETUP),
                "--root",
                str(home),
                "--allow-home-settings",
                "--no-diet-scan",
                "--json",
                *arguments,
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_alias_requires_explicit_agent_before_any_home_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()
            completed = self.run_setup(home, "--yes")

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("explicit agent", completed.stderr)
            self.assertFalse((home / ".claude" / "settings.json").exists())
            self.assertFalse((home / ".context-guard").exists())

    def test_alias_rejects_no_backup_for_existing_home_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text("{}\n", encoding="utf-8")
            settings.chmod(0o600)
            before = settings.read_bytes()

            completed = self.run_setup(
                home, "--agent", "claude", "--yes", "--no-backup"
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("Refusing --no-backup for user-scope", completed.stderr)
            self.assertEqual(settings.read_bytes(), before)
            self.assertFalse((home / ".context-guard" / "rollback").exists())

    def test_alias_success_uses_user_scope_backup_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text("{}\n", encoding="utf-8")
            settings.chmod(0o600)

            completed = self.run_setup(home, "--agent", "claude", "--yes")

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["scope"], "user")
            self.assertEqual(result["root"], str(home.resolve()))
            self.assertTrue(Path(result["backup_path"]).is_file())
            rollback_path = Path(result["rollback_path"])
            self.assertTrue(rollback_path.is_file())
            rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
            self.assertEqual(rollback["target_path"], str(settings.resolve()))
            self.assertEqual(rollback["backup_path"], result["backup_path"])

    def test_alias_doctor_uses_effective_scope_in_every_recovery_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir()

            completed = self.run_setup(home, "--verify")

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            recovery_commands = [
                check["next_action"]
                for check in result["checks"]
                if check.get("id") in {"setup-plan", "adapter-plan"}
            ]
            recovery_commands.extend(result["recommended_commands"])
            self.assertTrue(recovery_commands)
            for command in recovery_commands:
                self.assertIn("--scope user", command)
                self.assertNotIn("--scope project", command)
                self.assertNotIn("--root", command)


if __name__ == "__main__":
    unittest.main()
