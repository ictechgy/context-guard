from __future__ import annotations

import json
import os
import stat
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
class UserSettingsPermissionTests(unittest.TestCase):
    def run_setup(self, home: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HOME"] = str(home)
        return subprocess.run(
            [
                sys.executable,
                str(SETUP),
                "--scope",
                "user",
                "--agent",
                "claude",
                "--yes",
                "--no-diet-scan",
                "--json",
            ],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )

    def test_user_scope_rejects_group_or_world_writable_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(mode=0o700)
            home.chmod(0o777)

            completed = self.run_setup(home)

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse((home / ".claude").exists())
            self.assertFalse((home / ".context-guard").exists())

    def test_user_scope_rejects_writable_claude_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True, mode=0o700)
            settings.write_text("{}\n", encoding="utf-8")
            settings.chmod(0o600)
            settings.parent.chmod(0o777)
            before = settings.read_bytes()

            completed = self.run_setup(home)

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(settings.read_bytes(), before)
            self.assertEqual(stat.S_IMODE(settings.parent.stat().st_mode), 0o777)
            self.assertFalse((home / ".context-guard").exists())

    def test_user_scope_rejects_writable_settings_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True, mode=0o700)
            settings.write_text("{}\n", encoding="utf-8")
            settings.chmod(0o666)
            before = settings.read_bytes()

            completed = self.run_setup(home)

            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(settings.read_bytes(), before)
            self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o666)
            self.assertFalse((home / ".context-guard").exists())

    def test_user_scope_accepts_owned_non_writable_existing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            settings = home / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True, mode=0o700)
            settings.write_text("{}\n", encoding="utf-8")
            settings.chmod(0o600)

            completed = self.run_setup(home)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertTrue(result["applied"])
            self.assertEqual(result["scope"], "user")


if __name__ == "__main__":
    unittest.main()
