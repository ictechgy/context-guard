from __future__ import annotations

import runpy
import subprocess
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_homebrew_formula.py"


class HomebrewFormulaVerificationTests(unittest.TestCase):
    def test_temp_tap_verification_ignores_only_cross_formula_duplicate(self) -> None:
        namespace = runpy.run_path(
            str(SCRIPT), run_name="homebrew_formula_verifier_test"
        )
        self.assertIn("homebrew_commands", namespace)
        output = Path("/tmp/context-guard.rb")
        formula_name = "contextguard/release-verification-123/context-guard"
        commands = namespace["homebrew_commands"](
            Path("/trusted/brew"), output, formula_name
        )
        self.assertEqual(
            commands[0],
            [
                "/trusted/brew",
                "style",
                "--except-cops",
                "Lint/DuplicateMethods",
                str(output),
            ],
        )
        self.assertEqual(commands[0].count("--except-cops"), 1)
        self.assertEqual(
            commands[1:],
            (
                [
                    "/trusted/brew",
                    "audit",
                    "--strict",
                    "--new",
                    "--formula",
                    formula_name,
                ],
                [
                    "/trusted/brew",
                    "install",
                    "--build-from-source",
                    formula_name,
                ],
                ["/trusted/brew", "test", formula_name],
            ),
        )
        self.assertEqual(namespace["render"]("0.5.1", "a" * 64).count("def install"), 1)

    def test_renders_only_exact_version_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "context-guard.rb"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.1",
                    "--sha256",
                    "a" * 64,
                    "--output",
                    str(output),
                    "--no-brew",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            formula = output.read_text(encoding="utf-8")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            self.assertTrue(
                formula.startswith("# typed: strict\n# frozen_string_literal: true\n")
            )
            self.assertIn("refs/tags/v0.5.1.tar.gz", formula)
            self.assertIn(f'sha256 "{"a" * 64}"', formula)
            self.assertNotIn("{{VERSION}}", formula)
            self.assertNotIn("REPLACE_WITH_RELEASE_TARBALL_SHA256", formula)
            self.assertIn(
                'system bin/"context-guard", "setup", "--root", testpath/"project",\n'
                '           "--agent", "codex", "--scope", "project", "--plan"',
                formula,
            )

    def test_rejects_noncanonical_version_or_digest_before_writing(self) -> None:
        for version, digest in (("v0.5.1", "a" * 64), ("0.5.1", "A" * 64)):
            with self.subTest(version=version, digest=digest), tempfile.TemporaryDirectory() as temporary_directory:
                output = Path(temporary_directory) / "context-guard.rb"
                completed = subprocess.run(
                    [sys.executable, str(SCRIPT), "--version", version, "--sha256", digest, "--output", str(output), "--no-brew"],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(output.exists())
if __name__ == "__main__":
    unittest.main()
