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


class FakeBrewRunner:
    def __init__(
        self,
        tap_root: Path,
        *,
        initially_installed: bool = False,
        fail_install: bool = False,
        fail_test: bool = False,
        fail_uninstall: bool = False,
    ) -> None:
        self.tap_root = tap_root
        self.initially_installed = initially_installed
        self.fail_install = fail_install
        self.fail_test = fail_test
        self.fail_uninstall = fail_uninstall
        self.install_attempted = False
        self.install_completed = False
        self.calls: list[list[str]] = []
        self.list_checks = 0

    def __call__(self, command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        command = list(command)
        self.calls.append(command)
        arguments = command[1:]
        if arguments == ["list", "--versions", "context-guard"]:
            self.list_checks += 1
            installed = self.initially_installed or self.install_attempted
            return subprocess.CompletedProcess(
                command,
                0 if installed else 1,
                "context-guard 0.6.0\n" if installed else "",
                "",
            )
        if arguments[:1] == ["--repo"]:
            return subprocess.CompletedProcess(command, 0, f"{self.tap_root}\n", "")
        if arguments[:1] == ["install"]:
            self.install_attempted = True
            if self.fail_install:
                raise subprocess.CalledProcessError(1, command)
            self.install_completed = True
        if arguments[:1] == ["test"] and self.fail_test:
            raise subprocess.CalledProcessError(1, command)
        if arguments[:1] == ["uninstall"] and self.fail_uninstall:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0, "", "")


class HomebrewFormulaVerificationTests(unittest.TestCase):
    def test_full_verification_refuses_preexisting_installation(self) -> None:
        namespace = runpy.run_path(str(SCRIPT), run_name="homebrew_preinstalled_test")
        self.assertIn("verify_with_homebrew", namespace)
        with tempfile.TemporaryDirectory() as temporary_directory:
            tap_root = Path(temporary_directory) / "tap"
            tap_root.mkdir()
            runner = FakeBrewRunner(tap_root, initially_installed=True)
            with self.assertRaisesRegex(SystemExit, "already installed"):
                namespace["verify_with_homebrew"](
                    Path("/trusted/brew"),
                    Path(temporary_directory) / "output.rb",
                    "formula",
                    {},
                    tap_name="contextguard/release-verification-test",
                    runner=runner,
                )
        self.assertFalse(any(call[1:2] == ["tap-new"] for call in runner.calls))
        self.assertFalse(any(call[1:2] == ["uninstall"] for call in runner.calls))

    def test_partial_install_is_removed_and_primary_error_is_preserved(self) -> None:
        namespace = runpy.run_path(str(SCRIPT), run_name="homebrew_partial_test")
        self.assertIn("verify_with_homebrew", namespace)
        with tempfile.TemporaryDirectory() as temporary_directory:
            tap_root = Path(temporary_directory) / "tap"
            (tap_root / "Formula").mkdir(parents=True)
            runner = FakeBrewRunner(tap_root, fail_install=True)
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                namespace["verify_with_homebrew"](
                    Path("/trusted/brew"),
                    Path(temporary_directory) / "output.rb",
                    "formula",
                    {},
                    tap_name="contextguard/release-verification-test",
                    runner=runner,
                )
        self.assertEqual(raised.exception.cmd[1], "install")
        self.assertTrue(any(call[1:2] == ["uninstall"] for call in runner.calls))
        self.assertTrue(any(call[1:2] == ["untap"] for call in runner.calls))

    def test_uninstall_failure_still_untaps_and_preserves_test_error(self) -> None:
        namespace = runpy.run_path(str(SCRIPT), run_name="homebrew_cleanup_test")
        self.assertIn("verify_with_homebrew", namespace)
        with tempfile.TemporaryDirectory() as temporary_directory:
            tap_root = Path(temporary_directory) / "tap"
            (tap_root / "Formula").mkdir(parents=True)
            runner = FakeBrewRunner(
                tap_root, fail_test=True, fail_uninstall=True
            )
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                namespace["verify_with_homebrew"](
                    Path("/trusted/brew"),
                    Path(temporary_directory) / "output.rb",
                    "formula",
                    {},
                    tap_name="contextguard/release-verification-test",
                    runner=runner,
                )
        self.assertEqual(raised.exception.cmd[1], "test")
        self.assertTrue(any(call[1:2] == ["uninstall"] for call in runner.calls))
        self.assertTrue(any(call[1:2] == ["untap"] for call in runner.calls))

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
