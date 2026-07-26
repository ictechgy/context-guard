#!/usr/bin/env python3
"""A2 staged-package behavior and exact public-surface regression tests."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from tests.context_guard_a2_oracles import (
    ENTRYPOINTS,
    ROOT as ORACLE_ROOT,
    env_path_cases,
    migration_cases,
    surface_claim_cases,
)


ROOT = Path(
    os.environ.get("CONTEXT_GUARD_A2_REPO_ROOT", str(ORACLE_ROOT))
).resolve()
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PACKAGE_JSON = ROOT / "package.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def run_json(
    argv: list[str],
    *,
    cwd: Path,
    payload: dict[str, object] | None = None,
) -> tuple[subprocess.CompletedProcess[str], object]:
    proc = subprocess.run(
        argv,
        cwd=cwd,
        input=(json.dumps(payload) if payload is not None else None),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed rc={proc.returncode}: {argv!r}\n"
            f"stdout={proc.stdout[:1000]!r}\nstderr={proc.stderr[:1000]!r}"
        )
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"command did not emit one JSON document: {argv!r}\n"
            f"stdout={proc.stdout[:1000]!r}\nstderr={proc.stderr[:1000]!r}"
        ) from exc
    return proc, parsed


def hook_reason(response: object) -> str:
    if not isinstance(response, dict):
        return ""
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, dict):
        return ""
    reason = specific.get("permissionDecisionReason")
    return reason if isinstance(reason, str) else ""


class ContextGuardA2PackageSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="context-guard-a2-package-")
        cls.temp_root = Path(cls._tmp.name)
        cls.smoke = load_module(
            ROOT / "scripts" / "release_smoke.py",
            "context_guard_a2_release_smoke",
        )
        cls.staged = cls.smoke.copy_plugin_package_for_smoke(
            PLUGIN_DIR,
            cls.temp_root / "installed-plugin",
        )
        cls.guard = cls.staged / "bin" / "context-guard-guard-read"
        cls.setup = cls.staged / "bin" / "context-guard-setup"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_staged_package_has_regular_executable_a2_entrypoints_and_bins(self):
        package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        self.assertEqual(
            "plugins/context-guard/bin/context-guard-guard-read",
            package["bin"]["context-guard-guard-read"],
        )
        self.assertEqual(
            "plugins/context-guard/bin/context-guard-setup",
            package["bin"]["context-guard-setup"],
        )
        for path in (
            self.staged / ".claude-plugin" / "plugin.json",
            self.staged / "README.md",
            self.staged / "examples" / "settings.example.json",
            self.guard,
            self.setup,
        ):
            with self.subTest(path=path.relative_to(self.staged)):
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
        for path in (self.guard, self.setup):
            with self.subTest(executable=path.name):
                self.assertTrue(
                    stat.S_IMODE(path.stat().st_mode) & stat.S_IXUSR
                )
        self.assertFalse(
            any(path.is_symlink() for path in self.staged.rglob("*"))
        )

    def test_staged_settings_bind_env_guard_only_to_read_matcher(self):
        settings = json.loads(
            (self.staged / "examples" / "settings.example.json").read_text(
                encoding="utf-8"
            )
        )
        pre_tool = settings["hooks"]["PreToolUse"]
        guard_entries = [
            entry
            for entry in pre_tool
            if any(
                hook.get("command") == "context-guard-guard-read"
                for hook in entry.get("hooks", [])
                if isinstance(hook, dict)
            )
        ]
        self.assertEqual(1, len(guard_entries))
        self.assertEqual("Read", guard_entries[0]["matcher"])
        self.assertNotIn("Glob", {entry["matcher"] for entry in guard_entries})
        self.assertNotIn("Grep", {entry["matcher"] for entry in guard_entries})
        self.assertNotIn("Bash", {entry["matcher"] for entry in guard_entries})
        deny = settings["permissions"]["deny"]
        self.assertNotIn("Read(./.env)", deny)
        self.assertNotIn("Read(./.env.*)", deny)

    def test_staged_guard_matches_exact_env_classifier_and_tool_scope(self):
        with tempfile.TemporaryDirectory(
            prefix="context-guard-a2-guard-"
        ) as td:
            sandbox = Path(td)
            for name in (
                ".env",
                ".env.production",
                ".ENV",
                ".ENV.EXAMPLE",
                ".env.example",
                ".env.sample",
                ".env.template",
                "README.md",
            ):
                (sandbox / name).write_text(
                    "A2_SYNTHETIC_SECRET=fixture-only\n",
                    encoding="utf-8",
                )

            matrix = {
                case["path"]: case["expected_decision"]
                for case in env_path_cases()
                if (
                    case["entrypoint"] == "packaged"
                    and "/" not in case["path"].replace("\\", "/")
                    and not case["symlink_ambiguous"]
                    and (sandbox / case["path"]).is_file()
                )
            }
            for relative, expected in matrix.items():
                with self.subTest(path=relative, tool="Read"):
                    _proc, response = run_json(
                        [sys.executable, str(self.guard)],
                        cwd=sandbox,
                        payload={
                            "tool_name": "Read",
                            "tool_input": {"file_path": relative},
                        },
                    )
                    decision = "deny" if hook_reason(response) else "allow"
                    self.assertEqual(expected, decision)

            for tool in ("Glob", "Grep", "Bash"):
                with self.subTest(tool=tool):
                    _proc, response = run_json(
                        [sys.executable, str(self.guard)],
                        cwd=sandbox,
                        payload={
                            "tool_name": tool,
                            "tool_input": {"file_path": ".env"},
                        },
                    )
                    self.assertEqual({}, response)

            _proc, denied = run_json(
                [sys.executable, str(self.guard)],
                cwd=sandbox,
                payload={
                    "tool_name": "Read",
                    "tool_input": {"file_path": ".env"},
                },
            )
            reason = hook_reason(denied)
            self.assertIn("Read-only environment-file policy", reason)
            self.assertIn("protects Claude Read only", reason)
            self.assertIn(
                "Glob name listings, Grep, and Bash/process access are out of scope",
                reason,
            )
            self.assertNotIn("A2_SYNTHETIC_SECRET", json.dumps(denied))

    def test_staged_setup_migrates_only_exact_owned_env_denies(self):
        with tempfile.TemporaryDirectory(
            prefix="context-guard-a2-setup-"
        ) as td:
            project = Path(td)
            settings_path = project / ".claude" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            before = [
                "Read(./.env)",
                "Read(./nested/.env)",
                "Read(./.env.*)",
                "Read(./.env.example)",
            ]
            settings_path.write_text(
                json.dumps({"permissions": {"deny": before}}, indent=2) + "\n",
                encoding="utf-8",
            )
            _proc, result = run_json(
                [
                    sys.executable,
                    str(self.setup),
                    "--root",
                    str(project),
                    "--yes",
                    "--no-diet-scan",
                    "--json",
                ],
                cwd=project,
            )
            self.assertIsInstance(result, dict)
            after = json.loads(
                settings_path.read_text(encoding="utf-8")
            )["permissions"]["deny"]
            self.assertNotIn("Read(./.env)", after)
            self.assertNotIn("Read(./.env.*)", after)
            similar = ["Read(./nested/.env)", "Read(./.env.example)"]
            self.assertEqual(
                similar,
                [rule for rule in after if rule in similar],
            )

            expected_rows = [
                case
                for case in migration_cases()
                if (
                    case["entrypoint"] == "packaged"
                    and case["name"] == "remove-two-exact-rules"
                )
            ]
            self.assertEqual(1, len(expected_rows))
            self.assertEqual(2, expected_rows[0]["expected_removed_count"])

            first_bytes = settings_path.read_bytes()
            _proc, _second = run_json(
                [
                    sys.executable,
                    str(self.setup),
                    "--root",
                    str(project),
                    "--yes",
                    "--no-diet-scan",
                    "--json",
                ],
                cwd=project,
            )
            self.assertEqual(first_bytes, settings_path.read_bytes())

    def test_staged_plugin_readme_states_exact_limitations_and_toctou(self):
        readme = (self.staged / "README.md").read_text(encoding="utf-8")
        required = (
            "PreToolUse` hook with matcher `Read",
            "`Read(./.env)`",
            "`Read(./.env.*)`",
            "`.env.example`",
            "`.env.sample`",
            "`.env.template`",
            "`Glob` can still list names",
            "`Grep` and `Bash` can read file contents and are outside this hook",
            "not universal `.env` or Bash protection",
            "separate open after the hook returns",
            "documented TOCTOU limitation",
        )
        for phrase in required:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, readme)
        forbidden = (
            "universal environment-file protection",
            "Bash is protected by the Read hook",
            "all Claude tools are protected",
        )
        for phrase in forbidden:
            self.assertNotIn(phrase, readme)

    def test_repository_docs_cover_the_oracle_surface_matrix(self):
        english_docs = (
            ROOT / "README.md",
            ROOT / "plugins" / "context-guard" / "README.md",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8") for path in english_docs
        )
        canonical_rows = [
            row
            for row in surface_claim_cases()
            if row["entrypoint"] == ENTRYPOINTS[0]
        ]
        self.assertEqual(
            {
                "Claude Read",
                "Claude Glob",
                "Claude Grep",
                "Claude Bash/process",
                "raw Read range proof",
                "Claude setup migration",
            },
            {row["surface"] for row in canonical_rows},
        )
        for phrase in (
            "| `Read` |",
            "| `Glob` |",
            "| `Grep` |",
            "| `Bash` |",
            "not universal `.env` or Bash protection",
            "post-hook window",
            "TOCTOU limitation",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, combined)
        for row in canonical_rows:
            for forbidden_claim in row["forbidden_claims"]:
                with self.subTest(
                    surface=row["surface"],
                    forbidden_claim=forbidden_claim,
                ):
                    self.assertNotIn(forbidden_claim, combined)


if __name__ == "__main__":
    unittest.main()
