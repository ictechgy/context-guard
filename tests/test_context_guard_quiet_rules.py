#!/usr/bin/env python3
"""Gate C regressions for the Claude-only quiet-narration rules branch.

Gate C is deliberately static/setup-only.  These tests prove the CLI boundary,
managed-file behavior, mandatory rule content, and canonical/package parity;
they do not claim that a model complied or that tokens/cost were saved.
"""

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPTS = (
    ROOT / "context-guard-kit" / "setup_wizard.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-setup",
)

BEGIN = "<!-- BEGIN context-guard:narration-mode mode=quiet version=1 -->"
END = "<!-- END context-guard:narration-mode -->"


def quiet_argv(script: Path, root: Path, mode: str, action: str) -> list[str]:
    return [
        sys.executable,
        str(script),
        "--root",
        str(root),
        "--scope",
        "project",
        "--agent",
        "claude",
        "--rules-only",
        "--narration-mode",
        mode,
        action,
        "--json",
    ]


def run_quiet(
    script: Path,
    root: Path,
    mode: str,
    action: str,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        quiet_argv(script, root, mode, action),
        text=True,
        capture_output=True,
        check=check,
    )


def relative_file_state(root: Path) -> dict[str, tuple[bytes, int]]:
    state: dict[str, tuple[bytes, int]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            state[str(path.relative_to(root))] = (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
    return state


def write_hostile_settings(root: Path) -> Path:
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_bytes(b"{ malformed settings that rules-only must not parse")
    return settings


class QuietNarrationGateCTests(unittest.TestCase):
    maxDiff = None

    def test_plan_is_no_settings_no_write_and_canonical_matches_packaged(self) -> None:
        payloads: list[dict[str, object]] = []
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    settings = write_hostile_settings(root)
                    sentinel = root / "AGENTS.md"
                    sentinel.write_bytes(b"user-owned\n")
                    before = relative_file_state(root)
                    proc = run_quiet(script, root, "quiet", "--plan")
                    self.assertEqual(proc.stderr, "")
                    payload = json.loads(proc.stdout)
                    payloads.append(payload)
                    self.assertFalse(payload["applied"])
                    self.assertEqual(relative_file_state(root), before)
                    self.assertEqual(sentinel.read_bytes(), b"user-owned\n")

        # Ignore absolute temp-root paths while pinning the observable plan.
        normalized = []
        for payload in payloads:
            copy = json.loads(json.dumps(payload))
            copy["root"] = "<root>"
            copy["settings_path"] = "<root>/.claude/settings.json"
            copy["rule_file"] = "<root>/CLAUDE.md"
            for entry in copy.get("adapter_plan", []):
                if entry.get("rule_file") == "CLAUDE.md":
                    entry["rule_file"] = "CLAUDE.md"
            normalized.append(copy)
        self.assertEqual(len(normalized), len(SETUP_SCRIPTS))
        self.assertEqual(normalized[0], normalized[1])

    def test_apply_quiet_is_idempotent_and_default_removes_only_owned_span(self) -> None:
        outputs: list[bytes] = []
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    settings = write_hostile_settings(root)
                    rule = root / "CLAUDE.md"
                    prefix = b"\xffuser prefix without utf8 normalization\n"
                    suffix = b"user suffix without final newline"
                    rule.write_bytes(prefix + suffix)
                    original_settings = settings.read_bytes()
                    applied = run_quiet(script, root, "quiet", "--yes")
                    self.assertEqual(applied.stderr, "")
                    first = rule.read_bytes()
                    outputs.append(first)
                    self.assertIn(BEGIN.encode("ascii"), first)
                    self.assertIn(END.encode("ascii"), first)
                    self.assertTrue(first.startswith(prefix + suffix + b"\n" + BEGIN.encode("ascii")))
                    self.assertEqual(first.count(BEGIN.encode("ascii")), 1)
                    self.assertEqual(first.count(END.encode("ascii")), 1)

                    second = run_quiet(script, root, "quiet", "--yes")
                    self.assertEqual(second.stderr, "")
                    self.assertEqual(rule.read_bytes(), first)

                    removed = run_quiet(script, root, "default", "--yes")
                    self.assertEqual(removed.stderr, "")
                    self.assertEqual(rule.read_bytes(), prefix + suffix)
                    self.assertEqual(settings.read_bytes(), original_settings)

                    unexpected = [
                        path.relative_to(root)
                        for path in root.rglob("*")
                        if path.is_file()
                        and path not in {settings, rule}
                        and not (
                            path.parent == root
                            and (
                                path.name == ".CLAUDE.md.lock"
                                or path.name.startswith("CLAUDE.md.bak-")
                            )
                        )
                    ]
                    self.assertEqual(unexpected, [])
                    for backup in root.glob("CLAUDE.md.bak-*"):
                        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

        self.assertEqual(len(outputs), len(SETUP_SCRIPTS))
        self.assertEqual(outputs[0], outputs[1])

    def test_rule_static_contract_preserves_mandatory_user_facing_output(self) -> None:
        assets = (
            ROOT / "context-guard-kit" / "brief" / "narration-mode.quiet.md",
            ROOT / "plugins" / "context-guard" / "brief" / "narration-mode.quiet.md",
        )
        self.assertEqual(assets[0].read_bytes(), assets[1].read_bytes())
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                namespace = runpy.run_path(str(script), run_name="quiet_rules_static_test")
                with mock.patch.object(
                    Path,
                    "read_text",
                    side_effect=AssertionError("runtime narration rendering must not open assets"),
                ):
                    rendered = namespace["render_quiet_narration_block"]()
                self.assertEqual(rendered.encode("utf-8") + b"\n", assets[0].read_bytes())
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    run_quiet(script, root, "quiet", "--yes")
                    text = (root / "CLAUDE.md").read_text(encoding="utf-8")
                    lowered = text.lower()

                    for label, alternatives in {
                        "approvals/decisions": ("approval", "decision"),
                        "blockers": ("blocker", "blocked"),
                        "failures": ("failure", "failed"),
                        "destructive/security warnings": ("destructive", "security", "safety"),
                        "higher-priority progress": ("higher-priority", "required progress"),
                        "final result": ("final result",),
                        "changed files": ("changed files",),
                        "verification": ("verification",),
                    }.items():
                        with self.subTest(script=script, requirement=label):
                            self.assertTrue(
                                any(term in lowered for term in alternatives),
                                f"quiet rule omits mandatory category: {label}",
                            )

                    for label, alternatives in {
                        "preambles": ("preamble",),
                        "per-tool narration": ("per-tool", "tool narration"),
                        "filler": ("filler",),
                        "repeated interim summaries": ("repeated interim", "interim summar"),
                    }.items():
                        with self.subTest(script=script, suppression=label):
                            self.assertTrue(
                                any(term in lowered for term in alternatives),
                                f"quiet rule omits bounded suppression category: {label}",
                            )

                    self.assertTrue("best-effort" in lowered or "best effort" in lowered)
                    self.assertTrue(
                        "does not guarantee" in lowered
                        or "no guaranteed" in lowered
                        or "does not promise" in lowered
                    )
                    self.assertIn("reasoning", lowered)
                    self.assertIn("final", lowered)
                    self.assertNotIn("guaranteed token savings", lowered)
                    self.assertNotIn("guarantees token savings", lowered)

    def test_rules_branch_open_trace_excludes_assets_settings_and_other_rules(self) -> None:
        audit_source = r'''
import atexit
import json
import os
import sys

events = []

def audit(event, args):
    if event != "open" or not args:
        return
    value = args[0]
    if isinstance(value, (str, bytes, os.PathLike)):
        events.append(os.fsdecode(value))

sys.addaudithook(audit)

@atexit.register
def write_trace():
    with open(os.environ["CONTEXTGUARD_TEST_OPEN_TRACE"], "w", encoding="utf-8") as handle:
        json.dump(events, handle)
'''
        for script in SETUP_SCRIPTS:
            for action in ("--plan", "--yes"):
                with self.subTest(script=script, action=action):
                    with tempfile.TemporaryDirectory() as tmp:
                        workspace = Path(tmp)
                        root = workspace / "project"
                        root.mkdir()
                        write_hostile_settings(root)
                        (root / "AGENTS.md").write_text("sentinel\n", encoding="utf-8")
                        audit_dir = workspace / "audit"
                        audit_dir.mkdir()
                        (audit_dir / "sitecustomize.py").write_text(audit_source, encoding="utf-8")
                        trace = workspace / "open-trace.json"
                        env = os.environ.copy()
                        env["PYTHONPATH"] = os.pathsep.join(
                            [str(audit_dir), env.get("PYTHONPATH", "")]
                        )
                        env["CONTEXTGUARD_TEST_OPEN_TRACE"] = str(trace)
                        proc = subprocess.run(
                            quiet_argv(script, root, "quiet", action),
                            text=True,
                            capture_output=True,
                            check=False,
                            env=env,
                        )
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        opened = json.loads(trace.read_text(encoding="utf-8"))
                        lowered = "\n".join(opened).lower()
                        self.assertNotIn("narration-mode.quiet.md", lowered)
                        self.assertNotIn(".claude/settings", lowered)
                        self.assertNotIn("agents.md", lowered)
                        project_opens = [
                            path
                            for path in opened
                            if str(root) in path
                            or Path(path).name.startswith(("CLAUDE.md", ".CLAUDE.md"))
                        ]
                        for path in project_opens:
                            name = Path(path).name
                            self.assertTrue(
                                name == "CLAUDE.md"
                                or name == ".CLAUDE.md.lock"
                                or name.startswith("CLAUDE.md.bak-")
                                or (name.startswith(".CLAUDE.md.") and name.endswith(".tmp")),
                                f"unexpected rules-only open: {path}",
                            )

    def test_invalid_target_and_conflict_matrix_exits_two_without_writes(self) -> None:
        invalid_extras = (
            ("rules-only-without-operation", ("--rules-only", "--agent", "claude", "--plan")),
            (
                "narration-without-rules-only",
                ("--agent", "claude", "--narration-mode", "quiet", "--plan"),
            ),
            (
                "unsupported-agent",
                (
                    "--rules-only",
                    "--agent",
                    "codex",
                    "--narration-mode",
                    "quiet",
                    "--plan",
                ),
            ),
            (
                "multiple-agents",
                (
                    "--rules-only",
                    "--agent",
                    "claude,codex",
                    "--narration-mode",
                    "quiet",
                    "--plan",
                ),
            ),
            (
                "user-scope",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--scope",
                    "user",
                    "--narration-mode",
                    "quiet",
                    "--plan",
                ),
            ),
            (
                "with-init",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--with-init",
                    "--plan",
                ),
            ),
            (
                "with-skill",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--with-skill",
                    "--plan",
                ),
            ),
            (
                "brief-mode",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--brief-mode",
                    "lite",
                    "--plan",
                ),
            ),
            (
                "verify",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--verify",
                ),
            ),
            (
                "no-backup",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--no-backup",
                    "--plan",
                ),
            ),
            (
                "settings-flag",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--no-statusline",
                    "--plan",
                ),
            ),
            (
                "missing-plan-or-yes",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                ),
            ),
            (
                "plan-and-yes",
                (
                    "--rules-only",
                    "--agent",
                    "claude",
                    "--narration-mode",
                    "quiet",
                    "--plan",
                    "--yes",
                ),
            ),
        )
        for script in SETUP_SCRIPTS:
            for label, extra in invalid_extras:
                with self.subTest(script=script, case=label):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        sentinel = root / "keep.bin"
                        sentinel.write_bytes(b"\x00\xffkeep")
                        before = relative_file_state(root)
                        proc = subprocess.run(
                            [
                                sys.executable,
                                str(script),
                                "--root",
                                str(root),
                                "--json",
                                *extra,
                            ],
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                        self.assertEqual(relative_file_state(root), before)

    def test_malformed_ambiguous_and_unsupported_markers_fail_closed(self) -> None:
        fixtures = {
            "orphan-end": f"user\n{END}\n".encode(),
            "unterminated": f"user\n{BEGIN}\nquiet\n".encode(),
            "ambiguous": (
                f"{BEGIN}\none\n{END}\n{BEGIN}\ntwo\n{END}\n"
            ).encode(),
            "unsupported-version": (
                "<!-- BEGIN context-guard:narration-mode mode=quiet version=2 -->\n"
                "future\n"
                f"{END}\n"
            ).encode(),
        }
        for script in SETUP_SCRIPTS:
            for mode in ("quiet", "default"):
                for label, original in fixtures.items():
                    with self.subTest(script=script, mode=mode, state=label):
                        with tempfile.TemporaryDirectory() as tmp:
                            root = Path(tmp)
                            target = root / "CLAUDE.md"
                            target.write_bytes(original)
                            proc = run_quiet(script, root, mode, "--yes", check=False)
                            self.assertNotEqual(proc.returncode, 0)
                            self.assertEqual(target.read_bytes(), original)
                            self.assertEqual(proc.stdout, "")
                            self.assertEqual(list(root.glob("CLAUDE.md.bak-*")), [])

    def test_concurrent_snapshot_conflict_fails_closed(self) -> None:
        for script in SETUP_SCRIPTS:
            with self.subTest(script=script):
                namespace = runpy.run_path(str(script), run_name="quiet_rules_conflict_test")
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / "CLAUDE.md"
                    original = b"user-owned without final newline"
                    target.write_bytes(original)
                    args = namespace["build_parser"]().parse_args(
                        [
                            "--root",
                            str(root),
                            "--scope",
                            "project",
                            "--agent",
                            "claude",
                            "--rules-only",
                            "--narration-mode",
                            "quiet",
                            "--yes",
                            "--json",
                        ]
                    )
                    globals_dict = namespace["run_quiet_narration_rules"].__globals__
                    real_writer = globals_dict["write_managed_file"]
                    globals_dict["write_managed_file"] = lambda *a, **k: {
                        "status": "conflict",
                        "reason": "synthetic concurrent snapshot conflict",
                    }
                    try:
                        with self.assertRaisesRegex(
                            SystemExit,
                            "synthetic concurrent snapshot conflict",
                        ):
                            namespace["run_quiet_narration_rules"](args)
                    finally:
                        globals_dict["write_managed_file"] = real_writer
                    self.assertEqual(target.read_bytes(), original)
                    self.assertEqual(list(root.glob("CLAUDE.md.bak-*")), [])

    def test_rules_branch_requires_exact_claude_project_shape(self):
        invalid = (
            ("--root", "{root}", "--agent", "claude", "--narration-mode", "quiet", "--plan"),
            ("--root", "{root}", "--rules-only", "--agent", "claude", "--plan"),
            (
                "--root",
                "{root}",
                "--rules-only",
                "--only",
                "claude",
                "--scope",
                "project",
                "--narration-mode",
                "quiet",
                "--plan",
            ),
            (
                "--root",
                "{root}",
                "--rules-only",
                "--agent",
                "codex",
                "--scope",
                "project",
                "--narration-mode",
                "quiet",
                "--plan",
            ),
            (
                "--root",
                "{root}",
                "--rules-only",
                "--agent",
                "claude,codex",
                "--scope",
                "project",
                "--narration-mode",
                "quiet",
                "--plan",
            ),
            (
                "--root",
                "{root}",
                "--rules-only",
                "--agent",
                "claude",
                "--scope",
                "project",
                "--narration-mode",
                "quiet",
                "--plan",
                "--yes",
            ),
        )
        for entrypoint in SETUP_SCRIPTS:
            for argv in invalid:
                with self.subTest(entrypoint=entrypoint, argv=argv):
                    with tempfile.TemporaryDirectory() as tmp:
                        project = Path(tmp)
                        sentinel = project / "CLAUDE.md"
                        sentinel.write_bytes(b"unchanged\n")
                        proc = subprocess.run(
                            [
                                "python3",
                                str(entrypoint),
                                *(str(project) if arg == "{root}" else arg for arg in argv),
                            ],
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                        self.assertEqual(proc.returncode, 2, proc.stderr)
                        self.assertEqual(sentinel.read_bytes(), b"unchanged\n")
                        self.assertEqual(sorted(path.name for path in project.iterdir()), ["CLAUDE.md"])


if __name__ == "__main__":
    unittest.main()
