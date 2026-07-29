"""Focused offline contract tests for the S001 measurement substrate.

The substrate is deliberately opt-in through ``variant.measurement``.  These
tests use only a local fake CLI and exercise both the canonical runner and the
packaged mirror.  Existing benchmark tests are frozen compatibility surfaces
and are intentionally not imported or modified here.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
BENCH_SCRIPTS = (
    ROOT / "context-guard-kit" / "benchmark_runner.py",
    ROOT / "plugins" / "context-guard" / "bin" / "context-guard-bench",
)

MEASUREMENT_SCHEMA_VERSION = "contextguard.bench.measurement-substrate.v1"
RAW_RECEIPT_SCHEMA_VERSION = "contextguard.bench.raw-receipt.v1"
ARTIFACT_INDEX_SCHEMA_VERSION = "contextguard.bench.artifact-index.v1"

CANDIDATE_HASH = "a" * 64
RAW_SECRET = "RAW_EVENT_PAYLOAD_MUST_NOT_ESCAPE"
AUTH_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def expected_run_id(*, task: str, repetition: int, arm: str, attempt: int, namespace: str) -> str:
    """Return the public S001 identity digest used for duplicate/symlink probes."""
    identity_tuple = [CANDIDATE_HASH, task, repetition, arm, attempt, namespace]
    return hashlib.sha256(_canonical_json_bytes(identity_tuple)).hexdigest()


def _settings(*, managed_hooks: bool = False, divergent: bool = False) -> dict:
    data: dict[str, object] = {
        "permissions": {"allow": ["Read"] if not divergent else ["Read", "Bash"]},
        "model": "sonnet",
    }
    if managed_hooks:
        data["hooks"] = {
            "PreToolUse": [
                {
                    "matcher": "Read",
                    "hooks": [{"type": "command", "command": "context-guard-guard-read"}],
                }
            ],
            "PostToolUseFailure": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "context-guard-failed-nudge"}],
                }
            ],
        }
    return data


def _measurement(
    *,
    settings_file: str,
    arm: str = "baseline",
    attempt: int = 0,
    expected_hooks: list[str] | None = None,
    fake_mode: str = "auto",
    artifact_root: str = "artifacts",
) -> dict:
    return {
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
        "settings_file": settings_file,
        "setting_sources": ["user", "project"],
        "environment": {
            "allow": [
                "PATH",
                "LANG",
                "CG_FAKE_LOG",
                "CG_FAKE_MODE",
                "CG_FAKE_CAPABILITIES",
            ],
            "overrides": {
                "CG_FAKE_MODE": fake_mode,
                "CG_MEASUREMENT_OVERRIDE": "fixed",
            },
        },
        "workspace": {"mode": "isolated"},
        "session": {"mode": "isolated", "persistence": "disabled"},
        "hook_events": {
            "enabled": True,
            "expected_identities": list(expected_hooks or []),
        },
        "cli_capabilities": [
            "--settings",
            "--setting-sources",
            "--include-hook-events",
            "--no-session-persistence",
            "stream-json",
        ],
        "identity": {
            "candidate_hash": CANDIDATE_HASH,
            "repetition": 0,
            "arm": arm,
            "attempt": attempt,
            "namespace": "s001-tests",
        },
        "artifact_root": artifact_root,
    }


def _variant(name: str, measurement: dict, extra_args: list[str] | None = None) -> dict:
    return {"name": name, "extra_args": list(extra_args or []), "measurement": measurement}


def _write_fake_cli(root: Path) -> Path:
    fake = root / "fake-claude"
    fake.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            RAW_SECRET = {RAW_SECRET!r}
            DEFAULT_CAPABILITIES = (
                "--settings --setting-sources --include-hook-events "
                "--no-session-persistence stream-json"
            )

            def log(kind):
                path = os.environ.get("CG_FAKE_LOG")
                if not path:
                    return
                selected = {{
                    key: os.environ.get(key)
                    for key in (
                        "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
                        "TMPDIR", "CLAUDE_CONFIG_DIR", "LANG", "CG_MEASUREMENT_OVERRIDE",
                        "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN",
                        "AWS_SECRET_ACCESS_KEY", "UNRELATED_AMBIENT_VALUE",
                    )
                    if key in os.environ
                }}
                record = {{
                    "kind": kind,
                    "argv": sys.argv[1:],
                    "cwd": os.getcwd(),
                    "env": selected,
                }}
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\\n")

            if "--help" in sys.argv:
                log("help")
                print(os.environ.get("CG_FAKE_CAPABILITIES", DEFAULT_CAPABILITIES))
                raise SystemExit(0)
            if "--version" in sys.argv:
                log("version")
                print("fake-claude 1.0")
                raise SystemExit(0)

            log("provider")
            home = Path(os.environ["HOME"])
            home.mkdir(parents=True, exist_ok=True)
            sentinel = home / "cross-run-sentinel"
            if sentinel.exists():
                print(json.dumps({{"type": "result", "subtype": "error_during_execution", "is_error": True}}))
                raise SystemExit(19)
            sentinel.write_text("unique", encoding="utf-8")

            mode = os.environ.get("CG_FAKE_MODE", "auto")
            if mode == "auto":
                settings_index = sys.argv.index("--settings") + 1
                mode = "valid-hooks" if "treatment" in sys.argv[settings_index] else "valid-no-hooks"
            hook_events = [
                {{
                    "type": "hook_event",
                    "event_name": "PreToolUse",
                    "hook_identity": "context-guard-guard-read",
                    "tool": "Read",
                    "decision": "allow",
                    "timestamp": "2026-07-30T00:00:00Z",
                    "payload": RAW_SECRET,
                }},
                {{
                    "type": "hook_event",
                    "event_name": "PostToolUseFailure",
                    "hook_identity": "context-guard-failed-nudge",
                    "tool": "Bash",
                    "decision": "error",
                    "timestamp": "2026-07-30T00:00:01Z",
                    "payload": RAW_SECRET,
                }},
            ]
            terminal = {{
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "usage": {{"input_tokens": 7, "output_tokens": 3}},
                "total_cost_usd": 0.01,
            }}

            if mode in {{"valid-hooks", "baseline-contaminated", "crash-after-write"}}:
                for event in hook_events:
                    print(json.dumps(event, separators=(",", ":")), flush=True)
            if mode == "crash-after-write":
                raise SystemExit(23)
            if mode == "missing-terminal":
                print(json.dumps({{"type": "system", "subtype": "init"}}))
                raise SystemExit(0)
            if mode == "many-lines":
                for index in range(10005):
                    print(json.dumps({{"type": "system", "index": index}}))
                raise SystemExit(0)
            if mode == "oversized":
                print(json.dumps({{"type": "system", "payload": "x" * 1100000}}))
                raise SystemExit(0)
            if mode == "terminal-error":
                print(json.dumps({{"type": "result", "subtype": "error_during_execution", "is_error": True}}))
                raise SystemExit(2)
            print(json.dumps(terminal, separators=(",", ":")))
            """
        ),
        encoding="utf-8",
    )
    fake.chmod(0o755)
    return fake


class MeasurementHarness:
    def __init__(self, root: Path, script: Path):
        self.root = root
        self.script = script
        self.fake = _write_fake_cli(root)
        self.tasks_path = root / "tasks.json"
        self.variants_path = root / "variants.json"
        self.csv_path = root / "results.csv"
        self.log_path = root / "fake-calls.jsonl"
        (root / "baseline-settings.json").write_text(
            json.dumps(_settings(), sort_keys=True), encoding="utf-8"
        )
        (root / "treatment-settings.json").write_text(
            json.dumps(_settings(managed_hooks=True), sort_keys=True), encoding="utf-8"
        )
        self.tasks_path.write_text(
            json.dumps(
                [
                    {
                        "id": "t01",
                        "prompt": "offline fake task",
                        "model": "sonnet",
                        "max_turns": 1,
                        "output_format": "stream-json",
                        "success_command": "true",
                        "success_cwd": ".",
                    }
                ]
            ),
            encoding="utf-8",
        )

    def write_variants(self, variants: list[dict]) -> None:
        self.variants_path.write_text(json.dumps(variants), encoding="utf-8")

    def run(
        self,
        variants: list[dict] | None,
        *,
        extra_args: list[str] | None = None,
        env_updates: dict[str, str] | None = None,
        csv_name: str = "results.csv",
        script: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if variants is not None:
            self.write_variants(variants)
        env = os.environ.copy()
        env.update(
            {
                "CG_FAKE_LOG": str(self.log_path),
                "LANG": "C.UTF-8",
                "ANTHROPIC_API_KEY": "anthropic-secret-must-not-propagate",
                "CLAUDE_CODE_OAUTH_TOKEN": "oauth-secret-must-not-propagate",
                "AWS_SECRET_ACCESS_KEY": "aws-secret-must-not-propagate",
                "UNRELATED_AMBIENT_VALUE": "must-not-propagate",
            }
        )
        if env_updates:
            env.update(env_updates)
        cmd = [
            sys.executable,
            str(script or self.script),
            "--tasks",
            str(self.tasks_path),
            "--variants",
            str(self.variants_path),
            "--csv",
            str(self.root / csv_name),
            "--claude-bin",
            str(self.fake),
            "--project-root",
            str(self.root),
        ]
        cmd.extend(extra_args or [])
        return subprocess.run(cmd, cwd=self.root, env=env, text=True, capture_output=True)

    def calls(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]

    def provider_calls(self) -> list[dict]:
        return [call for call in self.calls() if call["kind"] == "provider"]

    def receipts(self) -> list[Path]:
        return sorted(self.root.glob("artifacts/runs/*/receipt.json"))

    def index_path(self) -> Path:
        return self.root / "artifacts" / "artifact-index.ndjson"


class BenchmarkMeasurementSubstrateTests(unittest.TestCase):
    maxDiff = 4000

    def _for_each_script(self):
        for script in BENCH_SCRIPTS:
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            yield script, Path(tmp.name)

    def _valid_pair(self) -> list[dict]:
        return [
            _variant(
                "baseline",
                _measurement(
                    settings_file="baseline-settings.json",
                    arm="baseline",
                    attempt=0,
                ),
            ),
            _variant(
                "treatment",
                _measurement(
                    settings_file="treatment-settings.json",
                    arm="treatment",
                    attempt=0,
                    expected_hooks=["context-guard-guard-read", "context-guard-failed-nudge"],
                ),
            ),
        ]

    def assert_private_regular(self, path: Path) -> None:
        self.assertFalse(path.is_symlink(), path)
        mode = stat.S_IMODE(path.stat().st_mode)
        self.assertEqual(mode, 0o600, path)

    def assert_prelaunch_rejection(
        self,
        harness: MeasurementHarness,
        variants: list[dict],
        *,
        message: str,
        env_updates: dict[str, str] | None = None,
        allow_capability_probe: bool = False,
    ) -> None:
        proc = harness.run(variants, env_updates=env_updates)
        self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
        self.assertIn(message, proc.stderr)
        self.assertEqual(harness.provider_calls(), [])
        if not allow_capability_probe:
            self.assertEqual(harness.calls(), [])
        self.assertFalse(harness.csv_path.exists())
        self.assertFalse((harness.root / "artifacts").exists())

    def test_exact_v1_schema_dry_run_is_opt_in_and_builds_required_cli_flags(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            proc = harness.run([treatment], extra_args=["--dry-run"])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("--settings", proc.stdout)
            self.assertIn("treatment-settings.json", proc.stdout)
            self.assertIn("--setting-sources user,project", proc.stdout)
            self.assertIn("--include-hook-events", proc.stdout)
            self.assertIn("--no-session-persistence", proc.stdout)
            self.assertIn("--output-format stream-json", proc.stdout)
            self.assertIn("--verbose", proc.stdout)
            self.assertFalse(harness.csv_path.exists())
            self.assertFalse((root / "artifacts").exists())
            self.assertEqual(harness.provider_calls(), [])

    def test_schema_and_path_failures_reject_before_provider_or_output(self):
        cases: list[tuple[str, Callable[[dict], None], str]] = [
            (
                "unknown-key",
                lambda value: value["measurement"].__setitem__("unknown", True),
                "unknown measurement key",
            ),
            (
                "schema-version",
                lambda value: value["measurement"].__setitem__("schema_version", "v2"),
                "measurement schema_version",
            ),
            (
                "secret-allow",
                lambda value: value["measurement"]["environment"]["allow"].append("ANTHROPIC_API_KEY"),
                "unsafe environment name",
            ),
            (
                "secret-override",
                lambda value: value["measurement"]["environment"]["overrides"].__setitem__(
                    "MY_ACCESS_TOKEN", "x"
                ),
                "unsafe environment name",
            ),
            (
                "settings-conflict",
                lambda value: value["extra_args"].extend(["--settings", "other.json"]),
                "runner-controlled Claude flag",
            ),
            (
                "setting-sources-conflict",
                lambda value: value["extra_args"].extend(["--setting-sources", "local"]),
                "runner-controlled Claude flag",
            ),
            (
                "safe-mode",
                lambda value: value["extra_args"].append("--safe-mode"),
                "unsafe Claude flag",
            ),
            (
                "bare",
                lambda value: value["extra_args"].append("--bare"),
                "unsafe Claude flag",
            ),
            (
                "path-escape",
                lambda value: value["measurement"].__setitem__("settings_file", "../escape.json"),
                "settings_file must stay within",
            ),
        ]
        for script, root in self._for_each_script():
            for label, mutate, message in cases:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    variant = copy.deepcopy(self._valid_pair()[1])
                    mutate(variant)
                    self.assert_prelaunch_rejection(harness, [variant], message=message)

            with self.subTest(script=script, case="output-format-conflict"):
                case_root = root / "output-format-conflict"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                harness.tasks_path.write_text(
                    json.dumps(
                        [
                            {
                                "id": "t01",
                                "prompt": "offline fake task",
                                "max_turns": 1,
                                "output_format": "json",
                                "success_command": "true",
                            }
                        ]
                    ),
                    encoding="utf-8",
                )
                self.assert_prelaunch_rejection(
                    harness,
                    [self._valid_pair()[1]],
                    message="measurement requires task output_format=stream-json",
                )

    def test_symlink_and_capability_failures_are_prelaunch_and_no_follow(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script, case="settings-symlink"):
                case_root = root / "settings"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                outside = case_root / "outside-settings.json"
                outside.write_text(json.dumps(_settings(managed_hooks=True)), encoding="utf-8")
                link = case_root / "linked-settings.json"
                link.symlink_to(outside)
                variant = copy.deepcopy(self._valid_pair()[1])
                variant["measurement"]["settings_file"] = "linked-settings.json"
                self.assert_prelaunch_rejection(harness, [variant], message="settings_file must not be a symlink")

            with self.subTest(script=script, case="artifact-parent-symlink"):
                case_root = root / "artifact"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                outside = case_root / "outside-artifacts"
                outside.mkdir()
                (case_root / "artifact-link").symlink_to(outside, target_is_directory=True)
                variant = copy.deepcopy(self._valid_pair()[1])
                variant["measurement"]["artifact_root"] = "artifact-link"
                self.assert_prelaunch_rejection(harness, [variant], message="artifact_root must not be a symlink")
                self.assertEqual(list(outside.iterdir()), [])

            with self.subTest(script=script, case="unsupported-capability"):
                case_root = root / "capability"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                variant = copy.deepcopy(self._valid_pair()[1])
                self.assert_prelaunch_rejection(
                    harness,
                    [variant],
                    message="required CLI capability unavailable",
                    env_updates={
                        "CG_FAKE_CAPABILITIES": "--settings --setting-sources --no-session-persistence stream-json"
                    },
                    allow_capability_probe=True,
                )

    def test_duplicate_json_keys_are_rejected_without_cli_or_output(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script, fixture="variant"):
                case_root = root / "variant-duplicate"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                measurement = _measurement(
                    settings_file="treatment-settings.json",
                    arm="treatment",
                    expected_hooks=["context-guard-guard-read", "context-guard-failed-nudge"],
                    fake_mode="valid-hooks",
                )
                encoded = json.dumps(measurement, separators=(",", ":"))
                harness.variants_path.write_text(
                    '[{"name":"treatment","extra_args":[],"measurement":'
                    + encoded
                    + ',"measurement":'
                    + encoded
                    + "}]",
                    encoding="utf-8",
                )
                proc = harness.run(None)
                self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                self.assertIn("duplicate JSON key", proc.stderr)
                self.assertEqual(harness.calls(), [])
                self.assertFalse(harness.csv_path.exists())
                self.assertFalse((case_root / "artifacts").exists())

            with self.subTest(script=script, fixture="settings"):
                case_root = root / "settings-duplicate"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                (case_root / "treatment-settings.json").write_text(
                    '{"permissions":{"allow":["Read"]},"permissions":{"allow":["Read"]}}',
                    encoding="utf-8",
                )
                variant = self._valid_pair()[1]
                self.assert_prelaunch_rejection(
                    harness,
                    [variant],
                    message="duplicate JSON key",
                )

    def test_isolated_roots_identity_and_credential_boundary(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            proc = harness.run(self._valid_pair())
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            calls = harness.provider_calls()
            self.assertEqual(len(calls), 2, calls)

            roots_by_call: list[tuple[str, ...]] = []
            for call in calls:
                argv = call["argv"]
                self.assertIn("--settings", argv)
                self.assertIn("--setting-sources", argv)
                self.assertEqual(argv[argv.index("--setting-sources") + 1], "user,project")
                self.assertIn("--include-hook-events", argv)
                self.assertIn("--no-session-persistence", argv)
                env = call["env"]
                for name in AUTH_ENV_NAMES:
                    self.assertNotIn(name, env)
                self.assertNotIn("UNRELATED_AMBIENT_VALUE", env)
                self.assertEqual(env["CG_MEASUREMENT_OVERRIDE"], "fixed")
                root_values = (
                    env["HOME"],
                    env["XDG_CONFIG_HOME"],
                    env["XDG_CACHE_HOME"],
                    env["XDG_STATE_HOME"],
                    env["TMPDIR"],
                    env["CLAUDE_CONFIG_DIR"],
                    call["cwd"],
                )
                self.assertEqual(len(set(root_values)), len(root_values))
                roots_by_call.append(root_values)
            self.assertTrue(set(roots_by_call[0]).isdisjoint(roots_by_call[1]))

            receipts = [json.loads(path.read_text(encoding="utf-8")) for path in harness.receipts()]
            self.assertEqual(len(receipts), 2)
            identities = {receipt["run_identity"]["arm"]: receipt["run_identity"] for receipt in receipts}
            for arm, identity in identities.items():
                self.assertEqual(
                    identity,
                    {
                        "candidate_hash": CANDIDATE_HASH,
                        "task": "t01",
                        "repetition": 0,
                        "arm": arm,
                        "attempt": 0,
                        "namespace": "s001-tests",
                        "run_id": expected_run_id(
                            task="t01", repetition=0, arm=arm, attempt=0, namespace="s001-tests"
                        ),
                    },
                )

    def test_raw_receipt_index_hash_permissions_and_hook_normalization(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt_paths = harness.receipts()
            self.assertEqual(len(receipt_paths), 1)
            receipt_path = receipt_paths[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            raw_path = receipt_path.parent / receipt["raw_artifact"]["path"]
            index_path = harness.index_path()
            for path in (raw_path, receipt_path, index_path):
                self.assert_private_regular(path)

            raw = raw_path.read_bytes()
            raw_meta = receipt["raw_artifact"]
            self.assertEqual(receipt["schema_version"], RAW_RECEIPT_SCHEMA_VERSION)
            self.assertEqual(receipt["terminal_status"], "success")
            self.assertEqual(raw_meta["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(raw_meta["bytes"], len(raw))
            self.assertEqual(raw_meta["lines"], len(raw.splitlines()))
            self.assertEqual(raw_meta["events"], len(raw.splitlines()))
            self.assertIn(RAW_SECRET.encode(), raw)
            self.assertEqual(
                receipt["hooks"],
                [
                    {
                        "event_name": "PreToolUse",
                        "hook_identity": "context-guard-guard-read",
                        "tool": "Read",
                        "decision": "allow",
                        "timestamp": "2026-07-30T00:00:00Z",
                    },
                    {
                        "event_name": "PostToolUseFailure",
                        "hook_identity": "context-guard-failed-nudge",
                        "tool": "Bash",
                        "decision": "error",
                        "timestamp": "2026-07-30T00:00:01Z",
                    },
                ],
            )
            index_rows = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(index_rows), 1)
            index = index_rows[0]
            self.assertEqual(index["schema_version"], ARTIFACT_INDEX_SCHEMA_VERSION)
            self.assertEqual(index["run_id"], receipt["run_identity"]["run_id"])
            self.assertEqual(index["terminal_status"], "success")
            self.assertEqual(index["receipt_sha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())
            self.assertNotIn(RAW_SECRET, proc.stdout + proc.stderr + receipt_path.read_text() + index_path.read_text())

    def test_invalid_streams_are_bounded_and_crash_after_write_is_receipted(self):
        cases = (
            ("missing-terminal", "missing_terminal"),
            ("many-lines", "line_limit"),
            ("oversized", "byte_limit"),
            ("terminal-error", "terminal_error"),
            ("crash-after-write", "process_error"),
        )
        for script, root in self._for_each_script():
            for attempt, (mode, terminal_status) in enumerate(cases, start=1):
                with self.subTest(script=script, mode=mode):
                    case_root = root / mode
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    variant = _variant(
                        "treatment",
                        _measurement(
                            settings_file="treatment-settings.json",
                            arm="treatment",
                            attempt=attempt,
                            expected_hooks=(
                                ["context-guard-guard-read", "context-guard-failed-nudge"]
                                if mode == "crash-after-write"
                                else []
                            ),
                            fake_mode=mode,
                        ),
                    )
                    proc = harness.run([variant])
                    self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    self.assertIn("FAIL", proc.stdout)
                    receipt_paths = harness.receipts()
                    self.assertEqual(len(receipt_paths), 1)
                    receipt = json.loads(receipt_paths[0].read_text(encoding="utf-8"))
                    self.assertEqual(receipt["terminal_status"], terminal_status)
                    raw_path = receipt_paths[0].parent / receipt["raw_artifact"]["path"]
                    self.assertLessEqual(raw_path.stat().st_size, 1_000_000)
                    self.assertNotIn(RAW_SECRET, proc.stdout + proc.stderr + receipt_paths[0].read_text())

    def test_baseline_purity_and_settings_parity_fail_before_or_at_first_result(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script, case="managed-baseline-settings"):
                case_root = root / "managed-baseline"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                (case_root / "baseline-settings.json").write_text(
                    json.dumps(_settings(managed_hooks=True)), encoding="utf-8"
                )
                variant = _variant(
                    "baseline",
                    _measurement(settings_file="baseline-settings.json", arm="baseline"),
                )
                self.assert_prelaunch_rejection(
                    harness, [variant], message="baseline settings contain managed ContextGuard hook"
                )

            with self.subTest(script=script, case="settings-parity"):
                case_root = root / "parity"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                (case_root / "treatment-settings.json").write_text(
                    json.dumps(_settings(managed_hooks=True, divergent=True)), encoding="utf-8"
                )
                self.assert_prelaunch_rejection(
                    harness,
                    self._valid_pair(),
                    message="baseline and treatment settings differ outside registered hooks",
                )

            with self.subTest(script=script, case="runtime-baseline-hook"):
                case_root = root / "runtime-baseline"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                variant = _variant(
                    "baseline",
                    _measurement(
                        settings_file="baseline-settings.json",
                        arm="baseline",
                        fake_mode="baseline-contaminated",
                    ),
                )
                proc = harness.run([variant])
                self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                self.assertIn("FAIL", proc.stdout)
                self.assertEqual(len(harness.receipts()), 1)
                receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
                self.assertEqual(receipt["terminal_status"], "baseline_hook_activity")

    def test_duplicate_identity_corruption_and_raw_symlink_attacks_do_not_relaunch(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            self.assertEqual(len(harness.provider_calls()), 1)
            self.assertEqual(len(harness.receipts()), 1)
            receipt_path = harness.receipts()[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            raw_path = receipt_path.parent / receipt["raw_artifact"]["path"]
            raw_path.write_bytes(raw_path.read_bytes() + b"corruption")
            second = harness.run([treatment], csv_name="second.csv")
            self.assertNotEqual(second.returncode, 0, (second.stdout, second.stderr))
            self.assertIn("measurement artifact integrity check failed", second.stderr)
            self.assertEqual(len(harness.provider_calls()), 1)

            symlink_root = root / "symlink-attack"
            symlink_root.mkdir()
            symlink_harness = MeasurementHarness(symlink_root, script)
            run_id = expected_run_id(
                task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests"
            )
            run_dir = symlink_root / "artifacts" / "runs" / run_id
            run_dir.mkdir(parents=True)
            victim = symlink_root / "victim"
            victim.write_text("unchanged", encoding="utf-8")
            (run_dir / "raw.ndjson").symlink_to(victim)
            attacked = symlink_harness.run([treatment])
            self.assertNotEqual(attacked.returncode, 0, (attacked.stdout, attacked.stderr))
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
            self.assertEqual(symlink_harness.provider_calls(), [])

    def test_unrelated_comment_mutation_is_a_no_kill_control(self):
        for script, root in self._for_each_script():
            mutated = root / "benchmark-runner-comment-mutant.py"
            shutil.copyfile(script, mutated)
            with mutated.open("a", encoding="utf-8") as handle:
                handle.write("\n# S001 unrelated comment mutation no-kill control\n")
            harness = MeasurementHarness(root, mutated)
            treatment = self._valid_pair()[1]
            proc = harness.run([treatment], script=mutated)
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertEqual(len(harness.provider_calls()), 1)


if __name__ == "__main__":
    unittest.main()
