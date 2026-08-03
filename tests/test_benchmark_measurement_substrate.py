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
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
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

MEASUREMENT_SCHEMA_VERSION = "contextguard.bench.measurement-substrate.v2"
RAW_RECEIPT_SCHEMA_VERSION = "contextguard.bench.raw-receipt.v2"
ARTIFACT_INDEX_SCHEMA_VERSION = "contextguard.bench.artifact-index.v2"
SUPPORTED_HOOK_EVENTS = (
    "PreToolUse", "PermissionRequest", "PostToolUse", "PostToolUseFailure",
    "Notification", "UserPromptSubmit", "SessionStart", "SessionEnd", "Stop",
    "SubagentStart", "SubagentStop", "PreCompact",
)
DEFAULT_BINDINGS = (
    ("PreToolUse", "context-guard-guard-read"),
    ("PreToolUse", "context-guard-guard-search"),
    ("PostToolUseFailure", "context-guard-failed-nudge"),
)

CANDIDATE_HASH = "a" * 64
RAW_SECRET = "RAW_EVENT_PAYLOAD_MUST_NOT_ESCAPE"
AUTH_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_PAT",
    "AWS_ACCESS_KEY_ID",
    "NETRC",
    "KUBECONFIG",
    "NPM_CONFIG_USERCONFIG",
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def expected_v1_run_id(*, task: str, repetition: int, arm: str, attempt: int, namespace: str) -> str:
    identity_tuple = [CANDIDATE_HASH, task, repetition, arm, attempt, namespace]
    return hashlib.sha256(_canonical_json_bytes(identity_tuple)).hexdigest()


def expected_run_id(*, task: str, repetition: int, arm: str, attempt: int, namespace: str) -> str:
    identity_tuple = [
        MEASUREMENT_SCHEMA_VERSION, CANDIDATE_HASH, task, repetition, arm, attempt, namespace,
    ]
    encoded = _canonical_json_bytes(identity_tuple)
    payload = b"contextguard.bench.run-id.v2\0" + struct.pack(">Q", len(encoded)) + encoded
    return hashlib.sha256(payload).hexdigest()


def _domain_hash(domain: bytes, *values: str) -> str:
    encoded = b"".join(struct.pack(">Q", len(value.encode())) + value.encode() for value in values)
    return hashlib.sha256(domain + b"\0" + encoded).hexdigest()


def expected_binding_set_hash(bindings: tuple[tuple[str, str], ...] = DEFAULT_BINDINGS) -> str:
    encoded = _canonical_json_bytes([list(binding) for binding in bindings])
    return hashlib.sha256(
        b"contextguard.bench.binding-set.v2\0" + struct.pack(">Q", len(encoded)) + encoded
    ).hexdigest()


def _load_benchmark_module(script: Path, suffix: str):
    name = f"_s001_benchmark_{suffix}_{hashlib.sha256(str(script).encode()).hexdigest()[:8]}"
    loader = importlib.machinery.SourceFileLoader(name, str(script))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise AssertionError(f"cannot load benchmark script: {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


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
                    "hooks": [
                        {"type": "command", "command": "context-guard-guard-read"},
                        {"type": "command", "command": "context-guard-guard-search"},
                    ],
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
    bindings: tuple[tuple[str, str], ...] = (),
    required_event_classes: tuple[str, ...] | None = None,
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
            "registered_bindings": [
                {"hook_event": event, "configured_command": command}
                for event, command in bindings
            ],
            "required_event_classes": list(
                dict.fromkeys(event for event, _ in bindings)
                if required_event_classes is None
                else required_event_classes
            ),
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
                        "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                        "TMPDIR", "CLAUDE_CONFIG_DIR", "LANG", "CG_MEASUREMENT_OVERRIDE",
                        "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN",
                        "AWS_SECRET_ACCESS_KEY", "GITHUB_PAT", "AWS_ACCESS_KEY_ID", "NETRC",
                        "KUBECONFIG", "NPM_CONFIG_USERCONFIG", "UNRELATED_AMBIENT_VALUE",
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
                if os.environ.get("CG_FAKE_MODE") == "launch-error":
                    marker = Path(sys.argv[0]).with_name("launch-error-help-seen")
                    if marker.exists():
                        Path(sys.argv[0]).unlink()
                    else:
                        marker.write_text("seen", encoding="utf-8")
                raise SystemExit(0)
            if "--version" in sys.argv:
                log("version")
                legacy_path = os.environ.get("CG_FAKE_VERSION_CREATE_LEGACY_DIR")
                legacy_marker = Path(sys.argv[0]).with_name("version-create-legacy-path")
                if legacy_marker.exists():
                    legacy_path = legacy_marker.read_text(encoding="utf-8")
                if legacy_path:
                    Path(legacy_path).mkdir(parents=True, exist_ok=True)
                print("fake-claude 1.0")
                raise SystemExit(0)

            log("provider")
            isolated_roots = [
                Path(os.environ[name])
                for name in (
                    "HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                    "XDG_STATE_HOME", "TMPDIR", "CLAUDE_CONFIG_DIR",
                )
            ] + [Path.cwd()]
            for isolated_root in isolated_roots:
                isolated_root.mkdir(parents=True, exist_ok=True)
                sentinel = isolated_root / "cross-run-sentinel"
                if sentinel.exists():
                    print(json.dumps({{"type": "result", "subtype": "error_during_execution", "is_error": True}}))
                    raise SystemExit(19)
                sentinel.write_text("unique", encoding="utf-8")

            mode = os.environ.get("CG_FAKE_MODE", "auto")
            if mode == "auto":
                settings_index = sys.argv.index("--settings") + 1
                mode = "valid-hooks" if "treatment" in sys.argv[settings_index] else "valid-no-hooks"
            def lifecycle(hook_id, hook_name, hook_event, *, outcome="success", exit_code=0,
                          progress=1, session_id="session-1", uuid_prefix="uuid"):
                common = {{
                    "type": "system", "hook_id": hook_id, "hook_name": hook_name,
                    "hook_event": hook_event, "session_id": session_id,
                }}
                records = [dict(common, subtype="hook_started", uuid=f"{{uuid_prefix}}-start")]
                for index in range(progress):
                    records.append(dict(
                        common, subtype="hook_progress", uuid=f"{{uuid_prefix}}-progress-{{index}}",
                        stdout=RAW_SECRET, stderr="", output=RAW_SECRET,
                    ))
                records.append(dict(
                    common, subtype="hook_response", uuid=f"{{uuid_prefix}}-response",
                    stdout=RAW_SECRET, stderr="", output=RAW_SECRET,
                    outcome=outcome, exit_code=exit_code,
                ))
                return records

            hook_events = (
                lifecycle("hook-pre", "opaque-runtime-name-not-a-command", "PreToolUse")
                + lifecycle("hook-failure", "another-opaque-name", "PostToolUseFailure", progress=0)
            )
            terminal = {{
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "usage": {{"input_tokens": 7, "output_tokens": 3}},
                "total_cost_usd": 0.01,
            }}

            if mode == "post-tool-outcomes":
                hook_events = (
                    lifecycle("hook-ok", "opaque-a", "PostToolUse")
                    + lifecycle("hook-failed", "opaque-b", "PostToolUseFailure")
                )
            if mode == "uuid-drift":
                hook_events = lifecycle("hook-pre", "opaque-runtime-name-not-a-command", "PreToolUse")
            if mode == "multi-progress":
                hook_events = (
                    lifecycle("hook-pre", "opaque-runtime-name-not-a-command", "PreToolUse", progress=3)
                    + lifecycle("hook-failure", "another-opaque-name", "PostToolUseFailure", progress=0)
                )
            if mode == "name-drift":
                hook_events = lifecycle("hook-pre", "opaque-name", "PreToolUse")
                hook_events[-1]["hook_name"] = "drifted-name"
            if mode == "event-drift":
                hook_events = lifecycle("hook-pre", "opaque-name", "PreToolUse")
                hook_events[-1]["hook_event"] = "PostToolUse"
            if mode == "response-without-start":
                hook_events = lifecycle("hook-pre", "opaque-name", "PreToolUse")[-1:]
            if mode == "unsupported-hook-class":
                hook_events = lifecycle("hook-weird", "opaque-name", "FutureToolUse")
            if mode == "malformed-hook-class":
                hook_events = lifecycle("hook-weird", "opaque-name", "PreToolUse")
                hook_events[0]["hook_event"] = 7
            if mode == "hook-process-error":
                hook_events = (
                    lifecycle("hook-pre", "opaque-name", "PreToolUse", outcome="error", exit_code=9)
                    + lifecycle("hook-failure", "another-opaque-name", "PostToolUseFailure", progress=0)
                )
            if mode == "hook-error-missing-required":
                hook_events = lifecycle("hook-pre", "opaque-name", "PreToolUse", outcome="error", exit_code=9)
            if mode == "process-error-invalid-hook":
                hook_events = lifecycle("hook-pre", "opaque-name", "PreToolUse")
                hook_events[-1]["hook_name"] = "drifted-name"
            if mode == "synthetic-v1":
                hook_events = [{{
                    "type":"hook_event", "event_name":"PreToolUse", "hook_identity":"legacy",
                    "tool":"Read", "decision":"allow", "timestamp":"2026-07-30T00:00:00Z",
                }}]
            if mode == "line-256001":
                print(json.dumps({{"type":"system", "payload":"x" * 256100}}, separators=(",", ":")))
                raise SystemExit(0)
            if mode in {{
                "valid-hooks", "baseline-contaminated", "crash-after-write", "post-tool-outcomes",
                "uuid-drift", "multi-progress", "name-drift", "event-drift", "response-without-start",
                "unsupported-hook-class", "malformed-hook-class", "hook-process-error", "synthetic-v1",
                "process-error-invalid-hook", "hook-error-missing-required",
            }}:
                for event in hook_events:
                    print(json.dumps(event, separators=(",", ":")), flush=True)
            if mode == "mutate-settings-snapshot":
                settings_index = sys.argv.index("--settings") + 1
                Path(sys.argv[settings_index]).write_text("{{}}", encoding="utf-8")
                for event in hook_events:
                    print(json.dumps(event, separators=(",", ":")), flush=True)
            if mode in {{"crash-after-write", "process-error-invalid-hook"}}:
                raise SystemExit(23)
            if mode == "exit-126":
                raise SystemExit(126)
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
            if mode in {"terminal-error", "terminal-error-zero"}:
                print(json.dumps({{"type": "result", "subtype": "error_during_execution", "is_error": True}}))
                raise SystemExit(2 if mode == "terminal-error" else 0)
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
        ensure_pair: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        selected_variant: str | None = None
        if ensure_pair and variants is not None:
            measured = [value for value in variants if "measurement" in value]
            if len(measured) == 1 and measured[0]["name"] in {"baseline", "treatment"}:
                selected_variant = measured[0]["name"]
                source = measured[0]["measurement"]
                opposite = "treatment" if selected_variant == "baseline" else "baseline"
                counterpart = copy.deepcopy(source)
                counterpart["settings_file"] = f"{opposite}-settings.json"
                counterpart["identity"]["arm"] = opposite
                counterpart["hook_events"]["registered_bindings"] = (
                    [{"hook_event": event, "configured_command": command} for event, command in DEFAULT_BINDINGS]
                    if opposite == "treatment" else []
                )
                counterpart["hook_events"]["required_event_classes"] = (
                    list(dict.fromkeys(event for event, _ in DEFAULT_BINDINGS))
                    if opposite == "treatment" else []
                )
                variants = list(variants) + [_variant(opposite, counterpart)]
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
                "GITHUB_PAT": "github-pat-must-not-propagate",
                "AWS_ACCESS_KEY_ID": "aws-access-id-must-not-propagate",
                "NETRC": "netrc-path-must-not-propagate",
                "KUBECONFIG": "kubeconfig-path-must-not-propagate",
                "NPM_CONFIG_USERCONFIG": "npm-userconfig-path-must-not-propagate",
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
        if selected_variant and "--variant" not in (extra_args or []):
            cmd.extend(["--variant", selected_variant])
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
                    bindings=DEFAULT_BINDINGS,
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

    def test_exact_v2_schema_dry_run_is_opt_in_and_builds_required_cli_flags(self):
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

    def test_settings_file_rejects_absolute_and_tilde_expanded_external_paths(self):
        for script, root in self._for_each_script():
            for label, path_value, env_updates in (
                ("absolute", str(root / "external-settings.json"), None),
                ("tilde", "~/external-settings.json", {"HOME": str(root)}),
            ):
                with self.subTest(script=script, case=label):
                    (root / "external-settings.json").write_text(
                        json.dumps(_settings(managed_hooks=True)), encoding="utf-8"
                    )
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    variant = copy.deepcopy(self._valid_pair()[1])
                    variant["measurement"]["settings_file"] = path_value
                    self.assert_prelaunch_rejection(
                        harness,
                        [variant],
                        message="settings_file must stay within the variant fixture directory",
                        env_updates=env_updates,
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
                    bindings=DEFAULT_BINDINGS,
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
                    env["XDG_DATA_HOME"],
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

    def test_v2_receipt_index_settings_and_official_hook_normalization_are_exact(self):
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
            settings_path = receipt_path.parent / receipt["settings_artifact"]["path"]
            index_path = harness.index_path()
            for path in (raw_path, settings_path, receipt_path, index_path):
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
                set(receipt),
                {"schema_version", "run_identity", "raw_artifact", "settings_artifact",
                 "process_status", "terminal_status", "hook_summary", "hooks"},
            )
            settings_bytes = settings_path.read_bytes()
            self.assertEqual(receipt["settings_artifact"], {
                "path": "session/treatment-settings.json",
                "sha256": hashlib.sha256(settings_bytes).hexdigest(),
                "bytes": len(settings_bytes),
                "binding_set_sha256": expected_binding_set_hash(),
            })
            self.assertEqual(receipt["process_status"], "exited_zero")
            self.assertEqual(receipt["hook_summary"], {
                "required_event_classes": ["PreToolUse", "PostToolUseFailure"],
                "observed_lifecycle_count": 2,
                "completed_lifecycle_count": 2,
                "event_class_counts": [
                    {"hook_event": "PreToolUse", "count": 1},
                    {"hook_event": "PostToolUseFailure", "count": 1},
                ],
            })
            self.assertEqual(
                receipt["hooks"],
                [
                    {
                        "hook_event": "PreToolUse",
                        "opaque_hook_name_sha256": _domain_hash(
                            b"contextguard.bench.opaque-hook-name.v2", "opaque-runtime-name-not-a-command"
                        ),
                        "lifecycle_key_sha256": _domain_hash(
                            b"contextguard.bench.hook-lifecycle-key.v2", "session-1", "hook-pre"
                        ),
                        "hook_process_outcome": "success",
                        "hook_process_exit_code": 0,
                        "triggering_tool_outcome": "not_applicable",
                        "progress_count": 1,
                    },
                    {
                        "hook_event": "PostToolUseFailure",
                        "opaque_hook_name_sha256": _domain_hash(
                            b"contextguard.bench.opaque-hook-name.v2", "another-opaque-name"
                        ),
                        "lifecycle_key_sha256": _domain_hash(
                            b"contextguard.bench.hook-lifecycle-key.v2", "session-1", "hook-failure"
                        ),
                        "hook_process_outcome": "success",
                        "hook_process_exit_code": 0,
                        "triggering_tool_outcome": "failed",
                        "progress_count": 0,
                    },
                ],
            )
            index_rows = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(index_rows), 1)
            index = index_rows[0]
            self.assertEqual(index["schema_version"], ARTIFACT_INDEX_SCHEMA_VERSION)
            self.assertEqual(set(index), {"schema_version", "run_id", "receipt_path", "receipt_sha256", "terminal_status"})
            self.assertEqual(index["run_id"], receipt["run_identity"]["run_id"])
            self.assertEqual(index["terminal_status"], "success")
            self.assertEqual(index["receipt_sha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())
            self.assertNotIn(RAW_SECRET, proc.stdout + proc.stderr + receipt_path.read_text() + index_path.read_text())

    def test_invalid_streams_are_bounded_and_crash_after_write_is_receipted(self):
        cases = (
            ("missing-terminal", "missing_terminal"),
            ("many-lines", "raw_line_limit"),
            ("oversized", "raw_byte_limit"),
            ("terminal-error", "process_error"),
            ("terminal-error-zero", "terminal_error"),
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
                            settings_file=(
                                "treatment-settings.json"
                                if mode == "crash-after-write" else "baseline-settings.json"
                            ),
                            arm="treatment",
                            attempt=attempt,
                            bindings=(DEFAULT_BINDINGS if mode == "crash-after-write" else ()),
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
                self.assertEqual(receipt["terminal_status"], "baseline_hook_contamination")

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

    def test_existing_raw_mode_is_integrity_checked_without_relaunch(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            raw_path = receipt_path.parent / "raw.ndjson"
            raw_path.chmod(0o644)
            calls = len(harness.provider_calls())

            duplicate = harness.run([treatment], csv_name="raw-mode.csv")

            self.assertNotEqual(duplicate.returncode, 0, (duplicate.stdout, duplicate.stderr))
            self.assertIn("measurement artifact integrity check failed", duplicate.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)

    def test_v1_and_v2_run_id_and_binding_hash_goldens_are_version_separated(self):
        values = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        self.assertEqual(
            expected_v1_run_id(**values),
            "4bf30f7c190b2673a22a0fbd8e1586af0325fe1366b7eb9fa6c1fb08a8b476d9",
        )
        self.assertEqual(
            expected_run_id(**values),
            "1ae86fc0dc5267b6e388c5650abd9da3a80519caaa7c6c355a9110602bee3d1e",
        )
        self.assertEqual(
            expected_binding_set_hash(),
            "864e4cbb202ab33fe3f8f3fe6a79148cbc26a714eee2d3f15b2040b03ad3637c",
        )
        self.assertNotEqual(expected_v1_run_id(**values), expected_run_id(**values))

    def test_legacy_v1_path_blocks_v2_creation_and_wins_over_existing_v2_path(self):
        values = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            runs = root / "artifacts" / "runs"
            (runs / expected_v1_run_id(**values)).mkdir(parents=True)
            (runs / expected_run_id(**values)).mkdir()
            proc = harness.run([self._valid_pair()[1]])
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("legacy_v1_artifact_conflict", proc.stderr)
            self.assertEqual(harness.provider_calls(), [])
            self.assertEqual(list((runs / expected_run_id(**values)).iterdir()), [])

    def test_v1_schema_and_cross_version_index_join_are_rejected_prelaunch(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script, case="v1-config"):
                case_root = root / "v1-config"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                pair = self._valid_pair()
                pair[1]["measurement"]["schema_version"] = "contextguard.bench.measurement-substrate.v1"
                proc = harness.run(pair)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(harness.calls(), [])
            with self.subTest(script=script, case="v1-index-join"):
                case_root = root / "v1-index"
                case_root.mkdir()
                harness = MeasurementHarness(case_root, script)
                index = harness.index_path()
                index.parent.mkdir(parents=True)
                row = {
                    "schema_version":"contextguard.bench.artifact-index.v1",
                    "run_id":expected_v1_run_id(
                        task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests"
                    ),
                    "receipt_path":"runs/legacy/receipt.json", "receipt_sha256":"0" * 64,
                    "terminal_status":"success",
                }
                index.write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                index.chmod(0o600)
                proc = harness.run([self._valid_pair()[1]])
                self.assertEqual(harness.provider_calls(), [])
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("legacy_v1_artifact_conflict", proc.stderr)

    def test_legacy_lookup_types_and_v2_schema_legacy_join_fail_with_exact_precedence(self):
        identity = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        for script, root in self._for_each_script():
            for label in ("symlink", "file", "directory", "v2-row-with-v1-id"):
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    legacy = case_root / "artifacts" / "runs" / expected_v1_run_id(**identity)
                    legacy.parent.mkdir(parents=True)
                    expected = "measurement artifact integrity check failed"
                    if label == "symlink":
                        victim = case_root / "victim"
                        victim.mkdir()
                        legacy.symlink_to(victim, target_is_directory=True)
                    elif label == "file":
                        legacy.write_text("not-a-directory", encoding="utf-8")
                    elif label == "directory":
                        legacy.mkdir()
                        expected = "legacy_v1_artifact_conflict"
                    else:
                        index = harness.index_path()
                        index.parent.mkdir(parents=True, exist_ok=True)
                        row = {"schema_version":ARTIFACT_INDEX_SCHEMA_VERSION,
                               "run_id":expected_v1_run_id(**identity),
                               "receipt_path":"runs/legacy/receipt.json", "receipt_sha256":"0" * 64,
                               "terminal_status":"success"}
                        index.write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                        index.chmod(0o600)
                        expected = "legacy_v1_artifact_conflict"
                    proc = harness.run([self._valid_pair()[1]])
                    self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    self.assertIn(expected, proc.stderr)
                    self.assertEqual(harness.provider_calls(), [])

    def test_legacy_conflict_is_checked_before_otherwise_valid_v2_raw_only_recovery(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt = harness.receipts()[0]
            receipt.unlink()
            harness.index_path().unlink()
            legacy = root / "artifacts" / "runs" / expected_v1_run_id(
                task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests"
            )
            legacy.mkdir()
            calls = len(harness.provider_calls())
            proc = harness.run([treatment], csv_name="blocked-recovery.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("legacy_v1_artifact_conflict", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertFalse(receipt.exists())

    def test_legacy_conflict_created_by_capability_probe_is_rechecked_under_execution_lock(self):
        identity = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            legacy = root / "artifacts" / "runs" / expected_v1_run_id(**identity)
            harness.fake.with_name("version-create-legacy-path").write_text(
                str(legacy), encoding="utf-8",
            )
            proc = harness.run([self._valid_pair()[1]])
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("legacy_v1_artifact_conflict", proc.stderr)
            self.assertEqual(harness.provider_calls(), [])
            self.assertFalse((root / "artifacts" / "runs" / expected_run_id(**identity)).exists())

    def test_legacy_index_classifies_malformed_rows_as_integrity_and_only_matching_v1_join_as_conflict(self):
        identity = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        unrelated_v1 = expected_v1_run_id(
            task="unrelated", repetition=9, arm="treatment", attempt=4, namespace="other",
        )
        def canonical_row(value: dict) -> bytes:
            return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode() + b"\n"

        cases = (
            ("malformed-json", b'{"schema_version":\n', "measurement artifact integrity check failed"),
            ("malformed-schema", canonical_row({
                "schema_version":"contextguard.bench.artifact-index.v1", "run_id":7,
                "receipt_path":"runs/x/receipt.json", "receipt_sha256":"0" * 64,
                "terminal_status":"success",
            }), "measurement artifact integrity check failed"),
            ("unrelated-v1", canonical_row({
                "schema_version":"contextguard.bench.artifact-index.v1", "run_id":unrelated_v1,
                "receipt_path":"runs/unrelated/receipt.json", "receipt_sha256":"0" * 64,
                "terminal_status":"success",
            }), "measurement artifact integrity check failed"),
            ("matching-v1", canonical_row({
                "schema_version":"contextguard.bench.artifact-index.v1",
                "run_id":expected_v1_run_id(**identity),
                "receipt_path":"runs/legacy/receipt.json", "receipt_sha256":"0" * 64,
                "terminal_status":"success",
            }), "legacy_v1_artifact_conflict"),
        )
        for script, root in self._for_each_script():
            for label, payload, expected in cases:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    index = harness.index_path()
                    index.parent.mkdir(parents=True)
                    index.write_bytes(payload)
                    index.chmod(0o600)
                    proc = harness.run([self._valid_pair()[1]])
                    self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    self.assertIn(expected, proc.stderr)
                    self.assertEqual(harness.provider_calls(), [])

    def test_duplicate_or_conflicting_matching_legacy_rows_are_integrity_not_legacy_conflict(self):
        identity = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        legacy_run_id = expected_v1_run_id(**identity)
        base = {
            "schema_version": "contextguard.bench.artifact-index.v1",
            "run_id": legacy_run_id,
            "receipt_path": "runs/legacy/receipt.json",
            "receipt_sha256": "0" * 64,
            "terminal_status": "success",
        }
        cases = (
            ("duplicate", [base, copy.deepcopy(base)]),
            ("conflicting", [base, dict(base, receipt_path="runs/other/receipt.json")]),
        )
        for script, root in self._for_each_script():
            for label, rows in cases:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    index = harness.index_path()
                    index.parent.mkdir(parents=True)
                    index.write_text("".join(
                        json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
                        for row in rows
                    ), encoding="utf-8")
                    index.chmod(0o600)
                    proc = harness.run([self._valid_pair()[1]])
                    self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertNotIn("legacy_v1_artifact_conflict", proc.stderr)
                    self.assertEqual(harness.provider_calls(), [])

    def test_current_v2_index_row_without_run_directory_is_integrity_and_never_launches(self):
        identity = dict(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            run_id = expected_run_id(**identity)
            row = {
                "schema_version": ARTIFACT_INDEX_SCHEMA_VERSION,
                "run_id": run_id,
                "receipt_path": str(root / "artifacts" / "runs" / run_id / "receipt.json"),
                "receipt_sha256": "0" * 64,
                "terminal_status": "success",
            }
            index = harness.index_path()
            index.parent.mkdir(parents=True)
            index.write_text(
                json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            index.chmod(0o600)
            proc = harness.run([self._valid_pair()[1]])
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertEqual(harness.provider_calls(), [])
            self.assertFalse((root / "artifacts" / "runs" / run_id).exists())

    def test_unrelated_valid_v2_index_row_does_not_block_new_current_run(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            first_variant = self._valid_pair()[1]
            first = harness.run([first_variant])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            second_variant = copy.deepcopy(first_variant)
            second_variant["measurement"]["identity"]["attempt"] = 1
            second = harness.run([second_variant], csv_name="second.csv")
            self.assertEqual(second.returncode, 0, (second.stdout, second.stderr))
            self.assertEqual(len(harness.provider_calls()), 2)
            self.assertEqual(len(harness.receipts()), 2)

    def test_settings_snapshot_tamper_is_rejected_at_duplicate_seam_without_relaunch(self):
        mutations = (
            ("bytes", lambda path: path.write_bytes(path.read_bytes() + b" ")),
            ("mode", lambda path: path.chmod(0o644)),
            ("source", lambda path: path.write_bytes(b"{}")),
        )
        for script, root in self._for_each_script():
            for label, mutate in mutations:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    snapshot = receipt_path.parent / receipt["settings_artifact"]["path"]
                    mutate(snapshot)
                    calls = len(harness.provider_calls())
                    second = harness.run([treatment], csv_name="duplicate.csv")
                    self.assertNotEqual(second.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", second.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)

    def test_receipt_without_index_is_appended_without_receipt_rewrite_or_relaunch(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            receipt_before = receipt_path.read_bytes()
            harness.index_path().unlink()
            calls = len(harness.provider_calls())
            proc = harness.run([treatment], csv_name="recover-index.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("duplicate measurement run id", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            rows = harness.index_path().read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(rows), 1)

    def test_receipt_and_index_unknown_keys_are_rejected_without_relaunch(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["unknown"] = True
            receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
            row = json.loads(harness.index_path().read_text(encoding="utf-8"))
            row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            row["unknown"] = True
            harness.index_path().write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            calls = len(harness.provider_calls())
            proc = harness.run([treatment], csv_name="unknown-keys.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)

    def test_receipt_and_index_reject_noncanonical_json_and_duplicate_keys(self):
        cases = ("receipt-whitespace", "receipt-key-order", "receipt-no-lf", "receipt-ensure-ascii", "receipt-duplicate",
                 "index-whitespace", "index-key-order", "index-no-lf", "index-duplicate")
        for script, root in self._for_each_script():
            for label in cases:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    if label == "receipt-ensure-ascii":
                        treatment["measurement"]["identity"]["namespace"] = "측정"
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    index_path = harness.index_path()
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    row = json.loads(index_path.read_text(encoding="utf-8"))
                    if label.startswith("receipt"):
                        if label.endswith("whitespace"):
                            payload = json.dumps(receipt, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
                        elif label.endswith("key-order"):
                            reversed_receipt = {
                                key: receipt[key] for key in reversed(tuple(receipt))
                            }
                            payload = json.dumps(
                                reversed_receipt,
                                ensure_ascii=True,
                                sort_keys=False,
                                separators=(",", ":"),
                            ) + "\n"
                        elif label.endswith("no-lf"):
                            payload = json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                        elif label.endswith("ensure-ascii"):
                            payload = json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                        else:
                            canonical = json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                            payload = canonical[:-1] + ',"schema_version":"duplicate"}\n'
                        receipt_path.write_text(payload, encoding="utf-8")
                        row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                        index_path.write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                    else:
                        if label.endswith("whitespace"):
                            payload = json.dumps(row, sort_keys=True, indent=2) + "\n"
                        elif label.endswith("key-order"):
                            reversed_row = {key: row[key] for key in reversed(tuple(row))}
                            payload = json.dumps(
                                reversed_row, sort_keys=False, separators=(",", ":")
                            ) + "\n"
                        elif label.endswith("no-lf"):
                            payload = json.dumps(row, sort_keys=True, separators=(",", ":"))
                        else:
                            canonical = json.dumps(row, sort_keys=True, separators=(",", ":"))
                            payload = canonical[:-1] + ',"run_id":"duplicate"}\n'
                        index_path.write_text(payload, encoding="utf-8")
                    calls = len(harness.provider_calls())
                    proc = harness.run([treatment], csv_name="verify.csv")
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)

    def test_receipt_rejects_bool_as_int_for_every_numeric_contract_field(self):
        paths = (
            ("run_identity", "repetition"), ("run_identity", "attempt"),
            ("raw_artifact", "bytes"), ("raw_artifact", "lines"), ("raw_artifact", "events"),
            ("settings_artifact", "bytes"),
            ("hook_summary", "observed_lifecycle_count"),
            ("hook_summary", "completed_lifecycle_count"),
        )
        for script, root in self._for_each_script():
            for parent, field in paths:
                with self.subTest(script=script, field=f"{parent}.{field}"):
                    case_root = root / f"{parent}-{field}"
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    receipt[parent][field] = True
                    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
                    row = json.loads(harness.index_path().read_text(encoding="utf-8"))
                    row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                    harness.index_path().write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                    calls = len(harness.provider_calls())
                    proc = harness.run([treatment], csv_name="verify.csv")
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)

    def test_receipt_rejects_bool_as_int_in_event_counts_exit_codes_and_progress(self):
        selectors = ("event-count", "exit-code", "progress-count")
        for script, root in self._for_each_script():
            for label in selectors:
                with self.subTest(script=script, field=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    if label == "event-count":
                        receipt["hook_summary"]["event_class_counts"][0]["count"] = True
                    elif label == "exit-code":
                        receipt["hooks"][0]["hook_process_exit_code"] = True
                    else:
                        receipt["hooks"][0]["progress_count"] = True
                    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
                    row = json.loads(harness.index_path().read_text(encoding="utf-8"))
                    row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                    harness.index_path().write_text(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                    calls = len(harness.provider_calls())
                    proc = harness.run([treatment], csv_name="verify.csv")
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)

    def test_live_terminal_status_precedence_places_process_error_before_hook_errors(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", attempt=88,
                bindings=DEFAULT_BINDINGS, fake_mode="process-error-invalid-hook",
            ))
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["process_status"], "exited_nonzero")
            self.assertEqual(receipt["terminal_status"], "process_error")

    def test_exit_126_after_launch_is_process_error_but_failed_popen_is_launch_error(self):
        cases = (("exit-126", "exited_nonzero", "process_error"),
                 ("launch-error", "launch_error", "process_launch_error"))
        for script, root in self._for_each_script():
            for attempt, (mode, process_status, terminal_status) in enumerate(cases, start=91):
                with self.subTest(script=script, mode=mode):
                    case_root = root / mode
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = _variant("treatment", _measurement(
                        settings_file="treatment-settings.json", arm="treatment", attempt=attempt,
                        bindings=DEFAULT_BINDINGS, fake_mode=mode,
                    ))
                    proc = harness.run([treatment])
                    self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
                    self.assertEqual(receipt["process_status"], process_status)
                    self.assertEqual(receipt["terminal_status"], terminal_status)

    def test_raw_journal_integrity_failure_never_becomes_process_launch_error_or_receipt(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            run_id = expected_run_id(task="t01", repetition=0, arm="treatment", attempt=0, namespace="s001-tests")
            run_dir = root / "artifacts" / "runs" / run_id
            (run_dir / "session").mkdir(parents=True)
            victim = root / "victim"
            victim.write_bytes(b"unchanged")
            (run_dir / "raw.ndjson").symlink_to(victim)
            proc = harness.run([self._valid_pair()[1]])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertNotIn("process_launch_error", proc.stderr)
            self.assertEqual(victim.read_bytes(), b"unchanged")
            self.assertEqual(harness.provider_calls(), [])
            self.assertEqual(harness.receipts(), [])

    def test_forced_v1_v2_run_id_collision_fails_before_paths_or_provider(self):
        for script, root in self._for_each_script():
            mutant = root / "run-id-collision-mutant.py"
            source = script.read_text(encoding="utf-8")
            needle = "legacy_run_id = spec.identity.legacy_v1_run_id(task.id)"
            self.assertIn(needle, source)
            mutant.write_text(source.replace(needle, "legacy_run_id = run_id"), encoding="utf-8")
            harness = MeasurementHarness(root, mutant)
            proc = harness.run([self._valid_pair()[1]], script=mutant)
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("run_id_version_collision", proc.stderr)
            self.assertEqual(harness.calls(), [])
            self.assertFalse((root / "artifacts").exists())

    def test_missing_required_class_precedes_hook_process_failure(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", attempt=89,
                bindings=DEFAULT_BINDINGS, fake_mode="hook-error-missing-required",
            ))
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "missing_required_hook_event_class")

    def test_registered_hook_classes_are_allowed_without_being_required(self):
        cases = (
            ("valid-no-hooks", [], "success"),
            ("valid-hooks", ["PreToolUse", "PostToolUseFailure"], "success"),
        )
        for script, root in self._for_each_script():
            for attempt, (mode, observed, expected_status) in enumerate(cases, start=120):
                with self.subTest(script=script, mode=mode):
                    case_root = root / mode
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = _variant("treatment", _measurement(
                        settings_file="treatment-settings.json",
                        arm="treatment",
                        attempt=attempt,
                        bindings=DEFAULT_BINDINGS,
                        required_event_classes=(),
                        fake_mode=mode,
                    ))

                    proc = harness.run([treatment])

                    self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
                    self.assertEqual(receipt["terminal_status"], expected_status)
                    self.assertEqual(receipt["hook_summary"]["required_event_classes"], [])
                    self.assertEqual([row["hook_event"] for row in receipt["hooks"]], observed)

    def test_required_hook_classes_are_an_ordered_subset_and_still_enforced(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json",
                arm="treatment",
                attempt=122,
                bindings=DEFAULT_BINDINGS,
                required_event_classes=("PreToolUse",),
                fake_mode="valid-no-hooks",
            ))

            proc = harness.run([treatment])

            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["hook_summary"]["required_event_classes"], ["PreToolUse"])
            self.assertEqual(receipt["terminal_status"], "missing_required_hook_event_class")

    def test_registered_hook_failure_remains_fatal_when_no_class_is_required(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json",
                arm="treatment",
                attempt=123,
                bindings=DEFAULT_BINDINGS,
                required_event_classes=(),
                fake_mode="hook-process-error",
            ))

            proc = harness.run([treatment])

            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "hook_process_failure")

    def test_unregistered_hook_class_remains_fatal_when_no_class_is_required(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json",
                arm="treatment",
                attempt=124,
                bindings=DEFAULT_BINDINGS,
                required_event_classes=(),
                fake_mode="unsupported-hook-class",
            ))

            proc = harness.run([treatment])

            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "unexpected_hook_event_class")

    def test_empty_required_classes_still_validate_every_registered_binding(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            settings = _settings(managed_hooks=True)
            del settings["hooks"]["PostToolUseFailure"]
            (root / "treatment-settings.json").write_text(json.dumps(settings), encoding="utf-8")
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json",
                arm="treatment",
                attempt=125,
                bindings=DEFAULT_BINDINGS,
                required_event_classes=(),
                fake_mode="valid-no-hooks",
            ))

            proc = harness.run([treatment])

            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("differ outside registered hooks", proc.stderr)
            self.assertEqual(harness.provider_calls(), [])

    def test_raw_only_recovery_rejects_invalid_or_oversized_raw_without_creating_outputs(self):
        terminal = _canonical_json_bytes({
            "type":"result", "subtype":"success", "is_error":False,
            "usage":{"input_tokens":1, "output_tokens":1}, "total_cost_usd":0.0,
        })
        started = _canonical_json_bytes({
            "type":"system", "subtype":"hook_started", "hook_id":"h", "hook_name":"opaque",
            "hook_event":"PreToolUse", "uuid":"u", "session_id":"s",
        })
        malformed = _canonical_json_bytes({
            "type":"system", "subtype":"hook_response", "hook_id":"h", "hook_name":"opaque",
            "hook_event":"PreToolUse", "uuid":"u", "session_id":"s", "stdout":"", "stderr":"",
            "output":"", "outcome":"success", "exit_code":0,
        })
        oversized_payload = _canonical_json_bytes({
            "type":"system", "subtype":"hook_progress", "hook_id":"h", "hook_name":"opaque",
            "hook_event":"PreToolUse", "uuid":"u", "session_id":"s", "stdout":"x" * 64001,
            "stderr":"", "output":"",
        })
        raw_cases = {
            "partial-lifecycle": started + b"\n" + terminal + b"\n",
            "response-without-start": malformed + b"\n" + terminal + b"\n",
            "hook-payload-overflow": started + b"\n" + oversized_payload + b"\n" + terminal + b"\n",
            "raw-line-count": (b"{}\n" * 10001),
            "raw-line-bytes": b'"' + (b"x" * 256001) + b'"\n',
        }
        for script, root in self._for_each_script():
            for label, replacement in raw_cases.items():
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    raw_path = receipt_path.parent / "raw.ndjson"
                    receipt_path.unlink()
                    harness.index_path().unlink()
                    raw_path.write_bytes(replacement)
                    raw_path.chmod(0o600)
                    calls = len(harness.provider_calls())
                    proc = harness.run([treatment], csv_name="recovery.csv")
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)
                    self.assertFalse(receipt_path.exists())
                    self.assertFalse(harness.index_path().exists())

    def test_receipt_without_index_reparses_raw_and_rejects_hook_or_status_inconsistency(self):
        for script, root in self._for_each_script():
            for label in ("hooks", "summary", "status", "process-terminal"):
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    if label == "hooks":
                        receipt["hooks"][0]["progress_count"] += 1
                    elif label == "summary":
                        receipt["hook_summary"]["event_class_counts"][0]["count"] += 1
                    elif label == "status":
                        receipt["terminal_status"] = "hook_process_failure"
                    elif label == "process-terminal":
                        receipt["process_status"] = "exited_zero"
                        receipt["terminal_status"] = "process_error"
                    receipt_path.write_text(
                        json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
                        encoding="utf-8",
                    )
                    harness.index_path().unlink()
                    calls = len(harness.provider_calls())
                    proc = harness.run([treatment], csv_name="recovery.csv")
                    self.assertNotEqual(proc.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", proc.stderr)
                    self.assertEqual(len(harness.provider_calls()), calls)
                    self.assertFalse(harness.index_path().exists())

    def test_unsupported_class_live_receipt_is_duplicate_safe_or_fails_closed_without_artifacts(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", attempt=96,
                bindings=DEFAULT_BINDINGS, fake_mode="unsupported-hook-class",
            ))
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            if not harness.receipts():
                self.assertFalse(harness.index_path().exists())
                continue
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "unexpected_hook_event_class")
            calls = len(harness.provider_calls())
            second = harness.run([treatment], csv_name="duplicate.csv")
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("duplicate measurement run id", second.stderr)
            self.assertNotIn("artifact integrity check failed", second.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)

    def test_structurally_valid_unsupported_class_raw_only_recovery_is_duplicate_safe(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", attempt=97,
                bindings=DEFAULT_BINDINGS, fake_mode="unsupported-hook-class",
            ))
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            raw_path = receipt_path.parent / "raw.ndjson"
            raw_before = raw_path.read_bytes()
            receipt_path.unlink()
            harness.index_path().unlink()
            calls = len(harness.provider_calls())

            recovered = harness.run([treatment], csv_name="recover-unsupported.csv")

            self.assertNotEqual(recovered.returncode, 0, (recovered.stdout, recovered.stderr))
            self.assertIn("duplicate measurement run id", recovered.stderr)
            self.assertNotIn("artifact integrity check failed", recovered.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertEqual(raw_path.read_bytes(), raw_before)
            receipt_before = receipt_path.read_bytes()
            receipt = json.loads(receipt_before)
            self.assertEqual(receipt["process_status"], "unknown_after_crash")
            self.assertEqual(receipt["terminal_status"], "recovered_process_status_unknown")
            self.assertEqual([hook["hook_event"] for hook in receipt["hooks"]], ["FutureToolUse"])
            index_before = harness.index_path().read_bytes()

            duplicate = harness.run([treatment], csv_name="duplicate-unsupported.csv")
            self.assertNotEqual(duplicate.returncode, 0, (duplicate.stdout, duplicate.stderr))
            self.assertIn("duplicate measurement run id", duplicate.stderr)
            self.assertNotIn("artifact integrity check failed", duplicate.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            self.assertEqual(harness.index_path().read_bytes(), index_before)

    def test_live_provider_settings_snapshot_mutation_creates_no_valid_receipt_or_index(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", attempt=90,
                bindings=DEFAULT_BINDINGS, fake_mode="mutate-settings-snapshot",
            ))
            proc = harness.run([treatment])
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), 1)
            self.assertEqual(harness.receipts(), [])
            self.assertFalse(harness.index_path().exists())

    def test_receipt_without_current_index_row_appends_alongside_unrelated_row_only(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            first_variant = self._valid_pair()[1]
            first = harness.run([first_variant])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            second_variant = copy.deepcopy(first_variant)
            second_variant["measurement"]["identity"]["attempt"] = 1
            second = harness.run([second_variant], csv_name="second.csv")
            self.assertEqual(second.returncode, 0, (second.stdout, second.stderr))
            receipts = harness.receipts()
            second_receipt = next(
                path for path in receipts
                if json.loads(path.read_text(encoding="utf-8"))["run_identity"]["attempt"] == 1
            )
            receipt_before = second_receipt.read_bytes()
            rows = [json.loads(line) for line in harness.index_path().read_text(encoding="utf-8").splitlines()]
            unrelated = next(row for row in rows if row["run_id"] != json.loads(receipt_before)["run_identity"]["run_id"])
            harness.index_path().write_text(
                json.dumps(unrelated, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            calls = len(harness.provider_calls())
            proc = harness.run([second_variant], csv_name="recover-index.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("duplicate measurement run id", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertEqual(second_receipt.read_bytes(), receipt_before)
            recovered = [json.loads(line) for line in harness.index_path().read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(recovered), 2)
            self.assertEqual(recovered[0], unrelated)

    def test_exclusive_writer_never_truncates_or_follows_an_existing_target(self):
        for index, script in enumerate(BENCH_SCRIPTS):
            module = _load_benchmark_module(script, f"exclusive_{index}")
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                existing = root / "raw.ndjson"
                existing.write_bytes(b"immutable-existing-bytes")
                existing.chmod(0o600)
                with self.assertRaises(SystemExit):
                    module._measurement_write_exclusive(existing, b"replacement")
                self.assertEqual(existing.read_bytes(), b"immutable-existing-bytes")

                victim = root / "victim"
                victim.write_bytes(b"victim-must-not-change")
                link = root / "receipt.json"
                link.symlink_to(victim)
                with self.assertRaises(SystemExit):
                    module._measurement_write_exclusive(link, b"replacement")
                self.assertEqual(victim.read_bytes(), b"victim-must-not-change")

    def test_partial_raw_run_recovers_receipt_and_index_without_provider_relaunch(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            raw_path = receipt_path.parent / "raw.ndjson"
            raw_before = raw_path.read_bytes()
            receipt_path.unlink()
            harness.index_path().unlink()
            provider_calls_before = len(harness.provider_calls())

            recovered = harness.run([treatment], csv_name="recovery.csv")

            self.assertNotEqual(recovered.returncode, 0, (recovered.stdout, recovered.stderr))
            self.assertIn("duplicate measurement run id", recovered.stderr)
            self.assertNotIn("artifact integrity check failed", recovered.stderr)
            self.assertEqual(len(harness.provider_calls()), provider_calls_before)
            self.assertEqual(raw_path.read_bytes(), raw_before)
            self.assertTrue(receipt_path.exists(), "receipt must be reconstructed from immutable raw bytes")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["raw_artifact"]["sha256"], hashlib.sha256(raw_before).hexdigest())
            self.assertEqual(receipt["process_status"], "unknown_after_crash")
            self.assertEqual(receipt["terminal_status"], "recovered_process_status_unknown")
            self.assertTrue(harness.index_path().exists(), "artifact index must be recovered without a provider call")
            receipt_before = receipt_path.read_bytes()
            index_before = harness.index_path().read_bytes()
            rows = [json.loads(line) for line in index_before.splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0], {
                "schema_version": ARTIFACT_INDEX_SCHEMA_VERSION,
                "run_id": receipt["run_identity"]["run_id"],
                "receipt_path": str(receipt_path),
                "receipt_sha256": hashlib.sha256(receipt_before).hexdigest(),
                "terminal_status": "recovered_process_status_unknown",
            })

            duplicate = harness.run([treatment], csv_name="duplicate-after-recovery.csv")
            self.assertNotEqual(duplicate.returncode, 0, (duplicate.stdout, duplicate.stderr))
            self.assertIn("duplicate measurement run id", duplicate.stderr)
            self.assertNotIn("artifact integrity check failed", duplicate.stderr)
            self.assertEqual(len(harness.provider_calls()), provider_calls_before)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            self.assertEqual(harness.index_path().read_bytes(), index_before)

            harness.index_path().unlink()
            missing_index = harness.run([treatment], csv_name="missing-index-after-recovery.csv")
            self.assertNotEqual(missing_index.returncode, 0, (missing_index.stdout, missing_index.stderr))
            self.assertIn("duplicate measurement run id", missing_index.stderr)
            self.assertNotIn("artifact integrity check failed", missing_index.stderr)
            self.assertEqual(len(harness.provider_calls()), provider_calls_before)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            self.assertEqual(harness.index_path().read_bytes(), index_before)

    def test_raw_only_recovery_rejects_tampered_settings_and_creates_no_receipt_or_index(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            snapshot = receipt_path.parent / receipt["settings_artifact"]["path"]
            receipt_path.unlink()
            harness.index_path().unlink()
            snapshot.write_bytes(snapshot.read_bytes() + b" ")
            calls = len(harness.provider_calls())
            proc = harness.run([treatment], csv_name="tampered-recovery.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertFalse(receipt_path.exists())
            self.assertFalse(harness.index_path().exists())

    def test_receipt_without_index_recovery_rejects_settings_binding_hash_tamper(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["settings_artifact"]["binding_set_sha256"] = "0" * 64
            receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
            harness.index_path().unlink()
            calls = len(harness.provider_calls())
            proc = harness.run([treatment], csv_name="bad-binding-recovery.csv")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("measurement artifact integrity check failed", proc.stderr)
            self.assertEqual(len(harness.provider_calls()), calls)
            self.assertFalse(harness.index_path().exists())

    def test_settings_parity_does_not_prune_identity_substrings_in_unregistered_hooks(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment_settings = _settings(managed_hooks=True)
            treatment_settings["hooks"]["PreToolUse"].append(
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "unregistered-evil-command",
                            "description": "mentions context-guard-guard-read but is not that hook",
                        }
                    ],
                }
            )
            (root / "treatment-settings.json").write_text(
                json.dumps(treatment_settings), encoding="utf-8"
            )
            self.assert_prelaunch_rejection(
                harness,
                self._valid_pair(),
                message="baseline and treatment settings differ outside registered hooks",
            )

    def test_settings_parity_rejects_registered_command_with_unregistered_suffix(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script):
                harness = MeasurementHarness(root, script)
                treatment_settings = _settings(managed_hooks=True)
                treatment_settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = (
                    "context-guard-guard-read --unregistered-extra"
                )
                (root / "treatment-settings.json").write_text(
                    json.dumps(treatment_settings), encoding="utf-8"
                )
                self.assert_prelaunch_rejection(
                    harness,
                    self._valid_pair(),
                    message="baseline and treatment settings differ outside registered hooks",
                )

    def test_settings_parity_requires_source_byte_equivalence_outside_registered_hooks(self):
        for script, root in self._for_each_script():
            with self.subTest(script=script):
                harness = MeasurementHarness(root, script)
                (root / "baseline-settings.json").write_text(
                    '{"permissions":{"allow":["Read"]},"model":"sonnet"}\n',
                    encoding="utf-8",
                )
                (root / "treatment-settings.json").write_text(
                    textwrap.dedent(
                        """\
                        {
                          "model": "sonnet",
                          "hooks": {
                            "PreToolUse": [{"matcher":"Read","hooks":[
                              {"type":"command","command":"context-guard-guard-read"},
                              {"type":"command","command":"context-guard-guard-search"}
                            ]}],
                            "PostToolUseFailure": [{"matcher":"Bash","hooks":[{"type":"command","command":"context-guard-failed-nudge"}]}]
                          },
                          "permissions": { "allow": [ "Read" ] }
                        }
                        """
                    ),
                    encoding="utf-8",
                )
                self.assert_prelaunch_rejection(
                    harness,
                    self._valid_pair(),
                    message="baseline and treatment settings differ outside registered hooks",
                )

    def test_existing_receipt_identity_is_bound_to_the_requested_run(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = self._valid_pair()[1]
            first = harness.run([treatment])
            self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
            receipt_path = harness.receipts()[0]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["run_identity"]["candidate_hash"] = "b" * 64
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            index_row = json.loads(harness.index_path().read_text(encoding="utf-8"))
            index_row["receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            harness.index_path().write_text(
                json.dumps(index_row, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            provider_calls_before = len(harness.provider_calls())
            second = harness.run([treatment], csv_name="identity-tamper.csv")
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("measurement artifact integrity check failed", second.stderr)
            self.assertEqual(len(harness.provider_calls()), provider_calls_before)

    def test_existing_receipt_and_index_modes_and_hash_are_integrity_checked(self):
        cases = ("receipt-mode", "index-mode", "index-hash")
        for script, root in self._for_each_script():
            for case in cases:
                with self.subTest(script=script, case=case):
                    case_root = root / case
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = self._valid_pair()[1]
                    first = harness.run([treatment])
                    self.assertEqual(first.returncode, 0, (first.stdout, first.stderr))
                    receipt_path = harness.receipts()[0]
                    if case == "receipt-mode":
                        receipt_path.chmod(0o644)
                    elif case == "index-mode":
                        harness.index_path().chmod(0o644)
                    else:
                        row = json.loads(harness.index_path().read_text(encoding="utf-8"))
                        row["receipt_sha256"] = "0" * 64
                        harness.index_path().write_text(json.dumps(row) + "\n", encoding="utf-8")
                    provider_calls_before = len(harness.provider_calls())
                    second = harness.run([treatment], csv_name="tamper.csv")
                    self.assertNotEqual(second.returncode, 0)
                    self.assertIn("measurement artifact integrity check failed", second.stderr)
                    self.assertEqual(len(harness.provider_calls()), provider_calls_before)

    def test_official_lifecycle_allows_uuid_drift_and_hashes_only_opaque_fields(self):
        records = [
            {"type":"system", "subtype":"hook_started", "hook_id":"h", "hook_name":"opaque",
             "hook_event":"PostToolUse", "uuid":"u-start", "session_id":"s"},
            {"type":"system", "subtype":"hook_progress", "hook_id":"h", "hook_name":"opaque",
             "hook_event":"PostToolUse", "uuid":"u-progress", "session_id":"s",
             "stdout":RAW_SECRET, "stderr":"", "output":RAW_SECRET},
            {"type":"system", "subtype":"hook_response", "hook_id":"h", "hook_name":"opaque",
             "hook_event":"PostToolUse", "uuid":"u-response", "session_id":"s",
             "stdout":RAW_SECRET, "stderr":"", "output":RAW_SECRET,
             "outcome":"success", "exit_code":0},
        ]
        raw = b"\n".join(_canonical_json_bytes(record) for record in records)
        for index, script in enumerate(BENCH_SCRIPTS):
            module = _load_benchmark_module(script, f"official_uuid_{index}")
            normalized = module.normalize_measurement_hook_events(raw)
            self.assertEqual(normalized, [{
                "hook_event":"PostToolUse",
                "opaque_hook_name_sha256":_domain_hash(b"contextguard.bench.opaque-hook-name.v2", "opaque"),
                "lifecycle_key_sha256":_domain_hash(b"contextguard.bench.hook-lifecycle-key.v2", "s", "h"),
                "hook_process_outcome":"success", "hook_process_exit_code":0,
                "triggering_tool_outcome":"succeeded", "progress_count":1,
            }])
            self.assertNotIn(RAW_SECRET, json.dumps(normalized))
            self.assertNotIn("u-start", json.dumps(normalized))

    def test_official_lifecycle_rejects_name_event_and_transition_drift(self):
        base = {"type":"system", "hook_id":"h", "hook_name":"opaque", "hook_event":"PreToolUse",
                "uuid":"u", "session_id":"s"}
        cases = {
            "name-drift": [dict(base, subtype="hook_started"), dict(base, subtype="hook_response",
                hook_name="other", stdout="", stderr="", output="", outcome="success")],
            "event-drift": [dict(base, subtype="hook_started"), dict(base, subtype="hook_response",
                hook_event="PostToolUse", stdout="", stderr="", output="", outcome="success")],
            "response-without-start": [dict(base, subtype="hook_response", stdout="", stderr="",
                output="", outcome="success")],
            "duplicate-start": [dict(base, subtype="hook_started"), dict(base, subtype="hook_started")],
            "unterminated": [dict(base, subtype="hook_started")],
        }
        for index, script in enumerate(BENCH_SCRIPTS):
            module = _load_benchmark_module(script, f"official_drift_{index}")
            for label, records in cases.items():
                with self.subTest(script=script, case=label):
                    raw = b"\n".join(_canonical_json_bytes(record) for record in records)
                    with self.assertRaises(ValueError):
                        module.normalize_measurement_hook_events(raw)

    def test_hook_classification_flags_preserve_normative_priority_when_failures_coexist(self):
        unsupported = {
            "type":"system", "subtype":"hook_started", "hook_id":"u", "hook_name":"opaque",
            "hook_event":"FutureToolUse", "uuid":"uuid", "session_id":"s",
        }
        invalid = {"type":"system", "subtype":"hook_started", "hook_id":"", "hook_name":"opaque",
                   "hook_event":"PreToolUse", "uuid":"uuid", "session_id":"s"}
        payload = {
            "type":"system", "subtype":"hook_progress", "hook_id":"u", "hook_name":"opaque",
            "hook_event":"FutureToolUse", "uuid":"uuid", "session_id":"s",
            "stdout":"x" * 64001, "stderr":"", "output":"",
        }
        for index, script in enumerate(BENCH_SCRIPTS):
            module = _load_benchmark_module(script, f"classification_priority_{index}")
            raw = b"\n".join(_canonical_json_bytes(value) for value in (unsupported, invalid, payload))
            result = module._parse_measurement_hook_events(raw)
            self.assertEqual(result["classification"], "hook_payload_limit")

            many = [_canonical_json_bytes(unsupported)] * 1001 + [_canonical_json_bytes(payload)]
            result = module._parse_measurement_hook_events(b"\n".join(many))
            self.assertEqual(result["classification"], "hook_payload_limit")

    def test_synthetic_v1_hook_event_is_rejected_not_normalized(self):
        raw = _canonical_json_bytes({
            "type":"hook_event", "event_name":"PreToolUse", "hook_identity":"legacy",
            "tool":"Read", "decision":"allow", "timestamp":"2026-07-30T00:00:00Z",
        })
        for index, script in enumerate(BENCH_SCRIPTS):
            module = _load_benchmark_module(script, f"reject_synthetic_{index}")
            with self.assertRaises(ValueError):
                module.normalize_measurement_hook_events(raw)

    def test_registered_bindings_are_exact_and_required_classes_are_an_ordered_subset(self):
        mutations: list[tuple[str, Callable[[dict, dict], None]]] = [
            ("hook-events-unknown", lambda m, s: m["hook_events"].__setitem__("unknown", 1)),
            ("binding-unknown", lambda m, s: m["hook_events"]["registered_bindings"][0].__setitem__("unknown", 1)),
            ("duplicate-pair", lambda m, s: m["hook_events"]["registered_bindings"].append(
                copy.deepcopy(m["hook_events"]["registered_bindings"][0]))),
            ("required-order", lambda m, s: m["hook_events"].__setitem__(
                "required_event_classes", ["PostToolUseFailure", "PreToolUse"])),
            ("required-unregistered", lambda m, s: m["hook_events"].__setitem__(
                "required_event_classes", ["PostToolUse"])),
            ("unsupported-class", lambda m, s: m["hook_events"]["registered_bindings"][0].__setitem__(
                "hook_event", "FutureToolUse")),
            ("oversized-command", lambda m, s: m["hook_events"]["registered_bindings"][0].__setitem__(
                "configured_command", "x" * 4097)),
            ("nul-command", lambda m, s: m["hook_events"]["registered_bindings"][0].__setitem__(
                "configured_command", "bad\0command")),
            ("wrong-event", lambda m, s: m["hook_events"]["registered_bindings"][0].__setitem__(
                "hook_event", "PostToolUse")),
            ("unrepresented-command", lambda m, s: s["hooks"]["PreToolUse"][0]["hooks"].append(
                {"type":"command", "command":"unregistered"})),
            ("non-command", lambda m, s: s["hooks"]["PreToolUse"][0]["hooks"].append(
                {"type":"prompt", "prompt":"unmanaged"})),
            ("malformed-hook", lambda m, s: s["hooks"]["PreToolUse"][0]["hooks"].append("bad")),
            ("duplicate-occurrence", lambda m, s: s["hooks"]["PreToolUse"][0]["hooks"].append(
                copy.deepcopy(s["hooks"]["PreToolUse"][0]["hooks"][0]))),
        ]
        for script, root in self._for_each_script():
            for label, mutate in mutations:
                with self.subTest(script=script, case=label):
                    case_root = root / label
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    pair = copy.deepcopy(self._valid_pair())
                    settings = _settings(managed_hooks=True)
                    mutate(pair[1]["measurement"], settings)
                    (case_root / "treatment-settings.json").write_text(json.dumps(settings), encoding="utf-8")
                    proc = harness.run(pair)
                    self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    self.assertEqual(harness.provider_calls(), [], label)
                    self.assertFalse(harness.csv_path.exists())
                    self.assertFalse((case_root / "artifacts").exists())

    def test_baseline_is_exact_treatment_derived_pruning_not_independent_hook_policy(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            baseline = _settings()
            baseline["hooks"] = {
                "Notification": [{"matcher":"idle", "hooks":[{"type":"command", "command":"keep-me"}]}]
            }
            treatment = _settings(managed_hooks=True)
            treatment["hooks"]["Notification"] = copy.deepcopy(baseline["hooks"]["Notification"])
            (root / "baseline-settings.json").write_text(json.dumps(baseline), encoding="utf-8")
            (root / "treatment-settings.json").write_text(json.dumps(treatment), encoding="utf-8")
            proc = harness.run(self._valid_pair(), extra_args=["--dry-run"])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))

            baseline["hooks"]["Notification"][0]["matcher"] = "changed"
            (root / "baseline-settings.json").write_text(json.dumps(baseline), encoding="utf-8")
            proc = harness.run(self._valid_pair(), extra_args=["--dry-run"])
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(harness.provider_calls(), [])

    def test_runtime_uses_event_classes_not_opaque_hook_names_or_binding_count(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            proc = harness.run([self._valid_pair()[1]])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "success")
            self.assertEqual(receipt["hook_summary"]["event_class_counts"][0], {
                "hook_event":"PreToolUse", "count":1,
            })
            self.assertEqual(len(DEFAULT_BINDINGS), 3)
            serialized = json.dumps(receipt)
            for command in (command for _, command in DEFAULT_BINDINGS):
                self.assertNotIn(command, serialized)

    def test_post_tool_success_and_failure_have_separate_triggering_outcomes(self):
        bindings = (
            ("PostToolUse", "context-guard-post-success"),
            ("PostToolUseFailure", "context-guard-failed-nudge"),
        )
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            settings = _settings()
            settings["hooks"] = {
                event: [{"matcher":"x", "hooks":[{"type":"command", "command":command}]}]
                for event, command in bindings
            }
            (root / "treatment-settings.json").write_text(json.dumps(settings), encoding="utf-8")
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", bindings=bindings,
                fake_mode="post-tool-outcomes",
            ))
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(
                [item["triggering_tool_outcome"] for item in receipt["hooks"]],
                ["succeeded", "failed"],
            )
            self.assertEqual([item["hook_process_outcome"] for item in receipt["hooks"]], ["success", "success"])

    def test_zero_and_multiple_progress_records_preserve_response_order_and_counts(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", bindings=DEFAULT_BINDINGS,
                fake_mode="multi-progress", attempt=76,
            ))
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual([item["hook_event"] for item in receipt["hooks"]], ["PreToolUse", "PostToolUseFailure"])
            self.assertEqual([item["progress_count"] for item in receipt["hooks"]], [3, 0])

    def test_lifecycle_classification_and_transition_failures_have_exact_statuses(self):
        cases = (
            ("name-drift", "invalid_hook_lifecycle"),
            ("event-drift", "invalid_hook_lifecycle"),
            ("response-without-start", "invalid_hook_lifecycle"),
            ("unsupported-hook-class", "unexpected_hook_event_class"),
            ("malformed-hook-class", "invalid_hook_lifecycle"),
            ("hook-process-error", "hook_process_failure"),
            ("synthetic-v1", "invalid_hook_lifecycle"),
        )
        for script, root in self._for_each_script():
            for attempt, (mode, expected_status) in enumerate(cases, start=30):
                with self.subTest(script=script, mode=mode):
                    case_root = root / mode
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    treatment = _variant("treatment", _measurement(
                        settings_file="treatment-settings.json", arm="treatment", attempt=attempt,
                        bindings=DEFAULT_BINDINGS, fake_mode=mode,
                    ))
                    proc = harness.run([treatment])
                    self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
                    receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
                    self.assertEqual(receipt["terminal_status"], expected_status)

    def test_256001_byte_raw_line_has_reachable_distinct_terminal_status(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            treatment = _variant("treatment", _measurement(
                settings_file="treatment-settings.json", arm="treatment", bindings=DEFAULT_BINDINGS,
                fake_mode="line-256001", attempt=77,
            ))
            proc = harness.run([treatment])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            receipt = json.loads(harness.receipts()[0].read_text(encoding="utf-8"))
            self.assertEqual(receipt["terminal_status"], "raw_line_byte_limit")

    def test_credential_aliases_do_not_reach_any_measurement_subprocess_or_output(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            success_log = root / "success-env.json"
            success_probe = root / "success-env-probe"
            success_probe.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os\n"
                f"names = {AUTH_ENV_NAMES!r}\n"
                f"open({str(success_log)!r}, 'w').write(json.dumps([n for n in names if n in os.environ]))\n",
                encoding="utf-8",
            )
            success_probe.chmod(0o755)
            tasks = json.loads(harness.tasks_path.read_text(encoding="utf-8"))
            tasks[0]["success_command"] = str(success_probe)
            harness.tasks_path.write_text(json.dumps(tasks), encoding="utf-8")
            proc = harness.run([self._valid_pair()[1]])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertTrue({"help", "version", "provider"}.issubset({call["kind"] for call in harness.calls()}))
            for call in harness.calls():
                for name in AUTH_ENV_NAMES:
                    self.assertNotIn(name, call["env"])
            self.assertEqual(json.loads(success_log.read_text(encoding="utf-8")), [])
            all_output = proc.stdout + proc.stderr
            all_output += "".join(path.read_text(encoding="utf-8") for path in harness.receipts())
            all_output += harness.index_path().read_text(encoding="utf-8")
            for value in (
                "anthropic-secret-must-not-propagate", "oauth-secret-must-not-propagate",
                "aws-secret-must-not-propagate", "github-pat-must-not-propagate",
                "aws-access-id-must-not-propagate", "netrc-path-must-not-propagate",
                "kubeconfig-path-must-not-propagate", "npm-userconfig-path-must-not-propagate",
            ):
                self.assertNotIn(value, all_output)

    def test_cli_capability_probe_requires_token_boundaries_not_substrings(self):
        cases = (
            "--settings-extra --setting-sources --include-hook-events --no-session-persistence stream-json",
            "--settings --setting-sources --include-hook-events --no-session-persistence stream-json-x",
        )
        for script, root in self._for_each_script():
            for index, capabilities in enumerate(cases):
                with self.subTest(script=script, capabilities=capabilities):
                    case_root = root / f"lookalike-{index}"
                    case_root.mkdir()
                    harness = MeasurementHarness(case_root, script)
                    self.assert_prelaunch_rejection(
                        harness,
                        [self._valid_pair()[1]],
                        message="required CLI capability unavailable",
                        env_updates={"CG_FAKE_CAPABILITIES": capabilities},
                        allow_capability_probe=True,
                    )

    def test_measurement_fixture_requires_exact_pair_but_filter_may_select_one_arm(self):
        for script, root in self._for_each_script():
            invalid_root = root / "missing-pair"
            invalid_root.mkdir()
            invalid = MeasurementHarness(invalid_root, script)
            proc = invalid.run([self._valid_pair()[1]], ensure_pair=False)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("baseline and treatment", proc.stderr)
            self.assertEqual(invalid.provider_calls(), [])
            self.assertFalse(invalid.csv_path.exists())
            self.assertFalse((invalid_root / "artifacts").exists())

            selected_root = root / "selected-arm"
            selected_root.mkdir()
            selected = MeasurementHarness(selected_root, script)
            proc = selected.run(self._valid_pair(), extra_args=["--variant", "treatment"])
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
            self.assertEqual(len(selected.provider_calls()), 1)
            self.assertEqual(len(selected.receipts()), 1)

    def test_preflight_rejection_creates_no_optional_outputs_or_sidecars(self):
        for script, root in self._for_each_script():
            harness = MeasurementHarness(root, script)
            bad = copy.deepcopy(self._valid_pair()[1])
            bad["measurement"]["unknown"] = True
            ledger = root / "evidence.jsonl"
            report = root / "report.json"
            dashboard = root / "dashboard.md"
            proc = harness.run(
                [bad],
                extra_args=[
                    "--ledger-jsonl", str(ledger),
                    "--report-json", str(report),
                    "--dashboard-md", str(dashboard),
                ],
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(harness.calls(), [])
            for path in (harness.csv_path, ledger, report, dashboard):
                self.assertFalse(path.exists(), path)
            self.assertEqual(list(root.glob("*.lock")), [])
            self.assertEqual(list(root.glob("*.tmp")), [])
            self.assertFalse((root / "artifacts").exists())

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

    def test_deliberate_source_mutations_are_killed_by_behavioral_oracles(self):
        canonical = BENCH_SCRIPTS[0]
        source = canonical.read_text(encoding="utf-8")
        mutations = (
            ("synthetic-resurrection",
             'if event.get("type") == "hook_event":\n            classification = classification or "invalid_hook_lifecycle"\n            continue',
             'if event.get("type") == "hook_event":\n            continue',
             "test_synthetic_v1_hook_event_is_rejected_not_normalized"),
            ("uuid-equality",
             'identity = (event["hook_name"], hook_event)',
             'identity = (event["hook_name"], hook_event, event["uuid"])',
             "test_official_lifecycle_allows_uuid_drift_and_hashes_only_opaque_fields"),
            ("weak-substring-pruning",
             'binding = (event, hook["command"])\n                if binding not in binding_set:',
             'matching = [item for item in binding_set if item[0] == event and item[1] in hook["command"]]\n'
             '                binding = matching[0] if matching else (event, hook["command"])\n'
             '                if binding not in binding_set:',
             "test_settings_parity_rejects_registered_command_with_unregistered_suffix"),
            ("v1-conflict-relabel",
             'raise SystemExit("legacy_v1_artifact_conflict")',
             'raise SystemExit("mutant_relabelled_v1_as_v2")',
             "test_legacy_v1_path_blocks_v2_creation_and_wins_over_existing_v2_path"),
            ("recovery-success-equivalence",
             'terminal_status = "recovered_process_status_unknown"',
             'terminal_status = "success"',
             "test_partial_raw_run_recovers_receipt_and_index_without_provider_relaunch"),
            ("opaque-name-command-equality",
             'identity = (event["hook_name"], hook_event)',
             'if event["hook_name"] not in {"context-guard-guard-read", "context-guard-guard-search", "context-guard-failed-nudge"}:\n'
             '            failure_flags.add("invalid_hook_lifecycle")\n'
             '        identity = (event["hook_name"], hook_event)',
             "test_runtime_uses_event_classes_not_opaque_hook_names_or_binding_count"),
            ("per-command-runtime-attribution",
             'required_event_classes=spec.required_event_classes,',
             'required_event_classes=tuple(command for _event, command in spec.pair_registered_bindings),',
             "test_runtime_uses_event_classes_not_opaque_hook_names_or_binding_count"),
            ("unrelated-hook-satisfies-required",
             'completed_classes = {item["hook_event"] for item in hook_result["hooks"]}',
             'completed_classes = set(required_event_classes)',
             "test_missing_required_class_precedes_hook_process_failure"),
            ("hook-status-before-process-error",
             '    if process_status == "exited_nonzero":',
             '    if process_status == "exited_nonzero" and not hook_result.get("failure_flags"):',
             "test_live_terminal_status_precedence_places_process_error_before_hook_errors"),
            ("skip-settings-snapshot-integrity",
             'settings_bytes = _measurement_validate_snapshot(context, spec)',
             'settings_bytes = spec.settings_source_bytes',
             "test_settings_snapshot_tamper_is_rejected_at_duplicate_seam_without_relaunch"),
            ("skip-raw-private-file-integrity",
             'def _measurement_read_private_raw(path: Path) -> bytes:\n'
             '    fd = _open_regular_no_symlink(path)\n'
             '    try:\n'
             '        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:\n'
             '            raise ValueError("raw mode")',
             'def _measurement_read_private_raw(path: Path) -> bytes:\n'
             '    fd = _open_regular_no_symlink(path)\n'
             '    try:\n'
             '        if False:\n'
             '            raise ValueError("raw mode")',
             "test_existing_raw_mode_is_integrity_checked_without_relaunch"),
            ("v1-index-reuse-bypass",
             '    if matching_legacy_rows:\n'
             '        raise SystemExit("legacy_v1_artifact_conflict")',
             '    if False and matching_legacy_rows:\n'
             '        raise SystemExit("legacy_v1_artifact_conflict")',
             "test_v1_schema_and_cross_version_index_join_are_rejected_prelaunch"),
            ("under-lock-identity-recheck-removal",
             '    _measurement_check_artifact_identity_locked(\n'
             '        spec, task, run_id, artifact_root_locked=True,\n'
             '    )\n'
             '    context = _measurement_create_run_context(spec, task.id, locked_root_fd=locked_root_fd)',
             '    context = _measurement_create_run_context(spec, task.id, locked_root_fd=locked_root_fd)',
             "test_legacy_conflict_created_by_capability_probe_is_rechecked_under_execution_lock"),
        )
        original_scripts = BENCH_SCRIPTS
        try:
            for label, needle, replacement, oracle in mutations:
                with self.subTest(mutant=label):
                    self.assertIn(needle, source)
                    with tempfile.TemporaryDirectory() as tmp:
                        mutant = Path(tmp) / f"{label}.py"
                        mutated_source = source.replace(needle, replacement)
                        if label == "weak-substring-pruning":
                            mutated_source = mutated_source.replace(
                                'value.get("type") == "command" and value.get("command") == command',
                                'value.get("type") == "command" and command in value.get("command", "")',
                            )
                        mutant.write_text(mutated_source, encoding="utf-8")
                        globals()["BENCH_SCRIPTS"] = (mutant,)
                        nested = unittest.TestResult()
                        BenchmarkMeasurementSubstrateTests(oracle).run(nested)
                        self.assertGreater(
                            len(nested.failures) + len(nested.errors), 0,
                            f"mutation survived: {label}",
                        )
        finally:
            globals()["BENCH_SCRIPTS"] = original_scripts


if __name__ == "__main__":
    unittest.main()
