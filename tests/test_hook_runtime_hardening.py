from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "context-guard-kit"
PLUGIN_BIN = ROOT / "plugins" / "context-guard" / "bin"


def load_setup_module():
    spec = importlib.util.spec_from_file_location(
        "context_guard_setup_runtime_hardening",
        KIT_DIR / "setup_wizard.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


class HookRuntimeHardeningTests(unittest.TestCase):
    HOOK_PAYLOADS = {
        "rewrite": {
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "pwd"},
        },
        "guard-read": {
            "hook_event_name": "PreToolUse",
            "tool_input": {"file_path": "README.md", "offset": 1, "limit": 5},
        },
        "failed-nudge": {
            "hook_event_name": "PostToolUse",
            "session_id": "hardening-test",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "pwd"},
            "tool_response": {"exit_code": 0},
        },
    }

    def _hostile_environment(self, root: Path) -> tuple[dict[str, str], dict[str, Path]]:
        hostile_bin = root / "hostile-bin"
        hostile_bin.mkdir()
        markers = {
            name: root / f"{name}-executed"
            for name in (
                "python3",
                "bash",
                "node",
                "perl",
                "sitecustomize",
                "pythonstartup",
                "bash_env",
                "env",
                "omc",
                "statusline_override",
            )
        }
        for name in ("python3", "bash", "node", "perl"):
            write_executable(
                hostile_bin / name,
                f"touch {shlex.quote(str(markers[name]))}\n"
                "cat >/dev/null 2>&1 || true\n"
                "exit 0\n",
            )
        (root / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(markers['sitecustomize'])!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        (root / "pythonstartup.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(markers['pythonstartup'])!r}).write_text('ran')\n",
            encoding="utf-8",
        )
        write_executable(
            root / "shell-env.sh",
            f"touch {shlex.quote(str(markers['bash_env']))}\n",
        )
        home = root / "home"
        hud_dir = home / ".claude" / "hud"
        hud_dir.mkdir(parents=True)
        (hud_dir / "omc-hud.mjs").write_text(
            "// hostile HOME content must never be selected automatically\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(hostile_bin) + os.pathsep + os.defpath,
                "PYTHONPATH": str(root),
                "PYTHONSTARTUP": str(root / "pythonstartup.py"),
                "BASH_ENV": str(root / "shell-env.sh"),
                "ENV": str(root / "shell-env.sh"),
                "HOME": str(home),
            }
        )
        return env, markers

    def test_setup_generated_automatic_commands_ignore_hostile_runtime_environment(self) -> None:
        setup = load_setup_module()
        settings: dict[str, object] = {}
        setup.apply_choices(settings, setup.Choices())

        commands: list[tuple[str, str]] = [
            ("statusline", settings["statusLine"]["command"]),  # type: ignore[index]
        ]
        hooks = settings["hooks"]  # type: ignore[index]
        for event_name in ("PreToolUse", "PostToolUse", "PostToolUseFailure"):
            for entry in hooks.get(event_name, []):  # type: ignore[union-attr]
                for hook in entry.get("hooks", []):
                    command = hook.get("command", "")
                    if command:
                        commands.append((event_name, command))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env, markers = self._hostile_environment(root)
            seen: set[str] = set()
            for label, command in commands:
                if command in seen:
                    continue
                seen.add(command)
                if label == "statusline":
                    payload = {
                        "model": {"display_name": "Sonnet"},
                        "workspace": {"current_dir": str(ROOT)},
                        "context_window": {"used_percentage": 12},
                        "cost": {"total_cost_usd": 0.001},
                    }
                elif "guard-read" in command:
                    payload = self.HOOK_PAYLOADS["guard-read"]
                elif "failed-nudge" in command:
                    payload = self.HOOK_PAYLOADS["failed-nudge"]
                else:
                    payload = self.HOOK_PAYLOADS["rewrite"]
                proc = subprocess.run(
                    command,
                    shell=True,
                    executable="/bin/sh",
                    cwd=ROOT,
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, (label, proc.stderr))

            executed = sorted(name for name, marker in markers.items() if marker.exists())
            self.assertEqual(executed, [], f"hostile runtime executed: {executed}")

    def test_setup_migrates_known_statusline_alias_but_preserves_custom_command(self) -> None:
        setup = load_setup_module()
        choices = setup.Choices(
            denies=False,
            statusline=True,
            bash_hook=False,
            read_guard=False,
            model_defaults=False,
            failed_attempt_nudge=False,
        )
        for alias in (
            "context-guard-statusline-merged",
            "claude-token-statusline-merged",
            "bash context-guard-kit/statusline_merged.sh",
        ):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as tmp:
                env, markers = self._hostile_environment(Path(tmp))
                settings = {"statusLine": {"type": "command", "command": alias}}
                with mock.patch.dict(os.environ, env, clear=True):
                    actions = setup.apply_choices(settings, choices)
                migrated = settings["statusLine"]["command"]
                self.assertNotEqual(migrated, alias)
                self.assertIn("migrated token statusline", actions)
                proc = subprocess.run(
                    migrated,
                    shell=True,
                    executable="/bin/sh",
                    cwd=ROOT,
                    input=json.dumps(
                        {
                            "model": {"display_name": "Sonnet"},
                            "workspace": {"current_dir": str(ROOT)},
                            "context_window": {"used_percentage": 12},
                            "cost": {"total_cost_usd": 0.001},
                        }
                    ),
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=10,
                    check=True,
                )
                self.assertIn("ctx 12%", proc.stdout)
                self.assertFalse(any(marker.exists() for marker in markers.values()))

        custom = {"statusLine": {"type": "command", "command": "/opt/acme/custom-hud --json"}}
        actions = setup.apply_choices(custom, choices)
        self.assertEqual(custom["statusLine"]["command"], "/opt/acme/custom-hud --json")
        self.assertIn("kept existing statusLine", actions[0])

        pipeline_command = "bash -c 'context-guard-statusline-merged | custom-filter'"
        pipeline = {"statusLine": {"type": "command", "command": pipeline_command}}
        actions = setup.apply_choices(pipeline, choices)
        self.assertEqual(pipeline["statusLine"]["command"], pipeline_command)
        self.assertIn("kept existing statusLine", actions[0])

        custom_same_basename_commands = (
            "/opt/acme/context-guard-statusline-merged",
            "/opt/acme/statusline_merged.sh",
            "bash /opt/acme/statusline_merged.sh",
            (
                "bash /opt/acme/statusline_merged.sh "
                "--approved-bash /bin/bash "
                f"--approved-python {shlex.quote(str(Path(sys.executable).resolve()))} "
                "--approved-token-statusline /opt/acme/context-guard-statusline"
            ),
        )
        for custom_command in custom_same_basename_commands:
            with self.subTest(custom_same_basename=custom_command):
                custom_same_basename = {
                    "statusLine": {"type": "command", "command": custom_command}
                }
                actions = setup.apply_choices(custom_same_basename, choices)
                self.assertEqual(
                    custom_same_basename["statusLine"]["command"],
                    custom_command,
                )
                self.assertIn("kept existing statusLine", actions[0])

        with mock.patch.dict(
            os.environ,
            {"CONTEXT_GUARD_STATUSLINE_CTX_WARN": "90"},
            clear=False,
        ):
            old_pinned = setup.statusline_setting()
        pinned_settings = {"statusLine": old_pinned}
        with mock.patch.dict(
            os.environ,
            {"CONTEXT_GUARD_STATUSLINE_CTX_WARN": "91"},
            clear=False,
        ):
            actions = setup.apply_choices(pinned_settings, choices)
        self.assertNotEqual(pinned_settings["statusLine"], old_pinned)
        self.assertIn("migrated token statusline", actions)

    def test_generic_hook_migration_requires_exact_authenticated_command(self) -> None:
        setup = load_setup_module()
        desired_rewrite = setup.bash_hook_setting()["hooks"][0]["command"]
        custom_commands = (
            "/tmp/context-guard-rewrite-bash --custom-mode",
            "./context-guard-rewrite-bash",
            "context-guard-rewrite-bash --custom-mode",
            "bash -c 'context-guard-rewrite-bash | custom-filter'",
        )
        for custom_command in custom_commands:
            with self.subTest(custom=custom_command):
                value = {"command": custom_command}
                found, changed = setup.canonicalize_equivalent_command(
                    value,
                    desired_rewrite,
                )
                self.assertFalse(found)
                self.assertFalse(changed)
                self.assertEqual(value["command"], custom_command)

        other_custom_commands = (
            (
                "/tmp/context-guard-guard-read --custom-mode",
                setup.read_hook_setting()["hooks"][0]["command"],
            ),
            (
                "context-guard-failed-nudge --custom-mode",
                setup.failed_nudge_setting()["hooks"][0]["command"],
            ),
        )
        for custom_command, desired in other_custom_commands:
            with self.subTest(custom=custom_command):
                value = {"command": custom_command}
                found, changed = setup.canonicalize_equivalent_command(value, desired)
                self.assertFalse(found)
                self.assertFalse(changed)
                self.assertEqual(value["command"], custom_command)

        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": custom_commands[0],
                            }
                        ],
                    }
                ]
            }
        }
        choices = setup.Choices(
            denies=False,
            statusline=False,
            bash_hook=True,
            read_guard=False,
            model_defaults=False,
            failed_attempt_nudge=False,
        )
        setup.apply_choices(settings, choices)
        bash_entries = settings["hooks"]["PreToolUse"]
        self.assertEqual(bash_entries[0]["hooks"][0]["command"], custom_commands[0])
        self.assertEqual(len(bash_entries), 2)

        migration_cases = (
            (
                "claude-token-rewrite-bash",
                str(PLUGIN_BIN / "context-guard-rewrite-bash"),
                desired_rewrite,
            ),
            (
                "claude-token-guard-read",
                str(PLUGIN_BIN / "context-guard-guard-read"),
                setup.read_hook_setting()["hooks"][0]["command"],
            ),
            (
                "claude-token-failed-nudge",
                str(PLUGIN_BIN / "context-guard-failed-nudge"),
                setup.failed_nudge_setting()["hooks"][0]["command"],
            ),
        )
        for legacy_alias, bundled_path, desired in migration_cases:
            for existing in (legacy_alias, bundled_path):
                with self.subTest(existing=existing):
                    value = {"command": existing}
                    found, changed = setup.canonicalize_equivalent_command(
                        value,
                        desired,
                    )
                    self.assertTrue(found)
                    self.assertTrue(changed)
                    self.assertEqual(value["command"], desired)

    def test_legacy_sanitizer_shape_resolves_trusted_bash_not_hostile_path(self) -> None:
        for script in (
            KIT_DIR / "sanitize_output.py",
            PLUGIN_BIN / "context-guard-sanitize-output",
        ):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                hostile_bin = root / "bin"
                hostile_bin.mkdir()
                marker = root / "fake-bash-executed"
                startup_marker = root / "bash-env-executed"
                write_executable(
                    hostile_bin / "bash",
                    f"touch {shlex.quote(str(marker))}\nexec /bin/bash \"$@\"\n",
                )
                startup = root / "bash-env.sh"
                write_executable(
                    startup,
                    f"touch {shlex.quote(str(startup_marker))}\n",
                )
                env = os.environ.copy()
                env["PATH"] = str(hostile_bin) + os.pathsep + os.defpath
                env["BASH_ENV"] = str(startup)
                env["ENV"] = str(startup)
                proc = subprocess.run(
                    [
                        str(Path(sys.executable).resolve()),
                        "-I",
                        str(script),
                        "--context-guard-wrapper-v1",
                        "command_search_diff",
                        "--",
                        "bash",
                        "-c",
                        "printf legacy-shape-ok",
                    ],
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=10,
                    check=True,
                )
                self.assertIn("legacy-shape-ok", proc.stdout)
                self.assertFalse(marker.exists())
                self.assertFalse(startup_marker.exists())

    def test_secure_and_legacy_sanitizer_shapes_ignore_bash_shell_state_and_functions(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "context_guard_rewrite_shell_state_test",
            KIT_DIR / "rewrite_bash_for_token_budget.py",
        )
        assert spec is not None and spec.loader is not None
        rewrite = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = rewrite
        spec.loader.exec_module(rewrite)
        shapes = {
            "secure": list(rewrite._runtime_shell_argv()),
            "legacy": ["bash", "-c"],
        }
        logical = (
            "if type cg_attack >/dev/null 2>&1; then cg_attack; fi; "
            "printf shell-state-ok"
        )
        for script in (
            KIT_DIR / "sanitize_output.py",
            PLUGIN_BIN / "context-guard-sanitize-output",
        ):
            for shape_name, shell_argv in shapes.items():
                with (
                    self.subTest(script=script, shape=shape_name),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp)
                    ps4_marker = root / "ps4-executed"
                    function_marker = root / "function-executed"
                    env = os.environ.copy()
                    env.update(
                        {
                            "SHELLOPTS": "xtrace",
                            "PS4": f"$(/usr/bin/touch {ps4_marker})+ ",
                            "BASH_FUNC_cg_attack%%": (
                                "() { /usr/bin/touch " + str(function_marker) + "; }"
                            ),
                        }
                    )
                    proc = subprocess.run(
                        [
                            str(Path(sys.executable).resolve()),
                            "-I",
                            str(script),
                            "--context-guard-wrapper-v1",
                            "command_search_diff",
                            "--",
                            *shell_argv,
                            logical,
                        ],
                        text=True,
                        capture_output=True,
                        env=env,
                        timeout=10,
                        check=True,
                    )
                    self.assertIn("shell-state-ok", proc.stdout)
                    self.assertFalse(ps4_marker.exists())
                    self.assertFalse(function_marker.exists())

    def test_automatic_commands_preserve_only_safe_behavior_configuration(self) -> None:
        setup = load_setup_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            large = root / "large.txt"
            large.write_text("x" * 60_000, encoding="utf-8")
            loader_marker = root / "loader-executed"
            (root / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(loader_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            safe_env = {
                "CONTEXT_GUARD_READ_GUARD": "1",
                "CONTEXT_GUARD_READ_GUARD_MAX_BYTES": "100000",
                "CONTEXT_GUARD_READ_GUARD_MAX_LINES": "20000",
                "CONTEXT_GUARD_READ_GUARD_PROOF_BYTES": "1048576",
                "CONTEXT_GUARD_SANITIZER_FAIL_OPEN": "1",
                "CONTEXT_GUARD_STATUSLINE_INPUT_MAX_BYTES": "2048",
                "CONTEXT_GUARD_STATUSLINE_CTX_WARN": "10",
                "CONTEXT_GUARD_STATUSLINE_CACHE_TTL_SECONDS": "0",
                "PYTHONPATH": str(root),
                "PYTHONSTARTUP": str(root / "sitecustomize.py"),
                "BASH_ENV": str(root / "sitecustomize.py"),
                "ENV": str(root / "sitecustomize.py"),
            }
            with mock.patch.dict(os.environ, safe_env, clear=False):
                read_command = setup.read_hook_setting()["hooks"][0]["command"]
                rewrite_command = setup.bash_hook_setting()["hooks"][0]["command"]
                status_command = setup.statusline_setting()["command"]
                isolated_rewrite_prefix = setup._isolated_runtime_prefix(
                    setup.REWRITE_BEHAVIOR_ENV
                )

            for command, expected_names in (
                (
                    read_command,
                    (
                        "CONTEXT_GUARD_READ_GUARD",
                        "CONTEXT_GUARD_READ_GUARD_MAX_BYTES",
                        "CONTEXT_GUARD_READ_GUARD_MAX_LINES",
                        "CONTEXT_GUARD_READ_GUARD_PROOF_BYTES",
                    ),
                ),
                (rewrite_command, ("CONTEXT_GUARD_SANITIZER_FAIL_OPEN",)),
                (
                    status_command,
                    (
                        "CONTEXT_GUARD_STATUSLINE_INPUT_MAX_BYTES",
                        "CONTEXT_GUARD_STATUSLINE_CTX_WARN",
                        "CONTEXT_GUARD_STATUSLINE_CACHE_TTL_SECONDS",
                    ),
                ),
            ):
                argv = shlex.split(command)
                for name in expected_names:
                    self.assertTrue(any(value.startswith(name + "=") for value in argv), (name, argv))
                for denied in ("PYTHONPATH", "PYTHONSTARTUP", "BASH_ENV", "ENV"):
                    self.assertFalse(any(value.startswith(denied + "=") for value in argv), (denied, argv))

            read_proc = subprocess.run(
                read_command,
                shell=True,
                executable="/bin/sh",
                cwd=root,
                input=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_input": {"file_path": str(large)},
                    }
                ),
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(json.loads(read_proc.stdout), {})

            isolated_rewrite = root / "context-guard-rewrite-bash"
            isolated_rewrite.write_bytes(
                (KIT_DIR / "rewrite_bash_for_token_budget.py").read_bytes()
            )
            isolated_rewrite.chmod(0o700)
            fail_open_proc = subprocess.run(
                [
                    *isolated_rewrite_prefix,
                    str(Path(sys.executable).resolve()),
                    "-I",
                    str(isolated_rewrite),
                ],
                input=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_input": {"command": "rg token ."},
                    }
                ),
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            )
            self.assertEqual(json.loads(fail_open_proc.stdout), {})
            self.assertIn("CONTEXT_GUARD_SANITIZER_FAIL_OPEN=1 active", fail_open_proc.stderr)

            status_proc = subprocess.run(
                status_command,
                shell=True,
                executable="/bin/sh",
                cwd=root,
                input="{" + ("x" * 3000),
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            )
            self.assertIn("[input-too-large]", status_proc.stdout)
            self.assertFalse(loader_marker.exists())

    def test_setup_accepts_secure_homebrew_node_symlink_to_physical_cellar(self) -> None:
        setup = load_setup_module()
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp).resolve()
            home = root / "home"
            hud = home / ".claude" / "hud"
            hud.mkdir(parents=True)
            for directory in (home, home / ".claude", hud):
                directory.chmod(0o700)
            omc = hud / "omc-hud.mjs"
            omc.write_text("// secure OMC fixture\n", encoding="utf-8")
            omc.chmod(0o600)

            prefix = root / "opt" / "homebrew"
            cellar_bin = prefix / "Cellar" / "node" / "24.0.0" / "bin"
            cellar_bin.mkdir(parents=True)
            for directory in (
                root / "opt",
                prefix,
                prefix / "Cellar",
                prefix / "Cellar" / "node",
                prefix / "Cellar" / "node" / "24.0.0",
                cellar_bin,
            ):
                directory.chmod(0o700)
            physical_node = cellar_bin / "node"
            write_executable(physical_node, "cat >/dev/null\n")
            physical_node.chmod(0o700)
            homebrew_bin = prefix / "bin"
            homebrew_bin.mkdir()
            homebrew_bin.chmod(0o700)
            node_link = homebrew_bin / "node"
            node_link.symlink_to(physical_node)

            real_which = setup.shutil.which

            def no_system_node(name: str, *args, **kwargs):
                if name == "node":
                    return None
                return real_which(name, *args, **kwargs)

            with (
                mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(home))),
                mock.patch.object(setup.shutil, "which", side_effect=no_system_node),
                mock.patch.object(
                    setup,
                    "HOMEBREW_NODE_CANDIDATES",
                    (node_link,),
                    create=True,
                ),
            ):
                setting = setup.statusline_setting()
            argv = shlex.split(setting["command"])
            self.assertIn("--approved-node", argv)
            self.assertIn("--approved-omc-script", argv)
            self.assertEqual(argv[argv.index("--approved-node") + 1], str(physical_node))
            self.assertEqual(argv[argv.index("--approved-omc-script") + 1], str(omc))
            self.assertIn(f"HOME={home}", argv)

            (prefix / "Cellar" / "node" / "24.0.0").chmod(0o770)
            with (
                mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(home))),
                mock.patch.object(setup.shutil, "which", side_effect=no_system_node),
                mock.patch.object(
                    setup,
                    "HOMEBREW_NODE_CANDIDATES",
                    (node_link,),
                ),
            ):
                writable_parent_setting = setup.statusline_setting()
            writable_parent_argv = shlex.split(writable_parent_setting["command"])
            self.assertNotIn("--approved-node", writable_parent_argv)
            self.assertNotIn("--approved-omc-script", writable_parent_argv)

    def test_setup_approves_only_secure_default_passwd_home_omc(self) -> None:
        setup = load_setup_module()
        choices = setup.Choices(
            denies=False,
            statusline=True,
            bash_hook=False,
            read_guard=False,
            model_defaults=False,
            failed_attempt_nudge=False,
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp).resolve()
            home = root / "passwd-home"
            hud_dir = home / ".claude" / "hud"
            hud_dir.mkdir(parents=True)
            for path in (home, home / ".claude", hud_dir):
                path.chmod(0o700)
            omc = hud_dir / "omc-hud.mjs"
            omc.write_text("// approved setup fixture\n", encoding="utf-8")
            omc.chmod(0o600)
            node = root / "node"
            write_executable(node, "cat >/dev/null\nprintf '[approved-omc]\\n'\n")
            node.chmod(0o700)
            hostile_home = root / "ambient-home"
            hostile_home.mkdir()

            real_which = setup.shutil.which

            def fixed_which(name: str, *args, **kwargs):
                if name == "node":
                    return str(node)
                return real_which(name, *args, **kwargs)

            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(home)),
                ),
                mock.patch.object(setup.shutil, "which", side_effect=fixed_which),
                mock.patch.dict(os.environ, {"HOME": str(hostile_home)}),
            ):
                settings: dict[str, object] = {}
                actions = setup.apply_choices(settings, choices)
            command = settings["statusLine"]["command"]  # type: ignore[index]
            argv = shlex.split(command)
            self.assertIn("--approved-node", argv)
            self.assertEqual(argv[argv.index("--approved-node") + 1], str(node))
            self.assertEqual(argv[argv.index("--approved-omc-script") + 1], str(omc))
            self.assertNotIn(str(hostile_home), command)
            self.assertIn("included setup-approved OMC HUD", actions)

            hud_dir.chmod(0o777)
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(home)),
                ),
                mock.patch.object(setup.shutil, "which", side_effect=fixed_which),
            ):
                insecure_setting = setup.statusline_setting()
            insecure_argv = shlex.split(insecure_setting["command"])
            self.assertNotIn("--approved-node", insecure_argv)
            self.assertNotIn("--approved-omc-script", insecure_argv)

            hud_dir.chmod(0o700)
            omc.unlink()
            real_omc = root / "real-omc-hud.mjs"
            real_omc.write_text("// symlink target must not be approved\n", encoding="utf-8")
            real_omc.chmod(0o600)
            omc.symlink_to(real_omc)
            with (
                mock.patch(
                    "pwd.getpwuid",
                    return_value=SimpleNamespace(pw_dir=str(home)),
                ),
                mock.patch.object(setup.shutil, "which", side_effect=fixed_which),
            ):
                symlink_setting = setup.statusline_setting()
            symlink_argv = shlex.split(symlink_setting["command"])
            self.assertNotIn("--approved-node", symlink_argv)
            self.assertNotIn("--approved-omc-script", symlink_argv)

    def test_direct_statusline_uses_isolated_absolute_python(self) -> None:
        payload = json.dumps(
            {
                "model": {"display_name": "Sonnet"},
                "workspace": {"current_dir": str(ROOT)},
                "context_window": {"used_percentage": 12},
                "cost": {"total_cost_usd": 0.001},
            }
        )
        for script in (KIT_DIR / "statusline.sh", PLUGIN_BIN / "context-guard-statusline"):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                env, markers = self._hostile_environment(Path(tmp))
                # An already-started Bash reads BASH_ENV before this script's
                # first instruction. The installed automatic command owns that
                # outer boundary and is covered by the env-isolation test.
                env.pop("BASH_ENV", None)
                env.pop("ENV", None)
                proc = subprocess.run(
                    [
                        "/bin/bash",
                        "--noprofile",
                        "--norc",
                        str(script),
                        "--approved-python",
                        str(Path(sys.executable).resolve()),
                    ],
                    cwd=ROOT,
                    input=payload,
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=10,
                    check=True,
                )
                self.assertIn("ctx 12%", proc.stdout)
                executed = sorted(name for name, marker in markers.items() if marker.exists())
                self.assertEqual(executed, [], f"hostile runtime executed: {executed}")

    def test_merged_statusline_ignores_ambient_executable_overrides_and_home_hud(self) -> None:
        payload = json.dumps(
            {
                "model": {"display_name": "Sonnet"},
                "workspace": {"current_dir": str(ROOT)},
                "context_window": {"used_percentage": 12},
                "cost": {"total_cost_usd": 0.001},
            }
        )
        for script in (
            KIT_DIR / "statusline_merged.sh",
            PLUGIN_BIN / "context-guard-statusline-merged",
        ):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                env, markers = self._hostile_environment(root)
                env.pop("BASH_ENV", None)
                env.pop("ENV", None)
                hostile_omc = root / "hostile-omc.mjs"
                hostile_omc.write_text("// must not execute\n", encoding="utf-8")
                hostile_statusline = root / "hostile-statusline"
                write_executable(
                    hostile_statusline,
                    f"touch {shlex.quote(str(markers['statusline_override']))}\n"
                    "cat >/dev/null\n"
                    "printf 'hostile statusline\\n'\n",
                )
                env.update(
                    {
                        "OMC_HUD_SCRIPT": str(hostile_omc),
                        "CONTEXT_GUARD_STATUSLINE_BIN": str(hostile_statusline),
                        "CLAUDE_TOKEN_STATUSLINE_BIN": str(hostile_statusline),
                    }
                )
                proc = subprocess.run(
                    [
                        "/bin/bash",
                        "--noprofile",
                        "--norc",
                        str(script),
                        "--approved-python",
                        str(Path(sys.executable).resolve()),
                    ],
                    cwd=ROOT,
                    input=payload,
                    text=True,
                    capture_output=True,
                    env=env,
                    timeout=10,
                    check=True,
                )
                self.assertIn("ctx 12%", proc.stdout)
                self.assertNotIn("hostile", proc.stdout)
                executed = sorted(name for name, marker in markers.items() if marker.exists())
                self.assertEqual(executed, [], f"hostile runtime executed: {executed}")

    def test_rewrite_emits_isolated_absolute_python_and_shell_for_wrappers(self) -> None:
        proc = subprocess.run(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                str(KIT_DIR / "rewrite_bash_for_token_budget.py"),
            ],
            cwd=ROOT,
            input=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_input": {"command": "rg -n token README.md"},
                }
            ),
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        updated = json.loads(proc.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
        argv = shlex.split(updated)
        expected_python = str(Path(sys.executable).resolve())
        expected_bash_raw = shutil.which("bash", path=os.defpath)
        self.assertIsNotNone(expected_bash_raw)
        expected_bash = str(Path(expected_bash_raw or "").resolve())
        expected_env_raw = shutil.which("env", path=os.defpath)
        self.assertIsNotNone(expected_env_raw)
        expected_env = str(Path(expected_env_raw or "").resolve())
        self.assertEqual(argv[:2], [expected_python, "-I"])
        self.assertTrue(Path(argv[2]).is_absolute(), argv)
        separator = argv.index("--")
        expected_shell = [
            expected_env,
            "-u", "BASH_ENV",
            "-u", "ENV",
            "-u", "PYTHONHOME",
            "-u", "PYTHONPATH",
            "-u", "PYTHONSTARTUP",
            "-u", "SHELLOPTS",
            "-u", "BASHOPTS",
            "-u", "PS4",
            expected_bash,
            "--noprofile",
            "--norc",
            "-p",
            "-c",
        ]
        self.assertEqual(
            argv[separator + 1 : separator + 1 + len(expected_shell)],
            expected_shell,
        )

    def test_rewritten_wrapper_neutralizes_shell_startup_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env, markers = self._hostile_environment(root)
            rewrite = subprocess.run(
                [
                    str(Path(sys.executable).resolve()),
                    "-I",
                    str(KIT_DIR / "rewrite_bash_for_token_budget.py"),
                ],
                cwd=ROOT,
                input=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_input": {"command": "git diff --stat"},
                    }
                ),
                text=True,
                capture_output=True,
                timeout=10,
                check=True,
            )
            updated = json.loads(rewrite.stdout)["hookSpecificOutput"]["updatedInput"]["command"]
            proc = subprocess.run(
                shlex.split(updated),
                cwd=ROOT,
                text=True,
                capture_output=True,
                env=env,
                timeout=20,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            executed = sorted(name for name, marker in markers.items() if marker.exists())
            self.assertEqual(executed, [], f"hostile runtime executed: {executed}")

            bash_index = next(
                index
                for index, value in enumerate(shlex.split(updated))
                if value.endswith("/bash")
            )
            wrong_shell = shlex.split(updated)
            wrong_shell[bash_index] = "/bin/sh"
            rejected = subprocess.run(
                wrong_shell,
                cwd=ROOT,
                text=True,
                capture_output=True,
                env={key: value for key, value in env.items() if key not in {"BASH_ENV", "ENV"}},
                timeout=20,
                check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("invalid context-guard wrapper v1 shape", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
