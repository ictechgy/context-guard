#!/usr/bin/env python3
"""Dependency-free smoke gate for the packaged Claude token optimizer plugin."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, NoReturn


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_BIN = ROOT / "plugins" / "claude-token-optimizer" / "bin"
REQUIRED_COMMANDS = (
    "claude-token-setup",
    "claude-token-diet",
    "claude-token-audit",
    "claude-token-delegate",
)
ENTRYPOINT_SMOKE_COMMANDS = {
    "claude-read-symbol": ["--help"],
    "claude-sanitize-output": ["--help"],
    "claude-token-audit": ["--help"],
    "claude-token-bench": ["--help"],
    "claude-token-delegate": ["--help"],
    "claude-token-diet": ["--help"],
    "claude-token-failed-nudge": [],
    "claude-token-guard-read": [],
    "claude-token-rewrite-bash": [],
    "claude-token-setup": ["--help"],
    "claude-token-statusline": [],
    "claude-token-statusline-merged": [],
    "claude-trim-output": ["--help"],
}
HOOK_STDIN_COMMANDS = {
    "claude-token-failed-nudge",
    "claude-token-guard-read",
    "claude-token-rewrite-bash",
    "claude-token-statusline-merged",
}
PRESERVED_ENV_KEYS = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release smoke failed: {message}")


def load_json(stdout: str, command: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        fail(f"{command} did not emit valid JSON: line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        fail(f"{command} JSON output must be an object")
    return data


def command_path(plugin_bin: Path, name: str) -> Path:
    path = plugin_bin / name
    if not path.is_file():
        fail(f"missing plugin entrypoint: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & stat.S_IXUSR == 0:
        fail(f"plugin entrypoint is not owner-executable: {path} mode={oct(mode)}")
    return path


def entrypoint_smoke_plan(plugin_bin: Path) -> dict[str, list[str]]:
    files = {path.name for path in plugin_bin.iterdir() if path.is_file()}
    missing = sorted(files - set(ENTRYPOINT_SMOKE_COMMANDS))
    if missing:
        fail(f"release smoke has no launch plan for plugin entrypoints: {', '.join(missing)}")
    return {name: ENTRYPOINT_SMOKE_COMMANDS[name] for name in sorted(files)}


def smoke_environment(home: Path, tmp: Path) -> dict[str, str]:
    env = {key: value for key in PRESERVED_ENV_KEYS if (value := os.environ.get(key))}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "TMPDIR": str(tmp),
            "TEMP": str(tmp),
            "TMP": str(tmp),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def parse_key_value_lines(stdout: str) -> dict[str, str]:
    items: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            items[key.strip()] = value.strip()
    return items


def assert_path_under(raw_path: str | None, parent: Path, label: str) -> None:
    if not raw_path:
        fail(f"{label} missing from command output")
    raw = Path(raw_path).expanduser()
    if not raw.is_absolute():
        raw = parent / raw
    try:
        path = raw.resolve()
        root = parent.resolve()
    except OSError as exc:
        fail(f"{label} could not be resolved: {exc}")
    if path != root and root not in path.parents:
        fail(f"{label} escaped smoke project: {path}")


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    expect: Callable[[subprocess.CompletedProcess[str]], None],
    input_text: str | None = None,
) -> None:
    stdin = subprocess.DEVNULL if input_text is None else None
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            stdin=stdin,
            input=input_text,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        fail(f"{Path(argv[0]).name} timed out after {timeout:g}s")
    except OSError as exc:
        fail(f"{Path(argv[0]).name} could not be launched: {exc}")
    if proc.returncode != 0:
        fail(
            f"{Path(argv[0]).name} exited {proc.returncode}: "
            f"{(proc.stderr or proc.stdout).strip()[:500]}"
        )
    expect(proc)


def check_json_field(data: dict[str, Any], key: str, expected: Any, command: str) -> None:
    if data.get(key) != expected:
        fail(f"{command} JSON field {key!r} was {data.get(key)!r}, expected {expected!r}")


def run_smoke(plugin_bin: Path, timeout: float) -> None:
    plugin_bin = plugin_bin.resolve()
    commands = {name: command_path(plugin_bin, name) for name in REQUIRED_COMMANDS}
    launch_plan = entrypoint_smoke_plan(plugin_bin)

    with tempfile.TemporaryDirectory(prefix="claude-token-release-smoke-") as td:
        project = Path(td) / "project"
        smoke_home = Path(td) / "home"
        smoke_tmp = Path(td) / "tmp"
        project.mkdir()
        smoke_home.mkdir()
        smoke_tmp.mkdir()
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        (project / "CLAUDE.md").write_text("Keep project context short.\n", encoding="utf-8")
        env = smoke_environment(smoke_home, smoke_tmp)

        run_command(
            [str(commands["claude-token-setup"]), "--root", str(project), "--plan", "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-setup"), "applied", False, "claude-token-setup")
            ),
        )
        run_command(
            [str(commands["claude-token-diet"]), "scan", str(project), "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-diet"), "tool", "claude-token-diet", "claude-token-diet")
            ),
        )
        run_command(
            [str(commands["claude-token-audit"]), str(project), "--json"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-audit"), "records", 1, "claude-token-audit")
            ),
        )
        run_command(
            [str(commands["claude-token-delegate"]), "status"],
            cwd=project,
            env=env,
            timeout=timeout,
            expect=lambda proc: check_delegate_status(proc.stdout, project),
        )

        for name, args in launch_plan.items():
            run_command(
                [str(command_path(plugin_bin, name)), *args],
                cwd=project,
                env=env,
                timeout=timeout,
                input_text="{}" if name in HOOK_STDIN_COMMANDS else None,
                expect=lambda proc, command=name: check_launch_smoke(proc, command),
            )


def check_delegate_status(stdout: str, project: Path) -> None:
    fields = parse_key_value_lines(stdout)
    if "aux_ai_enabled" not in fields:
        fail("claude-token-delegate status missing aux_ai_enabled")
    assert_path_under(fields.get("project_root"), project, "claude-token-delegate project_root")
    assert_path_under(fields.get("config_path"), project, "claude-token-delegate config_path")


def check_launch_smoke(proc: subprocess.CompletedProcess[str], command: str) -> None:
    if not proc.stdout.strip():
        fail(f"{command} launch smoke emitted no stdout")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin-bin", type=Path, default=PLUGIN_BIN)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    if args.timeout <= 0:
        fail("--timeout must be positive")
    run_smoke(args.plugin_bin, args.timeout)
    print("release smoke: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
