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
ENTRYPOINT_SMOKE_COMMANDS: dict[str, dict[str, Any]] = {
    "claude-read-symbol": {"args": ["--help"], "mode": "text"},
    "claude-sanitize-output": {"args": ["--help"], "mode": "text"},
    "claude-token-audit": {"args": ["--help"], "mode": "text"},
    "claude-token-bench": {"args": ["--help"], "mode": "text"},
    "claude-token-delegate": {"args": ["--help"], "mode": "text"},
    "claude-token-diet": {"args": ["--help"], "mode": "text"},
    "claude-token-failed-nudge": {"args": [], "mode": "hook-json"},
    "claude-token-guard-read": {"args": [], "mode": "hook-json"},
    "claude-token-rewrite-bash": {"args": [], "mode": "hook-json"},
    "claude-token-setup": {"args": ["--help"], "mode": "text"},
    "claude-token-statusline": {"args": [], "mode": "statusline"},
    "claude-token-statusline-merged": {"args": [], "mode": "statusline"},
    "claude-trim-output": {"args": ["--help"], "mode": "text"},
}
HOOK_STDIN = "{}"
STATUSLINE_STDIN = json.dumps({"cwd": ".", "session_id": "release-smoke", "transcript_path": ""})
STATUSLINE_MAX_CHARS = 1_000
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


def entrypoint_smoke_plan(plugin_bin: Path) -> dict[str, dict[str, Any]]:
    files = {path.name for path in plugin_bin.iterdir() if path.is_file()}
    unexpected = sorted(files - set(ENTRYPOINT_SMOKE_COMMANDS))
    if unexpected:
        fail(f"release smoke has no launch plan for plugin entrypoints: {', '.join(unexpected)}")
    missing = sorted(set(ENTRYPOINT_SMOKE_COMMANDS) - files)
    if missing:
        fail(f"release smoke planned entrypoints are missing from plugin bin: {', '.join(missing)}")
    return {name: ENTRYPOINT_SMOKE_COMMANDS[name] for name in sorted(ENTRYPOINT_SMOKE_COMMANDS)}


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

        for name, plan in launch_plan.items():
            mode = str(plan["mode"])
            run_command(
                [str(command_path(plugin_bin, name)), *plan["args"]],
                cwd=project,
                env=env,
                timeout=timeout,
                input_text=launch_stdin(mode),
                expect=lambda proc, command=name, launch_mode=mode: check_launch_smoke(proc, command, launch_mode),
            )


def check_delegate_status(stdout: str, project: Path) -> None:
    fields = parse_key_value_lines(stdout)
    if "aux_ai_enabled" not in fields:
        fail("claude-token-delegate status missing aux_ai_enabled")
    assert_path_under(fields.get("project_root"), project, "claude-token-delegate project_root")
    assert_path_under(fields.get("config_path"), project, "claude-token-delegate config_path")


def launch_stdin(mode: str) -> str | None:
    if mode == "hook-json":
        return HOOK_STDIN
    if mode == "statusline":
        return STATUSLINE_STDIN
    return None


def check_launch_smoke(proc: subprocess.CompletedProcess[str], command: str, mode: str) -> None:
    raw_stdout = proc.stdout
    if not raw_stdout.strip():
        fail(f"{command} launch smoke emitted no stdout")
    if mode == "hook-json":
        load_json(raw_stdout, command)
    elif mode == "statusline":
        line = raw_stdout[:-1] if raw_stdout.endswith("\n") else raw_stdout
        if "\n" in line or "\r" in line:
            fail(f"{command} statusline smoke emitted multiple lines")
        if len(line) > STATUSLINE_MAX_CHARS:
            fail(f"{command} statusline smoke exceeded {STATUSLINE_MAX_CHARS} characters")


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
