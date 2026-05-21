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
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_BIN = ROOT / "plugins" / "claude-token-optimizer" / "bin"
REQUIRED_COMMANDS = (
    "claude-token-setup",
    "claude-token-diet",
    "claude-token-audit",
    "claude-token-delegate",
)


def fail(message: str) -> None:
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


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float,
    expect: Callable[[subprocess.CompletedProcess[str]], None],
) -> None:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        fail(f"{Path(argv[0]).name} timed out after {timeout:g}s")
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

    with tempfile.TemporaryDirectory(prefix="claude-token-release-smoke-") as td:
        project = Path(td) / "project"
        project.mkdir()
        (project / ".claude").mkdir()
        (project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
        (project / "CLAUDE.md").write_text("Keep project context short.\n", encoding="utf-8")

        run_command(
            [str(commands["claude-token-setup"]), "--root", str(project), "--plan", "--json"],
            cwd=project,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-setup"), "applied", False, "claude-token-setup")
            ),
        )
        run_command(
            [str(commands["claude-token-diet"]), "scan", str(project), "--json"],
            cwd=project,
            timeout=timeout,
            expect=lambda proc: (
                check_json_field(load_json(proc.stdout, "claude-token-diet"), "tool", "claude-token-diet", "claude-token-diet")
            ),
        )
        run_command(
            [str(commands["claude-token-audit"]), str(project), "--json"],
            cwd=project,
            timeout=timeout,
            expect=lambda proc: load_json(proc.stdout, "claude-token-audit"),
        )
        run_command(
            [str(commands["claude-token-delegate"]), "status"],
            cwd=project,
            timeout=timeout,
            expect=lambda proc: (
                None
                if "aux_ai_enabled=" in proc.stdout and "config_path=" in proc.stdout
                else fail("claude-token-delegate status missing expected fields")
            ),
        )


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
