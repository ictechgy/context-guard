#!/usr/bin/env python3
"""Canonical ContextGuard command dispatcher.

The npm/Homebrew-friendly ``context-guard`` command is intentionally passive:
installation only exposes commands on PATH. Any project or user configuration is
performed later through explicit subcommands such as ``context-guard setup``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import NoReturn

COMMAND_NAME = "context-guard"
PACKAGE_NAME = "@ictechgy/context-guard"

HELPER_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    "setup": ("context-guard-setup",),
    "audit": ("context-guard-audit",),
    "diet": ("context-guard-diet",),
    "scan": ("context-guard-diet", "scan"),
    "trim-output": ("context-guard-trim-output",),
    "trim": ("context-guard-trim-output",),
    "sanitize-output": ("context-guard-sanitize-output",),
    "sanitize": ("context-guard-sanitize-output",),
    "artifact": ("context-guard-artifact",),
    "pack": ("context-guard-pack",),
    "tool-prune": ("context-guard-tool-prune",),
    "compress": ("context-guard-compress",),
    "bench": ("context-guard-bench",),
    "read-symbol": ("context-guard-read-symbol",),
    "rewrite-bash": ("context-guard-rewrite-bash",),
    "guard-read": ("context-guard-guard-read",),
    "failed-nudge": ("context-guard-failed-nudge",),
    "statusline": ("context-guard-statusline",),
    "statusline-merged": ("context-guard-statusline-merged",),
}


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def _candidate_roots() -> list[Path]:
    script_dir = _script_dir()
    roots = [script_dir.parent, script_dir.parent.parent, Path.cwd()]
    # When run from context-guard-kit in a checkout, the repo root is one level up.
    if script_dir.name == "context-guard-kit":
        roots.insert(0, script_dir.parent)
    return list(dict.fromkeys(roots))


def _load_json(path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def project_version() -> str:
    candidates: list[Path] = []
    for root in _candidate_roots():
        candidates.extend(
            [
                root / ".claude-plugin" / "plugin.json",
                root / "plugins" / "context-guard" / ".claude-plugin" / "plugin.json",
                root / "package.json",
            ]
        )
    for candidate in candidates:
        data = _load_json(candidate)
        version = data.get("version") if data else None
        if isinstance(version, str) and version.strip():
            return version.strip()
    return "0.0.0+unknown"


def print_help() -> None:
    version = project_version()
    commands = "\n".join(f"  {name}" for name in sorted(HELPER_SUBCOMMANDS))
    sys.stdout.write(
        f"ContextGuard {version}\n"
        f"\n"
        f"Usage:\n"
        f"  {COMMAND_NAME} --version\n"
        f"  {COMMAND_NAME} <subcommand> [args...]\n"
        f"\n"
        f"Install examples:\n"
        f"  npm install -g {PACKAGE_NAME}\n"
        f"  npx {PACKAGE_NAME} setup --agent codex --scope project --plan\n"
        f"\n"
        f"Common subcommands:\n"
        f"{commands}\n"
        f"\n"
        f"Run '{COMMAND_NAME} <subcommand> --help' for helper-specific options.\n"
        f"Installing ContextGuard never writes configuration; use 'setup' explicitly.\n"
    )


def helper_path(name: str) -> Path | None:
    script_dir = _script_dir()
    candidates = [
        script_dir / name,
        script_dir.parent / "plugins" / "context-guard" / "bin" / name,
        script_dir.parent.parent / "plugins" / "context-guard" / "bin" / name,
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def fail(message: str, code: int = 2) -> NoReturn:
    sys.stderr.write(f"{COMMAND_NAME}: {message}\n")
    raise SystemExit(code)


def run_helper(command: str, argv: list[str]) -> int:
    mapping = HELPER_SUBCOMMANDS[command]
    helper = helper_path(mapping[0])
    if helper is None:
        fail(
            f"could not find helper {mapping[0]!r}; reinstall {PACKAGE_NAME} "
            "or run from a complete ContextGuard checkout."
        )
    proc = subprocess.run([str(helper), *mapping[1:], *argv])
    return int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        print_help()
        return 0
    if args[0] in {"-V", "--version", "version"}:
        print(project_version())
        return 0
    command = args.pop(0).strip().lower()
    if command not in HELPER_SUBCOMMANDS:
        fail(f"unknown subcommand {command!r}. Run '{COMMAND_NAME} --help'.")
    return run_helper(command, args)


if __name__ == "__main__":
    raise SystemExit(main())
