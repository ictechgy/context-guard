#!/usr/bin/env python3
"""Generate the setup capability matrix and CLI flag reference."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "context-guard-kit" / "setup_wizard.py"
OUTPUT = ROOT / "docs" / "setup-reference.md"


def load_setup() -> Any:
    name = "context_guard_setup_reference_generator"
    spec = importlib.util.spec_from_file_location(name, SETUP)
    if spec is None or spec.loader is None:
        raise RuntimeError("setup module loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def cell(value: object) -> str:
    text = str(value).replace("|", "\\|").replace("\n", " ").strip()
    return text or "—"


def marker(enabled: bool, detail: str = "yes") -> str:
    return detail if enabled else "—"


def agent_rows(setup: Any) -> list[str]:
    rows: list[str] = []
    for adapter in setup.adapter_registry_payload():
        capabilities = set(adapter["capabilities"])
        key = adapter["key"]
        if key == "generic":
            project = "shell only"
        elif capabilities & {"native-hooks", "repo-rule", "project-skill", "project-mcp"}:
            project = "verified"
        else:
            project = "report-only"
        user = "verified write" if key == "claude" else "report-only"
        rows.append(
            "| "
            + " | ".join(
                (
                    f"`{cell(key)}`",
                    cell(adapter["display_name"]),
                    project,
                    user,
                    marker("repo-rule" in capabilities),
                    marker(bool(capabilities & {"project-skill", "native-skill"})),
                    marker("project-mcp" in capabilities),
                    marker("native-hooks" in capabilities),
                    cell(adapter["summary"]),
                )
            )
            + " |"
        )
    return rows


def default_text(action: argparse.Action) -> str:
    if action.default is argparse.SUPPRESS:
        return "suppressed"
    if action.default is None:
        return "—"
    if action.default is True:
        return "true"
    if action.default is False:
        return "false"
    return f"`{cell(action.default)}`"


def choice_text(action: argparse.Action) -> str:
    if action.choices is None:
        return "—"
    return ", ".join(f"`{cell(choice)}`" for choice in action.choices)


def flag_rows(setup: Any) -> list[str]:
    parser = setup.build_parser()
    rows: list[str] = []
    for action in parser._actions:
        if not action.option_strings or "--help" in action.option_strings:
            continue
        flags = ", ".join(f"`{flag}`" for flag in action.option_strings)
        rows.append(
            "| "
            + " | ".join(
                (
                    flags,
                    default_text(action),
                    choice_text(action),
                    cell(action.help),
                )
            )
            + " |"
        )
    return rows


def render() -> str:
    setup = load_setup()
    lines = [
        "# ContextGuard setup reference",
        "",
        "This file is generated from `context-guard-kit/setup_wizard.py`. Do not edit it manually.",
        "Regenerate it with `python3 scripts/generate_setup_reference.py --write` and verify it with `--check`.",
        "",
        "## Agent capability matrix",
        "",
        "`verified` means ContextGuard has a bounded project write path. `report-only` means setup reports guidance and does not claim a verified write target.",
        "Only Claude Code currently has a verified user-scope write path; every user-scope write requires explicit agent selection and `--yes`.",
        "",
        "| Key | Agent | Project scope | User scope | Rules | Skill | MCP | Hooks | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        *agent_rows(setup),
        "",
        "## Setup flags",
        "",
        "`--plan` and `--dry-run` are read-only. Writes require `--yes`; user scope additionally requires explicit `--agent` or `--only` selection.",
        "",
        "| Flag | Default | Choices | Description |",
        "| --- | --- | --- | --- |",
        *flag_rows(setup),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    expected = render().encode("utf-8")
    if arguments.write:
        OUTPUT.write_bytes(expected)
        print(f"setup reference generated: {OUTPUT.relative_to(ROOT)}")
        return 0
    try:
        observed = OUTPUT.read_bytes()
    except OSError:
        print("setup reference is missing", file=sys.stderr)
        return 1
    if observed != expected:
        print("setup reference is stale; run generate_setup_reference.py --write", file=sys.stderr)
        return 1
    print("setup reference: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
