#!/usr/bin/env python3
"""Repository-local release gate for the Claude token optimizer plugin.

The check is intentionally dependency-free so it can run in GitHub Actions and
from a maintainer shell before publishing the marketplace/plugin package.
"""
from __future__ import annotations

import argparse
import json
import os
import py_compile
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "claude-token-kit"
PLUGIN_DIR = ROOT / "plugins" / "claude-token-optimizer"
PLUGIN_BIN = PLUGIN_DIR / "bin"
PLUGIN_MANIFEST = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
MARKETPLACE_MANIFEST = ROOT / ".claude-plugin" / "marketplace.json"

IMPLEMENTATION_PAIRS = (
    ("aux_ai_delegate.py", "claude-token-delegate"),
    ("benchmark_runner.py", "claude-token-bench"),
    ("claude_transcript_cost_audit.py", "claude-token-audit"),
    ("claude_token_diet.py", "claude-token-diet"),
    ("failed_attempt_nudge.py", "claude-token-failed-nudge"),
    ("guard_large_read.py", "claude-token-guard-read"),
    ("read_symbol.py", "claude-read-symbol"),
    ("rewrite_bash_for_token_budget.py", "claude-token-rewrite-bash"),
    ("sanitize_output.py", "claude-sanitize-output"),
    ("setup_wizard.py", "claude-token-setup"),
    ("statusline.sh", "claude-token-statusline"),
    ("statusline_merged.sh", "claude-token-statusline-merged"),
    ("trim_command_output.py", "claude-trim-output"),
)

FORBIDDEN_PACKAGE_NAMES = {
    ".DS_Store",
}
FORBIDDEN_PACKAGE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
}
FORBIDDEN_PACKAGE_DIRS = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


def remove_python_cache_artifacts() -> None:
    for cache_dir in PLUGIN_DIR.rglob("__pycache__"):
        if cache_dir.is_dir():
            shutil.rmtree(cache_dir)
    for path in PLUGIN_DIR.rglob("*.py[co]"):
        if path.is_file():
            path.unlink()


def fail(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        fail(f"missing JSON manifest: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: line {exc.lineno}: {exc.msg}")
    if not isinstance(data, dict):
        fail(f"JSON manifest must be an object: {path}")
    return data


def iter_package_files() -> Iterable[Path]:
    for path in PLUGIN_DIR.rglob("*"):
        if path.is_file():
            yield path


def check_manifest() -> None:
    plugin = load_json(PLUGIN_MANIFEST)
    marketplace = load_json(MARKETPLACE_MANIFEST)

    for key in ("name", "description", "version", "license"):
        if not isinstance(plugin.get(key), str) or not plugin[key].strip():
            fail(f"plugin manifest missing non-empty string field: {key}")
    if plugin["name"] != "claude-token-optimizer":
        fail(f"unexpected plugin name: {plugin['name']}")
    if plugin["license"] != "Apache-2.0":
        fail(f"unexpected plugin license: {plugin['license']}")

    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        fail("marketplace manifest must contain at least one plugin")
    entry = next((item for item in plugins if isinstance(item, dict) and item.get("name") == plugin["name"]), None)
    if entry is None:
        fail("marketplace manifest does not list claude-token-optimizer")
    if entry.get("source") != "./plugins/claude-token-optimizer":
        fail(f"unexpected marketplace source: {entry.get('source')!r}")
    if entry.get("version") != plugin["version"]:
        fail(f"marketplace/plugin version mismatch: {entry.get('version')} != {plugin['version']}")
    if entry.get("license") != plugin["license"]:
        fail(f"marketplace/plugin license mismatch: {entry.get('license')} != {plugin['license']}")


def check_bin_copies() -> None:
    for kit_name, bin_name in IMPLEMENTATION_PAIRS:
        kit = KIT_DIR / kit_name
        plugin_bin = PLUGIN_BIN / bin_name
        if not kit.exists():
            fail(f"missing kit source: {kit}")
        if not plugin_bin.exists():
            fail(f"missing plugin bin copy: {plugin_bin}")
        if kit.read_bytes() != plugin_bin.read_bytes():
            fail(f"plugin bin is not synchronized with source: {plugin_bin} != {kit}")
        mode = stat.S_IMODE(plugin_bin.stat().st_mode)
        if mode & stat.S_IXUSR == 0:
            fail(f"plugin bin is not owner-executable: {plugin_bin} mode={oct(mode)}")


def check_package_clean() -> None:
    for path in iter_package_files():
        rel = path.relative_to(PLUGIN_DIR)
        if path.name in FORBIDDEN_PACKAGE_NAMES:
            fail(f"forbidden package artifact: {rel}")
        if path.suffix in FORBIDDEN_PACKAGE_SUFFIXES:
            fail(f"forbidden package artifact: {rel}")
        if any(part in FORBIDDEN_PACKAGE_DIRS for part in rel.parts):
            fail(f"forbidden package cache artifact: {rel}")


def check_python_compiles() -> None:
    # Shell wrappers are skipped by py_compile. Compile to a private temp
    # directory so a release gate does not dirty the source tree with
    # __pycache__ artifacts before packaging.
    with tempfile.TemporaryDirectory(prefix="claude-token-prepublish-pyc-") as td:
        pyc_dir = Path(td)
        for kit_name, _bin_name in IMPLEMENTATION_PAIRS:
            path = KIT_DIR / kit_name
            if path.suffix != ".py":
                continue
            try:
                py_compile.compile(str(path), cfile=str(pyc_dir / f"{path.stem}.pyc"), doraise=True)
            except py_compile.PyCompileError as exc:
                fail(f"python compile failed for {path}: {exc.msg}")


def run_tests() -> None:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_claude_token_kit.py")],
        cwd=ROOT,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        fail(f"test suite failed with exit code {proc.returncode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-tests", action="store_true", help="check package invariants without running unit tests")
    args = parser.parse_args()

    check_manifest()
    check_bin_copies()
    remove_python_cache_artifacts()
    check_package_clean()
    check_python_compiles()
    if not args.skip_tests:
        run_tests()
        check_package_clean()
    print("prepublish check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
