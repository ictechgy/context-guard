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
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT_DIR = ROOT / "claude-token-kit"
PLUGIN_DIR = ROOT / "plugins" / "claude-token-optimizer"
PLUGIN_BIN = PLUGIN_DIR / "bin"
PLUGIN_MANIFEST = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
MARKETPLACE_MANIFEST = ROOT / ".claude-plugin" / "marketplace.json"
SKILLS_DIR = PLUGIN_DIR / "skills"
PATH_OVERRIDE_FLAG = "CLAUDE_TOKEN_PREPUBLISH_ALLOW_PATH_OVERRIDES"
PATH_OVERRIDE_ENVS = (
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_DIR",
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_BIN",
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_MANIFEST",
    "CLAUDE_TOKEN_PREPUBLISH_MARKETPLACE_MANIFEST",
    "CLAUDE_TOKEN_PREPUBLISH_SKILLS_DIR",
)
BASH_ALLOWED_TOOL_RE = re.compile(r"Bash\(([^\s)]+)")
PLUGIN_HELPER_COMMAND_RE = re.compile(r"^(?:claude-token-|claude-(?:read-symbol|trim-output|sanitize-output)$)")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)[^/\s@]+@", re.IGNORECASE)
SENSITIVE_LABEL_RE = re.compile(
    r"(?i)("
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{12,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"sk-(?:ant|proj)-[A-Za-z0-9_-]{12,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*[:=]\s*[^/\s]+"
    r")"
)
PATH_LABEL_MAX_CHARS = 160

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
HELPER_PAIRS = (
    ("hook_secret_patterns.py", "lib/hook_secret_patterns.py"),
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


def remove_generated_plugin_bin_python_caches() -> None:
    # Tests and reviewer diagnostics may import/compile suffix-less Python bin
    # entrypoints and leave import bytecode under bin/__pycache__. Keep cleanup
    # scoped to that generated cache location; unrelated package artifacts still
    # fail check_package_clean().
    for cache_dir in (PLUGIN_BIN / "__pycache__", PLUGIN_DIR / "lib" / "__pycache__"):
        if cache_dir.is_dir():
            shutil.rmtree(cache_dir, ignore_errors=True)
    for generated_dir in (PLUGIN_BIN, PLUGIN_DIR / "lib"):
        for suffix in ("*.pyc", "*.pyo"):
            for path in list(generated_dir.glob(suffix)):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass


def fail(message: str) -> None:
    raise SystemExit(message)


def compact_label_text(value: str, limit: int = PATH_LABEL_MAX_CHARS) -> str:
    compact = " ".join(CONTROL_CHAR_RE.sub(" ", value.strip()).split())
    compact = URL_USERINFO_RE.sub(r"\1[REDACTED]@", compact)
    compact = SENSITIVE_LABEL_RE.sub("[REDACTED]", compact)
    if len(compact) > limit:
        compact = compact[: limit - 15].rstrip() + " ...[truncated]"
    return compact


def label_has_sensitive_evidence(value: str) -> bool:
    return bool(CONTROL_CHAR_RE.search(value) or URL_USERINFO_RE.search(value) or SENSITIVE_LABEL_RE.search(value))


def safe_path_label(path: Path, *, base: Path | None = None) -> str:
    raw = str(path)
    if label_has_sensitive_evidence(raw):
        return "redacted-path"
    candidates: list[str] = []
    if base is not None:
        try:
            candidates.append(str(path.relative_to(base)))
        except ValueError:
            pass
    for root in (PLUGIN_DIR, ROOT):
        try:
            candidates.append(str(path.relative_to(root)))
        except ValueError:
            pass
    if path.is_absolute():
        candidates.append(path.name or "path")
    candidates.append(raw)
    for candidate in candidates:
        label = compact_label_text(candidate)
        if label and label != ".":
            return label
    return "path"


def path_overrides_allowed() -> bool:
    return os.environ.get(PATH_OVERRIDE_FLAG, "").strip().lower() in {"1", "true", "yes", "on"}


def apply_path_overrides() -> None:
    """Apply test-only path overrides after requiring an explicit guard flag."""
    global PLUGIN_DIR, PLUGIN_BIN, PLUGIN_MANIFEST, MARKETPLACE_MANIFEST, SKILLS_DIR

    requested = [name for name in PATH_OVERRIDE_ENVS if name in os.environ]
    if requested and not path_overrides_allowed():
        fail(f"prepublish path overrides require {PATH_OVERRIDE_FLAG}=1: {', '.join(sorted(requested))}")

    if "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_DIR" in os.environ:
        PLUGIN_DIR = Path(os.environ["CLAUDE_TOKEN_PREPUBLISH_PLUGIN_DIR"])
    PLUGIN_BIN = Path(os.environ.get("CLAUDE_TOKEN_PREPUBLISH_PLUGIN_BIN", PLUGIN_DIR / "bin"))
    PLUGIN_MANIFEST = Path(
        os.environ.get("CLAUDE_TOKEN_PREPUBLISH_PLUGIN_MANIFEST", PLUGIN_DIR / ".claude-plugin" / "plugin.json")
    )
    MARKETPLACE_MANIFEST = Path(
        os.environ.get("CLAUDE_TOKEN_PREPUBLISH_MARKETPLACE_MANIFEST", ROOT / ".claude-plugin" / "marketplace.json")
    )
    SKILLS_DIR = Path(os.environ.get("CLAUDE_TOKEN_PREPUBLISH_SKILLS_DIR", PLUGIN_DIR / "skills"))


def lexical_absolute(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def first_symlink_component(path: Path) -> Path | None:
    """Return the first symlink component in a path without following symlinks."""
    current = Path(path.anchor) if path.is_absolute() else Path()
    depth = 0
    for part in path.parts:
        if path.is_absolute() and part == path.anchor:
            continue
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return None
        except OSError as exc:
            fail(
                "could not inspect release path component: "
                f"{safe_path_label(current)}: {compact_label_text(exc.strerror or exc.__class__.__name__, 80)}"
            )
        if stat.S_ISLNK(st.st_mode) and not (path.is_absolute() and depth == 0):
            return current
        depth += 1
    return None


def check_trusted_release_paths() -> None:
    """Reject symlinked release roots and manifests before reading package data."""
    for label, path in (
        ("plugin package directory", PLUGIN_DIR),
        ("plugin bin directory", PLUGIN_BIN),
        ("plugin skills directory", SKILLS_DIR),
        ("plugin manifest", PLUGIN_MANIFEST),
        ("marketplace manifest", MARKETPLACE_MANIFEST),
    ):
        symlink = first_symlink_component(lexical_absolute(path))
        if symlink is not None:
            fail(f"{label} must not be or traverse a symlink: {safe_path_label(symlink)}")


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        fail(f"missing JSON manifest: {safe_path_label(path)}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {safe_path_label(path)}: line {exc.lineno}: {compact_label_text(exc.msg, 80)}")
    if not isinstance(data, dict):
        fail(f"JSON manifest must be an object: {safe_path_label(path)}")
    return data


def skill_label(skill: Path) -> str:
    try:
        return safe_path_label(skill.relative_to(PLUGIN_DIR))
    except ValueError:
        return safe_path_label(skill, base=SKILLS_DIR)


def skill_frontmatter(text: str, skill: Path) -> str:
    """Return the YAML-ish skill metadata block without inspecting body examples."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        fail(f"skill metadata missing frontmatter: {skill_label(skill)}")
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            metadata = "\n".join(lines[1:index])
            if not re.search(r"(?m)^description:\s*\S", metadata):
                fail(f"skill metadata missing description: {skill_label(skill)}")
            return metadata
    fail(f"skill metadata missing closing frontmatter: {skill_label(skill)}")


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


def check_skill_allowed_tool_commands() -> None:
    if not SKILLS_DIR.is_dir():
        fail(f"missing plugin skills directory: {safe_path_label(SKILLS_DIR)}")
    if not PLUGIN_BIN.is_dir():
        fail(f"missing plugin bin directory: {safe_path_label(PLUGIN_BIN)}")
    available = {path.name for path in PLUGIN_BIN.iterdir() if path.is_file()}
    for skill in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        try:
            text = skill.read_text(encoding="utf-8")
        except OSError as exc:
            fail(f"could not read skill metadata: {skill_label(skill)}: {compact_label_text(str(exc), 120)}")
        for command in BASH_ALLOWED_TOOL_RE.findall(skill_frontmatter(text, skill)):
            if not PLUGIN_HELPER_COMMAND_RE.match(command):
                continue
            if command not in available:
                fail(f"skill allowed-tools references missing plugin bin command: {skill_label(skill)}: {command}")


def check_bin_copies() -> None:
    if not PLUGIN_BIN.is_dir():
        fail(f"missing plugin bin directory: {safe_path_label(PLUGIN_BIN)}")
    for kit_name, bin_name in IMPLEMENTATION_PAIRS:
        kit = KIT_DIR / kit_name
        plugin_bin = PLUGIN_BIN / bin_name
        if not kit.exists():
            fail(f"missing kit source: {safe_path_label(kit)}")
        if not plugin_bin.exists():
            fail(f"missing plugin bin copy: {safe_path_label(plugin_bin)}")
        if kit.read_bytes() != plugin_bin.read_bytes():
            fail(
                "plugin bin is not synchronized with source: "
                f"{safe_path_label(plugin_bin)} != {safe_path_label(kit)}"
            )
        mode = stat.S_IMODE(plugin_bin.stat().st_mode)
        if mode & stat.S_IXUSR == 0:
            fail(f"plugin bin is not owner-executable: {safe_path_label(plugin_bin)} mode={oct(mode)}")
    for kit_name, plugin_rel in HELPER_PAIRS:
        kit = KIT_DIR / kit_name
        plugin_helper = PLUGIN_DIR / plugin_rel
        if not kit.exists():
            fail(f"missing kit helper: {safe_path_label(kit)}")
        if not plugin_helper.exists():
            fail(f"missing plugin helper copy: {safe_path_label(plugin_helper)}")
        if kit.read_bytes() != plugin_helper.read_bytes():
            fail(
                "plugin helper is not synchronized with source: "
                f"{safe_path_label(plugin_helper)} != {safe_path_label(kit)}"
            )
        mode = stat.S_IMODE(plugin_helper.stat().st_mode)
        if mode & 0o111 != 0:
            fail(f"plugin helper must not be executable: {safe_path_label(plugin_helper)} mode={oct(mode)}")


def check_package_symlinks() -> None:
    for path in PLUGIN_DIR.rglob("*"):
        rel = path.relative_to(PLUGIN_DIR)
        if path.is_symlink():
            fail(f"forbidden package symlink: {safe_path_label(rel)}")


def check_package_clean() -> None:
    check_package_symlinks()
    for path in PLUGIN_DIR.rglob("*"):
        rel = path.relative_to(PLUGIN_DIR)
        if not path.is_file():
            continue
        if path.name in FORBIDDEN_PACKAGE_NAMES:
            fail(f"forbidden package artifact: {safe_path_label(rel)}")
        if path.suffix in FORBIDDEN_PACKAGE_SUFFIXES:
            fail(f"forbidden package artifact: {safe_path_label(rel)}")
        if any(part in FORBIDDEN_PACKAGE_DIRS for part in rel.parts):
            fail(f"forbidden package cache artifact: {safe_path_label(rel)}")


def shell_syntax_paths() -> list[Path]:
    paths: list[Path] = []
    for kit_name, bin_name in IMPLEMENTATION_PAIRS:
        kit = KIT_DIR / kit_name
        if kit.suffix == ".sh":
            paths.extend((kit, PLUGIN_BIN / bin_name))
    return paths


def shell_arg(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def shell_syntax_detail(path: Path, stdout: str, stderr: str) -> str:
    raw = stderr.strip() or stdout.strip() or "syntax error"
    label = safe_path_label(path)
    for value in {str(path), path.as_posix()}:
        if value:
            raw = raw.replace(value, label)
    return compact_label_text(raw, 200)


def check_shell_syntax() -> None:
    paths = shell_syntax_paths()
    if not paths:
        return
    bash = shutil.which("bash")
    if bash is None:
        fail("bash not found for shell syntax check")
    for path in paths:
        try:
            proc = subprocess.run(
                [bash, "-n", shell_arg(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            fail(f"shell syntax check timed out for {safe_path_label(path)}")
        if proc.returncode != 0:
            detail = shell_syntax_detail(path, proc.stdout, proc.stderr)
            fail(f"shell syntax failed for {safe_path_label(path)}: {detail}")


def check_python_compiles() -> None:
    # Shell wrappers are skipped by py_compile. Compile to a private temp
    # directory so a release gate does not dirty the source tree with
    # __pycache__ artifacts before packaging.
    with tempfile.TemporaryDirectory(prefix="claude-token-prepublish-pyc-") as td:
        pyc_dir = Path(td)
        for kit_name in [name for name, _bin_name in IMPLEMENTATION_PAIRS] + [name for name, _rel in HELPER_PAIRS]:
            path = KIT_DIR / kit_name
            if path.suffix != ".py":
                continue
            try:
                py_compile.compile(str(path), cfile=str(pyc_dir / f"{path.stem}.pyc"), doraise=True)
            except py_compile.PyCompileError as exc:
                fail(f"python compile failed for {safe_path_label(path)}: {compact_label_text(exc.msg, 160)}")


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

    apply_path_overrides()
    check_trusted_release_paths()
    check_package_symlinks()
    check_manifest()
    check_bin_copies()
    check_skill_allowed_tool_commands()
    remove_generated_plugin_bin_python_caches()
    check_package_clean()
    check_python_compiles()
    check_shell_syntax()
    if not args.skip_tests:
        run_tests()
        remove_generated_plugin_bin_python_caches()
        check_package_clean()
    print("prepublish check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
