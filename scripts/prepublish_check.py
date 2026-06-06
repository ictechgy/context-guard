#!/usr/bin/env python3
"""Repository-local release gate for the ContextGuard plugin.

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
KIT_DIR = ROOT / "context-guard-kit"
PLUGIN_DIR = ROOT / "plugins" / "context-guard"
PLUGIN_BIN = PLUGIN_DIR / "bin"
PLUGIN_MANIFEST = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
MARKETPLACE_MANIFEST = ROOT / ".claude-plugin" / "marketplace.json"
CHANGELOG = ROOT / "CHANGELOG.md"
NPM_PACKAGE = ROOT / "package.json"
SKILLS_DIR = PLUGIN_DIR / "skills"
PATH_OVERRIDE_FLAG = "CLAUDE_TOKEN_PREPUBLISH_ALLOW_PATH_OVERRIDES"
PATH_OVERRIDE_ENVS = (
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_DIR",
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_BIN",
    "CLAUDE_TOKEN_PREPUBLISH_PLUGIN_MANIFEST",
    "CLAUDE_TOKEN_PREPUBLISH_MARKETPLACE_MANIFEST",
    "CLAUDE_TOKEN_PREPUBLISH_SKILLS_DIR",
)
BASH_ALLOWED_TOOL_RE = re.compile(r"Bash\(([^)]*)\)")
PLUGIN_HELPER_COMMAND_RE = re.compile(r"^(?:(?:context-guard|claude-token)-|claude-(?:read-symbol|trim-output|sanitize-output)$)")
FORBIDDEN_SKILL_ALLOWED_HELPERS = {
    # These wrappers intentionally execute an arbitrary trailing command. They
    # are useful as examples but are too broad for skill frontmatter grants.
    "context-guard-trim-output",
    "context-guard-sanitize-output",
    "claude-trim-output",
    "claude-sanitize-output",
}
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
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}

IMPLEMENTATION_PAIRS = (
    ("context_guard_cli.py", "context-guard"),
    ("cost_guard.py", "context-guard-cost"),
    ("benchmark_runner.py", "context-guard-bench"),
    ("context_escrow.py", "context-guard-artifact"),
    ("context_compress.py", "context-guard-compress"),
    ("context_pack.py", "context-guard-pack"),
    ("tool_schema_pruner.py", "context-guard-tool-prune"),
    ("claude_transcript_cost_audit.py", "context-guard-audit"),
    ("context_guard_diet.py", "context-guard-diet"),
    ("failed_attempt_nudge.py", "context-guard-failed-nudge"),
    ("guard_large_read.py", "context-guard-guard-read"),
    ("read_symbol.py", "context-guard-read-symbol"),
    ("rewrite_bash_for_token_budget.py", "context-guard-rewrite-bash"),
    ("sanitize_output.py", "context-guard-sanitize-output"),
    ("setup_wizard.py", "context-guard-setup"),
    ("statusline.sh", "context-guard-statusline"),
    ("statusline_merged.sh", "context-guard-statusline-merged"),
    ("trim_command_output.py", "context-guard-trim-output"),
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
REQUIRED_NPM_BINS = {
    "context-guard",
    "context-guard-setup",
    "context-guard-diet",
    "context-guard-audit",
    "context-guard-trim-output",
    "context-guard-sanitize-output",
    "context-guard-artifact",
    "context-guard-pack",
    "context-guard-tool-prune",
    "context-guard-compress",
    "context-guard-cost",
    "context-guard-bench",
    "context-guard-read-symbol",
}
FORBIDDEN_NPM_LIFECYCLE_SCRIPTS = {
    "dependencies",
    "preinstall",
    "install",
    "postinstall",
    "prepack",
    "postpack",
    "prepublish",
    "prepublishOnly",
    "publish",
    "postpublish",
    "preprepare",
    "prepare",
    "postprepare",
    "preversion",
    "version",
    "postversion",
}
FORBIDDEN_NPM_PACK_PREFIXES = (
    ".git/",
    ".omx/",
    ".context-guard/",
    ".claude-token-optimizer/",
    ".serena/",
    ".remember/",
)
FORBIDDEN_KOREAN_TERMS = (
    "컨텍스트 위생",
    "영수증",
    "적용 가능한 표면",
    "권고형",
    "아티팩트",
    "트랜스크립트",
    "정제",
)
KOREAN_DOCS = (
    ROOT / "README.ko.md",
    PLUGIN_DIR / "README.ko.md",
    ROOT / "docs" / "index.html",
)
EXPECTED_NPM_PACK_FILES = {
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "README.ko.md",
    "README.md",
    "context-guard-kit/README.md",
    "context-guard-kit/benchmark_runner.py",
    "context-guard-kit/claude_transcript_cost_audit.py",
    "context-guard-kit/context_compress.py",
    "context-guard-kit/context_escrow.py",
    "context-guard-kit/context_guard_cli.py",
    "context-guard-kit/context_guard_diet.py",
    "context-guard-kit/cost_guard.py",
    "context-guard-kit/context_pack.py",
    "context-guard-kit/failed_attempt_nudge.py",
    "context-guard-kit/guard_large_read.py",
    "context-guard-kit/hook_secret_patterns.py",
    "context-guard-kit/read_symbol.py",
    "context-guard-kit/rewrite_bash_for_token_budget.py",
    "context-guard-kit/sanitize_output.py",
    "context-guard-kit/settings.example.json",
    "context-guard-kit/setup_wizard.py",
    "context-guard-kit/statusline.sh",
    "context-guard-kit/statusline_merged.sh",
    "context-guard-kit/tool_schema_pruner.py",
    "context-guard-kit/trim_command_output.py",
    "docs/distribution.md",
    "docs/benchmark-workflow-examples.md",
    "docs/benchmark-workflows/context-pack-byte-proxy.example.json",
    "docs/benchmark-workflows/measured-token-workflow.example.json",
    "docs/benchmark-workflows/provider-cache-telemetry.example.json",
    "package.json",
    "packaging/homebrew/context-guard.rb.template",
    "plugins/context-guard/.claude-plugin/plugin.json",
    "plugins/context-guard/LICENSE",
    "plugins/context-guard/NOTICE",
    "plugins/context-guard/README.ko.md",
    "plugins/context-guard/README.md",
    "plugins/context-guard/bin/claude-read-symbol",
    "plugins/context-guard/bin/claude-sanitize-output",
    "plugins/context-guard/bin/claude-token-artifact",
    "plugins/context-guard/bin/claude-token-audit",
    "plugins/context-guard/bin/claude-token-bench",
    "plugins/context-guard/bin/claude-token-diet",
    "plugins/context-guard/bin/claude-token-failed-nudge",
    "plugins/context-guard/bin/claude-token-guard-read",
    "plugins/context-guard/bin/claude-token-rewrite-bash",
    "plugins/context-guard/bin/claude-token-setup",
    "plugins/context-guard/bin/claude-token-statusline",
    "plugins/context-guard/bin/claude-token-statusline-merged",
    "plugins/context-guard/bin/claude-trim-output",
    "plugins/context-guard/bin/context-guard",
    "plugins/context-guard/bin/context-guard-artifact",
    "plugins/context-guard/bin/context-guard-audit",
    "plugins/context-guard/bin/context-guard-bench",
    "plugins/context-guard/bin/context-guard-compress",
    "plugins/context-guard/bin/context-guard-cost",
    "plugins/context-guard/bin/context-guard-diet",
    "plugins/context-guard/bin/context-guard-failed-nudge",
    "plugins/context-guard/bin/context-guard-guard-read",
    "plugins/context-guard/bin/context-guard-pack",
    "plugins/context-guard/bin/context-guard-read-symbol",
    "plugins/context-guard/bin/context-guard-rewrite-bash",
    "plugins/context-guard/bin/context-guard-sanitize-output",
    "plugins/context-guard/bin/context-guard-setup",
    "plugins/context-guard/bin/context-guard-statusline",
    "plugins/context-guard/bin/context-guard-statusline-merged",
    "plugins/context-guard/bin/context-guard-tool-prune",
    "plugins/context-guard/bin/context-guard-trim-output",
    "plugins/context-guard/brief/README.md",
    "plugins/context-guard/brief/brief-mode.lite.md",
    "plugins/context-guard/brief/brief-mode.standard.md",
    "plugins/context-guard/brief/brief-mode.ultra.md",
    "plugins/context-guard/lib/hook_secret_patterns.py",
    "plugins/context-guard/skills/audit/SKILL.md",
    "plugins/context-guard/skills/optimize/SKILL.md",
    "plugins/context-guard/skills/setup/SKILL.md",
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


def normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


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
        if stat.S_ISLNK(st.st_mode):
            if path.is_absolute() and depth == 0:
                expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(current.name)
                if expected is not None:
                    try:
                        if normalized_link_target(Path(path.anchor), os.readlink(current)) == expected:
                            depth += 1
                            continue
                    except OSError:
                        pass
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
        ("release notes", CHANGELOG),
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


def check_manifest() -> dict:
    plugin = load_json(PLUGIN_MANIFEST)
    marketplace = load_json(MARKETPLACE_MANIFEST)

    for key in ("name", "description", "version", "license"):
        if not isinstance(plugin.get(key), str) or not plugin[key].strip():
            fail(f"plugin manifest missing non-empty string field: {key}")
    if plugin["name"] != "context-guard":
        fail(f"unexpected plugin name: {plugin['name']}")
    if plugin["license"] != "Apache-2.0":
        fail(f"unexpected plugin license: {plugin['license']}")

    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        fail("marketplace manifest must contain at least one plugin")
    entry = next((item for item in plugins if isinstance(item, dict) and item.get("name") == plugin["name"]), None)
    if entry is None:
        fail("marketplace manifest does not list context-guard")
    if entry.get("source") != "./plugins/context-guard":
        fail(f"unexpected marketplace source: {entry.get('source')!r}")
    if entry.get("version") != plugin["version"]:
        fail(f"marketplace/plugin version mismatch: {entry.get('version')} != {plugin['version']}")
    if entry.get("license") != plugin["license"]:
        fail(f"marketplace/plugin license mismatch: {entry.get('license')} != {plugin['license']}")
    return plugin


def check_release_notes(version: str) -> None:
    try:
        text = CHANGELOG.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"missing release notes: {safe_path_label(CHANGELOG)}")
    except OSError as exc:
        fail(
            f"could not read release notes: {safe_path_label(CHANGELOG)}: "
            f"{compact_label_text(exc.strerror or exc.__class__.__name__, 80)}"
        )
    version_heading = rf"(?:\[{re.escape(version)}\]|{re.escape(version)})"
    heading = re.compile(rf"(?m)^##\s+{version_heading}(?:\s+-\s+\d{{4}}-\d{{2}}-\d{{2}})?\s*$")
    match = heading.search(text)
    if match is None:
        fail(f"release notes missing version entry: {safe_path_label(CHANGELOG)}: {version}")
    section = text[match.end() :]
    next_heading = re.search(r"(?m)^##\s+", section)
    if next_heading is not None:
        section = section[: next_heading.start()]
    if not any(line.strip() and not line.lstrip().startswith("<!--") for line in section.splitlines()):
        fail(f"release notes entry is empty: {safe_path_label(CHANGELOG)}: {version}")


def check_npm_package_metadata(version: str) -> None:
    package = load_json(NPM_PACKAGE)
    if package.get("name") != "@ictechgy/context-guard":
        fail(f"unexpected npm package name: {package.get('name')!r}")
    if package.get("version") != version:
        fail(f"npm/plugin version mismatch: {package.get('version')} != {version}")
    if package.get("license") != "Apache-2.0":
        fail(f"unexpected npm package license: {package.get('license')!r}")
    scripts = package.get("scripts", {})
    if isinstance(scripts, dict):
        forbidden = sorted(FORBIDDEN_NPM_LIFECYCLE_SCRIPTS & set(scripts))
        if forbidden:
            fail(f"npm package must not define install-time lifecycle scripts: {', '.join(forbidden)}")
    elif scripts is not None:
        fail("npm package scripts must be an object when present")
    bins = package.get("bin")
    if not isinstance(bins, dict):
        fail("npm package bin must be an object")
    missing = sorted(REQUIRED_NPM_BINS - set(bins))
    if missing:
        fail(f"npm package bin missing required commands: {', '.join(missing)}")
    for command, rel in bins.items():
        if not isinstance(command, str) or not isinstance(rel, str):
            fail("npm package bin entries must be string:string")
        target = ROOT / rel
        if not target.is_file():
            fail(f"npm package bin target missing: {command}: {safe_path_label(target)}")
        mode = stat.S_IMODE(target.stat().st_mode)
        if mode & stat.S_IXUSR == 0:
            fail(f"npm package bin target is not owner-executable: {command}: mode={oct(mode)}")
    files = package.get("files")
    if not isinstance(files, list) or not files:
        fail("npm package files allowlist must be a non-empty list")
    for item in files:
        if not isinstance(item, str) or not item.strip():
            fail("npm package files allowlist contains a non-string/empty entry")
        if item.startswith((".git", ".omx", ".context-guard", ".claude-token-optimizer", ".serena")):
            fail(f"npm package files allowlist includes forbidden path: {item}")


def check_npm_pack_file_list() -> None:
    npm = shutil.which("npm")
    if npm is None:
        print("npm package check: skipped (npm not found)")
        return
    with tempfile.TemporaryDirectory(prefix="context-guard-npm-pack-") as td:
        try:
            proc = subprocess.run(
                [npm, "pack", "--json", "--dry-run", "--ignore-scripts", "--pack-destination", td],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            fail("npm pack --dry-run timed out")
    if proc.returncode != 0:
        fail(f"npm pack --dry-run failed: {compact_label_text((proc.stderr or proc.stdout).strip(), 200)}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        fail(f"npm pack --dry-run did not emit JSON: line {exc.lineno}: {compact_label_text(exc.msg, 80)}")
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        fail("npm pack --dry-run JSON must contain one package object")
    files = payload[0].get("files")
    if not isinstance(files, list):
        fail("npm pack --dry-run JSON missing files list")
    paths = []
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            fail("npm pack file entries must contain string path")
        path = item["path"]
        paths.append(path)
        if path.startswith(FORBIDDEN_NPM_PACK_PREFIXES):
            fail(f"npm pack includes forbidden operational path: {path}")
        if "/__pycache__/" in f"/{path}/" or path.endswith((".pyc", ".pyo", ".log", ".tmp")):
            fail(f"npm pack includes generated/cache artifact: {path}")
    packed = set(paths)
    missing = sorted(EXPECTED_NPM_PACK_FILES - packed)
    if missing:
        fail(f"npm pack missing required files: {', '.join(missing)}")
    unexpected = sorted(packed - EXPECTED_NPM_PACK_FILES)
    if unexpected:
        fail(f"npm pack includes unexpected files: {', '.join(unexpected[:20])}")


def check_korean_copy_terms() -> None:
    for path in KOREAN_DOCS:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            fail(f"could not read Korean doc: {safe_path_label(path)}: {compact_label_text(str(exc), 120)}")
        for term in FORBIDDEN_KOREAN_TERMS:
            if term in text:
                fail(f"awkward Korean term still present in {safe_path_label(path)}: {term}")


def check_skill_allowed_tool_commands() -> None:
    if not SKILLS_DIR.is_dir():
        fail(f"missing plugin skills directory: {safe_path_label(SKILLS_DIR)}")
    if not PLUGIN_BIN.is_dir():
        fail(f"missing plugin bin directory: {safe_path_label(PLUGIN_BIN)}")
    available = {path.name: path for path in PLUGIN_BIN.iterdir() if path.is_file()}
    for skill in sorted(SKILLS_DIR.glob("*/SKILL.md")):
        try:
            text = skill.read_text(encoding="utf-8")
        except OSError as exc:
            fail(f"could not read skill metadata: {skill_label(skill)}: {compact_label_text(str(exc), 120)}")
        for spec in BASH_ALLOWED_TOOL_RE.findall(skill_frontmatter(text, skill)):
            parts = spec.strip().split(None, 1)
            if not parts:
                continue
            command = parts[0]
            if not PLUGIN_HELPER_COMMAND_RE.match(command):
                continue
            if command in FORBIDDEN_SKILL_ALLOWED_HELPERS:
                fail(
                    "skill allowed-tools must not grant arbitrary command wrapper helper: "
                    f"{skill_label(skill)}: {command}"
                )
            if command not in available:
                fail(f"skill allowed-tools references missing plugin bin command: {skill_label(skill)}: {command}")
            mode = stat.S_IMODE(available[command].stat().st_mode)
            if mode & stat.S_IXUSR == 0:
                fail(
                    "skill allowed-tools references non-executable plugin bin command: "
                    f"{skill_label(skill)}: {command} mode={oct(mode)}"
                )


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


def package_symlink_scan_roots() -> tuple[Path, ...]:
    return (
        ROOT / "CHANGELOG.md",
        ROOT / "LICENSE",
        ROOT / "NOTICE",
        ROOT / "README.md",
        ROOT / "README.ko.md",
        KIT_DIR,
        PLUGIN_DIR,
        ROOT / "docs" / "distribution.md",
        ROOT / "packaging" / "homebrew",
        NPM_PACKAGE,
    )


def check_package_path_symlinks(path: Path, *, base: Path = ROOT) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(
            "could not inspect package path: "
            f"{safe_path_label(path, base=base)}: {compact_label_text(exc.strerror or exc.__class__.__name__, 80)}"
        )
    if stat.S_ISLNK(st.st_mode):
        fail(f"forbidden package symlink: {safe_path_label(path, base=base)}")
    if not stat.S_ISDIR(st.st_mode):
        return
    try:
        entries = list(os.scandir(path))
    except OSError as exc:
        fail(
            "could not scan package directory: "
            f"{safe_path_label(path, base=base)}: {compact_label_text(exc.strerror or exc.__class__.__name__, 80)}"
        )
    for entry in entries:
        check_package_path_symlinks(Path(entry.path), base=base)


def check_package_symlinks() -> None:
    for path in package_symlink_scan_roots():
        check_package_path_symlinks(path)


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
    with tempfile.TemporaryDirectory(prefix="context-guard-prepublish-pyc-") as td:
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
        [sys.executable, str(ROOT / "tests" / "test_context_guard_kit.py")],
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
    plugin = check_manifest()
    check_release_notes(plugin["version"])
    check_npm_package_metadata(plugin["version"])
    check_bin_copies()
    check_skill_allowed_tool_commands()
    remove_generated_plugin_bin_python_caches()
    check_package_clean()
    check_npm_pack_file_list()
    check_korean_copy_terms()
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
