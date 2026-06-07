#!/usr/bin/env python3
"""Scan a project for Claude Code token-diet configuration gaps.

The scanner is intentionally local, read-only, and heuristic. It looks for
large always-in-context instruction files, missing read deny rules for bulky or
sensitive paths, and missing helper hooks/statusline settings that reduce token
burn during noisy command runs.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import errno
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

CONTEXT_FILE_NAMES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md"}
CONTEXT_EXACT_REL_FILES = {
    ".clinerules",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".windsurfrules",
}
CONTEXT_MD_DIRS = {
    ".claude/agents",
    ".claude/commands",
    ".claude/skills",
    ".clinerules",
    ".cursor/rules",
    ".windsurf/rules",
}
CONTEXT_SURFACE_LABELS = {
    "claude": "Claude Code instructions",
    "codex": "OpenAI Codex AGENTS.md",
    "gemini": "Gemini CLI instructions",
    "cursor": "Cursor rules",
    "windsurf": "Windsurf rules",
    "cline": "Cline rules",
    "copilot": "GitHub Copilot instructions",
}
EXCLUDED_DIR_NAMES = {
    ".cache",
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".omx",
    ".pytest_cache",
    ".ruff_cache",
    ".serena",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
MAX_CONTEXT_READ_BYTES = 512_000
MAX_SECRET_SCAN_BYTES = 5_000_000
MAX_SETTINGS_READ_BYTES = 256_000
DEFAULT_LARGE_CONTEXT_BYTES = 16_000
DEFAULT_HUGE_CONTEXT_BYTES = 64_000
DEFAULT_LONG_CONTEXT_LINES = 300
STRUCTURAL_WASTE_SCHEMA_VERSION = "contextguard.structural-waste.v1"
DEFAULT_STRUCTURAL_WASTE_TOP = 20
DEFAULT_DUPLICATE_RULE_MIN_CHARS = 48
DEFAULT_DUPLICATE_CALL_THRESHOLD = 3
DEFAULT_MCP_SERVER_THRESHOLD = 6
DEFAULT_TOOL_COUNT_THRESHOLD = 40
DEFAULT_LARGE_SCHEMA_BYTES = 12_000
DEFAULT_MAX_TOOL_CATALOG_BYTES = 1_000_000
DEFAULT_MAX_LOG_BYTES = 5_000_000
DEFAULT_MAX_LOG_LINE_BYTES = 1_000_000
DEFAULT_MAX_STRUCTURAL_FILES = 2_000
MAX_REPORT_LABEL_CHARS = 160
TEXT_REFERENCE_SUFFIXES = {".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh"}
TOOL_CALL_NAME_KEYS = ("tool_name", "toolName", "tool")
TOOL_CALL_INPUT_KEYS = ("tool_input", "input", "arguments", "args", "parameters")
READ_TOOL_NAMES = {"read", "read_file", "fileread", "view_file", "open_file", "get_file", "functions.get_file"}
FILE_PATH_KEYS = {"file_path", "filepath", "path", "absolute_path", "relative_path", "file"}

HEAVY_PROJECT_DENIES: tuple[tuple[str, str, str], ...] = (
    ("node_modules", "node_modules", "Read(./node_modules/**)"),
    ("dist", "dist", "Read(./dist/**)"),
    ("build", "build", "Read(./build/**)"),
    ("coverage", "coverage", "Read(./coverage/**)"),
    ("logs", "logs", "Read(./logs/**)"),
    ("tmp", "tmp", "Read(./tmp/**)"),
    ("target", "target", "Read(./target/**)"),
    (".next", ".next", "Read(./.next/**)"),
    (".venv", ".venv", "Read(./.venv/**)"),
    ("vendor", "vendor", "Read(./vendor/**)"),
    (".context-guard", ".context-guard", "Read(./.context-guard/**)"),
    (".claude-token-optimizer", ".claude-token-optimizer", "Read(./.claude-token-optimizer/**)"),
)
SENSITIVE_PROJECT_DENIES: tuple[tuple[str, str, str], ...] = (
    (".env", ".env", "Read(./.env)"),
    (".env.*", ".env.*", "Read(./.env.*)"),
    (".npmrc", ".npmrc", "Read(./.npmrc)"),
    (".pypirc", ".pypirc", "Read(./.pypirc)"),
    (".netrc", ".netrc", "Read(./.netrc)"),
)
SENSITIVE_HOME_DENIES: tuple[tuple[str, str], ...] = (
    ("~/.ssh", "Read(~/.ssh/**)"),
    ("~/.aws", "Read(~/.aws/**)"),
    ("~/.gnupg", "Read(~/.gnupg/**)"),
    ("~/.kube", "Read(~/.kube/**)"),
    ("~/.docker", "Read(~/.docker/**)"),
)
SECRET_CONTENT_RE = re.compile(
    r"(?is)("
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,}|"
    r"AIza[0-9A-Za-z_\-]{20,}|"
    r"(?i:Authorization)\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"(?<![A-Za-z0-9])(?:api[_-]?key|token|secret|password|client[_-]?secret)\s*[:=]\s*[^\s]+"
    r")"
)
REDACTED_PATH_COMPONENT = "[REDACTED-PATH-COMPONENT]"
BASH_TRIM_COMMAND_MARKERS = (
    "context-guard-rewrite-bash",
    "claude-token-rewrite-bash",
    "rewrite_bash_for_token_budget.py",
)
LARGE_READ_GUARD_COMMAND_MARKERS = (
    "context-guard-guard-read",
    "claude-token-guard-read",
    "guard_large_read.py",
)
STATUSLINE_COMMAND_MARKERS = (
    "context-guard-statusline",
    "claude-token-statusline",
    "statusline.sh",
    "statusline_merged.sh",
)


@dataclass
class Finding:
    id: str
    severity: str
    path: str
    message: str
    action: str
    evidence: dict[str, Any] = field(default_factory=dict)
    rule_id: str | None = None
    instance_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id or self.id,
            "instance_id": self.instance_id or self.id,
            "severity": self.severity,
            "path": self.path,
            "message": self.message,
            "action": self.action,
            "evidence": self.evidence,
        }


def path_hash(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:12]


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]


def safe_id_part(text: str) -> str:
    normalized = text.lower().replace("*", " star ")
    return re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")


def safe_resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path.absolute()


def path_component_contains_secret(component: str) -> bool:
    return bool(component and component not in {".", ".."} and SECRET_CONTENT_RE.search(component))


def sanitize_path_component(component: str) -> str:
    if not component or component in {".", ".."}:
        return component
    if not path_component_contains_secret(component):
        return component
    return REDACTED_PATH_COMPONENT


def sanitize_rel_path(path: str) -> str:
    return "/".join(sanitize_path_component(component) for component in path.split("/"))


def sanitize_path_text(path: str) -> str:
    return "/".join(sanitize_path_component(component) for component in path.replace(os.sep, "/").split("/"))


def display_path_hash(path: Path) -> str:
    return text_hash(sanitize_path_text(str(safe_resolve(path))))


def path_label(path: Path, show_paths: bool) -> str:
    if show_paths:
        return sanitize_path_text(str(path))
    name = sanitize_path_component(path.name or "path")
    return f"{name}#path:{display_path_hash(path)}"


def context_finding(
    rule_id: str,
    severity: str,
    path: str,
    message: str,
    action: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    instance_id = f"{rule_id}-{text_hash(path)}"
    return Finding(instance_id, severity, path, message, action, evidence or {}, rule_id=rule_id, instance_id=instance_id)


def root_label(root: Path, show_paths: bool) -> str:
    if show_paths:
        return sanitize_path_text(str(root))
    name = sanitize_path_component(root.name or "project")
    return f"{name}#path:{display_path_hash(root)}"


def rel_path(path: Path, root: Path) -> str:
    try:
        return sanitize_rel_path(path.resolve().relative_to(root.resolve()).as_posix())
    except (OSError, RuntimeError, ValueError):
        name = sanitize_path_component(path.name or "path")
        return f"{name}#path:{display_path_hash(path)}"


def raw_rel_path(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def context_surface_for_rel(raw_rel: str, name: str) -> dict[str, str] | None:
    if name == "CLAUDE.md" or raw_rel.startswith(".claude/"):
        key = "claude"
    elif name == "AGENTS.md":
        key = "codex"
    elif name == "GEMINI.md":
        key = "gemini"
    elif raw_rel == ".cursorrules" or raw_rel.startswith(".cursor/rules/"):
        key = "cursor"
    elif raw_rel == ".windsurfrules" or raw_rel.startswith(".windsurf/rules/"):
        key = "windsurf"
    elif raw_rel == ".clinerules" or raw_rel.startswith(".clinerules/"):
        key = "cline"
    elif raw_rel == ".github/copilot-instructions.md":
        key = "copilot"
    else:
        return None
    return {
        "surface": key,
        "surface_label": CONTEXT_SURFACE_LABELS.get(key, key),
        "surface_kind": "agent_rule",
    }


class SettingsFileTooLargeError(ValueError):
    pass


def load_json(path: Path, root: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = json.loads(read_settings_json_bytes_no_follow(path, root).decode("utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON at line {exc.lineno}: {exc.msg}"
    except SettingsFileTooLargeError as exc:
        return None, str(exc)
    except UnicodeDecodeError as exc:
        return None, f"invalid UTF-8 near byte {exc.start}"
    except OSError as exc:
        return None, f"unreadable: {format_os_error(exc)}"
    if not isinstance(data, dict):
        return None, "settings root must be a JSON object"
    return data, None


def _open_regular_under_root_no_follow(root: Path, path: Path, *, path_kind: str = "settings"):
    root_resolved = root.resolve()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError(errno.ENOTSUP, "safe no-follow open is unavailable")
    if os.open not in getattr(os, "supports_dir_fd", set()):
        raise OSError(errno.ENOTSUP, "safe directory-relative open is unavailable")
    try:
        relative = path.relative_to(root_resolved)
    except ValueError:
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise OSError(f"{path_kind} path is outside project root") from exc
    parts = relative.parts
    if not parts:
        raise OSError(errno.EINVAL, f"{path_kind} path is missing a file name")
    for component in parts:
        if component in {"", "."} or component == "..":
            raise OSError(errno.EINVAL, f"invalid {path_kind} path component")
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    if hasattr(os, "O_CLOEXEC"):
        dir_flags |= os.O_CLOEXEC
    dir_fd = os.open(root_resolved, dir_flags)
    try:
        if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
            raise OSError(errno.ENOTDIR, f"{path_kind} root is not a directory")
        for component in parts[:-1]:
            try:
                next_fd = os.open(component, dir_flags, dir_fd=dir_fd)
            except OSError as exc:
                if exc.errno in {errno.ENOTDIR, errno.ELOOP}:
                    raise OSError(exc.errno, f"{path_kind} parent is not a directory") from exc
                raise
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise OSError(errno.ENOTDIR, f"{path_kind} parent is not a directory")
            except Exception:
                os.close(next_fd)
                raise
            old_fd = dir_fd
            dir_fd = next_fd
            os.close(old_fd)
        file_flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            file_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NONBLOCK"):
            file_flags |= os.O_NONBLOCK
        if nofollow:
            file_flags |= nofollow
        try:
            fd = os.open(parts[-1], file_flags, dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise OSError(errno.ELOOP, "not a regular file") from exc
            raise
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise OSError(errno.EINVAL, "not a regular file")
            handle = os.fdopen(fd, "rb")
            fd = -1
            return handle
        except Exception:
            if fd != -1:
                os.close(fd)
            raise
    finally:
        if dir_fd != -1:
            os.close(dir_fd)


def read_settings_json_bytes_no_follow(path: Path, root: Path) -> bytes:
    with _open_regular_under_root_no_follow(root, path) as handle:
        st = os.fstat(handle.fileno())
        if st.st_size > MAX_SETTINGS_READ_BYTES:
            raise SettingsFileTooLargeError(
                f"settings file is too large ({st.st_size} bytes > {MAX_SETTINGS_READ_BYTES})"
            )
        data = handle.read(MAX_SETTINGS_READ_BYTES + 1)
    if len(data) > MAX_SETTINGS_READ_BYTES:
        raise SettingsFileTooLargeError(f"settings file is too large (> {MAX_SETTINGS_READ_BYTES} bytes)")
    return data


def iter_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from iter_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_values(item)
    else:
        yield value


def string_values(value: Any) -> list[str]:
    return [item for item in iter_values(value) if isinstance(item, str)]


def collect_settings(root: Path) -> tuple[list[dict[str, Any]], list[Finding]]:
    settings: list[dict[str, Any]] = []
    findings: list[Finding] = []
    candidates = [root / ".claude" / "settings.json", root / ".claude" / "settings.local.json"]
    has_project_settings = (root / ".claude" / "settings.json").exists() or (root / ".claude" / "settings.json").is_symlink()
    for path in candidates:
        if not path.exists() and not path.is_symlink():
            continue
        rel = rel_path(path, root)
        data, error = load_json(path, root)
        if error:
            findings.append(Finding(
                "settings-unreadable",
                "high" if "outside project" in error or "invalid JSON" in error else "medium",
                rel,
                f"Claude settings could not be used: {error}.",
                "Fix or remove the settings file so token-budget hooks and deny rules are predictable.",
            ))
            continue
        assert data is not None
        settings.append({"path": rel, "data": data})
    if not settings or not has_project_settings:
        findings.append(Finding(
            "missing-project-settings",
            "medium",
            ".claude/settings.json",
            "No shared project Claude settings file was found.",
            "Add an opt-in project .claude/settings.json with read deny rules, statusline, and Bash output trimming hook.",
        ))
    return settings, findings


def merged_settings(settings: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {"permissions": {"deny": [], "allow": []}, "hooks": {}, "mcpServers": {}}
    for item in settings:
        data = item["data"]
        permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        for key in ("deny", "allow"):
            values = permissions.get(key) if isinstance(permissions, dict) else []
            if isinstance(values, list):
                merged["permissions"][key].extend(str(v) for v in values if isinstance(v, str))
        if isinstance(data.get("hooks"), dict):
            for event, hooks in data["hooks"].items():
                if isinstance(hooks, list):
                    merged["hooks"].setdefault(event, [])
                    if isinstance(merged["hooks"][event], list):
                        merged["hooks"][event].extend(hooks)
                    else:
                        merged["hooks"][event] = hooks
                else:
                    merged["hooks"][event] = hooks
        if isinstance(data.get("statusLine"), dict):
            merged["statusLine"] = data["statusLine"]
        if "model" in data:
            merged["model"] = data["model"]
        if "effortLevel" in data:
            merged["effortLevel"] = data["effortLevel"]
        if isinstance(data.get("mcpServers"), dict):
            merged["mcpServers"].update(data["mcpServers"])
    return merged


READ_TARGET_RE = re.compile(r"(?i)^\s*Read\((?P<target>.*)\)\s*$")


def normalize_read_target(value: str) -> str:
    target = value.strip().strip('"').strip("'").replace("\\", "/")
    while target.startswith("./"):
        target = target[2:]
    target = re.sub(r"/+", "/", target)
    return target.rstrip("/") or "."


def parse_read_targets(deny_entries: list[str]) -> list[str]:
    targets: list[str] = []
    for entry in deny_entries:
        match = READ_TARGET_RE.match(entry)
        if not match:
            continue
        targets.append(normalize_read_target(match.group("target")))
    return targets


def path_target_denied(deny_entries: list[str], recommended: str) -> bool:
    """Return True only for exact/equivalent or intentionally broader Read denies."""
    required = parse_read_targets([recommended])
    if not required:
        return False
    required_target = required[0]
    if required_target in {"**", "*"}:
        return False
    targets = parse_read_targets(deny_entries)
    broader_targets = {"**", "*", "./**", "."}
    for target in targets:
        if target in broader_targets:
            return True
        if target == required_target:
            return True
        if target.endswith("/**"):
            base = target[:-3].rstrip("/")
            if required_target == base or required_target.startswith(base + "/"):
                return True
        if target == "~/**" and required_target.startswith("~/"):
            return True
    return False


def project_path_exists(root: Path, rel: str) -> bool:
    if rel == ".env":
        return (root / ".env").exists()
    if rel == ".env.*":
        return any(path.name.startswith(".env.") for path in root.iterdir() if path.exists())
    return (root / rel).exists()


def generic_context_pattern(rel: str) -> str:
    if rel in {".env", ".npmrc", ".pypirc", ".netrc"}:
        return rel
    if rel.endswith(".*"):
        return rel
    if "*" in rel:
        return rel.replace("./", "")
    return f"{rel.rstrip('/')}/**"


def context_exclusion_recommendation(
    *,
    label: str,
    rel: str,
    recommended: str,
    category: str,
    severity: str,
    deny_entries: list[str],
) -> dict[str, Any]:
    already_denied = path_target_denied(deny_entries, recommended)
    return {
        "id": f"context-exclude-{safe_id_part(label)}",
        "severity": severity,
        "path": rel,
        "category": category,
        "status": "already_denied" if already_denied else "missing",
        "reason": (
            "Sensitive local file should not be read into AI-agent context."
            if category == "sensitive"
            else "Bulky generated/cache path should stay out of AI-agent context."
        ),
        "recommended_deny": recommended,
        "generic_pattern": generic_context_pattern(rel),
        "applies_to": ["claude-permissions.deny", "agent-ignore-advisory"],
        "surfaces": ["Claude Code permissions.deny", "generic agent ignore/exclude rules"],
    }


def build_context_exclusion_recommendations(root: Path, deny_entries: list[str]) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    for label, rel, recommended in HEAVY_PROJECT_DENIES:
        if project_path_exists(root, rel):
            recommendations.append(context_exclusion_recommendation(
                label=label,
                rel=rel,
                recommended=recommended,
                category="generated_cache",
                severity="medium",
                deny_entries=deny_entries,
            ))
    for label, rel, recommended in SENSITIVE_PROJECT_DENIES:
        if project_path_exists(root, rel):
            recommendations.append(context_exclusion_recommendation(
                label=label,
                rel=rel,
                recommended=recommended,
                category="sensitive",
                severity="high",
                deny_entries=deny_entries,
            ))
    recommendations.sort(key=lambda item: (SEVERITY_ORDER.get(str(item["severity"]), 99), item["id"]))
    return recommendations


def scan_settings(root: Path, settings: list[dict[str, Any]]) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    merged = merged_settings(settings)
    deny_entries = merged["permissions"]["deny"]
    allow_entries = merged["permissions"]["allow"]

    for label, rel, recommended in HEAVY_PROJECT_DENIES:
        if project_path_exists(root, rel) and not path_target_denied(deny_entries, recommended):
            findings.append(Finding(
                f"missing-deny-{safe_id_part(label)}",
                "medium",
                rel,
                f"Bulky generated/cache path `{rel}` exists but is not denied from Read.",
                f"Add `{recommended}` to permissions.deny to avoid accidental large reads.",
                {"recommended_deny": recommended},
            ))

    for label, rel, recommended in SENSITIVE_PROJECT_DENIES:
        if project_path_exists(root, rel) and not path_target_denied(deny_entries, recommended):
            findings.append(Finding(
                f"missing-sensitive-deny-{safe_id_part(label)}",
                "high",
                rel,
                f"Sensitive project path `{rel}` exists but is not denied from Read.",
                f"Add `{recommended}` to permissions.deny; do not send secrets to Claude context.",
                {"recommended_deny": recommended},
            ))

    for label, recommended in SENSITIVE_HOME_DENIES:
        if not path_target_denied(deny_entries, recommended):
            findings.append(Finding(
                f"missing-home-deny-{safe_id_part(label)}",
                "low",
                label,
                f"Home credential path `{label}` is not explicitly denied.",
                f"Add `{recommended}` to permissions.deny as a guardrail against accidental credential reads.",
                {"recommended_deny": recommended},
            ))

    if not has_bash_trim_hook(merged):
        findings.append(Finding(
            "missing-bash-trim-hook",
            "medium",
            ".claude/settings.json",
            "No PreToolUse Bash hook for trimming noisy test/build/lint output was detected.",
            "Install the example hook using context-guard-rewrite-bash or rewrite_bash_for_token_budget.py.",
        ))

    if not has_large_read_guard(merged):
        findings.append(Finding(
            "missing-large-read-guard",
            "medium",
            ".claude/settings.json",
            "No PreToolUse Read hook for blocking large whole-file reads was detected.",
            "Install context-guard-guard-read so Claude is nudged toward context-guard-read-symbol or line-range reads before large files enter context.",
        ))

    if not has_statusline(merged):
        findings.append(Finding(
            "missing-token-statusline",
            "low",
            ".claude/settings.json",
            "No token/cost/context statusline command was detected.",
            "Add context-guard-statusline so context and cost pressure stay visible during a session.",
        ))

    for entry in allow_entries:
        if any(target in {"**", "*", "."} for target in parse_read_targets([entry])):
            findings.append(Finding(
                "broad-read-allow",
                "medium",
                ".claude/settings.json",
                "A broad Read allow rule can make accidental large reads more likely.",
                "Prefer narrow allow rules plus explicit deny entries for generated and secret paths.",
                {"allow_entry": entry},
            ))
            break

    model = str(merged.get("model", "")).lower()
    if "opus" in model:
        findings.append(Finding(
            "opus-default-model",
            "medium",
            ".claude/settings.json",
            "Default model appears to be Opus, which can burn scarce premium tokens on routine work.",
            "Use Sonnet as the default and reserve Opus/opusplan for planning or high-risk reasoning.",
            {"model": merged.get("model")},
        ))

    effort = str(merged.get("effortLevel", "")).lower()
    if effort in {"high", "max", "maximum"}:
        findings.append(Finding(
            "high-default-effort",
            "low",
            ".claude/settings.json",
            "Default effort is high, which can increase token burn on routine edits.",
            "Use medium/low by default and raise effort only for hard design/debugging work.",
            {"effortLevel": merged.get("effortLevel")},
        ))

    mcp_servers = merged.get("mcpServers") if isinstance(merged.get("mcpServers"), dict) else {}
    if len(mcp_servers) >= 6:
        findings.append(Finding(
            "many-mcp-servers",
            "low",
            ".claude/settings.json",
            "Many MCP servers are configured; tool schemas and discovery can add startup/context overhead.",
            "Disable unused MCP servers for Claude sessions that do not need them.",
            {"mcp_server_count": len(mcp_servers), "mcp_servers": sorted(mcp_servers)[:20]},
        ))

    settings_summary = {
        "files": [item["path"] for item in settings],
        "deny_count": len(deny_entries),
        "allow_count": len(allow_entries),
        "has_bash_trim_hook": has_bash_trim_hook(merged),
        "has_large_read_guard": has_large_read_guard(merged),
        "has_statusline": has_statusline(merged),
        "mcp_server_count": len(mcp_servers),
        "model": merged.get("model"),
        "effortLevel": merged.get("effortLevel"),
    }
    return settings_summary, findings


def has_bash_trim_hook(settings: dict[str, Any]) -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pre_tool = hooks.get("PreToolUse")
    if not isinstance(pre_tool, list):
        return False
    for entry in pre_tool:
        if not isinstance(entry, dict):
            continue
        matcher = entry.get("matcher")
        if isinstance(matcher, str) and not matcher_applies_to_bash(matcher):
            continue
        commands = (
            string_values(entry.get("hooks"))
            + string_values(entry.get("command"))
            + string_values(entry.get("commands"))
        )
        if any(any(marker in cmd for marker in BASH_TRIM_COMMAND_MARKERS) for cmd in commands):
            return True
    return False


def matcher_applies_to_bash(matcher: str) -> bool:
    parts = [part.strip().lower() for part in matcher.split("|")]
    return any(part in {"", "*", "bash"} for part in parts)


def has_large_read_guard(settings: dict[str, Any]) -> bool:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pre_tool = hooks.get("PreToolUse")
    if not isinstance(pre_tool, list):
        return False
    for entry in pre_tool:
        if not isinstance(entry, dict):
            continue
        matcher = entry.get("matcher")
        if isinstance(matcher, str) and not matcher_applies_to_read(matcher):
            continue
        commands = (
            string_values(entry.get("hooks"))
            + string_values(entry.get("command"))
            + string_values(entry.get("commands"))
        )
        if any(any(marker in cmd for marker in LARGE_READ_GUARD_COMMAND_MARKERS) for cmd in commands):
            return True
    return False


def matcher_applies_to_read(matcher: str) -> bool:
    parts = [part.strip().lower() for part in matcher.split("|")]
    return any(part in {"", "*", "read"} for part in parts)


def has_statusline(settings: dict[str, Any]) -> bool:
    status = settings.get("statusLine")
    if not isinstance(status, dict):
        return False
    command = status.get("command")
    return isinstance(command, str) and any(marker in command for marker in STATUSLINE_COMMAND_MARKERS)


def should_scan_context_file(path: Path, root: Path) -> bool:
    if path.name in CONTEXT_FILE_NAMES:
        return True
    raw_rel = raw_rel_path(path, root)
    if raw_rel is None:
        return False
    if raw_rel in CONTEXT_EXACT_REL_FILES:
        return True
    rel = sanitize_rel_path(raw_rel)
    return any(rel.startswith(prefix + "/") and path.suffix.lower() == ".md" for prefix in CONTEXT_MD_DIRS)


def iter_context_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [
            name
            for name in dirnames
            if name not in EXCLUDED_DIR_NAMES and not (current / name).is_symlink()
        ]
        for name in filenames:
            path = current / name
            if path.is_symlink():
                continue
            if should_scan_context_file(path, root):
                yield path


def read_text_prefix(path: Path, limit: int = MAX_CONTEXT_READ_BYTES, *, root: Path | None = None) -> tuple[str, bool]:
    opener = (
        _open_regular_under_root_no_follow(root, path, path_kind="context")
        if root is not None
        else open_regular_no_follow(path)
    )
    with opener as handle:
        data = handle.read(limit + 1)
    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    return data.decode("utf-8", "replace"), truncated


def file_contains_secret(
    path: Path,
    chunk_bytes: int = 64_000,
    *,
    root: Path | None = None,
    max_total_bytes: int = MAX_SECRET_SCAN_BYTES,
) -> bool:
    carry = ""
    bytes_read = 0
    opener = (
        _open_regular_under_root_no_follow(root, path, path_kind="context")
        if root is not None
        else open_regular_no_follow(path)
    )
    with opener as handle:
        while True:
            remaining = max_total_bytes - bytes_read
            if remaining <= 0:
                return False
            data = handle.read(min(chunk_bytes, remaining))
            if not data:
                return False
            bytes_read += len(data)
            text = carry + data.decode("utf-8", "replace")
            if SECRET_CONTENT_RE.search(text):
                return True
            carry = text[-512:]


def open_regular_no_follow(path: Path):
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("not a regular file")
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if nofollow:
        flags |= nofollow
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        after = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or not os.path.samestat(before, opened)
            or not os.path.samestat(after, opened)
        ):
            raise OSError("not a regular file")
        handle = os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise
    return handle


def format_os_error(exc: OSError) -> str:
    reason = exc.strerror or exc.__class__.__name__
    if exc.errno is not None:
        return f"{reason} (errno {exc.errno})"
    return reason


def scan_context(root: Path, large_bytes: int, huge_bytes: int, long_lines: int) -> tuple[list[dict[str, Any]], list[Finding]]:
    context_files: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for path in sorted(iter_context_files(root), key=lambda p: rel_path(p, root)):
        rel = rel_path(path, root)
        surface = context_surface_for_rel(raw_rel_path(path, root) or rel, path.name)
        try:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode):
                findings.append(context_finding(
                    "context-not-regular",
                    "medium",
                    rel,
                    "Context-like path is not a regular file.",
                    "Replace it with a regular markdown file or remove it from always-loaded context.",
                ))
                continue
            size = st.st_size
            text, sample_truncated = read_text_prefix(path, root=root)
            contains_secret = file_contains_secret(path, root=root)
        except OSError as exc:
            findings.append(context_finding(
                "context-unreadable",
                "low",
                rel,
                f"Context-like file could not be read: {format_os_error(exc)}.",
                "Check file permissions or remove stale symlinks.",
            ))
            continue
        lines = text.count("\n") + (1 if text else 0)
        code_fences = text.count("```")
        item = {
            "path": rel,
            "bytes": size,
            "sampled_lines": lines,
            "sample_truncated": sample_truncated,
            "code_fences": code_fences,
        }
        if surface is not None:
            item.update(surface)
        context_files.append(item)

        if size >= huge_bytes:
            evidence = {"bytes": size, "threshold_bytes": huge_bytes}
            if surface is not None:
                evidence.update(surface)
            findings.append(context_finding(
                "huge-context-file",
                "high",
                rel,
                f"Context-like file is very large ({size} bytes).",
                "Move long procedures/logs/examples into opt-in skills or commands and keep only a short index in always-loaded context.",
                evidence,
            ))
        elif size >= large_bytes or lines >= long_lines:
            evidence = {"bytes": size, "large_bytes": large_bytes, "sampled_lines": lines, "long_lines": long_lines}
            if surface is not None:
                evidence.update(surface)
            findings.append(context_finding(
                "large-context-file",
                "medium",
                rel,
                f"Context-like file is large ({size} bytes, sampled {lines} lines).",
                "Trim stable instructions, move volatile or lengthy material to skills/custom commands, and keep examples short.",
                evidence,
            ))
        if code_fences >= 12:
            findings.append(context_finding(
                "context-heavy-code-fences",
                "low",
                rel,
                "Context-like file contains many code fences, which can inflate startup context.",
                "Replace long embedded examples with links or opt-in command/skill files.",
                {"code_fences": code_fences},
            ))
        if contains_secret:
            findings.append(context_finding(
                "secret-like-context-content",
                "high",
                rel,
                "Context-like file contains credential-shaped text.",
                "Remove secrets from prompt context and rotate exposed credentials if this file was shared.",
            ))
    return context_files, findings


def bounded_top(value: int) -> int:
    return max(1, min(int(value), 200))


def path_text_label(path_text: str, show_paths: bool) -> str:
    sanitized = sanitize_path_text(str(path_text))
    if show_paths:
        return sanitized
    name = sanitize_path_component(Path(sanitized).name or "path")
    return f"{name}#path:{text_hash(sanitized)}"


def safe_report_label(value: Any, limit: int = MAX_REPORT_LABEL_CHARS) -> str:
    text = " ".join(str(value or "").split())
    text = SECRET_CONTENT_RE.sub("[REDACTED]", sanitize_path_text(text))
    if len(text) <= limit:
        return text
    marker = f"…[trimmed:{len(text)} chars]"
    return text[: max(0, limit - len(marker))] + marker


def json_byte_len(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8", "replace"))


def iter_project_files(root: Path, suffixes: set[str], max_files: int) -> Iterable[Path]:
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = [
            name
            for name in dirnames
            if name not in EXCLUDED_DIR_NAMES and not (current / name).is_symlink()
        ]
        for name in filenames:
            path = current / name
            if path.is_symlink() or path.suffix.lower() not in suffixes:
                continue
            yield path
            seen += 1
            if seen >= max_files:
                return


def walk_json(value: Any) -> Iterable[dict[str, Any]]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            yield current
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def normalize_rule_unit(line: str, min_chars: int) -> str | None:
    stripped = line.strip()
    if not stripped or stripped in {"```", "---"}:
        return None
    stripped = re.sub(r"^[-*+>]\s+", "", stripped)
    stripped = re.sub(r"^\d+[.)]\s+", "", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip().lower()
    if len(stripped) < min_chars:
        return None
    if len(stripped.split()) < 6:
        return None
    return stripped


def scan_duplicate_rules(root: Path, *, min_chars: int, top: int) -> tuple[list[dict[str, Any]], list[Finding]]:
    occurrences: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(iter_context_files(root), key=lambda p: rel_path(p, root)):
        rel = rel_path(path, root)
        try:
            text, truncated = read_text_prefix(path, root=root)
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            normalized = normalize_rule_unit(line, min_chars)
            if normalized is None:
                continue
            occurrences[normalized].append({"path": rel, "line": line_no, "sample_truncated": truncated})
    groups: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for normalized, items in occurrences.items():
        paths = sorted({item["path"] for item in items})
        if len(items) < 2 or len(paths) < 2:
            continue
        fingerprint = text_hash(normalized)
        group = {
            "fingerprint": fingerprint,
            "occurrence_count": len(items),
            "path_count": len(paths),
            "paths": paths[:top],
            "sample_chars": len(normalized),
            "confidence": "observed",
        }
        groups.append(group)
        findings.append(Finding(
            f"duplicate-context-rule-{fingerprint}",
            "low" if len(items) < 4 else "medium",
            "context-rules",
            "A normalized instruction/rule unit appears in multiple context-like files.",
            "Keep one canonical copy and replace duplicates with a short pointer if the rule is still needed.",
            group,
            rule_id="duplicate-context-rule",
            instance_id=f"duplicate-context-rule-{fingerprint}",
        ))
    groups.sort(key=lambda item: (-item["occurrence_count"], item["fingerprint"]))
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.id))
    return groups[:top], findings[:top]


def assigned_all_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                    for item in node.value.elts:
                        if isinstance(item, ast.Constant) and isinstance(item.value, str):
                            names.add(item.value)
    return names


def scan_python_imports(root: Path, *, top: int, max_files: int) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    files_scanned = 0
    parse_errors = 0
    for path in iter_project_files(root, {".py"}, max_files):
        files_scanned += 1
        rel = rel_path(path, root)
        try:
            text, _ = read_text_prefix(path, limit=MAX_CONTEXT_READ_BYTES, root=root)
            tree = ast.parse(text, filename=rel)
        except (OSError, SyntaxError, ValueError):
            parse_errors += 1
            continue
        imports: list[tuple[str, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".", 1)[0]
                    if not name.startswith("_"):
                        imports.append((name, node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.module == "__future__":
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    name = alias.asname or alias.name
                    if not name.startswith("_"):
                        imports.append((name, node.lineno, f"{node.module or ''}.{alias.name}".strip(".")))
        if not imports:
            continue
        used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | assigned_all_names(tree)
        for name, line, module in imports:
            if name in used:
                continue
            instance = f"stale-python-import-{text_hash(f'{rel}:{line}:{name}')}"
            findings.append(Finding(
                instance,
                "low",
                rel,
                f"Python import `{name}` appears unused in static AST analysis.",
                "Review before removing; dynamic imports, re-exports, and type-checking paths can make this a false positive.",
                {"imported_name": name, "module": module, "line": line, "confidence": "advisory-static-ast"},
                rule_id="stale-python-import",
                instance_id=instance,
            ))
            if len(findings) >= top:
                break
        if len(findings) >= top:
            break
    return {"files_scanned": files_scanned, "parse_errors": parse_errors, "unused_imports": [f.as_dict() for f in findings]}, findings


def iter_skill_files(root: Path, max_files: int) -> Iterable[Path]:
    count = 0
    for path in iter_project_files(root, {".md"}, max_files):
        if path.name == "SKILL.md" and "skills" in path.parts:
            yield path
            count += 1
            if count >= max_files:
                return


def safe_read_reference_text(path: Path, root: Path) -> str:
    try:
        text, _ = read_text_prefix(path, limit=128_000, root=root)
        return text.lower()
    except OSError:
        return ""


def scan_unused_skills(root: Path, *, top: int, max_files: int) -> tuple[dict[str, Any], list[Finding]]:
    skill_files = list(iter_skill_files(root, max_files))
    reference_files = [path for path in iter_project_files(root, TEXT_REFERENCE_SUFFIXES, max_files) if path.name != "SKILL.md"]
    reference_cache = {path: safe_read_reference_text(path, root) for path in reference_files}
    findings: list[Finding] = []
    candidates: list[dict[str, Any]] = []
    for skill in skill_files:
        skill_name = skill.parent.name
        needle_forms = {skill_name.lower(), f"/{skill_name.lower()}", f"context-guard:{skill_name.lower()}"}
        references = 0
        for ref_path, text in reference_cache.items():
            if ref_path == skill:
                continue
            if any(needle in text for needle in needle_forms):
                references += 1
        if references:
            continue
        rel = rel_path(skill, root)
        candidate = {"path": rel, "skill": safe_report_label(skill_name), "reference_count": 0, "confidence": "low-advisory"}
        candidates.append(candidate)
        instance = f"unused-skill-candidate-{text_hash(rel)}"
        findings.append(Finding(
            instance,
            "low",
            rel,
            "Skill file has no obvious project-local references outside its own SKILL.md.",
            "Confirm real usage through plugin manifests, user docs, or runtime telemetry before deleting or renaming it.",
            candidate,
            rule_id="unused-skill-candidate",
            instance_id=instance,
        ))
        if len(findings) >= top:
            break
    return {"skills_scanned": len(skill_files), "reference_files_scanned": len(reference_files), "unused_candidates": candidates[:top]}, findings


def read_json_file_limited(path: Path, max_bytes: int) -> tuple[Any | None, str | None, int]:
    try:
        with open_regular_no_follow(path) as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > max_bytes:
                return None, f"skipped oversized file ({size} bytes > {max_bytes})", size
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return None, f"skipped oversized file (> {max_bytes} bytes)", len(data)
        return json.loads(data.decode("utf-8", "replace")), None, len(data)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON at line {exc.lineno}: {exc.msg}", 0
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"unreadable: {format_os_error(exc) if isinstance(exc, OSError) else exc.__class__.__name__}", 0


def tool_name_from_schema(d: dict[str, Any]) -> str | None:
    for key in ("name", "tool", "id", "title"):
        value = d.get(key)
        if isinstance(value, str) and value.strip():
            return safe_report_label(value)
    return None


def collect_tool_schemas(raw: Any) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    for d in walk_json(raw):
        name = tool_name_from_schema(d)
        if not name:
            continue
        if not any(key in d for key in ("inputSchema", "input_schema", "schema", "parameters", "description")):
            continue
        server = safe_report_label(d.get("server")) if isinstance(d.get("server"), str) else None
        tools.append({"name": name, "schema_bytes": json_byte_len(d), "server": server})
    dedup: dict[tuple[str, str | None], dict[str, Any]] = {}
    for tool in tools:
        key = (tool["name"], tool.get("server"))
        prior = dedup.get(key)
        if prior is None or int(tool["schema_bytes"]) > int(prior["schema_bytes"]):
            dedup[key] = tool
    return list(dedup.values())


def scan_tool_catalogs(root: Path, args: argparse.Namespace, settings: list[dict[str, Any]], *, top: int) -> tuple[dict[str, Any], list[Finding]]:
    findings: list[Finding] = []
    catalogs: list[dict[str, Any]] = []
    merged = merged_settings(settings)
    mcp_servers = merged.get("mcpServers") if isinstance(merged.get("mcpServers"), dict) else {}
    if len(mcp_servers) >= args.mcp_server_threshold:
        evidence = {"mcp_server_count": len(mcp_servers), "threshold": args.mcp_server_threshold, "confidence": "observed-settings"}
        findings.append(Finding(
            "excessive-mcp-servers",
            "low",
            ".claude/settings.json",
            "Project Claude settings configure many MCP servers, which can increase tool discovery/schema overhead.",
            "Disable unused MCP servers for sessions that do not need them; keep this advisory until task-specific need is known.",
            evidence,
            rule_id="excessive-mcp-servers",
            instance_id="excessive-mcp-servers",
        ))
    for raw_path in getattr(args, "tool_catalog", []) or []:
        path = safe_resolve(Path(raw_path).expanduser())
        label = path_text_label(str(path), args.show_paths)
        raw, error, size = read_json_file_limited(path, args.max_tool_catalog_bytes)
        if error:
            catalogs.append({"path": label, "status": "skipped", "reason": error, "bytes": size})
            continue
        tools = collect_tool_schemas(raw)
        total_schema_bytes = sum(int(tool["schema_bytes"]) for tool in tools)
        large_tools = sorted([tool for tool in tools if int(tool["schema_bytes"]) >= args.large_schema_bytes], key=lambda item: (-int(item["schema_bytes"]), item["name"]))[:top]
        catalog = {"path": label, "status": "scanned", "tool_count": len(tools), "schema_bytes": total_schema_bytes, "large_schema_tools": large_tools}
        catalogs.append(catalog)
        if len(tools) >= args.tool_count_threshold:
            instance = f"excessive-tool-catalog-{text_hash(label)}"
            findings.append(Finding(
                instance,
                "medium",
                label,
                "Local tool catalog contains many tools for one task context.",
                "Use context-guard-tool-prune or a task-specific tool allowlist before injecting full schemas.",
                {"tool_count": len(tools), "threshold": args.tool_count_threshold, "schema_bytes": total_schema_bytes, "confidence": "observed-catalog"},
                rule_id="excessive-tool-catalog",
                instance_id=instance,
            ))
        for tool in large_tools:
            instance = f"large-tool-schema-{text_hash(label + ':' + tool['name'])}"
            findings.append(Finding(
                instance,
                "low",
                label,
                "A local tool schema is large enough to dominate narrow task context.",
                "Prefer a bounded top-k schema report and retrieve the full sanitized schema only when needed.",
                {"tool_name": tool["name"], "schema_bytes": tool["schema_bytes"], "threshold": args.large_schema_bytes, "confidence": "observed-catalog"},
                rule_id="large-tool-schema",
                instance_id=instance,
            ))
    return {"mcp_server_count": len(mcp_servers), "catalogs": catalogs[:top]}, findings[: max(top, 1) * 2]


def iter_log_candidates(root: Path, log_paths: list[str], max_files: int) -> Iterable[Path]:
    candidates: list[Path] = []
    explicit = [Path(item).expanduser() for item in log_paths]
    default_roots = [root / ".claude", root / ".codex"]
    for path in explicit + default_roots:
        try:
            resolved = safe_resolve(path)
        except OSError:
            resolved = path
        if resolved.exists() and not resolved.is_symlink():
            candidates.append(resolved)
    yielded = 0
    for candidate in candidates:
        if candidate.is_file() and candidate.suffix.lower() in {".json", ".jsonl", ".ndjson", ".log"}:
            yield candidate
            yielded += 1
        elif candidate.is_dir():
            for dirpath, dirnames, filenames in os.walk(candidate, followlinks=False):
                current = Path(dirpath)
                dirnames[:] = [name for name in dirnames if name not in EXCLUDED_DIR_NAMES and not (current / name).is_symlink()]
                for name in filenames:
                    path = current / name
                    if path.is_symlink() or path.suffix.lower() not in {".json", ".jsonl", ".ndjson", ".log"}:
                        continue
                    yield path
                    yielded += 1
                    if yielded >= max_files:
                        return
        if yielded >= max_files:
            return


def parse_possible_json(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return value
    return value


def call_name(d: dict[str, Any]) -> str | None:
    for key in TOOL_CALL_NAME_KEYS:
        value = d.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:120]
    typ = str(d.get("type") or "").lower()
    name = d.get("name")
    if isinstance(name, str) and name.strip() and (typ in {"tool_use", "tool_call", "function_call"} or any(key in d for key in TOOL_CALL_INPUT_KEYS)):
        return name.strip()[:120]
    return None


def call_input(d: dict[str, Any]) -> Any:
    for key in TOOL_CALL_INPUT_KEYS:
        if key in d:
            return parse_possible_json(d[key])
    return {}


def sanitized_fingerprint_value(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in sorted(value.items(), key=lambda kv: str(kv[0])):
            safe_key = sanitize_path_component(str(key))
            out[safe_key] = sanitized_fingerprint_value(item)
        return out
    if isinstance(value, list):
        return [sanitized_fingerprint_value(item) for item in value[:20]]
    if isinstance(value, str):
        return SECRET_CONTENT_RE.sub("[REDACTED]", sanitize_path_text(value))[:500]
    return value


def find_path_argument(value: Any) -> str | None:
    stack = [parse_possible_json(value)]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                if str(key) in FILE_PATH_KEYS and isinstance(item, str) and item.strip():
                    return item.strip()
                stack.append(item)
        elif isinstance(current, list):
            stack.extend(current)
    return None


def is_read_tool(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    tail = lowered.rsplit(".", 1)[-1]
    return lowered in READ_TOOL_NAMES or tail in READ_TOOL_NAMES or "read_file" in lowered


def scan_logs(root: Path, args: argparse.Namespace, *, top: int) -> tuple[dict[str, Any], list[Finding]]:
    tool_counts: Counter[tuple[str, str]] = Counter()
    tool_files: dict[tuple[str, str], set[str]] = defaultdict(set)
    read_counts: Counter[str] = Counter()
    read_labels: dict[str, str] = {}
    read_tools: dict[str, set[str]] = defaultdict(set)
    files_scanned = 0
    records_scanned = 0
    skipped_files: list[dict[str, Any]] = []
    skipped_records = 0
    for path in iter_log_candidates(root, getattr(args, "log_path", []) or [], args.max_structural_files):
        label = path_text_label(str(path), args.show_paths)
        try:
            with open_regular_no_follow(path) as handle:
                size = os.fstat(handle.fileno()).st_size
                if size > args.max_log_bytes:
                    skipped_files.append({"path": label, "reason": f"oversized:{size}>{args.max_log_bytes}"})
                    continue
                data = handle.read(args.max_log_bytes + 1)
            if len(data) > args.max_log_bytes:
                skipped_files.append({"path": label, "reason": f"oversized:>{args.max_log_bytes}"})
                continue
        except OSError as exc:
            skipped_files.append({"path": label, "reason": format_os_error(exc)})
            continue
        files_scanned += 1
        text = data.decode("utf-8", "replace")
        raw_records: list[Any] = []
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
                raw_records = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                skipped_records += 1
                continue
        else:
            for raw_line in text.splitlines():
                if len(raw_line.encode("utf-8", "replace")) > args.max_log_line_bytes:
                    skipped_records += 1
                    continue
                if not raw_line.strip():
                    continue
                try:
                    raw_records.append(json.loads(raw_line))
                except json.JSONDecodeError:
                    skipped_records += 1
        for record in raw_records:
            records_scanned += 1
            for d in walk_json(record):
                name = call_name(d)
                if not name:
                    continue
                value = call_input(d)
                fp = text_hash(json.dumps(sanitized_fingerprint_value(value), ensure_ascii=False, sort_keys=True, default=str))
                key = (name, fp)
                tool_counts[key] += 1
                tool_files[key].add(label)
                if is_read_tool(name):
                    path_arg = find_path_argument(value)
                    if path_arg:
                        read_fp = text_hash(sanitize_path_text(path_arg))
                        read_counts[read_fp] += 1
                        read_labels[read_fp] = path_text_label(path_arg, args.show_paths)
                        read_tools[read_fp].add(name)
    findings: list[Finding] = []
    repeated_reads: list[dict[str, Any]] = []
    for fp, count in read_counts.most_common(top):
        if count < args.duplicate_call_threshold:
            continue
        item = {"path": read_labels[fp], "path_fingerprint": fp, "read_count": count, "tools": sorted(safe_report_label(name) for name in read_tools[fp]), "confidence": "observed-log"}
        repeated_reads.append(item)
        instance = f"repeated-file-read-{fp}"
        findings.append(Finding(
            instance,
            "medium",
            "local-logs",
            "The same file path appears to be read repeatedly in local tool-call logs.",
            "Use search/symbol/slice reads or a local artifact receipt instead of repeating whole-file reads.",
            item,
            rule_id="repeated-file-read",
            instance_id=instance,
        ))
    duplicate_calls: list[dict[str, Any]] = []
    for (name, fp), count in tool_counts.most_common(top * 2):
        if count < args.duplicate_call_threshold:
            continue
        item = {"tool_name": safe_report_label(name), "input_fingerprint": fp, "call_count": count, "log_files": sorted(tool_files[(name, fp)])[:top], "confidence": "observed-log"}
        duplicate_calls.append(item)
        instance = f"duplicate-tool-call-{text_hash(name + ':' + fp)}"
        findings.append(Finding(
            instance,
            "low" if count < args.duplicate_call_threshold * 2 else "medium",
            "local-logs",
            "A tool call with the same sanitized input fingerprint repeats in local logs.",
            "Avoid replaying identical calls; keep one receipt or summarize the result before retrying.",
            item,
            rule_id="duplicate-tool-call",
            instance_id=instance,
        ))
        if len(duplicate_calls) >= top:
            break
    return {
        "files_scanned": files_scanned,
        "records_scanned": records_scanned,
        "skipped_files": skipped_files[:top],
        "skipped_records": skipped_records,
        "repeated_file_reads": repeated_reads[:top],
        "duplicate_tool_calls": duplicate_calls[:top],
    }, findings[: top * 2]


def structural_summary(findings: list[Finding]) -> dict[str, Any]:
    by_rule: Counter[str] = Counter(item.rule_id or item.id for item in findings)
    by_severity: Counter[str] = Counter(item.severity for item in findings)
    return {
        "finding_count": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def build_structural_waste_report(args: argparse.Namespace) -> dict[str, Any]:
    root = safe_resolve(Path(args.path).expanduser())
    try:
        is_scan_root = root.exists() and root.is_dir()
    except OSError:
        is_scan_root = False
    if not is_scan_root:
        raise SystemExit(f"context-guard-diet: structural-waste path is not a directory: {path_label(root, args.show_paths)}")
    top = bounded_top(args.top)
    settings, _settings_findings = collect_settings(root)
    context_files, context_findings = scan_context(root, args.large_context_bytes, args.huge_context_bytes, args.long_context_lines)
    oversized_rule_findings = [item for item in context_findings if (item.rule_id or item.id) in {"large-context-file", "huge-context-file", "context-heavy-code-fences"}]
    duplicate_rule_groups, duplicate_rule_findings = scan_duplicate_rules(root, min_chars=args.duplicate_rule_min_chars, top=top)
    imports_category, import_findings = scan_python_imports(root, top=top, max_files=args.max_structural_files)
    skills_category, skill_findings = scan_unused_skills(root, top=top, max_files=args.max_structural_files)
    tools_category, tool_findings = scan_tool_catalogs(root, args, settings, top=top)
    logs_category, log_findings = scan_logs(root, args, top=top)
    findings = oversized_rule_findings + duplicate_rule_findings + import_findings + skill_findings + tool_findings + log_findings
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.rule_id or item.id, item.path))
    return {
        "tool": "context-guard-diet",
        "mode": "structural-waste",
        "schema_version": STRUCTURAL_WASTE_SCHEMA_VERSION,
        "root": root_label(root, args.show_paths),
        "read_only": True,
        "network": "not-used",
        "destructive_actions": [],
        "limits": {
            "top": top,
            "max_structural_files": args.max_structural_files,
            "large_context_bytes": args.large_context_bytes,
            "huge_context_bytes": args.huge_context_bytes,
            "long_context_lines": args.long_context_lines,
            "duplicate_rule_min_chars": args.duplicate_rule_min_chars,
            "duplicate_call_threshold": args.duplicate_call_threshold,
            "mcp_server_threshold": args.mcp_server_threshold,
            "tool_count_threshold": args.tool_count_threshold,
            "large_schema_bytes": args.large_schema_bytes,
            "max_tool_catalog_bytes": args.max_tool_catalog_bytes,
            "max_log_bytes": args.max_log_bytes,
            "max_log_line_bytes": args.max_log_line_bytes,
        },
        "summary": structural_summary(findings),
        "categories": {
            "rule_files": {
                "context_files_scanned": len(context_files),
                "oversized_or_heavy": [item.as_dict() for item in oversized_rule_findings[:top]],
                "duplicate_rule_groups": duplicate_rule_groups,
            },
            "python_imports": imports_category,
            "skills": skills_category,
            "tool_schemas": tools_category,
            "local_logs": logs_category,
        },
        "finding_count": len(findings),
        "findings": [item.as_dict() for item in findings[: top * 10]],
        "caveats": [
            "Structural-waste diagnostics are advisory heuristics; verify before deleting rules, imports, skills, or tools.",
            "No network calls or destructive actions are performed by this command.",
            "Local log diagnostics use sanitized input fingerprints and do not print raw prompt, command, or tool-input text.",
            "Unused-skill and stale-import candidates can be false positives when usage is dynamic or outside the scanned project.",
        ],
    }


def print_structural_waste_text(report: dict[str, Any]) -> None:
    print("ContextGuard structural-waste diagnostics")
    print(f"root: {report['root']}")
    print("read_only: yes  network: not-used  destructive_actions: none")
    summary = report["summary"]
    print(f"findings: {summary['finding_count']} by_rule={json.dumps(summary['by_rule'], sort_keys=True)}")
    if not report["findings"]:
        print("\nFindings:\n- none")
        return
    print("\nFindings:")
    for finding in report["findings"]:
        print(f"- [{finding['severity'].upper()}] {finding['rule_id']} @ {finding['path']}")
        print(f"  why: {finding['message']}")
        print(f"  fix: {finding['action']}")


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    root = safe_resolve(Path(args.path).expanduser())
    try:
        is_scan_root = root.exists() and root.is_dir()
    except OSError:
        is_scan_root = False
    if not is_scan_root:
        raise SystemExit(f"context-guard-diet: scan path is not a directory: {path_label(root, args.show_paths)}")
    settings, settings_findings = collect_settings(root)
    settings_summary, config_findings = scan_settings(root, settings)
    context_files, context_findings = scan_context(root, args.large_context_bytes, args.huge_context_bytes, args.long_context_lines)
    deny_entries = merged_settings(settings)["permissions"]["deny"]
    exclusion_recommendations = build_context_exclusion_recommendations(root, deny_entries)
    findings = settings_findings + config_findings + context_findings
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.id, item.path))
    return {
        "tool": "context-guard-diet",
        "root": root_label(root, args.show_paths),
        "settings": settings_summary,
        "context_files": sorted(context_files, key=lambda item: item["bytes"], reverse=True)[: args.top],
        "context_exclusion_recommendations": exclusion_recommendations[: args.top],
        "finding_count": len(findings),
        "findings": [item.as_dict() for item in findings],
    }


def print_text(report: dict[str, Any]) -> None:
    print("Claude token diet scan")
    print(f"root: {report['root']}")
    settings = report["settings"]
    print(
        "settings: "
        f"files={len(settings['files'])} deny={settings['deny_count']} "
        f"trim_hook={'yes' if settings['has_bash_trim_hook'] else 'no'} "
        f"read_guard={'yes' if settings['has_large_read_guard'] else 'no'} "
        f"statusline={'yes' if settings['has_statusline'] else 'no'} "
        f"mcp={settings['mcp_server_count']}"
    )
    if report["context_files"]:
        print("\nTop context-like files:")
        for item in report["context_files"]:
            surface = f", surface={item['surface']}" if item.get("surface") else ""
            print(f"- {item['path']} ({item['bytes']} bytes, sampled_lines={item['sampled_lines']}{surface})")
    if report.get("context_exclusion_recommendations"):
        print("\nContext exclusion recommendations:")
        for item in report["context_exclusion_recommendations"]:
            status = item.get("status", "missing")
            print(f"- [{item['severity'].upper()}] {item['id']} @ {item['path']} ({status})")
            print(f"  claude: {item['recommended_deny']}")
            print(f"  generic: {item['generic_pattern']}")
    print("\nFindings:")
    if not report["findings"]:
        print("- none")
        return
    for finding in report["findings"]:
        print(f"- [{finding['severity'].upper()}] {finding['id']} @ {finding['path']}")
        print(f"  why: {finding['message']}")
        print(f"  fix: {finding['action']}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="context-guard-diet")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan project settings and context files for token-diet gaps")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument("--show-paths", action="store_true", help="show raw absolute root path instead of a stable anonymized root label; local debugging only because private paths may be exposed")
    scan.add_argument("--top", type=int, default=20, help="maximum context-like files and context-exclusion recommendations to list")
    scan.add_argument("--large-context-bytes", type=int, default=DEFAULT_LARGE_CONTEXT_BYTES)
    scan.add_argument("--huge-context-bytes", type=int, default=DEFAULT_HUGE_CONTEXT_BYTES)
    scan.add_argument("--long-context-lines", type=int, default=DEFAULT_LONG_CONTEXT_LINES)

    structural = sub.add_parser("structural-waste", help="run local read-only structural waste diagnostics")
    structural.add_argument("path", nargs="?", default=".")
    structural.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    structural.add_argument("--show-paths", action="store_true", help="show raw local paths for debugging; secret-shaped path components remain redacted")
    structural.add_argument("--top", type=int, default=DEFAULT_STRUCTURAL_WASTE_TOP, help="maximum findings per structural-waste category to list")
    structural.add_argument("--log-path", action="append", default=[], help="local JSON/JSONL log or directory to inspect for repeated reads/tool calls; may be repeated")
    structural.add_argument("--tool-catalog", action="append", default=[], help="local tool/MCP catalog JSON to inspect; may be repeated")
    structural.add_argument("--large-context-bytes", type=int, default=DEFAULT_LARGE_CONTEXT_BYTES)
    structural.add_argument("--huge-context-bytes", type=int, default=DEFAULT_HUGE_CONTEXT_BYTES)
    structural.add_argument("--long-context-lines", type=int, default=DEFAULT_LONG_CONTEXT_LINES)
    structural.add_argument("--duplicate-rule-min-chars", type=int, default=DEFAULT_DUPLICATE_RULE_MIN_CHARS)
    structural.add_argument("--duplicate-call-threshold", type=int, default=DEFAULT_DUPLICATE_CALL_THRESHOLD)
    structural.add_argument("--mcp-server-threshold", type=int, default=DEFAULT_MCP_SERVER_THRESHOLD)
    structural.add_argument("--tool-count-threshold", type=int, default=DEFAULT_TOOL_COUNT_THRESHOLD)
    structural.add_argument("--large-schema-bytes", type=int, default=DEFAULT_LARGE_SCHEMA_BYTES)
    structural.add_argument("--max-tool-catalog-bytes", type=int, default=DEFAULT_MAX_TOOL_CATALOG_BYTES)
    structural.add_argument("--max-log-bytes", type=int, default=DEFAULT_MAX_LOG_BYTES)
    structural.add_argument("--max-log-line-bytes", type=int, default=DEFAULT_MAX_LOG_LINE_BYTES)
    structural.add_argument("--max-structural-files", type=int, default=DEFAULT_MAX_STRUCTURAL_FILES)
    args = parser.parse_args()

    if args.command == "scan":
        report = build_report(args)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print_text(report)
        return 0
    if args.command == "structural-waste":
        report = build_structural_waste_report(args)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print_structural_waste_text(report)
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
