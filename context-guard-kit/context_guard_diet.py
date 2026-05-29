#!/usr/bin/env python3
"""Scan a project for Claude Code token-diet configuration gaps.

The scanner is intentionally local, read-only, and heuristic. It looks for
large always-in-context instruction files, missing read deny rules for bulky or
sensitive paths, and missing helper hooks/statusline settings that reduce token
burn during noisy command runs.
"""
from __future__ import annotations

import argparse
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

CONTEXT_FILE_NAMES = {"CLAUDE.md", "AGENTS.md"}
CONTEXT_MD_DIRS = {".claude/commands", ".claude/agents", ".claude/skills"}
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
        return str(path)
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
        return str(root)
    name = sanitize_path_component(root.name or "project")
    return f"{name}#path:{display_path_hash(root)}"


def rel_path(path: Path, root: Path) -> str:
    try:
        return sanitize_rel_path(path.resolve().relative_to(root.resolve()).as_posix())
    except (OSError, RuntimeError, ValueError):
        name = sanitize_path_component(path.name or "path")
        return f"{name}#path:{display_path_hash(path)}"


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
    rel = rel_path(path, root)
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
        context_files.append(item)

        if size >= huge_bytes:
            findings.append(context_finding(
                "huge-context-file",
                "high",
                rel,
                f"Context-like file is very large ({size} bytes).",
                "Move long procedures/logs/examples into opt-in skills or commands and keep only a short index in always-loaded context.",
                {"bytes": size, "threshold_bytes": huge_bytes},
            ))
        elif size >= large_bytes or lines >= long_lines:
            findings.append(context_finding(
                "large-context-file",
                "medium",
                rel,
                f"Context-like file is large ({size} bytes, sampled {lines} lines).",
                "Trim stable instructions, move volatile or lengthy material to skills/custom commands, and keep examples short.",
                {"bytes": size, "large_bytes": large_bytes, "sampled_lines": lines, "long_lines": long_lines},
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
    findings = settings_findings + config_findings + context_findings
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.id, item.path))
    return {
        "tool": "context-guard-diet",
        "root": root_label(root, args.show_paths),
        "settings": settings_summary,
        "context_files": sorted(context_files, key=lambda item: item["bytes"], reverse=True)[: args.top],
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
            print(f"- {item['path']} ({item['bytes']} bytes, sampled_lines={item['sampled_lines']})")
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
    scan.add_argument("--top", type=int, default=20, help="maximum context-like files to list")
    scan.add_argument("--large-context-bytes", type=int, default=DEFAULT_LARGE_CONTEXT_BYTES)
    scan.add_argument("--huge-context-bytes", type=int, default=DEFAULT_HUGE_CONTEXT_BYTES)
    scan.add_argument("--long-context-lines", type=int, default=DEFAULT_LONG_CONTEXT_LINES)
    args = parser.parse_args()

    if args.command == "scan":
        report = build_report(args)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print_text(report)
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
