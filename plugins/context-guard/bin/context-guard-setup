#!/usr/bin/env python3
"""Interactive project setup for the ContextGuard plugin.

The wizard applies only project-local, opt-in settings. It can run interactively
in a terminal, or non-interactively with --yes/--plan for Claude Code skills and
CI tests.
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - setup already requires POSIX no-follow file ops.
    fcntl = None

SETTINGS_REL = Path(".claude/settings.json")

RECOMMENDED_DENIES = [
    "Read(./node_modules/**)",
    "Read(./dist/**)",
    "Read(./build/**)",
    "Read(./coverage/**)",
    "Read(./logs/**)",
    "Read(./tmp/**)",
    "Read(./target/**)",
    "Read(./.next/**)",
    "Read(./.venv/**)",
    "Read(./vendor/**)",
    "Read(./.context-guard/**)",
    "Read(./.claude-token-optimizer/**)",
    "Read(./.env)",
    "Read(./.env.*)",
    "Read(./.npmrc)",
    "Read(./.pypirc)",
    "Read(./.netrc)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.kube/**)",
    "Read(~/.docker/**)",
]
HELPER_STATUSLINE = "context-guard-statusline-merged"
HELPER_REWRITE_BASH = "context-guard-rewrite-bash"
HELPER_GUARD_READ = "context-guard-guard-read"
HELPER_FAILED_NUDGE = "context-guard-failed-nudge"
HELPER_DIET = "context-guard-diet"
HELPER_EQUIVALENT_BASENAMES = {
    "context-guard-rewrite-bash": {
        "context-guard-rewrite-bash",
        "claude-token-rewrite-bash",
        "rewrite_bash_for_token_budget.py",
    },
    "context-guard-guard-read": {
        "context-guard-guard-read",
        "claude-token-guard-read",
        "guard_large_read.py",
    },
    "context-guard-failed-nudge": {
        "context-guard-failed-nudge",
        "claude-token-failed-nudge",
        "failed_attempt_nudge.py",
    },
    "context-guard-statusline-merged": {
        "context-guard-statusline-merged",
        "claude-token-statusline-merged",
        "statusline_merged.sh",
    },
    "context-guard-statusline": {
        "context-guard-statusline",
        "claude-token-statusline",
        "statusline.sh",
    },
}
DEFAULT_MODEL = "sonnet"
DEFAULT_EFFORT = "medium"
DEFAULT_FAILED_ATTEMPT_NUDGE = True
DEFAULT_POST_SETUP_SCAN_TOP = 5
POST_SETUP_SCAN_TIMEOUT_SECONDS = 20
PRIVATE_DIR_MODE = stat.S_IRWXU
ALLOWED_FIRST_ABSOLUTE_SYMLINKS = {
    "tmp": Path("/private/tmp"),
    "var": Path("/private/var"),
}


@dataclass
class Choices:
    denies: bool = True
    statusline: bool = True
    bash_hook: bool = True
    read_guard: bool = True
    model_defaults: bool = True
    # 동일 Bash 명령이 두 번 연속 실패하면 /clear 권유 — recommended setup 기본 ON.
    failed_attempt_nudge: bool = DEFAULT_FAILED_ATTEMPT_NUDGE


@dataclass
class SetupResult:
    root: Path
    settings_path: Path
    changed: bool
    applied: bool
    choices: Choices
    actions: list[str]
    backup_path: Path | None = None
    diet_scan: dict[str, Any] | None = None
    # Per-agent cross-agent plan; None preserves the legacy Claude-only payload
    # shape for callers that never engage the adapter registry.
    adapter_plan: list[dict[str, Any]] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "settings_path": str(self.settings_path),
            "changed": self.changed,
            "applied": self.applied,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "choices": self.choices.__dict__,
            "actions": self.actions,
            "diet_scan": self.diet_scan,
            "adapter_plan": self.adapter_plan,
        }


# --- Cross-agent adapter registry & dry-run setup planner --------------------
#
# ContextGuard's helpers speak plain JSON over stdin/stdout, so the same
# guardrails can be wired into more than just Claude Code. This registry maps
# known coding agents to a *capability class* that describes HOW ContextGuard
# can integrate with each one, and the planner renders a per-agent setup plan.
#
# The planner stays conservative and Claude-compatible:
# - Only the Claude native-plugin path writes hook settings (the legacy default).
# - Repo-rule agents get an idempotent advisory rule block, opt-in via --with-init.
# - native-skill / report-only agents are never written to; they are reported.
# It never sends work to external providers and never promises token/cost savings.

ADAPTER_RULE_BLOCK_BEGIN = "<!-- contextguard:begin -->"
ADAPTER_RULE_BLOCK_END = "<!-- contextguard:end -->"


class CapabilityClass:
    """How ContextGuard can integrate with a given agent."""

    NATIVE_PLUGIN = "native-plugin"  # writes native hook settings (Claude Code)
    NATIVE_SKILL = "native-skill"    # invokable skills/commands; no auto-written hooks
    REPO_RULE = "repo-rule"          # reads a repo rule file (AGENTS.md, GEMINI.md, ...)
    REPORT_ONLY = "report-only"      # no integration surface; advisory reporting only


@dataclass(frozen=True)
class AgentAdapter:
    """One known coding agent and how ContextGuard wires into it."""

    key: str
    display_name: str
    capability: str
    summary: str
    settings_rel: str | None = None
    rule_file: str | None = None
    detect: tuple[str, ...] = ()


AGENT_ADAPTERS: tuple[AgentAdapter, ...] = (
    AgentAdapter(
        key="claude",
        display_name="Claude Code",
        capability=CapabilityClass.NATIVE_PLUGIN,
        summary="Installs project-local hooks, denies, and statusline in .claude/settings.json.",
        settings_rel=str(SETTINGS_REL),
        rule_file="CLAUDE.md",
        detect=(".claude",),
    ),
    AgentAdapter(
        key="codex",
        display_name="OpenAI Codex CLI",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads AGENTS.md; add an advisory ContextGuard rule block with --with-init.",
        rule_file="AGENTS.md",
        detect=("AGENTS.md", ".codex"),
    ),
    AgentAdapter(
        key="gemini",
        display_name="Gemini CLI",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads GEMINI.md; add an advisory ContextGuard rule block with --with-init.",
        rule_file="GEMINI.md",
        detect=("GEMINI.md", ".gemini"),
    ),
    AgentAdapter(
        key="cursor",
        display_name="Cursor",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads project rules; add an advisory ContextGuard block with --with-init.",
        rule_file=".cursorrules",
        detect=(".cursor", ".cursorrules"),
    ),
    AgentAdapter(
        key="windsurf",
        display_name="Windsurf",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads project rules; add an advisory ContextGuard block with --with-init.",
        rule_file=".windsurf/rules/contextguard.md",
        detect=(".windsurf", ".windsurfrules"),
    ),
    AgentAdapter(
        key="cline",
        display_name="Cline",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads project rules; add an advisory ContextGuard block with --with-init.",
        rule_file=".clinerules",
        detect=(".clinerules", ".cline"),
    ),
    AgentAdapter(
        key="copilot",
        display_name="GitHub Copilot Coding Agent",
        capability=CapabilityClass.REPO_RULE,
        summary="Reads repository instructions; add an advisory ContextGuard block with --with-init.",
        rule_file=".github/copilot-instructions.md",
        detect=(".github/copilot-instructions.md",),
    ),
    AgentAdapter(
        key="opencode",
        display_name="OpenCode",
        capability=CapabilityClass.NATIVE_SKILL,
        summary="Expose ContextGuard helpers as OpenCode commands/rules manually; no hooks are auto-written.",
        detect=("opencode.json", ".opencode"),
    ),
    AgentAdapter(
        key="forgecode",
        display_name="ForgeCode",
        capability=CapabilityClass.REPORT_ONLY,
        summary="No automated setup surface yet; run ContextGuard helpers from the shell and keep evidence local.",
        detect=(".forgecode", "forgecode.json"),
    ),
    AgentAdapter(
        key="generic",
        display_name="Other / unknown agent",
        capability=CapabilityClass.REPORT_ONLY,
        summary="No automated setup surface; run ContextGuard helpers from the shell as needed.",
    ),
)


def adapter_registry() -> dict[str, AgentAdapter]:
    """Return the adapter registry keyed by adapter key."""
    return {adapter.key: adapter for adapter in AGENT_ADAPTERS}


def adapter_registry_payload() -> list[dict[str, Any]]:
    """JSON-friendly view of the adapter registry for --list-adapters."""
    return [
        {
            "key": adapter.key,
            "display_name": adapter.display_name,
            "capability": adapter.capability,
            "summary": adapter.summary,
            "settings_rel": adapter.settings_rel,
            "rule_file": adapter.rule_file,
            "detect": list(adapter.detect),
        }
        for adapter in AGENT_ADAPTERS
    ]


def detect_agents(root: Path) -> list[str]:
    """Return adapter keys whose detection markers exist under root."""
    found: list[str] = []
    for adapter in AGENT_ADAPTERS:
        for rel in adapter.detect:
            if (root / rel).exists():
                found.append(adapter.key)
                break
    return found


def resolve_target_adapters(root: Path, only: list[str] | None) -> list[AgentAdapter]:
    """Pick the adapters to plan/apply.

    Default keeps Claude compatibility: Claude is always targeted, plus any other
    agent detected in the repo. ``--only`` restricts to an explicit, validated set
    so a user can, for example, set up only Codex without touching Claude.
    """
    registry = adapter_registry()
    if only:
        keys: list[str] = []
        for raw in only:
            for part in str(raw).split(","):
                key = part.strip().lower()
                if not key:
                    continue
                if key not in registry:
                    known = ", ".join(sorted(registry))
                    raise SystemExit(f"Unknown adapter key: {key!r}. Known adapters: {known}.")
                if key not in keys:
                    keys.append(key)
        return [registry[key] for key in keys]
    detected = set(detect_agents(root))
    keys = ["claude"] + [
        adapter.key
        for adapter in AGENT_ADAPTERS
        if adapter.key not in ("claude", "generic") and adapter.key in detected
    ]
    return [registry[key] for key in keys]


def render_repo_rule_block() -> str:
    """Advisory rule block written into repo-rule files. No savings guarantees."""
    return "\n".join([
        ADAPTER_RULE_BLOCK_BEGIN,
        "## ContextGuard (advisory)",
        "",
        "This repository uses ContextGuard helpers to keep agent context focused.",
        "These guardrails are advisory and do not guarantee any token or cost savings.",
        "",
        "- Prefer reading symbols over whole large files.",
        "- Store large logs as local artifacts and query only the parts you need.",
        "- Trim or summarize noisy command output instead of pasting it whole.",
        "- Treat reported byte reductions as proxy evidence, not proof of savings.",
        "- Keep provider caches and semantic caches opt-in; verify cache hits before claiming savings.",
        "",
        "See the ContextGuard README for the helper commands.",
        ADAPTER_RULE_BLOCK_END,
    ])


def _read_rule_file_text(path: Path) -> str | None:
    """Best-effort no-follow read; treat missing/unreadable/symlinked files as absent.

    Unlike settings reads, a symlinked or unreadable repo rule file must not abort
    the whole setup — planning simply treats it as not-yet-initialized and the
    write path refuses to follow the symlink.
    """
    try:
        return _read_text_no_follow(path)
    except FileNotFoundError:
        return None
    except OSError:
        return None


def repo_rule_block_present(path: Path) -> bool:
    """True when the advisory ContextGuard block already exists in the rule file."""
    text = _read_rule_file_text(path)
    return text is not None and ADAPTER_RULE_BLOCK_BEGIN in text


def write_repo_rule_init(path: Path) -> dict[str, Any]:
    """Idempotently append the advisory ContextGuard block to a repo rule file.

    Returns a status dict: ``applied`` (block written), ``exists`` (already
    present), or ``skipped`` (refused, e.g. symlinked target) with a reason.
    """
    if path.exists() and path.is_symlink():
        return {"status": "skipped", "reason": f"refused to write through symlinked rule file: {path.name}"}
    if path.exists() and path.is_dir():
        return {"status": "skipped", "reason": f"refused to replace directory rule target: {path.name}"}
    existing = _read_rule_file_text(path)
    if existing is not None and ADAPTER_RULE_BLOCK_BEGIN in existing:
        return {"status": "exists"}
    block = render_repo_rule_block()
    if existing:
        new_text = existing.rstrip("\n") + "\n\n" + block + "\n"
        mode = existing_mode_or_default(path, 0o644)
    else:
        new_text = block + "\n"
        mode = 0o644
    try:
        atomic_write(path, new_text, mode)
    except OSError as exc:
        return {"status": "skipped", "reason": f"could not write repo rule file {path.name}: {exc.__class__.__name__}"}
    return {"status": "applied"}


def adapter_rule_path(root: Path, adapter: AgentAdapter) -> Path | None:
    """Resolve a repo-rule adapter's write target.

    Most adapters have a stable file target. Cline is deliberately flexible:
    existing projects commonly use `.clinerules` as a file, while some may use a
    directory-style rules surface. Pick a file when `.clinerules` is absent or a
    file; use a nested advisory file only when `.clinerules` already exists as a
    real directory. This avoids crashing or replacing a user-owned file-form rule.
    """
    if adapter.rule_file is None:
        return None
    if adapter.key == "cline":
        base = root / ".clinerules"
        if base.exists() and base.is_dir() and not base.is_symlink():
            return base / "contextguard.md"
        return base
    return root / adapter.rule_file


def build_adapter_plan(
    root: Path,
    targets: list[AgentAdapter],
    *,
    claude_actions: list[str],
    claude_changed: bool,
    claude_applied: bool,
    with_init: bool,
    applied: bool,
) -> list[dict[str, Any]]:
    """Render a per-adapter plan, performing safe repo-rule writes when applied.

    Only repo-rule adapters write, and only when both ``with_init`` and ``applied``
    are set. Native-plugin entries mirror the Claude settings result; native-skill
    and report-only entries are advisory and never write.
    """
    detected = set(detect_agents(root))
    plan: list[dict[str, Any]] = []
    for adapter in targets:
        entry: dict[str, Any] = {
            "key": adapter.key,
            "display_name": adapter.display_name,
            "capability": adapter.capability,
            "detected": adapter.key in detected,
            "summary": adapter.summary,
            "writable": False,
            "status": "report-only",
            "planned_actions": [],
            "applied_actions": [],
        }
        if adapter.capability == CapabilityClass.NATIVE_PLUGIN:
            entry["writable"] = True
            if adapter.settings_rel:
                entry["settings_path"] = str(root / adapter.settings_rel)
            entry["planned_actions"] = list(claude_actions)
            if claude_applied and claude_changed:
                entry["status"] = "applied"
            elif claude_changed:
                entry["status"] = "planned"
            else:
                entry["status"] = "unchanged"
        elif adapter.capability == CapabilityClass.REPO_RULE:
            entry["writable"] = True
            rule_path = adapter_rule_path(root, adapter)
            entry["rule_file"] = str(rule_path.relative_to(root)) if rule_path else adapter.rule_file
            if rule_path is not None and repo_rule_block_present(rule_path):
                entry["status"] = "exists"
                entry["planned_actions"] = [f"advisory ContextGuard rules already present in {entry['rule_file']}"]
            elif not with_init:
                entry["status"] = "planned"
                entry["planned_actions"] = [f"run with --with-init to add advisory ContextGuard rules to {entry['rule_file']}"]
            elif not applied:
                entry["status"] = "planned"
                entry["planned_actions"] = [f"would add advisory ContextGuard rules to {entry['rule_file']}"]
            elif rule_path is not None:
                result = write_repo_rule_init(rule_path)
                entry["status"] = result["status"]
                if result["status"] == "applied":
                    entry["applied_actions"] = [f"wrote advisory ContextGuard rules to {entry['rule_file']}"]
                    entry["planned_actions"] = list(entry["applied_actions"])
                elif result["status"] == "exists":
                    entry["planned_actions"] = [f"advisory ContextGuard rules already present in {entry['rule_file']}"]
                else:
                    entry["planned_actions"] = [result.get("reason", "skipped")]
        elif adapter.capability == CapabilityClass.NATIVE_SKILL:
            entry["planned_actions"] = [adapter.summary]
        else:  # REPORT_ONLY
            entry["planned_actions"] = [adapter.summary]
        plan.append(entry)
    return plan


class AtomicWriteDurabilityError(OSError):
    """Raised after rename when the new file exists but directory durability is uncertain."""


def find_project_root(start: Path | None = None) -> Path:
    current = (start or Path.cwd()).expanduser().resolve()
    if current.is_file():
        current = current.parent
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    return current


def resolve_setup_root(raw_root: str | None) -> Path:
    if raw_root is None:
        return find_project_root()
    root = Path(raw_root).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"Project root does not exist: {root}")
    return root.parent if root.is_file() else root


def validate_settings_target(root: Path, settings_path: Path, *, allow_home_settings: bool) -> None:
    root = root.resolve()
    home_settings = Path.home().expanduser().resolve() / SETTINGS_REL
    if settings_path.expanduser().resolve() == home_settings and not allow_home_settings:
        raise SystemExit(
            "Refusing to modify global ~/.claude/settings.json. Run from a project directory, "
            "pass --root <project>, or use --allow-home-settings if you intentionally want this."
        )
    claude_dir = root / ".claude"
    if claude_dir.exists() and claude_dir.is_symlink():
        raise SystemExit(f"Refusing to use symlinked Claude settings directory: {claude_dir}")
    if settings_path.exists() and settings_path.is_symlink():
        raise SystemExit(f"Refusing to write through symlinked settings file: {settings_path}")
    if claude_dir.exists():
        try:
            claude_dir.resolve().relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"Claude settings directory resolves outside project root: {claude_dir}") from exc


def _base_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _no_follow_flag() -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return os.O_NOFOLLOW
    raise OSError("platform does not support no-follow file opens")


def no_follow_file_ops_supported() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.mkdir in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
        and os.unlink in os.supports_dir_fd
    )


def require_no_follow_file_ops_supported() -> None:
    if not no_follow_file_ops_supported() or fcntl is None:
        raise SystemExit(
            "Setup requires POSIX no-follow file operations for safe project-local settings writes; "
            "this platform is not supported yet."
        )


def _directory_flag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def _normalized_link_target(parent: Path, raw_target: str) -> Path:
    target = Path(raw_target)
    if not target.is_absolute():
        target = parent / target
    return Path(os.path.normpath(str(target)))


def _normalize_allowed_first_absolute_symlink(path: Path) -> Path:
    """Rewrite narrow platform-owned absolute aliases before no-follow traversal."""
    if not path.is_absolute() or len(path.parts) < 2:
        return path
    first = path.parts[1]
    expected = ALLOWED_FIRST_ABSOLUTE_SYMLINKS.get(first)
    if expected is None:
        return path
    link = Path(path.anchor) / first
    try:
        if not stat.S_ISLNK(os.lstat(link).st_mode):
            return path
        if _normalized_link_target(Path(path.anchor), os.readlink(link)) != expected:
            return path
    except OSError:
        return path
    return expected.joinpath(*path.parts[2:])


def _open_directory_at(dir_fd: int, component: str, path: Path) -> int:
    flags = _base_open_flags() | _directory_flag() | _no_follow_flag()
    fd = os.open(component, flags, dir_fd=dir_fd)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(f"not a directory: {path}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _mkdir_directory_entry_at(dir_fd: int, component: str, mode: int) -> None:
    # mkdir modes are still filtered through umask.  Run only the mkdir in an
    # isolated child process with umask 0 so the parent process umask never
    # changes, then the parent immediately reopens with O_NOFOLLOW.
    helper = (
        "import os, sys\n"
        "dir_fd = int(sys.argv[1])\n"
        "component = sys.argv[2]\n"
        "mode = int(sys.argv[3], 8)\n"
        "os.umask(0)\n"
        "os.mkdir(component, mode, dir_fd=dir_fd)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-c", helper, str(dir_fd), component, oct(mode)],
        text=True,
        capture_output=True,
        pass_fds=(dir_fd,),
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or [f"exit {proc.returncode}"]
        raise OSError(f"could not create directory component safely: {component}: {detail[0]}")


def _open_regular_no_symlink(path: Path) -> int:
    if os.open not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative no-follow opens")
    path = _normalize_allowed_first_absolute_symlink(path)
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    if not components:
        raise OSError(f"not a regular file: {path}")

    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for component in components[:-1]:
            next_fd = _open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd

        fd = os.open(components[-1], _base_open_flags() | _no_follow_flag(), dir_fd=dir_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(f"not a regular file: {path}")
            return fd
        except Exception:
            os.close(fd)
            raise
    finally:
        os.close(dir_fd)


def _ensure_directory_no_symlink(path: Path, mode: int | None = None) -> int:
    if os.mkdir not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative directory creation")
    path = _normalize_allowed_first_absolute_symlink(path)
    components = list(path.parts)
    if path.is_absolute() and components:
        components = components[1:]
    root = path.anchor if path.is_absolute() else "."
    dir_fd = os.open(root or ".", _base_open_flags() | _directory_flag())
    try:
        for index, component in enumerate(components):
            try:
                next_fd = _open_directory_at(dir_fd, component, path)
            except FileNotFoundError:
                mkdir_mode = mode if mode is not None and index == len(components) - 1 else PRIVATE_DIR_MODE
                _mkdir_directory_entry_at(dir_fd, component, mkdir_mode)
                next_fd = _open_directory_at(dir_fd, component, path)
            os.close(dir_fd)
            dir_fd = next_fd
        if mode is not None and hasattr(os, "fchmod"):
            os.fchmod(dir_fd, mode)
        return dir_fd
    except Exception:
        os.close(dir_fd)
        raise


def _read_text_no_follow(path: Path) -> str:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def _read_optional_text_no_follow(path: Path) -> str | None:
    try:
        return _read_text_no_follow(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit(f"Could not read {path} without following symlinks: {exc}") from exc


def _parse_json_object_text(text: str | None, path: Path) -> dict[str, Any]:
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: line {exc.lineno}: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Settings file must contain a JSON object: {path}")
    return data


def load_json_object(path: Path) -> dict[str, Any]:
    return _parse_json_object_text(_read_optional_text_no_follow(path), path)


def ensure_permissions(settings: dict[str, Any], actions: list[str]) -> None:
    permissions = settings.get("permissions")
    if permissions is None:
        permissions = {}
        settings["permissions"] = permissions
    if not isinstance(permissions, dict):
        raise SystemExit("Refusing to replace non-object settings.permissions; repair it manually first.")
    deny = permissions.get("deny")
    if deny is None:
        deny = []
        permissions["deny"] = deny
    if not isinstance(deny, list):
        raise SystemExit("Refusing to replace non-list settings.permissions.deny; repair it manually first.")
    added = 0
    for rule in RECOMMENDED_DENIES:
        if rule not in deny:
            deny.append(rule)
            added += 1
    if added:
        actions.append(f"added {added} permissions.deny rules for bulky/sensitive paths")


def command_values(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "command" and isinstance(item, str):
                found.append(item)
            found.extend(command_values(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(command_values(item))
    return found


def matcher_covers(existing: Any, desired: str) -> bool:
    if not isinstance(existing, str):
        return False
    parts = {part.strip().lower() for part in existing.split("|") if part.strip()}
    return not parts or "*" in parts or desired.lower() in parts


def helper_argv(helper_name: str, kit_script: str, *, shell: str | None = None) -> list[str]:
    """Return argv for a bundled helper without invoking a shell."""
    script_dir = Path(__file__).resolve().parent
    colocated = script_dir / helper_name
    if colocated.exists() and os.access(colocated, os.X_OK):
        return [str(colocated)]
    repo_plugin = script_dir.parent / "plugins" / "context-guard" / "bin" / helper_name
    if repo_plugin.exists() and os.access(repo_plugin, os.X_OK):
        return [str(repo_plugin)]
    kit_path = script_dir / kit_script
    if kit_path.exists():
        prefix = [shell] if shell else [sys.executable]
        return [*prefix, str(kit_path)]
    found = shutil.which(helper_name)
    if found:
        return [str(Path(found).resolve())]
    raise SystemExit(
        f"Could not resolve required helper {helper_name!r}; install the plugin or run from a checked-out repository."
    )


def helper_command(helper_name: str, kit_script: str, *, shell: str | None = None) -> str:
    """hook 에 기록할 단일 셸 명령 문자열을 반환한다.

    경로에 공백이나 셸 메타문자가 들어와도 안전하도록 모든 분기에서 `shlex.join` 으로
    quote 한다. PATH 에서 찾은 helper 도 절대 경로로 고정해 hook hijacking 을 막는다.
    """
    argv = helper_argv(helper_name, kit_script, shell=shell)
    return shlex.join(argv)


def statusline_setting() -> dict[str, str]:
    return {"type": "command", "command": helper_command(HELPER_STATUSLINE, "statusline_merged.sh", shell="bash")}


def bash_hook_setting() -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": helper_command(HELPER_REWRITE_BASH, "rewrite_bash_for_token_budget.py")}],
    }


def read_hook_setting() -> dict[str, Any]:
    return {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": helper_command(HELPER_GUARD_READ, "guard_large_read.py")}],
    }


def failed_nudge_setting() -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": helper_command(HELPER_FAILED_NUDGE, "failed_attempt_nudge.py")}],
    }


def command_matches(existing: str, desired: str) -> bool:
    if existing == desired:
        return True
    try:
        existing_parts = shlex.split(existing) if existing else []
        desired_parts = shlex.split(desired) if desired else []
    except ValueError:
        return False
    return bool(existing_parts and desired_parts and existing_parts == desired_parts)


def command_helper_basenames(command: str) -> set[str]:
    try:
        parts = shlex.split(command) if command else []
    except ValueError:
        return set()
    if not parts:
        return set()
    index = 0
    if os.path.basename(parts[index]) == "env":
        index += 1
        while index < len(parts) and "=" in parts[index] and not parts[index].startswith("-"):
            index += 1
    if index >= len(parts):
        return set()
    head = os.path.basename(parts[index])
    interpreter_heads = {"bash", "sh"}
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", head):
        interpreter_heads.add(head)
    if head in interpreter_heads:
        for token_index in range(index + 1, len(parts)):
            token = parts[token_index]
            if token == "-c":
                if token_index + 1 < len(parts):
                    return command_helper_basenames(parts[token_index + 1])
                return set()
            if token.startswith("-"):
                continue
            return {os.path.basename(token)}
        return set()
    return {head}


def equivalent_helper_basenames(command: str) -> set[str]:
    bases = command_helper_basenames(command)
    equivalents = set(bases)
    for base in bases:
        equivalents.update(HELPER_EQUIVALENT_BASENAMES.get(base, ()))
    return equivalents


def command_matches_existing_or_equivalent(existing: str, desired: str) -> bool:
    if command_matches(existing, desired):
        return True
    desired_helpers = equivalent_helper_basenames(desired)
    if not desired_helpers:
        return False
    return bool(command_helper_basenames(existing) & desired_helpers)


def canonicalize_equivalent_command(value: Any, desired: str) -> tuple[bool, bool]:
    """Return (found_equivalent, changed), rewriting legacy/bare helpers to desired.

    Older project settings may contain bare `claude-token-*` hook commands from
    the pre-ContextGuard plugin. Treating those as equivalent for deduplication
    is useful, but preserving them can leave Claude Code hooks pointing at a
    command that no longer exists on PATH. When a matching command field is
    found, pin it to the current canonical helper command instead.
    """
    found = False
    changed = False
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "command" and isinstance(item, str) and command_matches_existing_or_equivalent(item, desired):
                found = True
                if not command_matches(item, desired):
                    value[key] = desired
                    changed = True
                continue
            child_found, child_changed = canonicalize_equivalent_command(item, desired)
            found = found or child_found
            changed = changed or child_changed
    elif isinstance(value, list):
        for item in value:
            child_found, child_changed = canonicalize_equivalent_command(item, desired)
            found = found or child_found
            changed = changed or child_changed
    return found, changed


def has_hook_command(pre_tool_use: list[Any], matcher: str, command: str) -> bool:
    for entry in pre_tool_use:
        if not isinstance(entry, dict) or not matcher_covers(entry.get("matcher"), matcher):
            continue
        if any(command_matches_existing_or_equivalent(value, command) for value in command_values(entry)):
            return True
    return False


def ensure_pre_tool_hook(settings: dict[str, Any], hook: dict[str, Any], command: str, label: str, actions: list[str]) -> None:
    _ensure_tool_hook(settings, hook, command, label, actions, event="PreToolUse")


def ensure_post_tool_hook(settings: dict[str, Any], hook: dict[str, Any], command: str, label: str, actions: list[str]) -> None:
    _ensure_tool_hook(settings, hook, command, label, actions, event="PostToolUse")


def _ensure_tool_hook(
    settings: dict[str, Any],
    hook: dict[str, Any],
    command: str,
    label: str,
    actions: list[str],
    *,
    event: str,
) -> None:
    hooks = settings.get("hooks")
    if hooks is None:
        hooks = {}
        settings["hooks"] = hooks
    if not isinstance(hooks, dict):
        raise SystemExit("Refusing to replace non-object settings.hooks; repair it manually first.")
    bucket = hooks.get(event)
    if bucket is None:
        bucket = []
        hooks[event] = bucket
    if not isinstance(bucket, list):
        raise SystemExit(f"Refusing to replace non-list settings.hooks.{event}; repair it manually first.")
    matcher = str(hook.get("matcher") or "")
    found_any = False
    changed_any = False
    for entry in bucket:
        if not isinstance(entry, dict) or not matcher_covers(entry.get("matcher"), matcher):
            continue
        found, changed = canonicalize_equivalent_command(entry, command)
        found_any = found_any or found
        changed_any = changed_any or changed
    if found_any:
        if changed_any:
            actions.append(f"migrated {label} hook to {command}")
        return
    bucket.append(copy.deepcopy(hook))
    actions.append(f"enabled {label} hook via {command}")


def summarize_diet_report(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    raw_findings = report.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("findings must be a list")
    findings: list[dict[str, Any]] = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            raise ValueError("findings must contain objects")
        findings.append(finding)

    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    top_findings = []
    for finding in findings[:DEFAULT_POST_SETUP_SCAN_TOP]:
        top_findings.append({
            "severity": finding.get("severity"),
            "id": finding.get("id"),
            "path": finding.get("path"),
            "message": finding.get("message"),
            "action": finding.get("action"),
        })
    raw_finding_count = report.get("finding_count", len(findings))
    try:
        finding_count = int(raw_finding_count)
    except (TypeError, ValueError) as exc:
        raise ValueError("finding_count must be an integer") from exc
    return {
        "status": "completed",
        "finding_count": finding_count,
        "severity_counts": counts,
        "top_findings": top_findings,
    }


def run_post_setup_diet_scan(root: Path) -> dict[str, Any]:
    argv = [
        *helper_argv(HELPER_DIET, "context_guard_diet.py"),
        "scan",
        str(root),
        "--json",
        "--top",
        str(DEFAULT_POST_SETUP_SCAN_TOP),
    ]
    try:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            check=False,
            timeout=POST_SETUP_SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "timeout", "timeout_seconds": POST_SETUP_SCAN_TIMEOUT_SECONDS}
    except UnicodeError:
        return {"status": "failed", "reason": "decode-error"}
    except OSError as exc:
        return {"status": "failed", "reason": exc.__class__.__name__}
    if proc.returncode != 0:
        return {"status": "failed", "reason": "nonzero-exit", "returncode": proc.returncode}
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"status": "failed", "reason": "invalid-json"}
    try:
        return summarize_diet_report(report)
    except ValueError:
        return {"status": "failed", "reason": "invalid-report"}


def apply_choices(settings: dict[str, Any], choices: Choices) -> list[str]:
    actions: list[str] = []
    if choices.model_defaults:
        if not settings.get("model"):
            settings["model"] = DEFAULT_MODEL
            actions.append(f"set default model to {DEFAULT_MODEL}")
        if not settings.get("effortLevel"):
            settings["effortLevel"] = DEFAULT_EFFORT
            actions.append(f"set default effortLevel to {DEFAULT_EFFORT}")
    if choices.statusline:
        statusline = statusline_setting()
        if "statusLine" not in settings:
            settings["statusLine"] = statusline
            actions.append("enabled token statusline")
        elif settings.get("statusLine") != statusline:
            actions.append("kept existing statusLine; add context-guard-statusline-merged manually if desired")
    if choices.denies:
        ensure_permissions(settings, actions)
    if choices.bash_hook:
        bash_hook = bash_hook_setting()
        bash_command = bash_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, bash_hook, bash_command, "Bash trim/sanitize", actions)
    if choices.read_guard:
        read_hook = read_hook_setting()
        read_command = read_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, read_hook, read_command, "large Read guard", actions)
    if choices.failed_attempt_nudge:
        nudge_hook = failed_nudge_setting()
        nudge_command = nudge_hook["hooks"][0]["command"]
        ensure_post_tool_hook(settings, nudge_hook, nudge_command, "failed-attempt /clear nudge", actions)
    return actions


def atomic_write(path: Path, text: str, mode: int = 0o600) -> None:
    if os.rename not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative atomic writes")
    parent_fd = _ensure_directory_no_symlink(path.parent)
    tmp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _no_follow_flag()
    fd = os.open(tmp_name, flags, mode, dir_fd=parent_fd)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.fsync(parent_fd)
        os.rename(tmp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise AtomicWriteDurabilityError(
                f"write committed but parent directory durability is uncertain: {path}"
            ) from exc
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(tmp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def existing_mode_or_default(path: Path, default: int = 0o600) -> int:
    try:
        fd = _open_regular_no_symlink(path)
    except FileNotFoundError:
        return default
    except OSError:
        return default
    try:
        return os.fstat(fd).st_mode & 0o777
    finally:
        os.close(fd)


def backup_existing(path: Path) -> Path | None:
    try:
        text = _read_text_no_follow(path)
    except FileNotFoundError:
        return None
    mode = existing_mode_or_default(path, 0o600)
    stamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup = path.with_name(f"{path.name}.bak-{stamp}-{uuid.uuid4().hex[:8]}")
    atomic_write(backup, text, mode)
    return backup


def acquire_settings_lock(path: Path) -> int:
    """Take an exclusive project-local settings lock without following links."""
    if fcntl is None:
        raise OSError("platform does not support advisory file locks")
    parent_fd = _ensure_directory_no_symlink(path.parent, PRIVATE_DIR_MODE)
    lock_name = f".{path.name}.lock"
    flags = os.O_CREAT | os.O_RDWR | _no_follow_flag()
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"settings lock is not a regular file: {path.with_name(lock_name)}")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except Exception:
        os.close(fd)
        raise


def release_settings_lock(fd: int) -> None:
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def prompt_bool(question: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{question} [{suffix}] ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer y or n.")


def interactive_choices(defaults: Choices) -> Choices:
    print("ContextGuard setup wizard")
    print("Project-local changes only. Existing settings are merged, not replaced.\n")
    choices = Choices(
        denies=prompt_bool("Add deny rules for bulky/sensitive paths?", defaults.denies),
        statusline=prompt_bool("Enable token/cost statusline?", defaults.statusline),
        bash_hook=prompt_bool("Enable Bash output trim + grep/diff sanitizer hook?", defaults.bash_hook),
        read_guard=prompt_bool("Enable large Read guard?", defaults.read_guard),
        model_defaults=prompt_bool("Set missing defaults to model=sonnet and effortLevel=medium?", defaults.model_defaults),
        failed_attempt_nudge=prompt_bool(
            "Enable failed-attempt /clear nudge? (PostToolUse hook on Bash; recommended default)",
            defaults.failed_attempt_nudge,
        ),
    )
    return choices


def choices_from_args(args: argparse.Namespace) -> Choices:
    return Choices(
        denies=not args.no_denies,
        statusline=not args.no_statusline,
        bash_hook=not args.no_bash_hook,
        read_guard=not args.no_read_guard,
        model_defaults=not args.no_model_defaults,
        failed_attempt_nudge=(
            DEFAULT_FAILED_ATTEMPT_NUDGE
            if args.failed_attempt_nudge is None
            else args.failed_attempt_nudge
        ),
    )


def render_text(result: SetupResult) -> str:
    mode = "applied" if result.applied else "plan only"
    lines = [
        f"ContextGuard setup ({mode})",
        f"root={result.root}",
        f"settings={result.settings_path}",
    ]
    if result.backup_path:
        lines.append(f"backup={result.backup_path}")
    if result.diet_scan:
        scan = result.diet_scan
        lines.append("post-setup diet scan:")
        if scan.get("status") == "completed":
            counts = scan.get("severity_counts", {})
            lines.append(
                "- "
                f"findings={scan.get('finding_count', 0)} "
                f"high={counts.get('high', 0)} medium={counts.get('medium', 0)} low={counts.get('low', 0)}"
            )
            for finding in scan.get("top_findings", []):
                lines.append(f"- [{str(finding.get('severity', '')).upper()}] {finding.get('id')} @ {finding.get('path')}")
        else:
            lines.append(f"- skipped/failed: {scan.get('reason', scan.get('status', 'unknown'))}")
    lines.append("actions:")
    if result.actions:
        lines.extend(f"- {action}" for action in result.actions)
    else:
        lines.append("- no settings changes needed")
    # Only surface the cross-agent section when a non-Claude adapter is engaged,
    # keeping the default Claude-only text output unchanged.
    extra_adapters = [entry for entry in (result.adapter_plan or []) if entry.get("key") != "claude"]
    if extra_adapters:
        lines.append("cross-agent adapters:")
        for entry in result.adapter_plan or []:
            lines.append(f"- {entry['key']} [{entry['capability']}] status={entry['status']}")
            for action in entry.get("planned_actions", []):
                lines.append(f"  - {action}")
    if not result.applied:
        lines.append("Run with --yes to apply the selected plan non-interactively.")
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> SetupResult:
    require_no_follow_file_ops_supported()
    root = resolve_setup_root(args.root)
    settings_path = root / SETTINGS_REL
    validate_settings_target(root, settings_path, allow_home_settings=args.allow_home_settings)

    # Cross-agent targets. Default keeps Claude compatibility (Claude is always
    # targeted plus any detected agent); --only narrows to an explicit set.
    targets = resolve_target_adapters(root, getattr(args, "only", None))
    claude_targeted = any(adapter.key == "claude" for adapter in targets)

    original_text = _read_optional_text_no_follow(settings_path)
    original = _parse_json_object_text(original_text, settings_path)
    settings = json.loads(json.dumps(original))

    choices = choices_from_args(args)
    interactive = (
        sys.stdin.isatty()
        and not args.yes
        and not args.plan
        and not args.dry_run
        and claude_targeted
    )
    if interactive:
        choices = interactive_choices(choices)

    actions = apply_choices(settings, choices) if claude_targeted else []
    changed = (settings != original) if claude_targeted else False

    applied = bool(args.yes and not args.dry_run and not args.plan)
    if interactive and changed:
        preview = SetupResult(root, settings_path, changed, False, choices, actions)
        print("\n" + render_text(preview))
        applied = prompt_bool("Apply these project-local changes now?", True)

    backup_path = None
    if claude_targeted and applied and changed:
        lock_fd = acquire_settings_lock(settings_path)
        try:
            current_text = _read_optional_text_no_follow(settings_path)
            if current_text != original_text:
                raise SystemExit(
                    f"Settings changed while setup was preparing changes; re-run setup to merge latest file: {settings_path}"
                )
            if original_text is not None and not args.no_backup and settings != original:
                backup_path = backup_existing(settings_path)
            if settings != original:
                atomic_write(
                    settings_path,
                    json.dumps(settings, indent=2, sort_keys=True) + "\n",
                    existing_mode_or_default(settings_path, 0o600),
                )
        finally:
            release_settings_lock(lock_fd)

    # Build the per-adapter plan; repo-rule writes happen here only when both
    # --with-init and an applying run (--yes) are in effect.
    adapter_plan = build_adapter_plan(
        root,
        targets,
        claude_actions=actions,
        claude_changed=changed,
        claude_applied=(claude_targeted and applied),
        with_init=bool(getattr(args, "with_init", False)),
        applied=applied,
    )
    # Surface any repo-rule writes in the top-level actions for visibility. Claude
    # actions are already in ``actions``; only adapter-side writes are appended.
    for entry in adapter_plan:
        actions.extend(entry.get("applied_actions", []))

    diet_scan = None
    if applied and not getattr(args, "no_diet_scan", False):
        diet_scan = run_post_setup_diet_scan(root)

    return SetupResult(
        root, settings_path, changed, applied, choices, actions, backup_path, diet_scan, adapter_plan
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactively configure ContextGuard project settings.")
    parser.add_argument("--root", default=None, help="project root to configure (default: nearest git root, else current directory)")
    parser.add_argument(
        "--allow-home-settings",
        action="store_true",
        help="allow writing ~/.claude/settings.json; off by default to keep setup project-local",
    )
    parser.add_argument("--yes", action="store_true", help="apply the recommended/selected setup without prompts")
    parser.add_argument("--plan", action="store_true", help="show the setup plan without writing files")
    parser.add_argument("--dry-run", action="store_true", help="alias for --plan")
    parser.add_argument("--json", action="store_true", help="print machine-readable result")
    parser.add_argument("--no-backup", action="store_true", help="do not create .bak-* before modifying existing settings")
    parser.add_argument("--no-denies", action="store_true", help="skip recommended permissions.deny rules")
    parser.add_argument("--no-statusline", action="store_true", help="skip token statusline")
    parser.add_argument("--no-bash-hook", action="store_true", help="skip Bash trim/sanitize hook")
    parser.add_argument("--no-read-guard", action="store_true", help="skip large Read guard hook")
    parser.add_argument("--no-model-defaults", action="store_true", help="skip model/effort defaults")
    parser.add_argument("--no-diet-scan", action="store_true", help="skip the read-only diet scan summary after applying setup")
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="ADAPTER",
        help="restrict cross-agent setup/plan to adapter key(s); comma-separated or repeatable "
        "(e.g. --only codex,gemini). Default: claude plus any detected agents.",
    )
    parser.add_argument(
        "--with-init",
        dest="with_init",
        action="store_true",
        help="also write advisory ContextGuard rule files for repo-rule agents (AGENTS.md, GEMINI.md, .cursorrules, etc.) "
        "when applying; safe and idempotent.",
    )
    parser.add_argument(
        "--list-adapters",
        dest="list_adapters",
        action="store_true",
        help="print the cross-agent adapter registry and exit",
    )
    nudge_group = parser.add_mutually_exclusive_group()
    nudge_group.add_argument(
        "--failed-attempt-nudge",
        dest="failed_attempt_nudge",
        action="store_true",
        default=None,
        help="enable PostToolUse Bash hook that suggests /clear when the same command fails twice in a row (recommended default)",
    )
    nudge_group.add_argument(
        "--no-failed-attempt-nudge",
        dest="failed_attempt_nudge",
        action="store_false",
        default=None,
        help="skip the failed-attempt /clear nudge hook",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.dry_run:
        args.plan = True
    if getattr(args, "list_adapters", False):
        payload = adapter_registry_payload()
        if args.json:
            print(json.dumps({"adapters": payload}, indent=2, sort_keys=True))
        else:
            print("ContextGuard cross-agent adapters:")
            for item in payload:
                print(f"- {item['key']} [{item['capability']}] {item['display_name']}: {item['summary']}")
        return 0
    # Safety default for non-interactive Claude Code Bash calls: do not write
    # unless --yes is explicit.
    if not sys.stdin.isatty() and not args.yes:
        args.plan = True
    result = run(args)
    if args.json:
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
