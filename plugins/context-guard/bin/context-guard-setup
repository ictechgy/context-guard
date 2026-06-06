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
    scope: str
    changed: bool
    applied: bool
    apply_requested: bool
    choices: Choices
    actions: list[str]
    backup_path: Path | None = None
    rollback_id: str | None = None
    rollback_path: Path | None = None
    warnings: list[str] | None = None
    diet_scan: dict[str, Any] | None = None
    # Per-agent cross-agent plan; None preserves the legacy Claude-only payload
    # shape for callers that never engage the adapter registry.
    adapter_plan: list[dict[str, Any]] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "settings_path": str(self.settings_path),
            "scope": self.scope,
            "changed": self.changed,
            "applied": self.applied,
            "apply_requested": self.apply_requested,
            "backup_path": str(self.backup_path) if self.backup_path else None,
            "rollback_id": self.rollback_id,
            "rollback_path": str(self.rollback_path) if self.rollback_path else None,
            "warnings": self.warnings or [],
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
CODEX_SKILL_REL = ".agents/skills/context-guard/SKILL.md"
CODEX_SKILL_MARKER_BEGIN = "<!-- contextguard:codex-skill:begin -->"
CODEX_SKILL_MARKER_END = "<!-- contextguard:codex-skill:end -->"
BRIEF_MODE_LEVELS = ("lite", "standard", "ultra")
BRIEF_MODE_OFF = "off"
BRIEF_MODE_CHOICES = (*BRIEF_MODE_LEVELS, BRIEF_MODE_OFF)
BRIEF_MODE_BLOCK_END = "<!-- END context-guard:brief-mode -->"
BRIEF_MODE_BEGIN_RE = re.compile(
    r"<!-- BEGIN context-guard:brief-mode level=(?P<level>[a-z]+) version=1 -->"
)
BRIEF_MODE_BLOCK_RE = re.compile(
    r"(?:\n{0,2})?"
    r"<!-- BEGIN context-guard:brief-mode level=(?P<level>[a-z]+) version=1 -->"
    r".*?"
    r"<!-- END context-guard:brief-mode -->"
    r"(?:\n{0,2})?",
    re.DOTALL,
)


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
    project_skill_rel: str | None = None
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
        summary="Reads AGENTS.md; add an advisory ContextGuard rule block with --with-init and optional project skill with --with-skill.",
        rule_file="AGENTS.md",
        project_skill_rel=CODEX_SKILL_REL,
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
            "project_skill_rel": adapter.project_skill_rel,
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


def render_codex_skill() -> str:
    """Render the optional project-local Codex skill for ContextGuard."""
    return "\n".join([
        "---",
        "name: context-guard",
        "description: Use ContextGuard helpers to keep Codex context focused with local-first setup, audit, trimming, and artifact commands.",
        "---",
        "",
        CODEX_SKILL_MARKER_BEGIN,
        "# ContextGuard for Codex",
        "",
        "Use this skill when a task would otherwise paste large files, long logs, or repeated setup context into Codex.",
        "",
        "## Progressive disclosure",
        "- Prefer `context-guard audit . --json` or `context-guard diet scan . --json` before broad repo reads.",
        "- Use `context-guard pack` for a small, prioritized local context pack.",
        "- Use `context-guard artifact` for large logs, then query only the relevant slices.",
        "- Use `context-guard trim-output` or `context-guard sanitize-output` before sharing noisy command output.",
        "",
        "## Setup",
        "- Project activation: `context-guard setup --agent codex --scope project --with-init --with-skill --yes`.",
        "- Plan first: `context-guard setup --agent codex --scope project --with-init --with-skill --plan`.",
        "- If `context-guard` is not on PATH, install it explicitly or run via `npx @ictechgy/context-guard`.",
        "",
        "Do not claim fixed token or cost savings from these helpers; treat byte reductions as local proxy evidence only.",
        CODEX_SKILL_MARKER_END,
        "",
    ])


def _brief_mode_source_candidates(level: str) -> list[Path]:
    """Return deterministic source candidates for packaged/repo brief snippets."""
    filename = f"brief-mode.{level}.md"
    here = Path(__file__).resolve()
    return [
        here.parent / "brief" / filename,
        here.parent.parent / "brief" / filename,
        here.parent.parent / "plugins" / "context-guard" / "brief" / filename,
        here.parent / "plugins" / "context-guard" / "brief" / filename,
    ]


def _extract_brief_mode_block(level: str, text: str) -> str | None:
    """Extract the single marker-delimited block for ``level`` from a snippet file."""
    matches = list(BRIEF_MODE_BLOCK_RE.finditer(text))
    level_matches = [match for match in matches if match.group("level") == level]
    if len(level_matches) != 1:
        return None
    block = level_matches[0].group(0).strip()
    if BRIEF_MODE_BLOCK_END not in block or not BRIEF_MODE_BEGIN_RE.search(block):
        return None
    return block


def render_fallback_brief_mode_block(level: str) -> str:
    """Render a resilient advisory brief-mode block when packaged files are absent."""
    descriptions = {
        "lite": "Keep replies focused. Trim pleasantries and repeated context, but keep helpful explanations.",
        "standard": "Lead with the result, prefer bullets, and keep only one short rationale when it matters.",
        "ultra": "Use terse result-first bullets or tables with no preamble or self-narration.",
    }
    if level not in BRIEF_MODE_LEVELS:
        raise ValueError(f"unknown brief mode level: {level}")
    return "\n".join([
        f"<!-- BEGIN context-guard:brief-mode level={level} version=1 -->",
        f"## Response style: brief mode ({level}) — advisory",
        "",
        descriptions[level],
        "This is best-effort guidance, not a hard rule.",
        "",
        "Always preserve this evidence, even when trimming wording:",
        "",
        "- Exact file paths, with line numbers where useful (e.g. `src/app.py:42`).",
        "- The exact commands you ran.",
        "- Relevant command output, error messages, stack traces, and exit codes — never hide a failure.",
        "- Code in fenced blocks whenever code is needed for correctness.",
        "- Verification status: what you ran and whether it passed or failed.",
        "- The list of changed files.",
        "- Known gaps, TODOs, and assumptions.",
        "- Caveats and anything I should double-check.",
        "",
        "This guidance does not promise reduced tokens or cost; measure real results before claiming savings.",
        BRIEF_MODE_BLOCK_END,
    ])


def render_brief_mode_block(level: str) -> str:
    """Render the marker-delimited advisory snippet for a brief-mode level."""
    if level not in BRIEF_MODE_LEVELS:
        raise ValueError(f"unknown brief mode level: {level}")
    for candidate in _brief_mode_source_candidates(level):
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        block = _extract_brief_mode_block(level, text)
        if block:
            return block
    return render_fallback_brief_mode_block(level)


def _brief_mode_levels_in_text(text: str) -> list[str]:
    return [match.group("level") for match in BRIEF_MODE_BLOCK_RE.finditer(text)]


def _remove_brief_mode_blocks(text: str) -> tuple[str, list[str]]:
    """Remove all ContextGuard-managed brief-mode blocks while preserving user text."""
    levels = _brief_mode_levels_in_text(text)
    stripped = BRIEF_MODE_BLOCK_RE.sub("\n\n", text)
    stripped = re.sub(r"\n{3,}", "\n\n", stripped).strip("\n")
    return ((stripped + "\n") if stripped else "", levels)


def _append_managed_block(existing: str, block: str) -> str:
    if existing.strip():
        return existing.rstrip("\n") + "\n\n" + block + "\n"
    return block + "\n"


def compose_rule_file_text(
    existing: str | None,
    *,
    with_init: bool,
    brief_mode: str | None,
) -> tuple[str, dict[str, Any]]:
    """Compose final repo rule text for combined init and brief-mode mutations."""
    text = existing or ""
    original_text = text
    existing_brief_levels = _brief_mode_levels_in_text(text)
    meta: dict[str, Any] = {
        "init_changed": False,
        "init_present_before": ADAPTER_RULE_BLOCK_BEGIN in text,
        "brief_levels_before": existing_brief_levels,
        "brief_changed": False,
    }
    if with_init and ADAPTER_RULE_BLOCK_BEGIN not in text:
        text = _append_managed_block(text, render_repo_rule_block())
        meta["init_changed"] = True
    if brief_mode:
        stripped, removed_levels = _remove_brief_mode_blocks(text)
        if brief_mode == BRIEF_MODE_OFF:
            text = stripped
            meta["brief_changed"] = bool(removed_levels)
        else:
            block = render_brief_mode_block(brief_mode)
            text = _append_managed_block(stripped, block)
            meta["brief_changed"] = removed_levels != [brief_mode] or text != original_text
        meta["brief_levels_removed"] = removed_levels
    meta["changed"] = text != original_text
    return text, meta


def plan_or_write_rule_file_blocks(
    path: Path,
    *,
    with_init: bool,
    brief_mode: str | None,
    applied: bool,
) -> dict[str, Any]:
    """Plan or apply managed rule-file blocks with one original backup per changed existing write."""
    result: dict[str, Any] = {
        "status": None,
        "planned_actions": [],
        "applied_actions": [],
        "brief_mode_status": None,
        "brief_mode_existing_levels": [],
        "brief_mode_backup_path": None,
        "reason": None,
    }
    state = _rule_file_state(path)
    if state["status"] not in {"missing", "file"}:
        reason = state.get("reason") or f"refused unsafe rule target: {path.name}"
        result.update({"status": "skipped", "brief_mode_status": "skipped", "reason": reason})
        result["planned_actions"].append(reason)
        return result

    existing = state.get("text")
    existing_text = str(existing or "")
    result["brief_mode_existing_levels"] = _brief_mode_levels_in_text(existing_text)
    rule_present = existing is not None and ADAPTER_RULE_BLOCK_BEGIN in existing_text
    planned_meta: dict[str, Any] | None = None
    if brief_mode:
        _, planned_meta = compose_rule_file_text(existing, with_init=with_init, brief_mode=brief_mode)

    if with_init:
        if rule_present:
            result["status"] = "exists"
            result["planned_actions"].append("advisory ContextGuard rules already present")
        elif not applied:
            result["status"] = "planned"
            result["planned_actions"].append("would add advisory ContextGuard rules")
    elif not brief_mode:
        result["status"] = "planned"
        result["planned_actions"].append("run with --with-init to add advisory ContextGuard rules")

    if brief_mode:
        brief_changed = bool(planned_meta and planned_meta.get("brief_changed"))
        if brief_mode == BRIEF_MODE_OFF:
            if brief_changed:
                result["brief_mode_status"] = "planned" if not applied else None
                if not applied:
                    result["planned_actions"].append("would remove advisory brief-mode rules")
            else:
                result["brief_mode_status"] = "absent"
                result["planned_actions"].append("advisory brief-mode rules already absent")
        else:
            levels = result["brief_mode_existing_levels"]
            if not brief_changed:
                result["brief_mode_status"] = "exists"
                result["planned_actions"].append(f"advisory brief-mode {brief_mode} rules already present")
            elif not applied:
                result["brief_mode_status"] = "planned"
                action = "refresh" if levels == [brief_mode] else ("replace" if levels else "add")
                result["planned_actions"].append(f"would {action} advisory brief-mode {brief_mode} rules")

    if not applied:
        if result["status"] is None:
            result["status"] = "planned" if result["planned_actions"] else "unchanged"
        return result

    final_text, meta = compose_rule_file_text(existing, with_init=with_init, brief_mode=brief_mode)
    if not meta["changed"]:
        if result["status"] is None:
            result["status"] = "exists" if rule_present else "unchanged"
        if result["brief_mode_status"] is None and brief_mode:
            result["brief_mode_status"] = "absent" if brief_mode == BRIEF_MODE_OFF else "exists"
        return result

    backup_path = None
    if existing is not None:
        try:
            backup_path = backup_existing(path)
        except OSError as exc:
            reason = f"could not back up repo rule file {path.name}: {exc.__class__.__name__}"
            result.update({"status": "skipped", "brief_mode_status": "skipped", "reason": reason})
            result["planned_actions"] = [reason]
            return result
    try:
        atomic_write(
            path,
            final_text,
            existing_mode_or_default(path, 0o644) if existing is not None else 0o644,
            dir_mode=0o755,
        )
    except OSError as exc:
        reason = f"could not write repo rule file {path.name}: {exc.__class__.__name__}"
        result.update({"status": "skipped", "brief_mode_status": "skipped", "reason": reason})
        result["planned_actions"] = [reason]
        return result

    if backup_path:
        result["brief_mode_backup_path"] = str(backup_path)
    if with_init:
        result["status"] = "applied" if meta["init_changed"] else "exists"
        if meta["init_changed"]:
            result["applied_actions"].append("wrote advisory ContextGuard rules")
        else:
            result["planned_actions"].append("advisory ContextGuard rules already present")
    elif result["status"] is None:
        result["status"] = "unchanged"
    if brief_mode:
        if brief_mode == BRIEF_MODE_OFF:
            result["brief_mode_status"] = "removed" if meta["brief_changed"] else "absent"
            if meta["brief_changed"]:
                result["applied_actions"].append("removed advisory brief-mode rules")
            else:
                result["planned_actions"].append("advisory brief-mode rules already absent")
        else:
            before = meta.get("brief_levels_removed") or []
            if before and before != [brief_mode]:
                result["brief_mode_status"] = "replaced"
            elif before == [brief_mode]:
                result["brief_mode_status"] = "updated"
            else:
                result["brief_mode_status"] = "applied"
            result["applied_actions"].append(f"wrote advisory brief-mode {brief_mode} rules")
    result["planned_actions"].extend(result["applied_actions"])
    return result


def _read_rule_file_text(path: Path) -> str | None:
    """Best-effort no-follow read; only a missing file is treated as absent.

    Unreadable, symlinked, directory, or otherwise unsafe targets must not be
    collapsed into "missing"; doing so could overwrite user-owned instruction
    files. Callers that want a non-throwing view should use
    ``_rule_file_state`` and skip unsafe targets explicitly.
    """
    try:
        return _read_text_no_follow(path)
    except FileNotFoundError:
        return None


def _existing_rule_parent_issue(path: Path) -> str | None:
    """Return a reason when an existing parent component is unsafe to traverse.

    Missing parent directories are intentionally allowed: atomic writes create them
    with explicit modes. Existing symlink/non-directory parents are not allowed,
    because plan/apply must agree and must never follow an attacker-swapped rule
    directory outside the project.
    """
    parts = path.parts[1:-1] if path.is_absolute() else path.parts[:-1]
    if not parts:
        return None
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in parts:
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            return None
        except OSError as exc:
            return f"could not inspect rule parent {current}: {exc.__class__.__name__}"
        if stat.S_ISLNK(st.st_mode):
            return f"refused to traverse symlinked rule parent: {current}"
        if not stat.S_ISDIR(st.st_mode):
            return f"refused non-directory rule parent: {current}"
    return None


def _rule_file_state(path: Path) -> dict[str, Any]:
    """Return a non-throwing state for project rule/skill files."""
    parent_issue = _existing_rule_parent_issue(path)
    if parent_issue:
        return {"status": "unsafe", "text": None, "reason": parent_issue}
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"status": "missing", "text": None, "reason": None}
    except OSError as exc:
        return {"status": "unsafe", "text": None, "reason": f"could not inspect rule file: {exc.__class__.__name__}"}
    if stat.S_ISLNK(st.st_mode):
        return {"status": "unsafe", "text": None, "reason": f"refused to read symlinked rule file: {path.name}"}
    if stat.S_ISDIR(st.st_mode):
        return {"status": "directory", "text": None, "reason": f"refused to replace directory rule target: {path.name}"}
    try:
        text = _read_text_no_follow(path)
    except OSError as exc:
        return {
            "status": "unsafe",
            "text": None,
            "reason": f"could not read rule file without following symlinks: {exc.__class__.__name__}",
        }
    return {"status": "file", "text": text, "reason": None}


def repo_rule_block_present(path: Path) -> bool:
    """True when the advisory ContextGuard block already exists in the rule file."""
    state = _rule_file_state(path)
    return state["status"] == "file" and ADAPTER_RULE_BLOCK_BEGIN in str(state.get("text") or "")


def write_repo_rule_init(path: Path) -> dict[str, Any]:
    """Idempotently append the advisory ContextGuard block to a repo rule file.

    Returns a status dict: ``applied`` (block written), ``exists`` (already
    present), or ``skipped`` (refused, e.g. symlinked target) with a reason.
    """
    state = _rule_file_state(path)
    if state["status"] not in {"missing", "file"}:
        return {"status": "skipped", "reason": state.get("reason") or f"refused unsafe rule target: {path.name}"}
    existing = state.get("text")
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
        atomic_write(path, new_text, mode, dir_mode=0o755)
    except OSError as exc:
        return {"status": "skipped", "reason": f"could not write repo rule file {path.name}: {exc.__class__.__name__}"}
    return {"status": "applied"}


def codex_skill_status(path: Path) -> str:
    state = _rule_file_state(path)
    if state["status"] == "missing":
        return "missing"
    if state["status"] != "file":
        return "unsafe"
    text = str(state.get("text") or "")
    if text == render_codex_skill():
        return "exists"
    if CODEX_SKILL_MARKER_BEGIN in text and CODEX_SKILL_MARKER_END in text:
        return "update-needed"
    return "foreign"


def write_codex_project_skill(path: Path) -> dict[str, Any]:
    """Idempotently create/update the project-local Codex ContextGuard skill."""
    state = _rule_file_state(path)
    if state["status"] not in {"missing", "file"}:
        return {"status": "skipped", "reason": state.get("reason") or f"refused unsafe skill target: {path.name}"}
    status = codex_skill_status(path)
    if status == "exists":
        return {"status": "exists"}
    if status == "foreign":
        return {
            "status": "skipped",
            "reason": f"refused to overwrite non-ContextGuard Codex skill file: {path}",
        }
    try:
        atomic_write(path, render_codex_skill(), 0o644, dir_mode=0o755)
    except OSError as exc:
        return {"status": "skipped", "reason": f"could not write Codex skill file {path}: {exc.__class__.__name__}"}
    return {"status": "updated" if status == "update-needed" else "applied"}


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
    scope: str,
    claude_actions: list[str],
    claude_changed: bool,
    claude_applied: bool,
    with_init: bool,
    with_skill: bool,
    applied: bool,
    brief_mode: str | None = None,
) -> list[dict[str, Any]]:
    """Render a per-adapter plan, performing safe repo-rule writes when applied.

    Repo-rule adapters write when ``applied`` is set and either ``with_init`` or
    project-scope ``brief_mode`` requested a managed rule-file block. Native-plugin
    entries mirror the Claude settings result; native-skill and report-only entries
    are advisory and never write.
    """
    detected = set(detect_agents(root))
    plan: list[dict[str, Any]] = []
    for adapter in targets:
        entry: dict[str, Any] = {
            "key": adapter.key,
            "display_name": adapter.display_name,
            "capability": adapter.capability,
            "scope": scope,
            "detected": adapter.key in detected,
            "summary": adapter.summary,
            "writable": False,
            "status": "report-only",
            "planned_actions": [],
            "applied_actions": [],
            "unsupported_reason": None,
        }
        if brief_mode:
            entry["brief_mode"] = brief_mode
            entry["brief_mode_status"] = "unsupported"
            entry["brief_mode_level"] = None if brief_mode == BRIEF_MODE_OFF else brief_mode
            entry["brief_mode_file"] = None
            entry["brief_mode_existing_levels"] = []
            entry["brief_mode_backup_path"] = None
            entry["brief_mode_reason"] = None
        if scope == "user" and adapter.key != "claude":
            entry["status"] = "unsupported"
            entry["writable"] = False
            entry["unsupported_reason"] = (
                f"user-scope activation for {adapter.display_name} is not implemented/verified yet; "
                "use --scope project or run the helper commands manually."
            )
            entry["planned_actions"] = [entry["unsupported_reason"]]
            if brief_mode:
                entry["brief_mode_reason"] = entry["unsupported_reason"]
            plan.append(entry)
            continue
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
            if brief_mode:
                rule_path = adapter_rule_path(root, adapter)
                entry["rule_file"] = str(rule_path.relative_to(root)) if rule_path and scope == "project" else adapter.rule_file
                entry["brief_mode_file"] = entry.get("rule_file")
                if scope != "project" or rule_path is None:
                    entry["brief_mode_status"] = "unsupported"
                    entry["brief_mode_reason"] = "brief-mode rule-file writes are project-scope only"
                    entry["planned_actions"].append(entry["brief_mode_reason"])
                else:
                    result = plan_or_write_rule_file_blocks(
                        rule_path,
                        with_init=False,
                        brief_mode=brief_mode,
                        applied=applied,
                    )
                    entry["brief_mode_status"] = result["brief_mode_status"]
                    entry["brief_mode_existing_levels"] = result["brief_mode_existing_levels"]
                    entry["brief_mode_backup_path"] = result["brief_mode_backup_path"]
                    entry["brief_mode_reason"] = result.get("reason")
                    for action in result.get("planned_actions", []):
                        entry["planned_actions"].append(f"{action} in {entry['rule_file']}")
                    for action in result.get("applied_actions", []):
                        entry["applied_actions"].append(f"{action} in {entry['rule_file']}")
                    if result.get("applied_actions"):
                        entry["status"] = "applied"
        elif adapter.capability == CapabilityClass.REPO_RULE:
            entry["writable"] = True
            rule_path = adapter_rule_path(root, adapter)
            entry["rule_file"] = str(rule_path.relative_to(root)) if rule_path else adapter.rule_file
            if brief_mode and scope != "project":
                entry["brief_mode_status"] = "unsupported"
                entry["brief_mode_reason"] = "brief-mode rule-file writes are project-scope only"
                entry["planned_actions"].append(entry["brief_mode_reason"])
            elif brief_mode and rule_path is not None:
                entry["brief_mode_file"] = entry["rule_file"]
                result = plan_or_write_rule_file_blocks(
                    rule_path,
                    with_init=with_init,
                    brief_mode=brief_mode,
                    applied=applied,
                )
                entry["status"] = result["status"]
                entry["brief_mode_status"] = result["brief_mode_status"]
                entry["brief_mode_existing_levels"] = result["brief_mode_existing_levels"]
                entry["brief_mode_backup_path"] = result["brief_mode_backup_path"]
                entry["brief_mode_reason"] = result.get("reason")
                entry["planned_actions"] = [f"{action} in {entry['rule_file']}" for action in result.get("planned_actions", [])]
                entry["applied_actions"] = [f"{action} in {entry['rule_file']}" for action in result.get("applied_actions", [])]
                if result.get("applied_actions"):
                    entry["status"] = "applied"
            else:
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
            if adapter.key == "codex" and adapter.project_skill_rel:
                skill_path = root / adapter.project_skill_rel
                entry["project_skill_file"] = adapter.project_skill_rel
                skill_state = codex_skill_status(skill_path)
                entry["project_skill_status"] = skill_state
                if skill_state == "exists":
                    entry["planned_actions"].append(
                        f"project Codex skill already present in {adapter.project_skill_rel}"
                    )
                elif skill_state == "unsafe":
                    entry["planned_actions"].append(
                        f"refused unsafe project Codex skill target at {adapter.project_skill_rel}"
                    )
                elif not with_skill:
                    entry["planned_actions"].append(
                        f"run with --with-skill to generate project Codex skill at {adapter.project_skill_rel}"
                    )
                elif not applied:
                    entry["planned_actions"].append(
                        f"would generate project Codex skill at {adapter.project_skill_rel}"
                    )
                else:
                    skill_result = write_codex_project_skill(skill_path)
                    entry["project_skill_status"] = skill_result["status"]
                    if skill_result["status"] in {"applied", "updated"}:
                        action = f"wrote project Codex skill to {adapter.project_skill_rel}"
                        entry["applied_actions"].append(action)
                        entry["planned_actions"].append(action)
                        if entry["status"] in {"planned", "exists", "unchanged"}:
                            entry["status"] = "applied"
                    elif skill_result["status"] == "exists":
                        entry["planned_actions"].append(
                            f"project Codex skill already present in {adapter.project_skill_rel}"
                        )
                    else:
                        entry["planned_actions"].append(skill_result.get("reason", "skipped"))
        elif adapter.capability == CapabilityClass.NATIVE_SKILL:
            entry["planned_actions"] = [adapter.summary]
            if brief_mode:
                entry["brief_mode_status"] = "unsupported"
                entry["brief_mode_reason"] = "adapter has no managed rule-file target"
                entry["planned_actions"].append(entry["brief_mode_reason"])
        else:  # REPORT_ONLY
            entry["planned_actions"] = [adapter.summary]
            if brief_mode:
                entry["brief_mode_status"] = "unsupported"
                entry["brief_mode_reason"] = "adapter has no managed rule-file target"
                entry["planned_actions"].append(entry["brief_mode_reason"])
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


def normalize_scope(raw_scope: str | None) -> str:
    scope = str(raw_scope or "project").strip().lower()
    if scope == "global":
        return "user"
    if scope not in {"project", "user"}:
        raise SystemExit("Unknown setup scope: {!r}. Known scopes: project, user.".format(raw_scope))
    return scope


def resolve_scope_root(raw_root: str | None, scope: str) -> Path:
    if scope == "project":
        return resolve_setup_root(raw_root)
    home = Path.home().expanduser().resolve()
    if home == Path(home.anchor or "/"):
        raise SystemExit("Refusing user-scope setup because HOME resolves to a filesystem root.")
    if not home.exists() or not home.is_dir():
        raise SystemExit(f"Refusing user-scope setup because HOME is not a directory: {home}")
    return home


def explicit_agent_selection(args: argparse.Namespace) -> list[str] | None:
    values: list[str] = []
    for attr in ("agent", "only"):
        raw_values = getattr(args, attr, None)
        if not raw_values:
            continue
        for raw in raw_values:
            for part in str(raw).split(","):
                key = part.strip()
                if key:
                    values.append(key)
    return values or None


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


def _ensure_directory_no_symlink(path: Path, mode: int | None = None, *, parents_mode: int | None = None) -> int:
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
            created = False
            mkdir_mode = (
                mode
                if mode is not None and index == len(components) - 1
                else (parents_mode if parents_mode is not None else PRIVATE_DIR_MODE)
            )
            try:
                next_fd = _open_directory_at(dir_fd, component, path)
            except FileNotFoundError:
                _mkdir_directory_entry_at(dir_fd, component, mkdir_mode)
                next_fd = _open_directory_at(dir_fd, component, path)
                created = True
            if created and hasattr(os, "fchmod"):
                os.fchmod(next_fd, mkdir_mode)
            os.close(dir_fd)
            dir_fd = next_fd
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


def atomic_write(path: Path, text: str, mode: int = 0o600, *, dir_mode: int = PRIVATE_DIR_MODE) -> None:
    if os.rename not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative atomic writes")
    parent_fd = _ensure_directory_no_symlink(path.parent, dir_mode, parents_mode=dir_mode)
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


def write_rollback_record(
    *,
    root: Path,
    scope: str,
    settings_path: Path,
    backup_path: Path | None,
    original_existed: bool,
) -> tuple[str | None, Path | None]:
    """Record a minimal rollback handle for user-scope writes.

    Project-scope setup keeps the legacy backup-only behavior. User-scope setup
    can affect many future projects, so every write gets a local rollback record
    under the user's ContextGuard state directory.
    """
    if scope != "user":
        return None, None
    rollback_id = _dt.datetime.now().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    rollback_dir = root / ".context-guard" / "rollback"
    rollback_path = rollback_dir / f"{rollback_id}.json"
    record = {
        "schema_version": "contextguard.rollback.v1",
        "rollback_id": rollback_id,
        "created_at": _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z"),
        "scope": scope,
        "target_path": str(settings_path),
        "backup_path": str(backup_path) if backup_path else None,
        "original_existed": original_existed,
        "restore": (
            f"cp {shlex.quote(str(backup_path))} {shlex.quote(str(settings_path))}"
            if backup_path
            else f"rm -f {shlex.quote(str(settings_path))}"
        ),
    }
    atomic_write(rollback_path, json.dumps(record, indent=2, sort_keys=True) + "\n", 0o600)
    return rollback_id, rollback_path


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
    mode = "applied" if result.applied else ("apply requested; no writes" if result.apply_requested else "plan only")
    lines = [
        f"ContextGuard setup ({mode})",
        f"scope={result.scope}",
        f"root={result.root}",
        f"settings={result.settings_path}",
    ]
    if result.backup_path:
        lines.append(f"backup={result.backup_path}")
    if result.rollback_path:
        lines.append(f"rollback={result.rollback_path}")
    for warning in result.warnings or []:
        lines.append(f"warning={warning}")
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
    brief_adapters = [entry for entry in (result.adapter_plan or []) if entry.get("brief_mode")]
    if extra_adapters or brief_adapters:
        lines.append("cross-agent adapters:")
        for entry in result.adapter_plan or []:
            lines.append(f"- {entry['key']} [{entry['capability']}] status={entry['status']}")
            for action in entry.get("planned_actions", []):
                lines.append(f"  - {action}")
            if entry.get("brief_mode_backup_path"):
                lines.append(f"  - backup={entry['brief_mode_backup_path']}")
    if result.apply_requested and not result.applied:
        lines.append("No supported writes were applied.")
    elif not result.applied:
        lines.append("Run with --yes to apply the selected plan non-interactively.")
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> SetupResult:
    require_no_follow_file_ops_supported()
    scope = normalize_scope(getattr(args, "scope", "project"))
    root = resolve_scope_root(args.root, scope)
    settings_path = root / SETTINGS_REL
    warnings: list[str] = []
    if scope == "user":
        warnings.append(
            "user-scope setup can affect future projects; writes require --yes and explicit --agent/--only selection"
        )

    # Cross-agent targets. Default keeps Claude compatibility (Claude is always
    # targeted plus any detected agent); --only narrows to an explicit set.
    selected_agents = explicit_agent_selection(args)
    targets = resolve_target_adapters(root, selected_agents)
    claude_targeted = any(adapter.key == "claude" for adapter in targets)

    if claude_targeted:
        validate_settings_target(root, settings_path, allow_home_settings=(args.allow_home_settings or scope == "user"))
        original_text = _read_optional_text_no_follow(settings_path)
        original = _parse_json_object_text(original_text, settings_path)
        settings = json.loads(json.dumps(original))
    else:
        original_text = None
        original = {}
        settings = {}

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

    apply_requested = bool(args.yes and not args.dry_run and not args.plan)
    if scope == "user" and apply_requested and not selected_agents:
        raise SystemExit(
            "Refusing user-scope writes without an explicit agent. "
            "Pass --agent claude (or another specific adapter) with --scope user."
        )
    if interactive and changed:
        preview = SetupResult(
            root=root,
            settings_path=settings_path,
            scope=scope,
            changed=changed,
            applied=False,
            apply_requested=False,
            choices=choices,
            actions=actions,
            warnings=warnings,
        )
        print("\n" + render_text(preview))
        prompt_scope = "user-level" if scope == "user" else "project-local"
        apply_requested = prompt_bool(f"Apply these {prompt_scope} changes now?", True)
        if scope == "user" and apply_requested and not selected_agents:
            raise SystemExit(
                "Refusing user-scope writes without an explicit agent. "
                "Pass --agent claude (or another specific adapter) with --scope user."
            )

    backup_path = None
    rollback_id = None
    rollback_path = None
    claude_settings_written = False
    if claude_targeted and apply_requested and changed:
        if scope == "user" and original_text is not None and args.no_backup:
            raise SystemExit("Refusing --no-backup for user-scope changes to existing Claude settings.")
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
                rollback_id, rollback_path = write_rollback_record(
                    root=root,
                    scope=scope,
                    settings_path=settings_path,
                    backup_path=backup_path,
                    original_existed=(original_text is not None),
                )
                atomic_write(
                    settings_path,
                    json.dumps(settings, indent=2, sort_keys=True) + "\n",
                    existing_mode_or_default(settings_path, 0o600),
                )
                claude_settings_written = True
        finally:
            release_settings_lock(lock_fd)

    # Build the per-adapter plan; repo-rule writes happen here when an applying
    # run (--yes) requested --with-init or project-scope --brief-mode.
    adapter_plan = build_adapter_plan(
        root,
        targets,
        scope=scope,
        claude_actions=actions,
        claude_changed=changed,
        claude_applied=(claude_targeted and apply_requested),
        with_init=bool(getattr(args, "with_init", False)),
        with_skill=bool(getattr(args, "with_skill", False)),
        applied=apply_requested,
        brief_mode=getattr(args, "brief_mode", None),
    )
    # Surface any repo-rule writes in the top-level actions for visibility. Claude
    # actions are already in ``actions``; only adapter-side writes are appended.
    for entry in adapter_plan:
        actions.extend(entry.get("applied_actions", []))
    adapter_writes = any(entry.get("applied_actions") for entry in adapter_plan)
    applied = bool(claude_settings_written or adapter_writes)

    diet_scan = None
    if (applied or (apply_requested and claude_targeted)) and not getattr(args, "no_diet_scan", False):
        diet_scan = run_post_setup_diet_scan(root)

    return SetupResult(
        root=root,
        settings_path=settings_path,
        scope=scope,
        changed=changed,
        applied=applied,
        apply_requested=apply_requested,
        choices=choices,
        actions=actions,
        backup_path=backup_path,
        rollback_id=rollback_id,
        rollback_path=rollback_path,
        warnings=warnings,
        diet_scan=diet_scan,
        adapter_plan=adapter_plan,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactively configure ContextGuard project settings.")
    parser.add_argument("--root", default=None, help="project root to configure (default: nearest git root, else current directory)")
    parser.add_argument(
        "--scope",
        choices=("project", "user", "global"),
        default="project",
        help="setup scope: project-local by default; user/global targets only known user-level paths and requires explicit --agent for writes",
    )
    parser.add_argument(
        "--allow-home-settings",
        action="store_true",
        help="deprecated compatibility alias for user-level Claude settings; prefer --scope user --agent claude",
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
        "--agent",
        action="append",
        default=None,
        metavar="ADAPTER",
        help="adapter key(s) to configure; comma-separated or repeatable. Alias for --only.",
    )
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
        "--with-skill",
        dest="with_skill",
        action="store_true",
        help="also generate optional project-local skill files where supported, currently Codex .agents/skills/context-guard/SKILL.md.",
    )
    parser.add_argument(
        "--brief-mode",
        choices=BRIEF_MODE_CHOICES,
        default=None,
        help="plan/apply advisory brief-mode snippets in project rule files; choose lite, standard, ultra, or off to remove.",
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
