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
import hashlib
import json
import os
import pwd
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import types
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
    "Read(./.npmrc)",
    "Read(./.pypirc)",
    "Read(./.netrc)",
    "Read(~/.ssh/**)",
    "Read(~/.aws/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.kube/**)",
    "Read(~/.docker/**)",
]
PRODUCT_OWNED_ENV_READ_DENIES = frozenset({
    "Read(./.env)",
    "Read(./.env.*)",
})
HELPER_STATUSLINE = "context-guard-statusline-merged"
HELPER_STATUSLINE_PLAIN = "context-guard-statusline"
HELPER_REWRITE_BASH = "context-guard-rewrite-bash"
HELPER_GUARD_READ = "context-guard-guard-read"
HELPER_FAILED_NUDGE = "context-guard-failed-nudge"
HELPER_DIET = "context-guard-diet"
ROOT_PACKAGE_NAME = "@ictechgy/context-guard"
RECEIPT_PACKAGE_NAME = "@ictechgy/context-guard-receipt"
_BASH_REFERENCE_UNAVAILABLE = (
    "bash_reference_v1 reference unavailable"
)
_BASH_REFERENCE_RECOVERY = (
    "repair or reinstall the exact paired npm packages in the target project, "
    "ensure a trusted system Node interpreter is available, then rerun setup"
)
BASH_REFERENCE_POLICY_MAX_BYTES = 512 * 1024
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
PATH_HELPER_PROBE_TIMEOUT_SECONDS = 5
PATH_HELPER_PROBE_MAX_OUTPUT_BYTES = 4096
ISOLATED_RUNTIME_PATH = os.defpath
READ_GUARD_BEHAVIOR_ENV = (
    "CONTEXT_GUARD_READ_GUARD",
    "CLAUDE_TOKEN_READ_GUARD",
    "CONTEXT_GUARD_READ_GUARD_MAX_BYTES",
    "CLAUDE_TOKEN_READ_GUARD_MAX_BYTES",
    "CONTEXT_GUARD_READ_GUARD_MAX_LINES",
    "CLAUDE_TOKEN_READ_GUARD_MAX_LINES",
    "CONTEXT_GUARD_READ_GUARD_PROOF_BYTES",
    "CLAUDE_TOKEN_READ_GUARD_PROOF_BYTES",
)
REWRITE_BEHAVIOR_ENV = (
    "CONTEXT_GUARD_SANITIZER_FAIL_OPEN",
    "CLAUDE_TOKEN_SANITIZER_FAIL_OPEN",
)
STATUSLINE_BEHAVIOR_ENV = (
    "CONTEXT_GUARD_STATUSLINE_INPUT_MAX_BYTES",
    "CLAUDE_TOKEN_STATUSLINE_INPUT_MAX_BYTES",
    "CONTEXT_GUARD_STATUSLINE_CTX_WARN",
    "CLAUDE_TOKEN_STATUSLINE_CTX_WARN",
    "CONTEXT_GUARD_STATUSLINE_CACHE_TTL_SECONDS",
)
HOMEBREW_NODE_CANDIDATES = (
    Path("/opt/homebrew/bin/node"),
    Path("/usr/local/bin/node"),
)
BEHAVIOR_ENV_VALUE_RE = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")
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
    # Provider-visible receipt handles are an explicit, default-off choice.
    bash_reference_v1: bool = False
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

LEGACY_ADAPTER_RULE_BLOCK_BEGIN = "<!-- contextguard:begin -->"
LEGACY_ADAPTER_RULE_BLOCK_END = "<!-- contextguard:end -->"
ADAPTER_RULE_BLOCK_BEGIN = "<!-- BEGIN context-guard:repo-rules version=1 -->"
ADAPTER_RULE_BLOCK_END = "<!-- END context-guard:repo-rules -->"
CODEX_SKILL_REL = ".agents/skills/context-guard/SKILL.md"
LEGACY_CODEX_SKILL_MARKER_BEGIN = "<!-- contextguard:codex-skill:begin -->"
LEGACY_CODEX_SKILL_MARKER_END = "<!-- contextguard:codex-skill:end -->"
CODEX_SKILL_MARKER_BEGIN = "<!-- BEGIN context-guard:codex-skill version=1 -->"
CODEX_SKILL_MARKER_END = "<!-- END context-guard:codex-skill -->"
BRIEF_MODE_LEVELS = ("lite", "standard", "ultra")
BRIEF_MODE_OFF = "off"
BRIEF_MODE_CHOICES = (*BRIEF_MODE_LEVELS, BRIEF_MODE_OFF)
NARRATION_MODE_CHOICES = ("quiet", "default")
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

LEGACY_REPO_RULE_MARKER_BEGIN = LEGACY_ADAPTER_RULE_BLOCK_BEGIN.encode("ascii")
LEGACY_REPO_RULE_MARKER_END = LEGACY_ADAPTER_RULE_BLOCK_END.encode("ascii")
REPO_RULE_MARKER_V1_BEGIN = ADAPTER_RULE_BLOCK_BEGIN.encode("ascii")
REPO_RULE_MARKER_V1_END = ADAPTER_RULE_BLOCK_END.encode("ascii")
LEGACY_CODEX_SKILL_MARKER_V0_BEGIN = LEGACY_CODEX_SKILL_MARKER_BEGIN.encode("ascii")
LEGACY_CODEX_SKILL_MARKER_V0_END = LEGACY_CODEX_SKILL_MARKER_END.encode("ascii")
CODEX_SKILL_MARKER_V1_BEGIN = CODEX_SKILL_MARKER_BEGIN.encode("ascii")
CODEX_SKILL_MARKER_V1_END = CODEX_SKILL_MARKER_END.encode("ascii")
BRIEF_MODE_MARKER_END = BRIEF_MODE_BLOCK_END.encode("ascii")
NARRATION_MODE_MARKER_BEGIN = b"<!-- BEGIN context-guard:narration-mode mode=quiet version=1 -->"
NARRATION_MODE_MARKER_END = b"<!-- END context-guard:narration-mode -->"


@dataclass(frozen=True)
class ManagedMarker:
    kind: str
    version: int
    begin: bytes
    end: bytes
    variant: str | None = None


MANAGED_MARKERS = (
    ManagedMarker(
        "repo-rules",
        0,
        LEGACY_REPO_RULE_MARKER_BEGIN,
        LEGACY_REPO_RULE_MARKER_END,
        "legacy",
    ),
    ManagedMarker(
        "repo-rules",
        1,
        REPO_RULE_MARKER_V1_BEGIN,
        REPO_RULE_MARKER_V1_END,
    ),
    ManagedMarker(
        "codex-skill",
        0,
        LEGACY_CODEX_SKILL_MARKER_V0_BEGIN,
        LEGACY_CODEX_SKILL_MARKER_V0_END,
        "legacy",
    ),
    ManagedMarker(
        "codex-skill",
        1,
        CODEX_SKILL_MARKER_V1_BEGIN,
        CODEX_SKILL_MARKER_V1_END,
    ),
    *(
        ManagedMarker(
            "brief-mode",
            1,
            f"<!-- BEGIN context-guard:brief-mode level={level} version=1 -->".encode("ascii"),
            BRIEF_MODE_MARKER_END,
            level,
        )
        for level in BRIEF_MODE_LEVELS
    ),
    ManagedMarker(
        "narration-mode",
        1,
        NARRATION_MODE_MARKER_BEGIN,
        NARRATION_MODE_MARKER_END,
        "quiet",
    ),
)
_MANAGED_BEGIN_MARKERS = {marker.begin: marker for marker in MANAGED_MARKERS}
_MANAGED_END_MARKERS: dict[bytes, tuple[ManagedMarker, ...]] = {}
for _marker in MANAGED_MARKERS:
    _MANAGED_END_MARKERS[_marker.end] = (*_MANAGED_END_MARKERS.get(_marker.end, ()), _marker)


@dataclass(frozen=True)
class ManagedSpan:
    kind: str
    version: int
    variant: str | None
    start: int
    end: int


@dataclass(frozen=True)
class ManagedParseResult:
    status: str
    spans: tuple[ManagedSpan, ...] = ()
    reason: str | None = None


@dataclass(frozen=True)
class ManagedFileSnapshot:
    data: bytes | None
    metadata: tuple[int, int, int, int, int] | None


class ManagedFileConflictError(OSError):
    """Raised when a managed target no longer matches its planned snapshot."""


def _iter_binary_lines(data: bytes):
    offset = 0
    while offset < len(data):
        newline = data.find(b"\n", offset)
        if newline < 0:
            yield offset, len(data), data[offset:], b""
            return
        end = newline + 1
        if newline > offset and data[newline - 1 : newline] == b"\r":
            content, ending = data[offset : newline - 1], b"\r\n"
        else:
            content, ending = data[offset:newline], b"\n"
        yield offset, end, content, ending
        offset = end


def _fence_open(content: bytes) -> tuple[int, int] | None:
    match = re.match(rb"^ {0,3}(`{3,}|~{3,}).*$", content)
    if not match:
        return None
    run = match.group(1)
    return run[0], len(run)


def _fence_close(content: bytes, fence: tuple[int, int]) -> bool:
    char, minimum = fence
    match = re.match(rb"^ {0,3}([`~]+) *$", content)
    if not match:
        return False
    run = match.group(1)
    return bool(run and run[0] == char and len(run) >= minimum and all(byte == char for byte in run))


def _looks_like_contextguard_marker(content: bytes) -> bool:
    lowered = content.lstrip(b" \t").lower()
    return (
        lowered.startswith(b"<!--")
        and b"-->" in lowered
        and (b"contextguard:" in lowered or b"context-guard:" in lowered)
    )


def _scan_managed_spans(data: bytes) -> ManagedParseResult:
    spans: list[ManagedSpan] = []
    open_marker: tuple[ManagedMarker, int] | None = None
    fence: tuple[int, int] | None = None
    unsupported = False
    malformed = False
    for start, end, content, ending in _iter_binary_lines(data):
        if fence is not None:
            if _fence_close(content, fence):
                fence = None
            continue
        opener = _fence_open(content)
        if opener is not None:
            fence = opener
            continue
        marker = _MANAGED_BEGIN_MARKERS.get(content) if ending else None
        end_markers = _MANAGED_END_MARKERS.get(content, ()) if ending else ()
        if marker is not None:
            if open_marker is not None:
                malformed = True
            else:
                open_marker = (marker, start)
            continue
        if end_markers:
            if open_marker is None:
                malformed = True
                continue
            active, span_start = open_marker
            if active.end != content:
                malformed = True
                open_marker = None
                continue
            spans.append(
                ManagedSpan(
                    kind=active.kind,
                    version=active.version,
                    variant=active.variant,
                    start=span_start,
                    end=end,
                )
            )
            open_marker = None
            continue
        if _looks_like_contextguard_marker(content):
            unsupported = True
    if open_marker is not None:
        malformed = True
    if malformed:
        return ManagedParseResult("malformed", tuple(spans), "malformed managed marker structure")
    if unsupported:
        return ManagedParseResult("unsupported", tuple(spans), "unsupported managed marker literal")
    return ManagedParseResult("valid" if spans else "absent", tuple(spans))


def parse_managed_bytes(data: bytes, *, kind: str | None = None) -> ManagedParseResult:
    """Classify exact ContextGuard-managed raw-byte spans without decoding user bytes."""
    scanned = _scan_managed_spans(data)
    if scanned.status in {"malformed", "unsupported"}:
        return scanned
    spans = tuple(span for span in scanned.spans if kind is None or span.kind == kind)
    by_kind: dict[str, int] = {}
    for span in spans:
        by_kind[span.kind] = by_kind.get(span.kind, 0) + 1
    if any(count > 1 for count in by_kind.values()) or (kind is None and len(spans) > 1):
        return ManagedParseResult("ambiguous", spans, "multiple managed spans")
    return ManagedParseResult("valid" if spans else "absent", spans)


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


def _render_codex_skill_with_markers(begin: str, end: str) -> str:
    return "\n".join([
        "---",
        "name: context-guard",
        "description: Use ContextGuard helpers to keep Codex context focused with local-first setup, audit, trimming, and artifact commands.",
        "---",
        "",
        begin,
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
        end,
        "",
    ])


def render_codex_skill() -> str:
    """Render the v1 project-local Codex skill."""
    return _render_codex_skill_with_markers(CODEX_SKILL_MARKER_BEGIN, CODEX_SKILL_MARKER_END)


def render_legacy_codex_skill_v0() -> str:
    """Render the exact legacy whole-file image released before managed-span v1."""
    return _render_codex_skill_with_markers(
        LEGACY_CODEX_SKILL_MARKER_BEGIN,
        LEGACY_CODEX_SKILL_MARKER_END,
    )


LEGACY_CODEX_SKILL_SHA256_ALLOWLIST = {
    hashlib.sha256(render_legacy_codex_skill_v0().encode("utf-8")).hexdigest(): "legacy-v0-current",
}


def render_codex_skill_block_bytes() -> bytes:
    rendered = render_codex_skill().encode("utf-8")
    start = rendered.index(CODEX_SKILL_MARKER_V1_BEGIN)
    end = rendered.index(CODEX_SKILL_MARKER_V1_END, start) + len(CODEX_SKILL_MARKER_V1_END)
    if rendered[end : end + 1] == b"\n":
        end += 1
    return rendered[start:end]


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


def render_quiet_narration_block() -> str:
    """Render embedded canonical bytes without opening any non-target file."""
    return "\n".join([
        NARRATION_MODE_MARKER_BEGIN.decode("ascii"),
        "## ContextGuard quiet narration (advisory)",
        "",
        "Best effort: reduce only discretionary intermediate narration. Skip routine preambles,",
        "per-tool narration, filler, and repeated interim summaries when they add no useful",
        "information.",
        "",
        "Always preserve required user-facing communication:",
        "",
        "- user approvals and decisions;",
        "- blockers and failures;",
        "- destructive-risk and security warnings;",
        "- progress required by higher-priority instructions;",
        "- the final result;",
        "- changed files; and",
        "- verification evidence.",
        "",
        "This mode does not require a shorter final answer and does not change reasoning effort.",
        "It asks Claude to reduce discretionary narration; it does not guarantee token or cost savings,",
        "and no numeric savings should be claimed without matched provider evidence.",
        NARRATION_MODE_MARKER_END.decode("ascii"),
    ])


def _append_narration_block_bytes(existing: bytes, block: bytes) -> bytes:
    """Append one deterministic separator that default-mode removes with the span."""
    block = block.rstrip(b"\r\n") + b"\n"
    return block if not existing else existing + b"\n" + block


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


def _managed_block_bytes(block: str) -> bytes:
    return block.encode("utf-8").rstrip(b"\r\n") + b"\n"


def _append_managed_block_bytes(existing: bytes, block: bytes) -> bytes:
    block = block.rstrip(b"\r\n") + b"\n"
    if not existing:
        return block
    if existing.endswith(b"\n\n"):
        separator = b""
    elif existing.endswith(b"\n"):
        separator = b"\n"
    else:
        separator = b"\n\n"
    return existing + separator + block


def _managed_span_for_kind(data: bytes, kind: str) -> ManagedSpan | None:
    parsed = parse_managed_bytes(data, kind=kind)
    if parsed.status == "absent":
        return None
    if parsed.status != "valid":
        raise ValueError(parsed.reason or f"{parsed.status} managed {kind} markers")
    return parsed.spans[0]


def _replace_managed_span(data: bytes, span: ManagedSpan, block: bytes) -> bytes:
    return data[: span.start] + block.rstrip(b"\r\n") + b"\n" + data[span.end :]


def _brief_mode_levels_in_bytes(data: bytes) -> list[str]:
    parsed = _scan_managed_spans(data)
    return [
        str(span.variant)
        for span in parsed.spans
        if span.kind == "brief-mode" and span.variant in BRIEF_MODE_LEVELS
    ]


def compose_rule_file_bytes(
    existing: bytes | None,
    *,
    with_init: bool,
    brief_mode: str | None,
) -> tuple[bytes, dict[str, Any]]:
    """Compose rule-file mutations from exact owned spans, preserving all other bytes."""
    data = existing or b""
    original = data
    before_brief = _brief_mode_levels_in_bytes(data)
    meta: dict[str, Any] = {
        "init_changed": False,
        "init_present_before": False,
        "init_migrated_legacy": False,
        "brief_levels_before": before_brief,
        "brief_changed": False,
    }
    repo_span = _managed_span_for_kind(data, "repo-rules")
    meta["init_present_before"] = repo_span is not None
    if with_init:
        block = _managed_block_bytes(render_repo_rule_block())
        if repo_span is None:
            data = _append_managed_block_bytes(data, block)
            meta["init_changed"] = True
        elif data[repo_span.start : repo_span.end] != block:
            data = _replace_managed_span(data, repo_span, block)
            meta["init_changed"] = True
            meta["init_migrated_legacy"] = repo_span.version == 0

    if brief_mode:
        span = _managed_span_for_kind(data, "brief-mode")
        removed = [str(span.variant)] if span is not None and span.variant else []
        meta["brief_levels_removed"] = removed
        if brief_mode == BRIEF_MODE_OFF:
            if span is not None:
                data = data[: span.start] + data[span.end :]
                meta["brief_changed"] = True
        else:
            block = _managed_block_bytes(render_brief_mode_block(brief_mode))
            if span is None:
                data = _append_managed_block_bytes(data, block)
                meta["brief_changed"] = True
            elif data[span.start : span.end] != block:
                data = _replace_managed_span(data, span, block)
                meta["brief_changed"] = True
    meta["changed"] = data != original
    return data, meta


def compose_rule_file_text(
    existing: str | None,
    *,
    with_init: bool,
    brief_mode: str | None,
) -> tuple[str, dict[str, Any]]:
    """Compatibility text wrapper around the byte-exact managed composer."""
    rendered, meta = compose_rule_file_bytes(
        existing.encode("utf-8") if existing is not None else None,
        with_init=with_init,
        brief_mode=brief_mode,
    )
    return rendered.decode("utf-8"), meta


def plan_or_write_rule_file_blocks(
    path: Path,
    *,
    with_init: bool,
    brief_mode: str | None,
    applied: bool,
) -> dict[str, Any]:
    """Plan/apply exact managed spans through the shared cooperative writer."""
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

    existing = state.get("bytes")
    snapshot = state["snapshot"]
    existing_bytes = bytes(existing or b"")
    result["brief_mode_existing_levels"] = _brief_mode_levels_in_bytes(existing_bytes)
    repo_state = parse_managed_bytes(existing_bytes, kind="repo-rules")
    rule_present = repo_state.status == "valid"
    try:
        final_bytes, planned_meta = compose_rule_file_bytes(
            existing,
            with_init=with_init,
            brief_mode=brief_mode,
        )
    except ValueError as exc:
        reason = f"refused unsafe managed rule state in {path.name}: {exc}"
        result.update({"status": "skipped", "brief_mode_status": "skipped", "reason": reason})
        result["planned_actions"].append(reason)
        return result

    if with_init:
        if rule_present and not planned_meta["init_changed"]:
            result["status"] = "exists"
            result["planned_actions"].append("advisory ContextGuard rules already present")
        elif not applied:
            result["status"] = "planned"
            verb = "migrate" if planned_meta.get("init_migrated_legacy") else "add"
            result["planned_actions"].append(f"would {verb} advisory ContextGuard rules")
    elif not brief_mode:
        result["status"] = "planned"
        result["planned_actions"].append("run with --with-init to add advisory ContextGuard rules")

    if brief_mode:
        brief_changed = bool(planned_meta.get("brief_changed"))
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

    meta = planned_meta
    if not meta["changed"]:
        if result["status"] is None:
            result["status"] = "exists" if rule_present else "unchanged"
        if result["brief_mode_status"] is None and brief_mode:
            result["brief_mode_status"] = "absent" if brief_mode == BRIEF_MODE_OFF else "exists"
        return result

    write_result = write_managed_file(
        path,
        expected=snapshot,
        desired=final_bytes,
        mode=0o644,
        dir_mode=0o755,
    )
    if write_result["status"] not in {"applied", "applied-durability-uncertain"}:
        reason = write_result.get("reason") or f"could not write repo rule file {path.name}"
        result.update({
            "status": write_result["status"],
            "brief_mode_status": write_result["status"],
            "reason": reason,
        })
        result["planned_actions"] = [reason]
        return result
    if write_result.get("backup_path"):
        result["brief_mode_backup_path"] = write_result["backup_path"]
    durability_warning = (
        write_result.get("reason")
        if write_result["status"] == "applied-durability-uncertain"
        else None
    )
    if durability_warning:
        result["status"] = "applied-durability-uncertain"
        result["reason"] = durability_warning
    if with_init:
        if not durability_warning:
            result["status"] = "applied" if meta["init_changed"] else "exists"
        if meta["init_changed"]:
            result["applied_actions"].append("wrote advisory ContextGuard rules")
        else:
            result["planned_actions"].append("advisory ContextGuard rules already present")
    elif result["status"] is None:
        result["status"] = "applied"
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
    if durability_warning:
        result["planned_actions"].append(durability_warning)
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
    path = _normalize_allowed_first_absolute_symlink(path)
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
    """Return a non-throwing exact-byte snapshot for project rule/skill files."""
    parent_issue = _existing_rule_parent_issue(path)
    if parent_issue:
        return {"status": "unsafe", "text": None, "reason": parent_issue}
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {
            "status": "missing",
            "text": None,
            "bytes": None,
            "snapshot": ManagedFileSnapshot(None, None),
            "reason": None,
        }
    except OSError as exc:
        return {"status": "unsafe", "text": None, "reason": f"could not inspect rule file: {exc.__class__.__name__}"}
    if stat.S_ISLNK(st.st_mode):
        return {"status": "unsafe", "text": None, "reason": f"refused to read symlinked rule file: {path.name}"}
    if stat.S_ISDIR(st.st_mode):
        return {"status": "directory", "text": None, "reason": f"refused to replace directory rule target: {path.name}"}
    try:
        snapshot = read_managed_file_snapshot(path)
    except OSError as exc:
        return {
            "status": "unsafe",
            "text": None,
            "bytes": None,
            "reason": f"could not read rule file without following symlinks: {exc.__class__.__name__}",
        }
    data = snapshot.data or b""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        "status": "file",
        "text": text,
        "bytes": data,
        "snapshot": snapshot,
        "reason": None,
    }


def repo_rule_block_present(path: Path) -> bool:
    """True when the advisory ContextGuard block already exists in the rule file."""
    state = _rule_file_state(path)
    return (
        state["status"] == "file"
        and parse_managed_bytes(bytes(state.get("bytes") or b""), kind="repo-rules").status == "valid"
    )


def write_repo_rule_init(path: Path) -> dict[str, Any]:
    """Idempotently append the advisory ContextGuard block to a repo rule file.

    Returns a status dict: ``applied`` (block written), ``exists`` (already
    present), or ``skipped`` (refused, e.g. symlinked target) with a reason.
    Existing user-owned rule files are backed up before any changed write.
    """
    state = _rule_file_state(path)
    if state["status"] not in {"missing", "file"}:
        return {"status": "skipped", "reason": state.get("reason") or f"refused unsafe rule target: {path.name}"}
    try:
        final, meta = compose_rule_file_bytes(
            state.get("bytes"),
            with_init=True,
            brief_mode=None,
        )
    except ValueError as exc:
        return {"status": "skipped", "reason": f"refused unsafe managed rule state: {exc}"}
    if not meta["changed"]:
        return {"status": "exists"}
    write_result = write_managed_file(
        path,
        expected=state["snapshot"],
        desired=final,
        mode=0o644,
        dir_mode=0o755,
    )
    return write_result


def codex_skill_status(path: Path) -> str:
    state = _rule_file_state(path)
    if state["status"] == "missing":
        return "missing"
    if state["status"] != "file":
        return "unsafe"
    data = bytes(state.get("bytes") or b"")
    if data == render_codex_skill().encode("utf-8"):
        return "exists"
    parsed = parse_managed_bytes(data, kind="codex-skill")
    if parsed.status != "valid":
        return "foreign"
    span = parsed.spans[0]
    if span.version == 0:
        digest = hashlib.sha256(data).hexdigest()
        return "update-needed" if digest in LEGACY_CODEX_SKILL_SHA256_ALLOWLIST else "foreign"
    if span.version == 1:
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
    existing = state.get("bytes")
    if status == "missing":
        desired = render_codex_skill().encode("utf-8")
    else:
        data = bytes(existing or b"")
        parsed = parse_managed_bytes(data, kind="codex-skill")
        span = parsed.spans[0]
        if span.version == 0:
            desired = render_codex_skill().encode("utf-8")
        else:
            desired = _replace_managed_span(data, span, render_codex_skill_block_bytes())
    result = write_managed_file(
        path,
        expected=state["snapshot"],
        desired=desired,
        mode=0o644,
        dir_mode=0o755,
    )
    if result["status"] == "applied":
        result["status"] = "updated" if status == "update-needed" else "applied"
    elif result["status"] == "applied-durability-uncertain":
        result["change_kind"] = "updated" if status == "update-needed" else "applied"
    return result


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
                        entry["status"] = (
                            result["status"]
                            if result.get("status") == "applied-durability-uncertain"
                            else "applied"
                        )
                    if result.get("reason"):
                        entry["brief_mode_reason"] = result.get("reason")
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
                    entry["status"] = (
                        result["status"]
                        if result.get("status") == "applied-durability-uncertain"
                        else "applied"
                    )
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
                    if result["status"] in {"applied", "applied-durability-uncertain"}:
                        entry["applied_actions"] = [f"wrote advisory ContextGuard rules to {entry['rule_file']}"]
                        entry["planned_actions"] = list(entry["applied_actions"])
                        if result.get("reason"):
                            entry["planned_actions"].append(result["reason"])
                            entry["reason"] = result["reason"]
                        if result.get("backup_path"):
                            entry["rule_backup_path"] = result["backup_path"]
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
                elif entry["status"] == "applied-durability-uncertain":
                    entry["project_skill_status"] = "blocked-durability-uncertain"
                    entry["planned_actions"].append(
                        "blocked project Codex skill write because the preceding rule-file "
                        "commit has uncertain directory durability"
                    )
                else:
                    skill_result = write_codex_project_skill(skill_path)
                    entry["project_skill_status"] = skill_result["status"]
                    if skill_result["status"] in {"applied", "updated", "applied-durability-uncertain"}:
                        action = f"wrote project Codex skill to {adapter.project_skill_rel}"
                        entry["applied_actions"].append(action)
                        entry["planned_actions"].append(action)
                        if skill_result["status"] == "applied-durability-uncertain":
                            entry["status"] = "applied-durability-uncertain"
                            entry["reason"] = skill_result.get("reason")
                        elif entry["status"] in {"planned", "exists", "unchanged"}:
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


def _user_scope_path_issue(
    path: Path,
    *,
    label: str,
    expected_directory: bool,
    allow_missing: bool,
) -> str | None:
    """Return a fail-closed reason for an existing user-scope path."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None if allow_missing else f"{label} does not exist: {path}"
    except OSError as error:
        return f"could not inspect {label}: {error.__class__.__name__}"

    if metadata.st_uid not in {0, os.geteuid()}:
        return f"refusing unsafe {label}: it is not owned by root or the effective user"
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"refusing unsafe {label}: group/world write bits are set"
    if expected_directory:
        if not stat.S_ISDIR(metadata.st_mode):
            return f"refusing unsafe {label}: it is not a directory"
    elif not stat.S_ISREG(metadata.st_mode):
        return f"refusing unsafe {label}: it is not a regular file"
    return None


def _validate_user_scope_home(home: Path) -> None:
    issue = _user_scope_path_issue(
        home,
        label="resolved HOME",
        expected_directory=True,
        allow_missing=False,
    )
    if issue:
        raise SystemExit(issue)


def resolve_scope_root(raw_root: str | None, scope: str) -> Path:
    if scope == "project":
        return resolve_setup_root(raw_root)
    home = Path.home().expanduser().resolve()
    if home == Path(home.anchor or "/"):
        raise SystemExit("Refusing user-scope setup because HOME resolves to a filesystem root.")
    _validate_user_scope_home(home)
    return home


def effective_scope(raw_root: str | None, raw_scope: str | None, *, allow_home_settings: bool) -> str:
    scope = normalize_scope(raw_scope)
    if scope != "project" or not allow_home_settings:
        return scope
    project_root = resolve_setup_root(raw_root)
    home_settings = Path.home().expanduser().resolve() / SETTINGS_REL
    if (project_root / SETTINGS_REL).expanduser().resolve() == home_settings:
        return "user"
    return scope


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
    if claude_dir.is_symlink():
        raise SystemExit(f"Refusing to use symlinked Claude settings directory: {claude_dir}")
    if settings_path.is_symlink():
        raise SystemExit(f"Refusing to write through symlinked settings file: {settings_path}")
    if claude_dir.exists():
        try:
            claude_dir.resolve().relative_to(root)
        except ValueError as exc:
            raise SystemExit(f"Claude settings directory resolves outside project root: {claude_dir}") from exc
    if root == home_settings.parent.parent:
        for path, label, expected_directory, allow_missing in (
            (root, "resolved HOME", True, False),
            (claude_dir, "existing .claude directory", True, True),
            (settings_path, "existing settings.json", False, True),
        ):
            issue = _user_scope_path_issue(
                path,
                label=label,
                expected_directory=expected_directory,
                allow_missing=allow_missing,
            )
            if issue:
                raise SystemExit(issue)


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


def _read_bytes_no_follow(path: Path) -> bytes:
    fd = _open_regular_no_symlink(path)
    try:
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd != -1:
            os.close(fd)


def _read_text_no_follow(path: Path) -> str:
    return _read_bytes_no_follow(path).decode("utf-8")


def _snapshot_metadata(st: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(st.st_dev),
        int(st.st_ino),
        int(st.st_mode),
        int(st.st_size),
        int(st.st_mtime_ns),
    )


def read_managed_file_snapshot(path: Path) -> ManagedFileSnapshot:
    """Read an exact byte+metadata snapshot without following target/parent links."""
    try:
        fd = _open_regular_no_symlink(path)
    except FileNotFoundError:
        return ManagedFileSnapshot(None, None)
    try:
        before = os.fstat(fd)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read()
            after = os.fstat(handle.fileno())
        if _snapshot_metadata(before) != _snapshot_metadata(after) or len(data) != after.st_size:
            raise ManagedFileConflictError(f"managed target changed during read: {path}")
        return ManagedFileSnapshot(data, _snapshot_metadata(after))
    finally:
        if fd != -1:
            os.close(fd)


def _verify_expected_snapshot(path: Path, expected: ManagedFileSnapshot) -> ManagedFileSnapshot:
    current = read_managed_file_snapshot(path)
    if current != expected:
        raise ManagedFileConflictError(f"managed target changed since planning: {path}")
    return current


def _read_optional_text_no_follow(path: Path) -> str | None:
    try:
        return _read_text_no_follow(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SystemExit(f"Could not read {path} without following symlinks: {exc}") from exc


def _path_exists_no_follow(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


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


def ensure_permissions(
    settings: dict[str, Any],
    actions: list[str],
    *,
    migrate_env_read_denies: bool = False,
) -> None:
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
    if migrate_env_read_denies:
        retained = [
            rule
            for rule in deny
            if not (
                isinstance(rule, str)
                and rule in PRODUCT_OWNED_ENV_READ_DENIES
            )
        ]
        removed = len(deny) - len(retained)
        if removed:
            deny[:] = retained
            actions.append(
                f"removed {removed} obsolete permissions.deny rules now enforced by the Claude Read hook"
            )
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


def _path_has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor) if path.is_absolute() else Path.cwd()
    parts = path.parts[1:] if path.is_absolute() else path.parts
    for part in parts:
        if part in {"", "."}:
            continue
        current = current / part
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return True
        except FileNotFoundError:
            return False
        except OSError:
            return True
    return False


def _probe_path_helper_identity(path: Path, helper_name: str) -> None:
    system_path = os.pathsep.join(part for part in ("/usr/bin", "/bin", "/usr/sbin", "/sbin") if Path(part).is_dir())
    env = {
        "LC_ALL": "C",
        "PATH": str(path.parent) + (os.pathsep + system_path if system_path else ""),
    }
    try:
        proc = subprocess.Popen(
            [str(path), "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except OSError as exc:
        raise SystemExit(f"PATH helper {helper_name!r} identity probe failed: {exc.strerror or exc.__class__.__name__}") from exc

    output = bytearray()
    selector = selectors.DefaultSelector()
    streams = [stream for stream in (proc.stdout, proc.stderr) if stream is not None]
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + PATH_HELPER_PROBE_TIMEOUT_SECONDS

    def stop_probe() -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop_probe()
                raise SystemExit(f"PATH helper {helper_name!r} identity probe timed out; refusing fallback")
            for key, _mask in selector.select(timeout=min(0.1, remaining)):
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                output.extend(chunk)
                if len(output) > PATH_HELPER_PROBE_MAX_OUTPUT_BYTES:
                    stop_probe()
                    raise SystemExit(f"PATH helper {helper_name!r} identity probe output exceeded {PATH_HELPER_PROBE_MAX_OUTPUT_BYTES} bytes")
        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            stop_probe()
            raise SystemExit(f"PATH helper {helper_name!r} identity probe timed out; refusing fallback")
    finally:
        selector.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass

    if returncode != 0:
        raise SystemExit(f"PATH helper {helper_name!r} identity probe exited {returncode}; refusing fallback")
    decoded = output.decode("utf-8", errors="replace")
    lowered = decoded.lower()
    if "contextguard" not in lowered and "context-guard" not in lowered and helper_name.lower() not in lowered:
        raise SystemExit(f"PATH helper {helper_name!r} identity probe did not identify ContextGuard; refusing fallback")


def validate_path_helper_fallback(helper_name: str, found: str) -> Path:
    raw = Path(found)
    if not raw.is_absolute():
        raise SystemExit(f"PATH helper {helper_name!r} did not resolve to an absolute path; refusing fallback")
    try:
        canonical = raw.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(f"PATH helper {helper_name!r} could not be canonicalized: {exc.strerror or exc.__class__.__name__}") from exc
    normalized_raw = _normalize_allowed_first_absolute_symlink(Path(os.path.normpath(str(raw))))
    if normalized_raw != canonical:
        raise SystemExit(f"PATH helper {helper_name!r} traverses a symlink or alias; refusing fallback")
    if _path_has_symlink_component(canonical):
        raise SystemExit(f"PATH helper {helper_name!r} has a symlink parent or leaf; refusing fallback")
    if canonical.name != helper_name:
        raise SystemExit(f"PATH helper {helper_name!r} resolved to unexpected basename {canonical.name!r}; refusing fallback")
    fd = _open_regular_no_symlink(canonical)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not os.access(canonical, os.X_OK):
            raise SystemExit(f"PATH helper {helper_name!r} must be an executable regular file; refusing fallback")
    finally:
        os.close(fd)
    _probe_path_helper_identity(canonical, helper_name)
    return canonical


def helper_argv(helper_name: str, kit_script: str, *, shell: str | None = None, allow_path_fallback: bool = False) -> list[str]:
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
    if allow_path_fallback:
        found = shutil.which(helper_name)
        if found:
            return [str(validate_path_helper_fallback(helper_name, found))]
        raise SystemExit(f"Could not resolve required helper {helper_name!r} from PATH even though --allow-path-helper-fallback was supplied.")
    raise SystemExit(
        f"Could not resolve required helper {helper_name!r}; install the plugin or run from a complete checkout. "
        "PATH helper fallback is disabled by default; pass --allow-path-helper-fallback only for trusted helpers."
    )


def helper_command(helper_name: str, kit_script: str, *, shell: str | None = None, allow_path_fallback: bool = False) -> str:
    """hook 에 기록할 단일 셸 명령 문자열을 반환한다.

    경로에 공백이나 셸 메타문자가 들어와도 안전하도록 모든 분기에서 `shlex.join` 으로
    quote 한다. PATH 에서 찾은 helper 도 절대 경로로 고정해 hook hijacking 을 막는다.
    """
    argv = helper_argv(helper_name, kit_script, shell=shell, allow_path_fallback=allow_path_fallback)
    return shlex.join(argv)


def _validated_runtime_executable(raw: str | Path, *, label: str) -> Path:
    """Bind a runtime/helper to the canonical executable seen during setup."""
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise SystemExit(f"{label} did not resolve to an absolute path")
    try:
        canonical = candidate.resolve(strict=True)
        metadata = canonical.stat()
    except OSError as exc:
        raise SystemExit(
            f"{label} could not be canonicalized: {exc.strerror or exc.__class__.__name__}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(canonical, os.X_OK):
        raise SystemExit(f"{label} must be an executable regular file")
    return canonical


def _approved_python_runtime() -> Path:
    if not sys.executable:
        raise SystemExit("Python runtime identity is unavailable")
    return _validated_runtime_executable(sys.executable, label="Python runtime")


def _approved_system_runtime(name: str) -> Path:
    found = shutil.which(name, path=ISOLATED_RUNTIME_PATH)
    if not found:
        raise SystemExit(f"Required {name!r} runtime was not found in the fixed system path")
    return _validated_runtime_executable(found, label=f"{name} runtime")


def _isolated_runtime_prefix(
    preserve_env_names: tuple[str, ...] = (),
    *,
    fixed_env: dict[str, str] | None = None,
) -> list[str]:
    prefix = [
        str(_approved_system_runtime("env")),
        "-i",
        f"PATH={ISOLATED_RUNTIME_PATH}",
        "LC_ALL=C",
    ]
    for name in preserve_env_names:
        value = os.environ.get(name)
        if value is not None and BEHAVIOR_ENV_VALUE_RE.fullmatch(value):
            prefix.append(f"{name}={value}")
    for name, value in (fixed_env or {}).items():
        if name in {"HOME"} and value and "\x00" not in value:
            prefix.append(f"{name}={value}")
    return prefix


def _helper_path_from_argv(argv: list[str], *, label: str) -> Path:
    if not argv:
        raise SystemExit(f"{label} helper argv is empty")
    return _validated_runtime_executable(argv[-1], label=label)


def _bundled_helper_candidates(helper_name: str, kit_script: str) -> set[Path]:
    script_dir = Path(__file__).resolve().parent
    raw_candidates = (
        script_dir / helper_name,
        script_dir.parent / "plugins" / "context-guard" / "bin" / helper_name,
        script_dir / kit_script,
    )
    candidates: set[Path] = set()
    for candidate in raw_candidates:
        try:
            candidates.add(candidate.resolve(strict=True))
        except OSError:
            continue
    return candidates


def automatic_helper_argv(
    helper_name: str,
    kit_script: str,
    *,
    shell: str | None = None,
    allow_path_fallback: bool = False,
    preserve_env_names: tuple[str, ...] = (),
    fixed_env: dict[str, str] | None = None,
) -> list[str]:
    """Build installed hook argv with isolated, setup-pinned runtimes."""
    resolved = helper_argv(
        helper_name,
        kit_script,
        shell=shell,
        allow_path_fallback=allow_path_fallback,
    )
    helper_path = _helper_path_from_argv(resolved, label=helper_name)
    prefix = _isolated_runtime_prefix(
        preserve_env_names,
        fixed_env=fixed_env,
    )
    if helper_path not in _bundled_helper_candidates(helper_name, kit_script):
        # An explicit PATH fallback may be a native executable. Its absolute
        # identity was already validated by validate_path_helper_fallback().
        return [*prefix, str(helper_path)]
    if shell:
        shell_runtime = _approved_system_runtime(shell)
        shell_flags = ["--noprofile", "--norc"] if shell_runtime.name == "bash" else []
        return [*prefix, str(shell_runtime), *shell_flags, str(helper_path)]
    return [*prefix, str(_approved_python_runtime()), "-I", str(helper_path)]


def automatic_helper_command(
    helper_name: str,
    kit_script: str,
    *,
    shell: str | None = None,
    allow_path_fallback: bool = False,
    preserve_env_names: tuple[str, ...] = (),
    fixed_env: dict[str, str] | None = None,
) -> str:
    return shlex.join(
        automatic_helper_argv(
            helper_name,
            kit_script,
            shell=shell,
            allow_path_fallback=allow_path_fallback,
            preserve_env_names=preserve_env_names,
            fixed_env=fixed_env,
        )
    )


def _secure_owned_regular_path(path: Path, *, executable: bool) -> Path | None:
    """Validate an approval path and every parent without following symlinks."""
    try:
        canonical = path.resolve(strict=True)
    except OSError:
        return None
    if not path.is_absolute() or canonical != path:
        return None
    allowed_owners = {0, os.geteuid()}
    current = Path(path.anchor)
    components = path.parts[1:]
    if not components:
        return None
    try:
        root_metadata = os.lstat(current)
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid not in allowed_owners
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            return None
        for index, component in enumerate(components):
            current = current / component
            metadata = os.lstat(current)
            is_leaf = index == len(components) - 1
            if stat.S_ISLNK(metadata.st_mode):
                return None
            if metadata.st_uid not in allowed_owners or stat.S_IMODE(metadata.st_mode) & 0o022:
                return None
            if is_leaf:
                if not stat.S_ISREG(metadata.st_mode):
                    return None
                if executable and not os.access(current, os.X_OK):
                    return None
            elif not stat.S_ISDIR(metadata.st_mode):
                return None
    except OSError:
        return None
    return canonical


def _secure_owned_directory_path(path: Path) -> Path | None:
    try:
        canonical = path.resolve(strict=True)
    except OSError:
        return None
    if not path.is_absolute() or canonical != path:
        return None
    allowed_owners = {0, os.geteuid()}
    current = Path(path.anchor)
    try:
        root_metadata = os.lstat(current)
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid not in allowed_owners
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            return None
        for component in path.parts[1:]:
            current = current / component
            metadata = os.lstat(current)
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in allowed_owners
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                return None
    except OSError:
        return None
    return canonical


def _approved_node_runtime() -> Path | None:
    system_node = shutil.which("node", path=ISOLATED_RUNTIME_PATH)
    if system_node:
        approved = _secure_owned_regular_path(Path(system_node), executable=True)
        if approved is not None:
            return approved

    allowed_owners = {0, os.geteuid()}
    for candidate in HOMEBREW_NODE_CANDIDATES:
        if len(candidate.parents) < 2:
            continue
        allowed_root = candidate.parents[1]
        if _secure_owned_directory_path(allowed_root) is None:
            continue
        if _secure_owned_directory_path(candidate.parent) is None:
            continue
        try:
            link_metadata = os.lstat(candidate)
            physical_target = candidate.resolve(strict=True)
            physical_target.relative_to(allowed_root)
        except (OSError, ValueError):
            continue
        if link_metadata.st_uid not in allowed_owners:
            continue
        approved = _secure_owned_regular_path(physical_target, executable=True)
        if approved is not None:
            return approved
    return None


def _approved_default_omc_hud() -> tuple[Path, Path] | None:
    """Approve only the effective user's default OMC HUD and fixed-path Node."""
    try:
        passwd_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        canonical_home = passwd_home.resolve(strict=True)
    except (KeyError, OSError, RuntimeError):
        return None
    if not passwd_home.is_absolute() or canonical_home != passwd_home:
        return None
    omc_script = _secure_owned_regular_path(
        canonical_home / ".claude" / "hud" / "omc-hud.mjs",
        executable=False,
    )
    if omc_script is None:
        return None
    node_runtime = _approved_node_runtime()
    if node_runtime is None:
        return None
    return node_runtime, omc_script


def _statusline_setting(*, allow_path_fallback: bool = False) -> tuple[dict[str, str], bool]:
    approved_omc = _approved_default_omc_hud()
    fixed_env = (
        {"HOME": str(approved_omc[1].parents[2])}
        if approved_omc is not None
        else None
    )
    argv = automatic_helper_argv(
        HELPER_STATUSLINE,
        "statusline_merged.sh",
        shell="bash",
        allow_path_fallback=allow_path_fallback,
        preserve_env_names=STATUSLINE_BEHAVIOR_ENV,
        fixed_env=fixed_env,
    )
    token_path = _helper_path_from_argv(
        helper_argv(
            HELPER_STATUSLINE_PLAIN,
            "statusline.sh",
            shell="bash",
            allow_path_fallback=allow_path_fallback,
        ),
        label=HELPER_STATUSLINE_PLAIN,
    )
    argv.extend(
        [
            "--approved-bash",
            str(_approved_system_runtime("bash")),
            "--approved-python",
            str(_approved_python_runtime()),
            "--approved-token-statusline",
            str(token_path),
        ]
    )
    if approved_omc is not None:
        node_runtime, omc_script = approved_omc
        argv.extend(
            [
                "--approved-node",
                str(node_runtime),
                "--approved-omc-script",
                str(omc_script),
            ]
        )
    return {"type": "command", "command": shlex.join(argv)}, approved_omc is not None


def statusline_setting(*, allow_path_fallback: bool = False) -> dict[str, str]:
    setting, _omc_included = _statusline_setting(allow_path_fallback=allow_path_fallback)
    return setting


def bash_hook_setting(*, allow_path_fallback: bool = False, bash_reference_v1: bool = False) -> dict[str, Any]:
    command = automatic_helper_command(
        HELPER_REWRITE_BASH,
        "rewrite_bash_for_token_budget.py",
        allow_path_fallback=allow_path_fallback,
        preserve_env_names=REWRITE_BEHAVIOR_ENV,
    )
    if bash_reference_v1:
        command = f"{command} --bash-reference-v1"
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": command}],
    }


def load_bash_reference_policy() -> object | None:
    """Load only the package-local runtime policy, never an import from PATH."""
    path = Path(__file__).resolve().parent / "bash_reference_policy.py"
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )
    if not hasattr(os, "O_NOFOLLOW"):
        return None
    flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(path, flags)
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > BASH_REFERENCE_POLICY_MAX_BYTES
        ):
            return None
        source = os.read(fd, BASH_REFERENCE_POLICY_MAX_BYTES + 1)
        if len(source) > BASH_REFERENCE_POLICY_MAX_BYTES:
            return None
        source_text = source.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    module_name = f"_context_guard_setup_reference_policy_{os.getpid()}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        exec(compile(source_text, str(path), "exec"), module.__dict__)
    except Exception:
        sys.modules.pop(module_name, None)
        return None
    return module


def bash_reference_adapter_readiness(root: Path) -> tuple[bool, str]:
    """Return the runtime adapter verdict for the effective setup project."""
    policy = load_bash_reference_policy()
    discover = getattr(policy, "discover_adapter", None)
    if policy is None:
        return False, "receipt_policy_unavailable"
    if not callable(discover):
        return False, "receipt_policy_invalid"
    try:
        discovered = discover(root)
    except Exception:
        return False, "receipt_policy_load_failed"
    if not isinstance(discovered, tuple) or len(discovered) != 2:
        return False, "receipt_policy_invalid"
    adapter, reason = discovered
    adapter_methods = ("start_broker", "query_reference")
    if (
        adapter is not None
        and reason == "receipt_adapter_available"
        and all(callable(getattr(adapter, name, None)) for name in adapter_methods)
    ):
        return True, reason
    if adapter is not None and reason == "receipt_adapter_available":
        return False, "receipt_adapter_invalid"
    if not isinstance(reason, str) or re.fullmatch(r"[a-z0-9_]{1,96}", reason) is None:
        return False, "receipt_policy_invalid"
    return False, reason


def bash_reference_unavailable_message(reason: str) -> str:
    return (
        f"{_BASH_REFERENCE_UNAVAILABLE}: reason={reason}; requires an exact paired npm install "
        f"of {ROOT_PACKAGE_NAME} and {RECEIPT_PACKAGE_NAME}; "
        f"recovery={_BASH_REFERENCE_RECOVERY}; ordinary Bash trimming remains enabled"
    )


def disable_unavailable_bash_reference(
    choices: Choices,
    warnings: list[str],
    *,
    root: Path,
) -> list[str]:
    """Fail closed without removing the ordinary Bash trimming choice."""
    if not choices.bash_reference_v1:
        return []
    available, reason = bash_reference_adapter_readiness(root)
    if available:
        return []
    choices.bash_reference_v1 = False
    warning = bash_reference_unavailable_message(reason)
    warnings.append(warning)
    return [warning]


def read_hook_setting(*, allow_path_fallback: bool = False) -> dict[str, Any]:
    return {
        "matcher": "Read",
        "hooks": [{"type": "command", "command": automatic_helper_command(
            HELPER_GUARD_READ,
            "guard_large_read.py",
            allow_path_fallback=allow_path_fallback,
            preserve_env_names=READ_GUARD_BEHAVIOR_ENV,
        )}],
    }


def failed_nudge_setting(*, allow_path_fallback: bool = False) -> dict[str, Any]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": automatic_helper_command(HELPER_FAILED_NUDGE, "failed_attempt_nudge.py", allow_path_fallback=allow_path_fallback)}],
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
        while index < len(parts):
            token = parts[index]
            if token in {"-i", "--ignore-environment"}:
                index += 1
                continue
            if token in {"-u", "--unset"} and index + 1 < len(parts):
                index += 2
                continue
            if token.startswith("--unset="):
                index += 1
                continue
            break
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


def _statusline_candidate_paths(*, merged: bool) -> set[Path]:
    script_dir = Path(__file__).resolve().parent
    helper_key = HELPER_STATUSLINE if merged else HELPER_STATUSLINE_PLAIN
    kit_script = "statusline_merged.sh" if merged else "statusline.sh"
    names = HELPER_EQUIVALENT_BASENAMES[helper_key]
    raw_candidates = {script_dir / kit_script}
    for name in names:
        raw_candidates.add(script_dir / name)
        raw_candidates.add(
            script_dir.parent / "plugins" / "context-guard" / "bin" / name
        )
    candidates: set[Path] = set()
    for candidate in raw_candidates:
        try:
            candidates.add(candidate.resolve(strict=True))
        except OSError:
            continue
    return candidates


def _authenticated_statusline_path(raw: str, *, merged: bool) -> Path | None:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        canonical = candidate.resolve(strict=True)
    except OSError:
        return None
    return canonical if canonical in _statusline_candidate_paths(merged=merged) else None


def exact_known_statusline_command(command: str) -> bool:
    """Match only authenticated complete historical merged-statusline commands."""
    try:
        parts = shlex.split(command) if command else []
    except ValueError:
        return False
    if not parts:
        return False
    known_helpers = HELPER_EQUIVALENT_BASENAMES[HELPER_STATUSLINE]
    direct_head = parts[0]
    if len(parts) == 1:
        if direct_head in known_helpers:
            return True
        return _authenticated_statusline_path(direct_head, merged=True) is not None

    index = 0
    generated_shape = False
    assignments: dict[str, str] = {}
    approved_env = str(_approved_system_runtime("env"))
    if direct_head == approved_env:
        generated_shape = True
        index += 1
        if index >= len(parts) or parts[index] != "-i":
            return False
        index += 1
        allowed_assignments = {
            "PATH",
            "LC_ALL",
            "HOME",
            *STATUSLINE_BEHAVIOR_ENV,
        }
        while index < len(parts) and "=" in parts[index] and not parts[index].startswith("-"):
            name, _separator, value = parts[index].partition("=")
            if name not in allowed_assignments or name in assignments:
                return False
            assignments[name] = value
            index += 1
        if assignments.get("PATH") != ISOLATED_RUNTIME_PATH or assignments.get("LC_ALL") != "C":
            return False
        for name, value in assignments.items():
            if name in STATUSLINE_BEHAVIOR_ENV and not BEHAVIOR_ENV_VALUE_RE.fullmatch(value):
                return False

    approved_bash = str(_approved_system_runtime("bash"))
    if index >= len(parts):
        return False
    shell = parts[index]
    if generated_shape:
        if shell != approved_bash:
            return False
    elif shell not in {"bash", "sh", approved_bash}:
        return False
    index += 1
    if generated_shape:
        if parts[index : index + 2] != ["--noprofile", "--norc"]:
            return False
        index += 2
    else:
        while index < len(parts) and parts[index] in {"--noprofile", "--norc"}:
            index += 1
    if index >= len(parts):
        return False
    if _authenticated_statusline_path(parts[index], merged=True) is None:
        return False
    index += 1
    if not generated_shape:
        return index == len(parts)

    required_prefix = [
        "--approved-bash",
        approved_bash,
        "--approved-python",
        str(_approved_python_runtime()),
        "--approved-token-statusline",
    ]
    if parts[index : index + len(required_prefix)] != required_prefix:
        return False
    index += len(required_prefix)
    if index >= len(parts):
        return False
    if _authenticated_statusline_path(parts[index], merged=False) is None:
        return False
    index += 1

    approved_omc = _approved_default_omc_hud()
    if index == len(parts):
        return "HOME" not in assignments
    if approved_omc is None or len(parts) - index != 4:
        return False
    node_runtime, omc_script = approved_omc
    expected_omc = [
        "--approved-node",
        str(node_runtime),
        "--approved-omc-script",
        str(omc_script),
    ]
    return (
        parts[index:] == expected_omc
        and assignments.get("HOME") == str(omc_script.parents[2])
    )


def equivalent_helper_basenames(command: str) -> set[str]:
    bases = command_helper_basenames(command)
    equivalents = set(bases)
    for base in bases:
        equivalents.update(HELPER_EQUIVALENT_BASENAMES.get(base, ()))
    return equivalents


def _generic_hook_spec(desired: str) -> tuple[str, str, tuple[str, ...]] | None:
    desired_bases = command_helper_basenames(desired)
    specs = (
        (HELPER_REWRITE_BASH, "rewrite_bash_for_token_budget.py", REWRITE_BEHAVIOR_ENV),
        (HELPER_GUARD_READ, "guard_large_read.py", READ_GUARD_BEHAVIOR_ENV),
        (HELPER_FAILED_NUDGE, "failed_attempt_nudge.py", ()),
    )
    for helper_name, kit_script, behavior_env in specs:
        if desired_bases & HELPER_EQUIVALENT_BASENAMES[helper_name]:
            return helper_name, kit_script, behavior_env
    return None


def _generic_hook_candidate_paths(helper_name: str, kit_script: str) -> set[Path]:
    script_dir = Path(__file__).resolve().parent
    raw_candidates = {script_dir / kit_script}
    for name in HELPER_EQUIVALENT_BASENAMES[helper_name]:
        raw_candidates.add(script_dir / name)
        raw_candidates.add(
            script_dir.parent / "plugins" / "context-guard" / "bin" / name
        )
    candidates: set[Path] = set()
    for candidate in raw_candidates:
        try:
            candidates.add(candidate.resolve(strict=True))
        except OSError:
            continue
    return candidates


def _authenticated_generic_hook_path(
    raw: str,
    *,
    helper_name: str,
    kit_script: str,
) -> Path | None:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        canonical = candidate.resolve(strict=True)
    except OSError:
        return None
    candidates = _generic_hook_candidate_paths(helper_name, kit_script)
    return canonical if canonical in candidates else None


def exact_known_hook_command(existing: str, desired: str) -> bool:
    if command_matches(existing, desired):
        return True
    spec = _generic_hook_spec(desired)
    if spec is None:
        return False
    helper_name, kit_script, behavior_env = spec
    known_names = HELPER_EQUIVALENT_BASENAMES[helper_name]
    try:
        parts = shlex.split(existing) if existing else []
    except ValueError:
        return False
    if not parts:
        return False
    if len(parts) == 1:
        if parts[0] in known_names:
            return True
        return _authenticated_generic_hook_path(
            parts[0],
            helper_name=helper_name,
            kit_script=kit_script,
        ) is not None

    index = 0
    generated_shape = parts[0] == str(_approved_system_runtime("env"))
    if generated_shape:
        index = 1
        if index >= len(parts) or parts[index] != "-i":
            return False
        index += 1
        assignments: dict[str, str] = {}
        allowed_assignments = {"PATH", "LC_ALL", *behavior_env}
        while index < len(parts) and "=" in parts[index] and not parts[index].startswith("-"):
            name, _separator, value = parts[index].partition("=")
            if name not in allowed_assignments or name in assignments:
                return False
            assignments[name] = value
            index += 1
        if assignments.get("PATH") != ISOLATED_RUNTIME_PATH or assignments.get("LC_ALL") != "C":
            return False
        for name, value in assignments.items():
            if name in behavior_env and not BEHAVIOR_ENV_VALUE_RE.fullmatch(value):
                return False

    if index >= len(parts):
        return False
    python_runtime = parts[index]
    if generated_shape:
        if python_runtime != str(_approved_python_runtime()):
            return False
    elif (
        "/" in python_runtime
        or re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", python_runtime) is None
    ):
        return False
    index += 1
    if index < len(parts) and parts[index] == "-I":
        index += 1
    elif generated_shape:
        return False
    if index >= len(parts):
        return False
    if _authenticated_generic_hook_path(
        parts[index],
        helper_name=helper_name,
        kit_script=kit_script,
    ) is None:
        return False
    index += 1
    if index == len(parts):
        return True
    return (
        helper_name == HELPER_REWRITE_BASH
        and parts[index:] == ["--bash-reference-v1"]
    )


def command_matches_existing_or_equivalent(existing: str, desired: str) -> bool:
    return exact_known_hook_command(existing, desired)


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


def ensure_post_tool_failure_hook(
    settings: dict[str, Any],
    hook: dict[str, Any],
    command: str,
    label: str,
    actions: list[str],
) -> None:
    _ensure_tool_hook(settings, hook, command, label, actions, event="PostToolUseFailure")


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


def run_post_setup_diet_scan(root: Path, *, allow_path_fallback: bool = False) -> dict[str, Any]:
    argv = [
        *helper_argv(HELPER_DIET, "context_guard_diet.py", allow_path_fallback=allow_path_fallback),
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


def doctor_check(
    ident: str,
    status: str,
    severity: str,
    message: str,
    *,
    detail: Any | None = None,
    next_action: str | None = None,
) -> dict[str, Any]:
    check = {
        "id": ident,
        "status": status,
        "severity": severity,
        "message": message,
    }
    if detail is not None:
        check["detail"] = detail
    if next_action:
        check["next_action"] = next_action
    return check


def _setup_command(
    args: argparse.Namespace,
    *,
    apply: bool,
    root: Path | None = None,
    scope: str | None = None,
) -> str:
    scope = scope or normalize_scope(getattr(args, "scope", "project"))
    parts = ["context-guard", "setup", "--scope", scope]
    if root is not None and scope == "project":
        parts.extend(["--root", str(root)])
    selected = explicit_agent_selection(args)
    if selected:
        parts.extend(["--agent", ",".join(selected)])
    elif scope == "user":
        parts.extend(["--agent", "claude"])
    if getattr(args, "allow_path_helper_fallback", False):
        parts.append("--allow-path-helper-fallback")
    if getattr(args, "with_init", False):
        parts.append("--with-init")
    if getattr(args, "with_skill", False):
        parts.append("--with-skill")
    brief_mode = getattr(args, "brief_mode", None)
    if brief_mode:
        parts.extend(["--brief-mode", str(brief_mode)])
    for attr, flag in (
        ("no_denies", "--no-denies"),
        ("no_statusline", "--no-statusline"),
        ("no_bash_hook", "--no-bash-hook"),
        ("no_read_guard", "--no-read-guard"),
        ("no_model_defaults", "--no-model-defaults"),
        ("no_diet_scan", "--no-diet-scan"),
    ):
        if getattr(args, attr, False):
            parts.append(flag)
    if getattr(args, "failed_attempt_nudge", None) is False:
        parts.append("--no-failed-attempt-nudge")
    elif getattr(args, "failed_attempt_nudge", None) is True:
        parts.append("--failed-attempt-nudge")
    parts.append("--yes" if apply else "--plan")
    return shlex.join(parts)


def _doctor_status(checks: list[dict[str, Any]]) -> str:
    if any(check.get("status") == "error" or check.get("severity") == "error" for check in checks):
        return "error"
    if any(check.get("status") == "warning" or check.get("severity") in {"high", "medium"} for check in checks):
        return "warning"
    return "ok"


def _helper_availability_check(*, include_diet: bool = True, allow_path_fallback: bool = False) -> dict[str, Any]:
    helpers = {
        HELPER_STATUSLINE: "statusline_merged.sh",
        HELPER_REWRITE_BASH: "rewrite_bash_for_token_budget.py",
        HELPER_GUARD_READ: "guard_large_read.py",
        HELPER_FAILED_NUDGE: "failed_attempt_nudge.py",
    }
    if include_diet:
        helpers[HELPER_DIET] = "context_guard_diet.py"
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for helper, kit_script in helpers.items():
        try:
            resolved[helper] = shlex.join(helper_argv(helper, kit_script, shell=("bash" if kit_script.endswith(".sh") else None), allow_path_fallback=allow_path_fallback))
        except SystemExit:
            missing.append(helper)
    if missing:
        return doctor_check(
            "helper-availability",
            "error",
            "error",
            "Some ContextGuard helper commands could not be resolved.",
            detail={"missing": missing, "resolved": resolved, "allow_path_helper_fallback": allow_path_fallback},
            next_action="Reinstall ContextGuard or run from a complete checkout.",
        )
    return doctor_check(
        "helper-availability",
        "ok",
        "low",
        "Required ContextGuard helper commands are resolvable.",
        detail={"resolved": resolved, "allow_path_helper_fallback": allow_path_fallback},
    )


def _adapter_warning_detail(entry: dict[str, Any]) -> dict[str, Any]:
    detail = {
        "key": entry.get("key"),
        "status": entry.get("status"),
        "planned_actions": entry.get("planned_actions", []),
        "unsupported_reason": entry.get("unsupported_reason"),
    }
    for key in ("brief_mode", "brief_mode_status", "brief_mode_reason", "brief_mode_file"):
        if key in entry:
            detail[key] = entry.get(key)
    return detail


def run_doctor(args: argparse.Namespace) -> dict[str, Any]:
    """Return a read-only setup health report.

    This intentionally mirrors setup planning while never prompting, backing up,
    writing settings, writing rule files, or creating rollback records.
    """
    require_no_follow_file_ops_supported()
    scope = effective_scope(
        args.root,
        getattr(args, "scope", "project"),
        allow_home_settings=bool(getattr(args, "allow_home_settings", False)),
    )
    root = resolve_scope_root(args.root, scope)
    settings_path = root / SETTINGS_REL
    helper_check = _helper_availability_check(include_diet=not getattr(args, "no_diet_scan", False), allow_path_fallback=bool(getattr(args, "allow_path_helper_fallback", False)))
    checks: list[dict[str, Any]] = [helper_check]
    warnings: list[str] = []
    if scope == "user":
        warnings.append("user-scope verify is read-only; applying user-scope setup still requires --yes and an explicit agent")

    selected_agents = explicit_agent_selection(args)
    targets = resolve_target_adapters(root, selected_agents)
    claude_targeted = any(adapter.key == "claude" for adapter in targets)

    original_text = None
    original: dict[str, Any] = {}
    settings: dict[str, Any] = {}
    if claude_targeted:
        try:
            validate_settings_target(root, settings_path, allow_home_settings=(args.allow_home_settings or scope == "user"))
            original_text = _read_optional_text_no_follow(settings_path)
            original = _parse_json_object_text(original_text, settings_path)
            settings = json.loads(json.dumps(original))
            checks.append(doctor_check(
                "settings-target",
                "ok",
                "low",
                "Claude settings target is readable without following symlinks.",
                detail={
                    "exists": original_text is not None,
                    "path": str(settings_path),
                },
            ))
        except SystemExit as exc:
            checks.append(doctor_check(
                "settings-target",
                "error",
                "error",
                "Claude settings target could not be read as a safe JSON object.",
                detail={
                    "exists": _path_exists_no_follow(settings_path),
                    "path": str(settings_path),
                    "error": str(exc),
                },
                next_action=f"Fix or remove {settings_path} before running setup or verify again.",
            ))
            return {
                "schema_version": "contextguard.doctor.v1",
                "status": "error",
                "root": str(root),
                "scope": scope,
                "settings_path": str(settings_path),
                "read_only": True,
                "warnings": warnings,
                "checks": checks,
                "setup_plan": {
                    "changed": False,
                    "actions": [],
                    "adapter_plan": [],
                },
                "diet_scan": {"status": "skipped", "reason": "settings-target-error"},
                "recommended_commands": [],
            }
    else:
        checks.append(doctor_check(
            "settings-target",
            "ok",
            "low",
            "Claude settings target was not requested for selected adapters.",
            detail={"path": str(settings_path)},
        ))

    if helper_check.get("status") == "error":
        diet_scan = {"status": "skipped", "reason": "helper-unavailable"}
        return {
            "schema_version": "contextguard.doctor.v1",
            "status": "error",
            "root": str(root),
            "scope": scope,
            "settings_path": str(settings_path),
            "read_only": True,
            "warnings": warnings,
            "checks": checks,
            "setup_plan": {
                "changed": False,
                "actions": [],
                "adapter_plan": [],
            },
            "diet_scan": diet_scan,
            "recommended_commands": [],
        }

    choices = choices_from_args(args)
    reference_actions = disable_unavailable_bash_reference(
        choices,
        warnings,
        root=root,
    )
    if reference_actions:
        checks.append(doctor_check(
            "bash-reference-distribution",
            "warning",
            "medium",
            reference_actions[0],
            next_action=_BASH_REFERENCE_RECOVERY + ".",
        ))
    actions = reference_actions + (
        apply_choices(
            settings,
            choices,
            allow_path_fallback=bool(getattr(args, "allow_path_helper_fallback", False)),
        )
        if claude_targeted
        else []
    )
    changed = (settings != original) if claude_targeted else False
    if changed:
        checks.append(doctor_check(
            "setup-plan",
            "warning",
            "medium",
            "ContextGuard setup is not fully applied for the requested selections.",
            detail={"planned_action_count": len(actions), "planned_actions": actions},
            next_action=_setup_command(args, apply=False, root=root),
        ))
    else:
        checks.append(doctor_check(
            "setup-plan",
            "ok",
            "low",
            "Requested setup settings are already satisfied.",
            detail={"planned_action_count": 0},
        ))

    adapter_plan = build_adapter_plan(
        root,
        targets,
        scope=scope,
        claude_actions=actions,
        claude_changed=changed,
        claude_applied=False,
        with_init=bool(getattr(args, "with_init", False)),
        with_skill=bool(getattr(args, "with_skill", False)),
        applied=False,
        brief_mode=getattr(args, "brief_mode", None),
    )
    adapter_warnings = [
        _adapter_warning_detail(entry)
        for entry in adapter_plan
        if entry.get("status") in {"planned", "unsupported", "skipped"}
    ]
    if adapter_warnings:
        checks.append(doctor_check(
            "adapter-plan",
            "warning",
            "medium",
            "Some requested adapters still have planned or unsupported setup actions.",
            detail={"adapters": adapter_warnings},
            next_action=_setup_command(args, apply=False, root=root),
        ))
    else:
        checks.append(doctor_check(
            "adapter-plan",
            "ok",
            "low",
            "Requested adapter setup plan has no pending supported writes.",
            detail={"adapter_count": len(adapter_plan)},
        ))

    diet_scan = None
    if getattr(args, "no_diet_scan", False):
        diet_scan = {"status": "skipped", "reason": "disabled-by-flag"}
        checks.append(doctor_check(
            "diet-scan",
            "ok",
            "low",
            "Context hygiene scan was skipped by flag.",
            detail=diet_scan,
        ))
    else:
        diet_next_action = shlex.join(["context-guard", "diet", "scan", str(root), "--json"])
        diet_scan = run_post_setup_diet_scan(root, allow_path_fallback=bool(getattr(args, "allow_path_helper_fallback", False)))
        if diet_scan.get("status") != "completed":
            checks.append(doctor_check(
                "diet-scan",
                "warning",
                "medium",
                "Context hygiene scan could not complete.",
                detail=diet_scan,
                next_action=diet_next_action,
            ))
        else:
            counts = diet_scan.get("severity_counts", {})
            high_medium = int(counts.get("high", 0) or 0) + int(counts.get("medium", 0) or 0)
            if high_medium:
                checks.append(doctor_check(
                    "diet-scan",
                    "warning",
                    "medium",
                    "Context hygiene scan found high/medium findings.",
                    detail=diet_scan,
                    next_action=diet_next_action,
                ))
            else:
                checks.append(doctor_check(
                    "diet-scan",
                    "ok",
                    "low",
                    "Context hygiene scan has no high/medium findings.",
                    detail=diet_scan,
                ))

    recommended = [_setup_command(args, apply=False, root=root, scope=scope)]
    if changed or adapter_warnings:
        recommended.append(_setup_command(args, apply=True, root=root, scope=scope))
    return {
        "schema_version": "contextguard.doctor.v1",
        "status": _doctor_status(checks),
        "root": str(root),
        "scope": scope,
        "settings_path": str(settings_path),
        "read_only": True,
        "warnings": warnings,
        "checks": checks,
        "setup_plan": {
            "changed": changed,
            "actions": actions,
            "adapter_plan": adapter_plan,
        },
        "diet_scan": diet_scan,
        "recommended_commands": recommended,
    }


def render_doctor_text(report: dict[str, Any]) -> str:
    lines = [
        f"ContextGuard doctor ({report.get('status', 'unknown')})",
        "read-only health check; no changes made",
        f"scope={report.get('scope')}",
        f"root={report.get('root')}",
        f"settings={report.get('settings_path')}",
    ]
    warnings = report.get("warnings") or []
    if warnings:
        lines.append("warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    lines.append("checks:")
    for check in report.get("checks", []):
        lines.append(
            f"- [{str(check.get('status', '')).upper()}] {check.get('id')}: {check.get('message')}"
        )
        if check.get("next_action"):
            lines.append(f"  next: {check['next_action']}")
    commands = report.get("recommended_commands") or []
    if commands:
        lines.append("recommended next commands:")
        lines.extend(f"- {command}" for command in commands)
    return "\n".join(lines) + "\n"


def apply_choices(settings: dict[str, Any], choices: Choices, *, allow_path_fallback: bool = False) -> list[str]:
    actions: list[str] = []
    if choices.model_defaults:
        if not settings.get("model"):
            settings["model"] = DEFAULT_MODEL
            actions.append(f"set default model to {DEFAULT_MODEL}")
        if not settings.get("effortLevel"):
            settings["effortLevel"] = DEFAULT_EFFORT
            actions.append(f"set default effortLevel to {DEFAULT_EFFORT}")
    if choices.statusline:
        statusline, omc_included = _statusline_setting(allow_path_fallback=allow_path_fallback)
        if "statusLine" not in settings:
            settings["statusLine"] = statusline
            actions.append("enabled token statusline")
            if omc_included:
                actions.append("included setup-approved OMC HUD")
        elif settings.get("statusLine") != statusline:
            existing_statusline = settings.get("statusLine")
            existing_command = (
                existing_statusline.get("command")
                if isinstance(existing_statusline, dict)
                else None
            )
            if (
                isinstance(existing_command, str)
                and exact_known_statusline_command(existing_command)
            ):
                settings["statusLine"] = statusline
                actions.append("migrated token statusline")
                if omc_included:
                    actions.append("included setup-approved OMC HUD")
            else:
                actions.append("kept existing statusLine; add context-guard-statusline-merged manually if desired")
    if choices.denies:
        ensure_permissions(
            settings,
            actions,
            migrate_env_read_denies=choices.read_guard,
        )
    if choices.bash_hook:
        bash_hook = bash_hook_setting(
            allow_path_fallback=allow_path_fallback,
            bash_reference_v1=choices.bash_reference_v1,
        )
        bash_command = bash_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, bash_hook, bash_command, "Bash trim/sanitize", actions)
        if choices.bash_reference_v1:
            actions.append(
                "enabled bash_reference_v1: a scoped 7-day bearer handle may appear in Claude/provider-visible transcripts"
            )
    if choices.read_guard:
        read_hook = read_hook_setting(allow_path_fallback=allow_path_fallback)
        read_command = read_hook["hooks"][0]["command"]
        ensure_pre_tool_hook(settings, read_hook, read_command, "large Read guard", actions)
    if choices.failed_attempt_nudge:
        nudge_hook = failed_nudge_setting(allow_path_fallback=allow_path_fallback)
        nudge_command = nudge_hook["hooks"][0]["command"]
        ensure_post_tool_hook(settings, nudge_hook, nudge_command, "failed-attempt /clear nudge", actions)
        ensure_post_tool_failure_hook(
            settings,
            nudge_hook,
            nudge_command,
            "failed-attempt /clear nudge",
            actions,
        )
    return actions


def atomic_write_bytes(
    path: Path,
    data: bytes,
    mode: int = 0o600,
    *,
    dir_mode: int = PRIVATE_DIR_MODE,
    expected: ManagedFileSnapshot | None = None,
) -> None:
    if os.rename not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd:
        raise OSError("platform does not support directory-relative atomic writes")
    parent_fd = _ensure_directory_no_symlink(path.parent, dir_mode, parents_mode=dir_mode)
    tmp_name = f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _no_follow_flag()
    fd = os.open(tmp_name, flags, mode, dir_fd=parent_fd)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.fsync(parent_fd)
        if expected is not None:
            _verify_expected_snapshot(path, expected)
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


def atomic_write(
    path: Path,
    content: str | bytes,
    mode: int = 0o600,
    *,
    dir_mode: int = PRIVATE_DIR_MODE,
) -> None:
    data = content if isinstance(content, bytes) else content.encode("utf-8")
    atomic_write_bytes(path, data, mode, dir_mode=dir_mode)


def _atomic_remove_expected(
    path: Path,
    expected: ManagedFileSnapshot,
    *,
    dir_mode: int,
) -> None:
    parent_fd = _ensure_directory_no_symlink(path.parent, dir_mode, parents_mode=dir_mode)
    try:
        _verify_expected_snapshot(path, expected)
        os.unlink(path.name, dir_fd=parent_fd)
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise AtomicWriteDurabilityError(
                f"remove committed but parent directory durability is uncertain: {path}"
            ) from exc
    finally:
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


def managed_lock_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.lock")


def acquire_managed_file_lock(path: Path, *, dir_mode: int = PRIVATE_DIR_MODE) -> int:
    """Acquire the shared sibling lock used by all managed forward/rollback writers."""
    if fcntl is None:
        raise OSError("platform does not support advisory file locks")
    parent_fd = _ensure_directory_no_symlink(path.parent, dir_mode, parents_mode=dir_mode)
    lock_name = managed_lock_path(path).name
    flags = os.O_CREAT | os.O_RDWR | _no_follow_flag()
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd: int | None = None
    try:
        for attempt in range(3):
            try:
                fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
                break
            except FileNotFoundError:
                if attempt == 2:
                    raise
                time.sleep(0.001)
    except OSError as exc:
        raise OSError(f"could not open cooperative lock {managed_lock_path(path)}: {exc}") from exc
    finally:
        os.close(parent_fd)
    if fd is None:
        raise OSError(f"could not open cooperative lock {managed_lock_path(path)}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"cooperative lock is not a regular file: {managed_lock_path(path)}")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except Exception:
        os.close(fd)
        raise


def release_managed_file_lock(fd: int) -> None:
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _managed_backup(path: Path, data: bytes, *, dir_mode: int) -> Path:
    stamp = _dt.datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup = path.with_name(f"{path.name}.bak-{stamp}-{uuid.uuid4().hex[:8]}")
    atomic_write_bytes(backup, data, 0o600, dir_mode=dir_mode)
    return backup


def write_managed_file(
    path: Path,
    *,
    expected: ManagedFileSnapshot,
    desired: bytes | None,
    mode: int = 0o644,
    dir_mode: int = 0o755,
    create_backup: bool = True,
    prepare_commit: Any = None,
) -> dict[str, Any]:
    """Apply one cooperative byte-exact transaction or return a fail-closed status."""
    if desired == expected.data:
        return {"status": "unchanged", "backup_path": None}
    try:
        lock_fd = acquire_managed_file_lock(path, dir_mode=dir_mode)
    except OSError as exc:
        return {"status": "skipped", "reason": f"could not acquire cooperative lock: {exc}"}
    backup_path: Path | None = None
    try:
        try:
            current = _verify_expected_snapshot(path, expected)
        except ManagedFileConflictError as exc:
            return {"status": "conflict", "reason": str(exc), "backup_path": None}

        target_mode = mode
        if current.metadata is not None:
            target_mode = stat.S_IMODE(current.metadata[2])
        if current.data is not None and create_backup:
            try:
                backup_path = _managed_backup(path, current.data, dir_mode=dir_mode)
            except OSError as exc:
                return {
                    "status": "skipped",
                    "reason": f"could not create private managed-file backup: {exc}",
                    "backup_path": None,
                }
        try:
            if desired is None:
                if prepare_commit is not None:
                    prepare_commit(backup_path)
                _atomic_remove_expected(path, current, dir_mode=dir_mode)
            else:
                _verify_expected_snapshot(path, current)
                if prepare_commit is not None:
                    prepare_commit(backup_path)
                atomic_write(
                    path,
                    desired,
                    target_mode,
                    dir_mode=dir_mode,
                )
        except ManagedFileConflictError as exc:
            return {
                "status": "conflict",
                "reason": str(exc),
                "backup_path": str(backup_path) if backup_path else None,
            }
        except AtomicWriteDurabilityError as exc:
            return {
                "status": "applied-durability-uncertain",
                "reason": str(exc),
                "backup_path": str(backup_path) if backup_path else None,
                "residual_risk": (
                    "A non-cooperating editor can still race after the final comparison; "
                    "automatic follow-on mutation is blocked."
                ),
            }
        except OSError as exc:
            return {
                "status": "skipped",
                "reason": f"could not commit managed file: {exc}",
                "backup_path": str(backup_path) if backup_path else None,
            }
        return {
            "status": "applied",
            "backup_path": str(backup_path) if backup_path else None,
            "residual_risk": (
                "Cooperating ContextGuard writers serialize; a non-cooperating editor can still race "
                "after the final comparison and before atomic replace."
            ),
        }
    finally:
        release_managed_file_lock(lock_fd)


def rollback_managed_file(
    path: Path,
    *,
    expected_post: ManagedFileSnapshot,
    restore: bytes | None,
    kind: str,
    mode: int = 0o644,
    dir_mode: int = 0o755,
) -> dict[str, Any]:
    """Rollback only a still-matching post-image with the same parser/lock authority."""
    if expected_post.data is None:
        return {"status": "skipped", "reason": "rollback post-image is missing"}
    ownership = parse_managed_bytes(expected_post.data, kind=kind)
    if ownership.status != "valid":
        return {
            "status": "skipped",
            "reason": f"rollback lacks valid {kind} ownership: {ownership.status}",
        }
    return write_managed_file(
        path,
        expected=expected_post,
        desired=restore,
        mode=mode,
        dir_mode=dir_mode,
    )


def rollback_restore_guidance(settings_path: Path, backup_path: Path | None, original_existed: bool) -> str:
    if backup_path is not None:
        return (
            "Restore only with a no-follow, symlink-safe copy that opens the backup and target parent "
            "without following links, then atomically replaces the target; do not use generic shell "
            f"copy/delete commands on this mutable target. Backup: {backup_path}. Target: {settings_path}."
        )
    if original_existed:
        return (
            "No backup path was recorded; inspect the target with no-follow file operations before any "
            f"manual recovery. Do not use generic shell copy/delete commands on this mutable target: {settings_path}."
        )
    return (
        "The target did not exist before setup. If cleanup is required, verify the target and every parent "
        "without following symlinks and remove only the verified regular file; do not use generic shell "
        f"delete commands on this mutable target: {settings_path}."
    )


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
        "restore": rollback_restore_guidance(settings_path, backup_path, original_existed),
        "restore_requires_no_follow": True,
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
        bash_reference_v1=prompt_bool(
            "Enable optional Bash receipt references? 7-day scoped bearer handles are visible to Claude/provider transcripts",
            defaults.bash_reference_v1,
        ),
        read_guard=prompt_bool("Enable large Read guard?", defaults.read_guard),
        model_defaults=prompt_bool("Set missing defaults to model=sonnet and effortLevel=medium?", defaults.model_defaults),
        failed_attempt_nudge=prompt_bool(
            "Enable failed-attempt /clear nudge? (Bash terminal-event hooks; recommended default)",
            defaults.failed_attempt_nudge,
        ),
    )
    return choices


def choices_from_args(args: argparse.Namespace) -> Choices:
    return Choices(
        denies=not args.no_denies,
        statusline=not args.no_statusline,
        bash_hook=not args.no_bash_hook,
        bash_reference_v1=getattr(args, "bash_reference_v1", False),
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
            if entry.get("rule_backup_path"):
                lines.append(f"  - backup={entry['rule_backup_path']}")
    if result.apply_requested and not result.applied:
        lines.append("No supported writes were applied.")
    elif not result.applied:
        lines.append("Run with --yes to apply the selected plan non-interactively.")
    return "\n".join(lines) + "\n"


def validate_rules_only_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> bool:
    """Validate and identify the isolated Claude quiet-narration CLI branch."""
    rules_only = bool(getattr(args, "rules_only", False))
    narration_mode = getattr(args, "narration_mode", None)
    if narration_mode and not rules_only:
        parser.error("--narration-mode requires --rules-only")
    if rules_only and not narration_mode:
        parser.error("--rules-only requires a rule operation such as --narration-mode")
    if not rules_only:
        return False

    if getattr(args, "scope", "project") != "project":
        parser.error("quiet narration rules support only --scope project")
    selected = [item.lower() for item in (explicit_agent_selection(args) or [])]
    if selected != ["claude"] or not getattr(args, "agent", None) or getattr(args, "only", None):
        parser.error("quiet narration rules require exactly one explicit --agent claude")
    action_count = sum(
        bool(value)
        for value in (
            getattr(args, "yes", False),
            getattr(args, "plan", False),
            getattr(args, "dry_run", False),
        )
    )
    if action_count != 1:
        parser.error("quiet narration rules require exactly one of --plan, --dry-run, or --yes")

    conflicting = [
        flag
        for attr, flag in (
            ("allow_home_settings", "--allow-home-settings"),
            ("verify", "--verify"),
            ("no_backup", "--no-backup"),
            ("no_denies", "--no-denies"),
            ("no_statusline", "--no-statusline"),
            ("no_bash_hook", "--no-bash-hook"),
            ("no_read_guard", "--no-read-guard"),
            ("no_model_defaults", "--no-model-defaults"),
            ("no_diet_scan", "--no-diet-scan"),
            ("allow_path_helper_fallback", "--allow-path-helper-fallback"),
            ("with_init", "--with-init"),
            ("with_skill", "--with-skill"),
            ("brief_mode", "--brief-mode"),
            ("list_adapters", "--list-adapters"),
        )
        if getattr(args, attr, False)
    ]
    if getattr(args, "failed_attempt_nudge", None) is not None:
        conflicting.append(
            "--failed-attempt-nudge"
            if args.failed_attempt_nudge
            else "--no-failed-attempt-nudge"
        )
    if conflicting:
        parser.error(
            "quiet narration rules cannot be combined with settings, hook, adapter, "
            f"or setup flags: {', '.join(conflicting)}"
        )
    return True


def run_quiet_narration_rules(args: argparse.Namespace) -> dict[str, Any]:
    """Plan/apply the isolated Claude/project CLAUDE.md narration span."""
    require_no_follow_file_ops_supported()
    root = resolve_setup_root(args.root)
    rule_path = root / "CLAUDE.md"
    state = _rule_file_state(rule_path)
    if state["status"] not in {"missing", "file"}:
        raise SystemExit(
            state.get("reason")
            or f"refused unsafe quiet narration rule target: {rule_path}"
        )
    existing = bytes(state.get("bytes") or b"")
    parsed = parse_managed_bytes(existing, kind="narration-mode")
    if parsed.status not in {"absent", "valid"}:
        raise SystemExit(
            f"refused unsafe managed narration state in {rule_path.name}: "
            f"{parsed.reason or parsed.status}"
        )

    mode = str(args.narration_mode)
    span = parsed.spans[0] if parsed.status == "valid" else None
    desired = existing
    if mode == "quiet":
        block = _managed_block_bytes(render_quiet_narration_block())
        if span is None:
            desired = _append_narration_block_bytes(existing, block)
        elif existing[span.start : span.end] != block:
            desired = _replace_managed_span(existing, span, block)
    elif span is not None:
        removal_start = span.start
        if removal_start > 0 and existing[removal_start - 1 : removal_start] == b"\n":
            removal_start -= 1
        desired = existing[:removal_start] + existing[span.end :]

    changed = desired != existing
    apply_requested = bool(args.yes)
    if not changed:
        status = "exists" if mode == "quiet" else "absent"
        return {
            "schema_version": "contextguard.narration-rules.v1",
            "operation": "quiet-narration",
            "mode": mode,
            "root": str(root),
            "rule_file": str(rule_path),
            "marker_state_before": parsed.status,
            "status": status,
            "changed": False,
            "applied": False,
            "apply_requested": apply_requested,
            "backup_path": None,
            "actions": [
                "quiet narration rules already present"
                if mode == "quiet"
                else "quiet narration rules already absent"
            ],
            "claim_boundary": "static setup result only; no model-compliance or savings claim",
        }

    planned_status = "planned"
    action = (
        ("add" if span is None else "refresh") + " quiet narration rules"
        if mode == "quiet"
        else "remove quiet narration rules"
    )
    if not apply_requested:
        return {
            "schema_version": "contextguard.narration-rules.v1",
            "operation": "quiet-narration",
            "mode": mode,
            "root": str(root),
            "rule_file": str(rule_path),
            "marker_state_before": parsed.status,
            "status": planned_status,
            "changed": True,
            "applied": False,
            "apply_requested": False,
            "backup_path": None,
            "actions": [f"would {action}"],
            "claim_boundary": "static setup result only; no model-compliance or savings claim",
        }

    write_result = write_managed_file(
        rule_path,
        expected=state["snapshot"],
        desired=desired,
        mode=existing_mode_or_default(rule_path, 0o644),
        dir_mode=0o755,
    )
    if write_result["status"] not in {"applied", "applied-durability-uncertain"}:
        raise SystemExit(
            write_result.get("reason")
            or f"could not safely update quiet narration rules in {rule_path}"
        )
    status = (
        write_result["status"]
        if write_result["status"] == "applied-durability-uncertain"
        else ("removed" if mode == "default" else ("applied" if span is None else "updated"))
    )
    payload = {
        "schema_version": "contextguard.narration-rules.v1",
        "operation": "quiet-narration",
        "mode": mode,
        "root": str(root),
        "rule_file": str(rule_path),
        "marker_state_before": parsed.status,
        "status": status,
        "changed": True,
        "applied": True,
        "apply_requested": True,
        "backup_path": write_result.get("backup_path"),
        "actions": [action],
        "claim_boundary": "static setup result only; no model-compliance or savings claim",
    }
    if write_result.get("reason"):
        payload["warning"] = write_result["reason"]
    if write_result.get("residual_risk"):
        payload["residual_risk"] = write_result["residual_risk"]
    return payload


def render_quiet_narration_text(result: dict[str, Any]) -> str:
    lines = [
        f"ContextGuard quiet narration ({result['status']})",
        f"root={result['root']}",
        f"rule_file={result['rule_file']}",
        f"mode={result['mode']}",
    ]
    if result.get("backup_path"):
        lines.append(f"backup={result['backup_path']}")
    lines.extend(f"- {action}" for action in result.get("actions", []))
    lines.append(str(result["claim_boundary"]))
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> SetupResult:
    require_no_follow_file_ops_supported()
    scope = effective_scope(
        args.root,
        getattr(args, "scope", "project"),
        allow_home_settings=bool(getattr(args, "allow_home_settings", False)),
    )
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
        settings_snapshot = read_managed_file_snapshot(settings_path)
        snapshot_text = (
            settings_snapshot.data.decode("utf-8")
            if settings_snapshot.data is not None
            else None
        )
        if snapshot_text != original_text:
            raise SystemExit(
                f"Settings changed while setup was preparing changes; re-run setup to merge latest file: {settings_path}"
            )
        original = _parse_json_object_text(original_text, settings_path)
        settings = json.loads(json.dumps(original))
    else:
        original_text = None
        settings_snapshot = ManagedFileSnapshot(None, None)
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

    reference_actions = disable_unavailable_bash_reference(
        choices,
        warnings,
        root=root,
    )
    actions = reference_actions + (
        apply_choices(
            settings,
            choices,
            allow_path_fallback=bool(getattr(args, "allow_path_helper_fallback", False)),
        )
        if claude_targeted
        else []
    )
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
        rollback_state: dict[str, Any] = {}

        def prepare_settings_commit(managed_backup_path: Path | None) -> None:
            prepared_rollback_id, prepared_rollback_path = write_rollback_record(
                root=root,
                scope=scope,
                settings_path=settings_path,
                backup_path=managed_backup_path,
                original_existed=(original_text is not None),
            )
            rollback_state.update({
                "rollback_id": prepared_rollback_id,
                "rollback_path": prepared_rollback_path,
            })

        desired_settings = (
            json.dumps(settings, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        write_result = write_managed_file(
            settings_path,
            expected=settings_snapshot,
            desired=desired_settings,
            mode=existing_mode_or_default(settings_path, 0o600),
            dir_mode=PRIVATE_DIR_MODE,
            create_backup=not args.no_backup,
            prepare_commit=prepare_settings_commit,
        )
        if write_result["status"] not in {"applied", "applied-durability-uncertain"}:
            reason = write_result.get("reason") or "managed settings transaction was not applied"
            raise SystemExit(f"Could not safely update {settings_path}: {reason}")
        if write_result.get("backup_path"):
            backup_path = Path(write_result["backup_path"])
        rollback_id = rollback_state.get("rollback_id")
        rollback_path = rollback_state.get("rollback_path")
        if write_result["status"] == "applied-durability-uncertain" and write_result.get("reason"):
            warnings.append(str(write_result["reason"]))
        if write_result.get("residual_risk"):
            warnings.append(str(write_result["residual_risk"]))
        claude_settings_written = True

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
        diet_scan = run_post_setup_diet_scan(root, allow_path_fallback=bool(getattr(args, "allow_path_helper_fallback", False)))

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
    parser.add_argument("--verify", action="store_true", help="run a read-only setup health check; never writes or prompts")
    parser.add_argument("--json", action="store_true", help="print machine-readable result")
    parser.add_argument(
        "--rules-only",
        action="store_true",
        help="run an isolated rule-file operation without reading or changing settings/hooks",
    )
    parser.add_argument(
        "--narration-mode",
        choices=NARRATION_MODE_CHOICES,
        default=None,
        help="with --rules-only, add quiet Claude narration guidance or restore default behavior",
    )
    parser.add_argument("--no-backup", action="store_true", help="do not create .bak-* before modifying existing settings")
    parser.add_argument("--no-denies", action="store_true", help="skip recommended permissions.deny rules")
    parser.add_argument("--no-statusline", action="store_true", help="skip token statusline")
    parser.add_argument("--no-bash-hook", action="store_true", help="skip Bash trim/sanitize hook")
    reference_group = parser.add_mutually_exclusive_group()
    reference_group.add_argument(
        "--bash-reference-v1",
        action="store_true",
        help="opt in to 7-day scoped receipt references in the Bash hook; handles are provider-visible",
    )
    reference_group.add_argument(
        "--no-bash-reference-v1",
        dest="bash_reference_v1",
        action="store_false",
        help="disable/remove the optional Bash receipt-reference hook flag (default)",
    )
    parser.set_defaults(bash_reference_v1=False)
    parser.add_argument("--no-read-guard", action="store_true", help="skip large Read guard hook")
    parser.add_argument("--no-model-defaults", action="store_true", help="skip model/effort defaults")
    parser.add_argument("--no-diet-scan", action="store_true", help="skip the read-only diet scan summary after applying setup")
    parser.add_argument("--allow-path-helper-fallback", action="store_true", help="allow trusted PATH helper resolution only after bundled/repo helpers are missing and identity validation passes")
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
        help="enable Bash terminal-event hooks that suggest /clear when the same command fails twice in a row (recommended default)",
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
    rules_only = validate_rules_only_args(parser, args)
    if rules_only:
        result = run_quiet_narration_rules(args)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(render_quiet_narration_text(result), end="")
        return 0
    if args.dry_run:
        args.plan = True
    if args.verify and args.yes:
        parser.error("--verify is read-only and cannot be combined with --yes")
    if getattr(args, "list_adapters", False):
        payload = adapter_registry_payload()
        if args.json:
            print(json.dumps({"adapters": payload}, indent=2, sort_keys=True))
        else:
            print("ContextGuard cross-agent adapters:")
            for item in payload:
                print(f"- {item['key']} [{item['capability']}] {item['display_name']}: {item['summary']}")
        return 0
    if args.verify:
        args.plan = True
        result = run_doctor(args)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(render_doctor_text(result))
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
