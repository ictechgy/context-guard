#!/usr/bin/env python3
"""Canonical ContextGuard command/package manifest.

This module is intentionally side-effect free. It centralizes command, copy,
package, and smoke-test inventories that were previously repeated across the
runtime dispatcher, release gates, sync tooling, smoke tests, and unit tests.
"""
from __future__ import annotations

from typing import Any

IMPLEMENTATION_PAIRS: tuple[tuple[str, str], ...] = (
    ("context_guard_cli.py", "context-guard"),
    ("cost_guard.py", "context-guard-cost"),
    ("cache_score.py", "context-guard-cache-score"),
    ("benchmark_runner.py", "context-guard-bench"),
    ("context_escrow.py", "context-guard-artifact"),
    ("context_compress.py", "context-guard-compress"),
    ("context_pack.py", "context-guard-pack"),
    ("context_filter.py", "context-guard-filter"),
    ("tool_schema_pruner.py", "context-guard-tool-prune"),
    ("claude_transcript_cost_audit.py", "context-guard-audit"),
    ("context_guard_diet.py", "context-guard-diet"),
    ("experimental_registry.py", "context-guard-experiments"),
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

HELPER_PAIRS: tuple[tuple[str, str], ...] = (
    ("hook_secret_patterns.py", "lib/hook_secret_patterns.py"),
    ("context_guard_commands.py", "lib/context_guard_commands.py"),
)

NPM_BINS: tuple[str, ...] = (
    "context-guard",
    "context-guard-cost",
    "context-guard-cache-score",
    "context-guard-bench",
    "context-guard-artifact",
    "context-guard-compress",
    "context-guard-pack",
    "context-guard-filter",
    "context-guard-tool-prune",
    "context-guard-audit",
    "context-guard-diet",
    "context-guard-experiments",
    "context-guard-failed-nudge",
    "context-guard-guard-read",
    "context-guard-read-symbol",
    "context-guard-rewrite-bash",
    "context-guard-sanitize-output",
    "context-guard-setup",
    "context-guard-statusline",
    "context-guard-statusline-merged",
    "context-guard-trim-output",
)
NPM_BIN_PATHS: dict[str, str] = {
    name: f"plugins/context-guard/bin/{name}" for name in NPM_BINS
}

DISPATCHER_SUBCOMMANDS: dict[str, tuple[str, ...]] = {
    "setup": ("context-guard-setup",),
    "doctor": ("context-guard-setup", "--verify"),
    "audit": ("context-guard-audit",),
    "diet": ("context-guard-diet",),
    "experiments": ("context-guard-experiments",),
    "scan": ("context-guard-diet", "scan"),
    "trim-output": ("context-guard-trim-output",),
    "trim": ("context-guard-trim-output",),
    "sanitize-output": ("context-guard-sanitize-output",),
    "sanitize": ("context-guard-sanitize-output",),
    "filter": ("context-guard-filter",),
    "artifact": ("context-guard-artifact",),
    "pack": ("context-guard-pack",),
    "tool-prune": ("context-guard-tool-prune",),
    "compress": ("context-guard-compress",),
    "cost": ("context-guard-cost",),
    "cache-score": ("context-guard-cache-score",),
    "bench": ("context-guard-bench",),
    "read-symbol": ("context-guard-read-symbol",),
    "rewrite-bash": ("context-guard-rewrite-bash",),
    "guard-read": ("context-guard-guard-read",),
    "failed-nudge": ("context-guard-failed-nudge",),
    "statusline": ("context-guard-statusline",),
    "statusline-merged": ("context-guard-statusline-merged",),
}

LEGACY_WRAPPERS: tuple[str, ...] = (
    "claude-read-symbol",
    "claude-sanitize-output",
    "claude-token-artifact",
    "claude-token-audit",
    "claude-token-bench",
    "claude-token-diet",
    "claude-token-failed-nudge",
    "claude-token-guard-read",
    "claude-token-rewrite-bash",
    "claude-token-setup",
    "claude-token-statusline",
    "claude-token-statusline-merged",
    "claude-trim-output",
)

ENTRYPOINT_SMOKE_CASES: dict[str, dict[str, Any]] = {
    "context-guard": {"args": ["--version"], "mode": "text"},
    "context-guard-read-symbol": {"args": ["--help"], "mode": "text"},
    "context-guard-sanitize-output": {"args": ["--help"], "mode": "text"},
    "context-guard-artifact": {"args": ["--help"], "mode": "text"},
    "context-guard-audit": {"args": ["--help"], "mode": "text"},
    "context-guard-bench": {"args": ["--help"], "mode": "text"},
    "context-guard-compress": {"args": ["--help"], "mode": "text"},
    "context-guard-cost": {"args": ["--help"], "mode": "text"},
    "context-guard-cache-score": {"args": ["--help"], "mode": "text"},
    "context-guard-pack": {"args": ["--help"], "mode": "text"},
    "context-guard-tool-prune": {"args": ["--help"], "mode": "text"},
    "context-guard-diet": {"args": ["--help"], "mode": "text"},
    "context-guard-experiments": {"args": ["--help"], "mode": "text"},
    "context-guard-failed-nudge": {"args": [], "mode": "hook-json"},
    "context-guard-filter": {"args": ["--help"], "mode": "text"},
    "context-guard-guard-read": {"args": [], "mode": "hook-json"},
    "context-guard-rewrite-bash": {"args": [], "mode": "hook-json"},
    "context-guard-setup": {"args": ["--help"], "mode": "text"},
    "context-guard-statusline": {"args": [], "mode": "statusline"},
    "context-guard-statusline-merged": {"args": [], "mode": "statusline"},
    "context-guard-trim-output": {"args": ["--help"], "mode": "text"},
    # Legacy wrappers kept so existing automation does not break during the rebrand.
    "claude-read-symbol": {"args": ["--help"], "mode": "text"},
    "claude-sanitize-output": {"args": ["--help"], "mode": "text"},
    "claude-token-artifact": {"args": ["--help"], "mode": "text"},
    "claude-token-audit": {"args": ["--help"], "mode": "text"},
    "claude-token-bench": {"args": ["--help"], "mode": "text"},
    "claude-token-diet": {"args": ["--help"], "mode": "text"},
    "claude-token-failed-nudge": {"args": [], "mode": "hook-json"},
    "claude-token-guard-read": {"args": [], "mode": "hook-json"},
    "claude-token-rewrite-bash": {"args": [], "mode": "hook-json"},
    "claude-token-setup": {"args": ["--help"], "mode": "text"},
    "claude-token-statusline": {"args": [], "mode": "statusline"},
    "claude-token-statusline-merged": {"args": [], "mode": "statusline"},
    "claude-trim-output": {"args": ["--help"], "mode": "text"},
}

PLUGIN_ENTRYPOINTS: tuple[str, ...] = (
    "claude-read-symbol",
    "claude-sanitize-output",
    "claude-token-artifact",
    "claude-token-audit",
    "claude-token-bench",
    "claude-token-diet",
    "claude-token-failed-nudge",
    "claude-token-guard-read",
    "claude-token-rewrite-bash",
    "claude-token-setup",
    "claude-token-statusline",
    "claude-token-statusline-merged",
    "claude-trim-output",
    "context-guard",
    "context-guard-artifact",
    "context-guard-audit",
    "context-guard-bench",
    "context-guard-compress",
    "context-guard-cost",
    "context-guard-cache-score",
    "context-guard-diet",
    "context-guard-experiments",
    "context-guard-failed-nudge",
    "context-guard-filter",
    "context-guard-guard-read",
    "context-guard-pack",
    "context-guard-read-symbol",
    "context-guard-rewrite-bash",
    "context-guard-sanitize-output",
    "context-guard-setup",
    "context-guard-statusline",
    "context-guard-statusline-merged",
    "context-guard-tool-prune",
    "context-guard-trim-output",
)

DISPATCHER_SMOKE_CASES: tuple[dict[str, Any], ...] = (
    {"entrypoint": "context-guard", "args": ["experiments", "list", "--json"], "mode": "json"},
    {"entrypoint": "context-guard", "args": ["cost", "--help"], "mode": "text"},
    {"entrypoint": "context-guard", "args": ["cache-score", "--help"], "mode": "text"},
    {"entrypoint": "context-guard-pack", "args": ["suggest", "--help"], "mode": "text"},
    {"entrypoint": "context-guard-pack", "args": ["auto", "--help"], "mode": "text"},
)


def expected_command_pack_files() -> tuple[str, ...]:
    # npm packages ship the plugin-local executable/helper copies only. The
    # checkout-local ``context-guard-kit`` files remain the source of truth for
    # maintainers and are kept byte-synchronized with these packaged copies by
    # ``scripts/sync_plugin_copies.py`` and ``scripts/prepublish_check.py``.
    files = {f"plugins/context-guard/bin/{bin_name}" for _kit_name, bin_name in IMPLEMENTATION_PAIRS}
    files.update(f"plugins/context-guard/{plugin_rel}" for _kit_name, plugin_rel in HELPER_PAIRS)
    files.update(f"plugins/context-guard/bin/{wrapper}" for wrapper in LEGACY_WRAPPERS)
    return tuple(sorted(files))
