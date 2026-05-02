---
description: Diagnose and reduce Claude Code token usage for a project or session using context hygiene, model and effort routing, MCP minimization, output trimming, subagent discipline, and measurement. Use when the user asks to lower Claude Code token usage, cost, context bloat, or usage-limit burn.
argument-hint: [project/session symptoms]
allowed-tools: Bash(claude-token-audit *), Bash(claude-token-diet scan *), Bash(claude-trim-output *), Bash(claude-token-statusline)
---

# Claude Token Optimizer

Goal: reduce Claude Code token usage without lowering task success quality.

Use this order:

1. Measure before changing behavior.
   - Ask the user to run `/usage` and `/context` if inside Claude Code.
   - If transcript files are available, run `claude-token-audit ~/.claude/projects --top 20 --recommend`.
   - For project configuration/context bloat, run `claude-token-diet scan .`.
2. Identify the largest bucket:
   - stale conversation history -> recommend `/clear` between unrelated tasks and focused `/compact` for long tasks.
   - startup context -> prune `CLAUDE.md`, move long workflows to skills, disable unused MCP servers.
   - noisy command output -> use `claude-trim-output` wrappers or the example PreToolUse hook.
   - expensive reasoning -> route default work to `sonnet` and lower `/effort`; reserve Opus/`opusplan` for planning.
   - noisy exploration -> use a subagent for logs/research, but avoid agent teams unless parallel value justifies the multiplier.
3. Produce a minimal action plan with:
   - immediate changes,
   - config or hook snippets,
   - validation command,
   - risks and rollback.
4. Do not recommend payment/limit bypasses, account sharing, leaked-source patches, or other unsafe/unauthorized methods.

Useful local commands provided by this plugin:

```bash
claude-token-audit ~/.claude/projects --top 20 --recommend
claude-token-diet scan .
claude-trim-output --max-lines 120 -- npm test
claude-token-statusline
```

If installing hook examples, prefer project-local opt-in settings first. Do not silently modify global `~/.claude/settings.json`.
