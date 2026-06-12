---
description: Interactive or guided project setup for Claude Code token optimizer settings. Use when the user asks to install, configure, setup, enable hooks, or choose token-saving options interactively.
argument-hint: [plan|apply|options]
allowed-tools: Bash(context-guard-setup *), Bash(context-guard-diet scan *)
---

# ContextGuard Setup

Goal: help the user configure this plugin without memorizing helper commands.

Default flow:

1. Run a read-only health check and plan first:

```bash
context-guard-setup --verify
context-guard-setup --plan
```

2. Explain the options briefly:
   - deny bulky/sensitive reads,
   - token/cost statusline,
   - Bash trim + grep/diff sanitizer hook,
   - large Read guard,
   - failed-attempt nudge for repeated Bash failures,
   - missing model/effort defaults.
3. If the user wants the recommended project-local setup, run:

```bash
context-guard-setup --yes
```

4. Treat the post-apply `context-guard-diet scan` summary emitted by setup as the default remaining-gap check; run `context-guard-diet scan .` separately only when the user wants the full report.
5. For automation that must skip the post-apply scan summary, run `context-guard-setup --no-diet-scan --yes`.
6. If they want extra token reduction beyond setup, prefer local artifact escrow, symbol reads, and semantic digests rather than external model offload.

Safety:

- Do not modify global `~/.claude/settings.json`.
- Prefer project-local `.claude/settings.json`.
- `context-guard-setup --verify` is a local read-only health check and never applies settings.
- Setup's post-apply scan is local, read-only, and prints a summary only; it does not mutate settings.
- Setup should use packaged/check-out helper paths by default; only pass `--allow-path-helper-fallback` when the user explicitly trusts a PATH-installed ContextGuard helper set.
