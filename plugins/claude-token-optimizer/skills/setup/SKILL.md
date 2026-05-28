---
description: Interactive or guided project setup for Claude Code token optimizer settings. Use when the user asks to install, configure, setup, enable hooks, or choose token-saving options interactively.
argument-hint: [plan|apply|options]
allowed-tools: Bash(claude-token-setup *), Bash(claude-token-diet scan *)
---

# Claude Token Optimizer Setup

Goal: help the user configure this plugin without memorizing helper commands.

Default flow:

1. Run a read-only plan first:

```bash
claude-token-setup --plan
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
claude-token-setup --yes
```

4. Treat the post-apply `claude-token-diet scan` summary emitted by setup as the default remaining-gap check; run `claude-token-diet scan .` separately only when the user wants the full report.
5. If they want extra token reduction beyond setup, prefer local artifact escrow, symbol reads, and semantic digests rather than external model offload.

Safety:

- Do not modify global `~/.claude/settings.json`.
- Prefer project-local `.claude/settings.json`.
- Setup's post-apply scan is read-only; use `claude-token-setup --no-diet-scan --yes` only for automation that must skip it.
