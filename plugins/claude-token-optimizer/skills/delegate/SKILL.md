---
description: Opt-in delegation to another locally authenticated AI CLI such as Gemini or Codex to reduce Claude Code token usage by offloading broad read-only analysis, logs, or planning. Use when the user asks to use Gemini, Codex, another AI, an auxiliary AI assistant, or non-Claude subscription to save Claude tokens.
argument-hint: enable|disable|status|ask [provider/task]
allowed-tools: Bash(claude-token-delegate *)
---

# Auxiliary AI Delegation

This skill helps use another local AI CLI as a bounded, read-only assistant so Claude does not need to ingest large context directly.

Safety and privacy rules:

- The feature is OFF by default. Do not call external AI with project context until `claude-token-delegate enable` has been run or `CLAUDE_TOKEN_OPTIMIZER_AUX_AI=1` is set.
- Do not send secrets, private customer data, proprietary files, or credentials to another provider unless the user explicitly confirms it is allowed by their policy.
- Prefer passing file paths via `--context` so the auxiliary AI receives the large context and Claude receives only a short preview. Obvious secret-like paths (`.env*`, key files, token/secret filenames) are blocked unless the user explicitly passes `--allow-sensitive-context`.
- Keep output bounded; the helper saves the full auxiliary response locally and prints a trimmed preview.
- Use this for read-only research, log summarization, root-cause hypothesis generation, file/symbol triage, and second-opinion planning. Do not use it for destructive operations.
- The default Codex command uses `--skip-git-repo-check` because providers run in a temporary directory outside the user repo; it still uses Codex read-only sandbox mode.

Common commands:

```bash
claude-token-delegate status
claude-token-delegate init --provider gemini
claude-token-delegate enable --provider gemini
claude-token-delegate enable --provider codex
claude-token-delegate disable
claude-token-delegate ask --provider gemini --prompt "Summarize likely root cause" --context path/to/log.txt
claude-token-delegate ask --provider codex --prompt "Find likely files to inspect for this bug" --context src/error.log
# Only when policy allows sending a secret-like file to the selected provider:
claude-token-delegate ask --provider gemini --allow-sensitive-context --prompt "Summarize this env-shaped sample" --context ./.env.example
```

When the user asks to enable/disable/status, run the matching command and report the result.

When the user asks to delegate a task:

1. Run `claude-token-delegate status`.
2. If disabled, explain the exact enable command and stop.
3. If enabled, choose provider from the user request or default provider.
4. Use a concise prompt and only the minimum relevant `--context` files.
5. Summarize the returned preview and cite the saved response path if deeper review is needed.
