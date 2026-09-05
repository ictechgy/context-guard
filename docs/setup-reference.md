# ContextGuard setup reference

This file is generated from `context-guard-kit/setup_wizard.py`. Do not edit it manually.
Regenerate it with `python3 scripts/generate_setup_reference.py --write` and verify it with `--check`.

## Agent capability matrix

`verified` means ContextGuard has a bounded project write path. `report-only` means setup reports guidance and does not claim a verified write target.
Only Claude Code currently has a verified user-scope write path; every user-scope write requires explicit agent selection and `--yes`.

| Key | Agent | Project scope | User scope | Rules | Skill | MCP | Hooks | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claude` | Claude Code | verified | verified write | yes | — | — | yes | Installs project-local hooks, denies, and statusline in .claude/settings.json. |
| `codex` | OpenAI Codex CLI | verified | report-only | yes | yes | yes | — | Reads AGENTS.md and supports an optional project skill and project-scoped stdio MCP configuration. |
| `gemini` | Gemini CLI | verified | report-only | yes | — | yes | — | Reads GEMINI.md and supports project .gemini/settings.json MCP setup. |
| `cursor` | Cursor | verified | report-only | yes | — | yes | — | Reads project rules and supports project .cursor/mcp.json setup. |
| `windsurf` | Windsurf | verified | report-only | yes | — | — | — | Reads project rules; add an advisory ContextGuard block with --with-init. |
| `cline` | Cline | verified | report-only | yes | — | — | — | Reads project rules; add an advisory ContextGuard block with --with-init. |
| `copilot` | GitHub Copilot Coding Agent | verified | report-only | yes | — | yes | — | Reads repository instructions and supports project .vscode/mcp.json setup. |
| `opencode` | OpenCode | verified | report-only | — | yes | yes | — | Supports a project skill and project opencode.json MCP setup; no hooks are auto-written. |
| `forgecode` | ForgeCode | verified | report-only | — | — | yes | — | Supports project-local .mcp.json setup; other helpers remain shell-driven. |
| `generic` | Other / unknown agent | shell only | report-only | — | — | — | — | No automated setup surface; run ContextGuard helpers from the shell as needed. |

## Setup flags

`--plan` and `--dry-run` are read-only. Writes require `--yes`; user scope additionally requires explicit `--agent` or `--only` selection.

| Flag | Default | Choices | Description |
| --- | --- | --- | --- |
| `--root` | — | — | project root to configure (default: nearest git root, else current directory) |
| `--scope` | `project` | `project`, `user`, `global` | setup scope: project-local by default; user/global targets only known user-level paths and requires explicit --agent for writes |
| `--profile` | `recommended` | `minimal`, `recommended`, `max` | which guardrails to enable: minimal (deny rules + Read guard), recommended (adds Bash trim/escrow and model defaults), max (adds the deprecated statusline and the failed-attempt nudge); individual --no-* flags still remove items |
| `--yes` | false | — | apply the recommended/selected setup without prompts |
| `--plan` | false | — | show the setup plan without writing files |
| `--verify` | false | — | run a read-only setup health check; never writes or prompts |
| `--json` | false | — | print machine-readable result |
| `--rules-only` | false | — | run an isolated rule-file operation without reading or changing settings/hooks |
| `--narration-mode` | — | `quiet`, `default` | with --rules-only, add quiet Claude narration guidance or restore default behavior |
| `--no-backup` | false | — | do not create .bak-* before modifying existing settings |
| `--no-denies` | false | — | skip recommended permissions.deny rules |
| `--no-statusline` | false | — | skip the token statusline (deprecated: it duplicates Claude Code /usage; only --profile max installs it) |
| `--no-bash-hook` | false | — | skip Bash trim/sanitize hook |
| `--bash-reference-v1` | false | — | opt in to 7-day scoped receipt references in the Bash hook; handles are provider-visible |
| `--no-bash-reference-v1` | false | — | disable/remove the optional Bash receipt-reference hook flag (default) |
| `--no-read-guard` | false | — | skip large Read guard hook |
| `--no-model-defaults` | false | — | skip model/effort defaults |
| `--no-diet-scan` | false | — | skip the read-only diet scan summary after applying setup |
| `--allow-path-helper-fallback` | false | — | allow trusted PATH helper resolution only after bundled/repo helpers are missing and identity validation passes |
| `--agent` | — | — | adapter key(s) to configure; comma-separated or repeatable. Alias for --only. |
| `--only` | — | — | restrict cross-agent setup/plan to adapter key(s); comma-separated or repeatable (e.g. --only codex,gemini). Default: claude plus any detected agents. |
| `--with-init` | false | — | also write advisory ContextGuard rule files for repo-rule agents (AGENTS.md, GEMINI.md, .cursorrules, etc.) when applying; safe and idempotent. |
| `--with-skill` | false | — | also generate optional project-local skill files where supported, currently Codex and OpenCode .agents/skills/context-guard/SKILL.md. |
| `--with-mcp` | false | — | also configure a verified project-scoped stdio MCP server for Codex, Gemini, Cursor, Copilot/VS Code, OpenCode, or ForgeCode. |
| `--brief-mode` | — | `lite`, `standard`, `ultra`, `off` | plan/apply advisory brief-mode snippets in project rule files; choose lite, standard, ultra, or off to remove. |
| `--list-adapters` | false | — | print the cross-agent adapter registry and exit |
| `--failed-attempt-nudge` | — | — | enable Bash terminal-event hooks that inject a one-line strategy-switch hint when the same command fails twice in a row (off by default; also enabled by --profile max) |
| `--no-failed-attempt-nudge` | — | — | skip the failed-attempt nudge hook even under --profile max |
