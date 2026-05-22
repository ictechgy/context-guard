# claude-token-tools

A Claude Code plugin and set of helper commands for reducing token usage, keeping context focused, and preventing large or sensitive output from reaching Claude.

Korean documentation: [`README.ko.md`](README.ko.md)

## TL;DR

Install the plugin, run `/claude-token-optimizer:setup` in your project, and Claude will automatically trim noisy output, guard against large file reads, and redact secrets — without touching your global settings. Optionally delegate read-only tasks to Gemini or Codex CLI to save even more tokens.

## Features

- **Claude Code plugin** — installable skills for guided setup, optimization, usage audits, and optional auxiliary AI delegation.
- **Project-local setup wizard** — merges recommended `.claude/settings.json` options without touching global Claude settings.
- **Context hygiene scanner** — finds missing guardrails, noisy hooks, expensive defaults, broad reads, excessive MCP servers, and large or secret-like context files.
- **Large Read guard and symbol reader** — nudges Claude toward `rg` plus symbol/line-range reads instead of full-file reads.
- **Output trimming and sanitizing** — keeps test, build, search, and diff output compact and redacts likely secrets before Claude sees them.
- **Statusline and transcript audit helpers** — surfaces token/cost/model state and usage hotspots.
- **Opt-in auxiliary AI delegation** — lets Gemini CLI or Codex CLI summarize safe read-only context; Claude receives only a bounded preview.

## Install in Claude Code

Add the marketplace and install the plugin:

```text
/plugin marketplace add ictechgy/claude-token-tools
/plugin install claude-token-optimizer@claude-token-tools
```

Then run the guided setup inside Claude Code:

```text
/claude-token-optimizer:setup
```

Available skills:

```text
/claude-token-optimizer:setup
/claude-token-optimizer:optimize
/claude-token-optimizer:audit
/claude-token-optimizer:delegate
```

The plugin does **not** auto-enable global hooks on install; setup is project-local and entirely opt-in. See `plugins/claude-token-optimizer/examples/settings.example.json` for an example settings file.

## Local testing from this repository

Run Claude Code with the plugin directory:

```bash
claude --plugin-dir ./plugins/claude-token-optimizer
```

To test marketplace installation from the repository root:

```text
/plugin marketplace add ./
/plugin install claude-token-optimizer@claude-token-tools
```

Plugin helper binaries are not added to `PATH` by default. For local testing, invoke them using their full path:

```bash
./plugins/claude-token-optimizer/bin/claude-token-setup --plan
./plugins/claude-token-optimizer/bin/claude-token-setup --yes
```

To use shorter commands during local development, add the plugin bin directory to your `PATH`:

```bash
export PATH="$PWD/plugins/claude-token-optimizer/bin:$PATH"
claude-token-setup --plan
```

## Helper commands

Scan project context hygiene:

```bash
./plugins/claude-token-optimizer/bin/claude-token-diet scan .
```

Read a symbol instead of an entire large file:

```bash
./plugins/claude-token-optimizer/bin/claude-read-symbol path/to/file.py TargetSymbol
```

Trim long test/build logs while preserving the exit code of the wrapped command:

```bash
./plugins/claude-token-optimizer/bin/claude-trim-output --max-lines 120 -- npm test
```

Wrapped commands are terminated after 600 seconds by default (`--timeout-seconds` to tune), so a silent or stuck command cannot hang a Claude session indefinitely.

Sanitize search or diff output before sending it to Claude:

```bash
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/claude-token-optimizer/bin/claude-sanitize-output -- git diff
```

Audit local Claude transcript usage:

```bash
./plugins/claude-token-optimizer/bin/claude-token-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files/JSONL records by default
(`--max-file-bytes`, `--max-line-bytes`) and reports the skipped counts so a
corrupt trace cannot dominate memory or hide scan gaps.

## Auxiliary AI delegation (optional)

With Gemini CLI or Codex CLI access, delegation uses another local AI as a read-only assistant for broad file triage, long-log summaries, root-cause hypotheses, or second-opinion planning.

```text
/claude-token-optimizer:delegate enable --provider gemini
/claude-token-optimizer:delegate auto-enable
/claude-token-optimizer:delegate ask --provider gemini --prompt "Summarize this failing test log" --context ./log.txt
/claude-token-optimizer:delegate disable
```

Manual delegation is **off by default** and stores project-local state under `.claude-token-optimizer/`. Automatic delegation is a separate, provider-bound opt-in. Only delegate context you are permitted to share with the external provider — do not delegate secrets, customer data, or policy-restricted content. Treat auxiliary output as untrusted until verified.

## Repository layout

- `.claude-plugin/marketplace.json` — Claude Code marketplace manifest
- `plugins/claude-token-optimizer/` — installable Claude Code plugin package
- `claude-token-kit/` — underlying Python/Bash helper tools
- `tests/` — regression tests for helper behavior

## Release checks

Before publishing or merging release-sensitive changes, run both gates:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` then executes representative packaged entrypoints from `plugins/claude-token-optimizer/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](docs/release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
