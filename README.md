# ContextGuard

A Claude Code plugin and local helper toolkit for keeping Claude Code context small, focused, and safer to share with the model.

Korean documentation: [`README.ko.md`](README.ko.md)

## TL;DR

Install the plugin, run `/context-guard:setup` in a project, and Claude Code gets project-local guardrails for noisy command output, large file reads, repeated failed attempts, and secret-like grep/diff results — without touching global settings.

This project is intentionally conservative about claims: it reduces common sources of token waste, and includes benchmark tooling for measuring real savings on your own tasks. It does **not** claim a fixed percentage reduction for every repository.

## Features

- **Claude Code plugin** — installable skills for guided setup, optimization, and usage audits.
- **Project-local setup wizard** — merges recommended `.claude/settings.json` options without touching global Claude settings.
- **Context hygiene scanner** — finds missing guardrails, noisy hooks, expensive defaults, broad reads, excessive MCP servers, and large or secret-like context files.
- **Large Read guard and symbol reader** — nudges Claude toward `rg` plus symbol/line-range reads instead of full-file reads.
- **Output trimming and sanitizing** — keeps test, build, search, and diff output compact and redacts likely secrets before Claude sees them.
- **Queryable artifact escrow** — stores large sanitized logs outside the conversation and returns only compact receipts or exact slices.
- **Repeated-failure nudge** — warns after repeated Bash failures so Claude switches strategy before stale logs bloat context.
- **Statusline, transcript audit, and benchmark helpers** — surfaces token/cost/model state, usage hotspots, and conservative before/after evidence.

## Install in Claude Code

Add the marketplace and install the plugin:

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```


Then run the guided setup inside Claude Code:

```text
/context-guard:setup
```

Available skills:

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

The plugin does **not** auto-enable global hooks on install. Setup is project-local, explicit, and reversible. It also does not configure external model delegation/offload; all token-reduction helpers run locally. The old `/claude-token-optimizer:*` plugin slash-command namespace is not aliased by Claude Code; use `/context-guard:*` after installing this plugin. CLI compatibility wrappers for legacy commands (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) still ship in `bin`. See `plugins/context-guard/examples/settings.example.json` for an example settings file.

## Local testing from this repository

Run Claude Code with the plugin directory:

```bash
claude --plugin-dir ./plugins/context-guard
```

To test marketplace installation from the repository root:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

Plugin helper binaries are not added to `PATH` by default. For local testing, invoke them using their full path:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

To use shorter commands during local development, add the plugin bin directory to your `PATH`:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

## Helper commands

The primary helper prefix is now `context-guard-*`. Legacy wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) remain in `bin/` so existing automation keeps working during the rebrand.

Most users should start with `/context-guard:setup`. The commands below are useful for local testing, automation, or targeted debugging.

Scan project context hygiene:

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

Read a symbol instead of an entire large file:

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

The optional Read guard now returns a progressive ladder for oversized files:
search first, then symbol slice, then a small line range, with a bounded
top-level outline when available. Repeated attempts to full-read the same
oversized file get a dedup hint instead of repeating the same context-wasting
path.

Store a large sanitized log outside the conversation and query exact slices later:

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

Pipeline mode is for capture/query. Preserve the producer command's exit code
explicitly (for example with shell `pipefail` or a saved `$?`) when using it in
release checks; use `context-guard-trim-output -- ...` when exit-code preservation is
the primary need.

Trim long test/build logs while preserving the exit code of the wrapped command:

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

Use `--digest markdown` or `--digest json` when you want a compact semantic digest
instead of head/tail logs. Digest mode keeps status, exit code, truncation counts,
runner failure facts, representative lines, redaction counts, and suggested next
queries while preserving the wrapped command exit code. Wrapped commands are
terminated after 600 seconds by default (`--timeout-seconds` to tune), so a silent
or stuck command cannot hang a Claude session indefinitely.

Sanitize search or diff output before sending it to Claude:

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

Audit local Claude transcript usage:

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files/JSONL records by default
(`--max-file-bytes`, `--max-line-bytes`) and reports the skipped counts so a
corrupt trace cannot dominate memory or hide scan gaps.

Use the Claude Code statusline to watch live context and cache health:

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%` is the cache-read share of observed input-side tokens in the
bounded transcript tail and stays hidden until there is at least one cache
read. `reuse X.Yx` is `cache_read / cache_creation` and is shown only when
cache read is positive and cache creation is non-zero. The `⚠` marker appears
when context usage reaches the warning threshold, defaulting to 80%; set
`CONTEXT_GUARD_STATUSLINE_CTX_WARN=90` to tune it for a project or shell.

Run a repeatable A/B token-savings benchmark and keep cost-shift evidence:

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

The report compares successful baseline/variant runs by real token and
`cost_usd + external_cost_usd`; byte reductions are recorded as proxy evidence,
not treated as proof of savings. If cost fields are zero or unavailable, the
report can still mark token savings but will not claim shifted-cost savings.
Claims are paired by matched successful tasks and downgraded when failure-rate
guardrails regress.

## What this tool does not do

- It does not guarantee a fixed token/cost reduction.
- It does not send work to external AI providers to “save” Claude tokens.
- It does not mutate global Claude settings during install.
- It does not replace real before/after measurement when you need a savings claim.

## Repository layout

- `.claude-plugin/marketplace.json` — Claude Code marketplace manifest
- `plugins/context-guard/` — installable Claude Code plugin package
- `context-guard-kit/` — underlying Python/Bash helper tools
- `tests/` — regression tests for helper behavior

## Release checks

Before publishing or merging release-sensitive changes, run both gates:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` then executes representative packaged entrypoints from `plugins/context-guard/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](docs/release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

Versioned release notes live in [CHANGELOG.md](CHANGELOG.md); the prepublish gate requires an entry matching the plugin manifest version before publishing.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
