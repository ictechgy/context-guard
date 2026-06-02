# ContextGuard

ContextGuard is a local-first context-hygiene toolkit for AI coding and tool agents. It ships a Claude Code plugin first, and the same project-local guardrails — for noisy command output, large file reads, repeated failures, likely-secret values, usage visibility, and repeatable token/cost measurement — extend to other agents through local helper commands and advisory rule snippets.

- Korean documentation: [`README.ko.md`](README.ko.md)
- Static landing page: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([source](docs/index.html))

## TL;DR

Install the plugin, run `/context-guard:setup` inside a project, and ContextGuard adds reversible project-local guardrails without changing your global Claude settings.

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

Then apply setup inside the project you want to protect.

```text
/context-guard:setup
```

ContextGuard is intentionally conservative about savings claims. It reduces common sources of context bloat and provides benchmark tooling so you can measure real before/after results on your own tasks. It does **not** promise a fixed token or cost reduction for every repository.

## How ContextGuard reduces token waste

ContextGuard does not make the model cheaper by itself. It reduces avoidable context before it reaches Claude Code, then gives you signals to measure whether that helped.

| Waste path | ContextGuard guardrail |
| --- | --- |
| Whole-file reads for one function | Suggest search, symbol slices, bounded outlines, and small line ranges before a full read. |
| Long test, build, search, or diff output | Trim output, emit structured digests, or store large logs locally and return compact receipts. |
| Repeated failing commands | Warn after repeated Bash failures so Claude changes strategy before more stale logs enter context. |
| Secret-like or noisy terminal output | Apply best-effort, pattern-based redaction for common credential patterns and sensitive-looking paths before output is copied into context. |
| Unknown token/cost hotspots | Surface statusline signals, transcript audits, and matched benchmark reports for before/after evidence. |

## How it fits with caching and compression tools

ContextGuard is complementary to provider and semantic caches, and adjacent to prompt compression. It focuses on **not sending unnecessary files, logs, or output in the first place**.

| Tool category | Saves by | ContextGuard relationship |
| --- | --- | --- |
| Provider prompt/context caching | Reusing stable prompt prefixes. | Complementary; ContextGuard helps keep the changing tail of context smaller and cleaner. |
| Semantic response cache | Reusing answers to identical or similar requests. | Complementary; ContextGuard does not serve cached AI answers. |
| Prompt/context compression | Shortening text that is already selected for the model. | Adjacent; ContextGuard trims and summarizes local output, but does not promise lossless semantic compression. |
| ContextGuard | Avoiding unnecessary files, logs, repeated failures, and noisy output before they enter Claude context. | Local Claude Code guardrails plus measurement. |

## ContextGuard for AI coding and tool agents

ContextGuard began as a Claude Code plugin and still ships that integration first. The same local-first guardrails apply to other AI coding and tool agents: helpers run as plain local commands, and advisory rule snippets install into an agent's own instruction file. Cross-agent setup is dry-run first, writes only local files, backs up before changing anything, and applies only with explicit approval.

| Approach | What it emphasizes | ContextGuard relationship |
| --- | --- | --- |
| Headroom-style compression | Shortening text already selected for the model. | ContextGuard prefers local, reversible artifact storage with exact retrieval over lossy one-way compression. |
| Caveman-style brief / cross-agent install | Terse-output rules installed across many agents. | ContextGuard offers advisory brief-mode snippets and dry-run cross-agent setup, without claiming guaranteed savings. |
| ContextGuard | Avoiding unnecessary files, logs, and output before they enter context, with conservative measurement. | Local guardrails, reversible artifacts and retrieval, and benchmark evidence you measure yourself. |

## Brief mode (advisory)

Brief mode is a set of agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving the evidence a reviewer needs: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels ship under [`plugins/context-guard/brief/`](plugins/context-guard/brief/): `lite`, `standard`, and `ultra`. Each level is a single marker-delimited block you install into an agent's rule/instruction file (for example `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions) and remove by deleting the block. See [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md).

## What to measure

When you need a savings claim, measure it on your own tasks:

- full-file reads versus symbol or line-range reads
- raw logs versus digest output or artifact receipts
- transcript hotspots reported by `context-guard-audit`
- statusline `cache` / `reuse` as observed transcript/provider-cache signals, not savings caused by ContextGuard
- matched successful baseline/variant runs from `context-guard-bench`

## What ContextGuard does not do

- It does not guarantee a fixed token or cost reduction.
- It does not send work to external AI providers to save Claude tokens.
- It does not mutate global Claude settings during install.
- It does not replace real before/after measurement when you need a savings claim.
- It does not alias the old `/claude-token-optimizer:*` Claude Code slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy local CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) still ship in `bin/` so existing automation can migrate gradually.

## Features

| Feature | What it helps with |
| --- | --- |
| Claude Code plugin skills | Guided setup, optimization, and transcript usage audits. |
| Project-local setup wizard | Applies recommended `.claude/settings.json` options without touching global settings. |
| Context hygiene scanner | Finds missing guardrails, noisy hooks, broad reads, large context files, secret-like files, excessive MCP servers, and expensive defaults. |
| Large-read guard and symbol reader | Nudges Claude toward `rg`, symbol reads, and small line ranges instead of full-file reads. |
| Output trimming and sanitizing | Keeps test, build, search, and diff output compact while redacting likely secrets before Claude sees them. |
| Local artifact store | Saves large sanitized logs outside the conversation and returns compact receipts or exact requested slices. |
| Conservative stdin compressor | Shrinks selected JSON, diffs, logs, search output, code, and prose with observed byte evidence and estimated token proxies. |
| Repeated-failure nudge | Warns after repeated Bash failures so Claude changes strategy before stale logs fill the context. |
| Statusline, audit, and benchmarks | Shows context/cache/cost signals, finds usage hotspots, and records conservative before/after evidence. |

## Install in Claude Code

Add the marketplace and install the plugin:

```text
/plugin marketplace add ictechgy/context-guard
/plugin install context-guard@context-guard
```

Then run setup from Claude Code in the project you want to protect:

```text
/context-guard:setup
```

Available plugin skills:

| Skill | Purpose |
| --- | --- |
| `/context-guard:setup` | First-time project setup wizard. |
| `/context-guard:optimize` | Inspect and tune context guardrails. |
| `/context-guard:audit` | Audit local Claude transcript token/cost hotspots. |

Setup is explicit, project-local, and reversible. The plugin does not configure external model delegation or offload; all helper commands run locally. See [`plugins/context-guard/examples/settings.example.json`](plugins/context-guard/examples/settings.example.json) for an example settings file.

## Helper commands

Most users should start with `/context-guard:setup`. The helper commands below are useful for local testing, automation, or targeted debugging. The canonical command prefix is `context-guard-*`.

### Scan context hygiene

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

The scanner reports missing guardrails, noisy hooks, broad context paths, large or secret-like files, and settings that can make Claude sessions unnecessarily expensive.

### Read symbols instead of whole large files

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

The optional Read guard uses a progressive path for oversized files: search first, then symbol slices, then small line ranges. When possible, it also returns a bounded top-level outline. Repeated attempts to full-read the same oversized file get a deduplicated warning instead of repeating the same context-heavy path.

### Store and query large logs locally

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

Artifact mode is for capture and retrieval. It stores sanitized output under `.context-guard/artifacts` by default and can still read legacy `.claude-token-optimizer/artifacts` receipts from before the rebrand. Preserve the producer command's exit code yourself when using shell pipelines in release checks, or use `context-guard-trim-output -- ...` when exit-code preservation is the primary requirement.

### Compress selected local text conservatively

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
```

`context-guard-compress` classifies sanitized stdin as JSON, diff, log, search output, code, or prose, then applies deterministic reductions such as JSON compaction, diff context folding, duplicate log/search line collapse, and whitespace normalization. It never claims observed model-token savings; byte counts are observed, token counts are labeled as estimates, and lossy receipts point you back to `context-guard-artifact store` for exact retrieval.

### Trim or summarize command output

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

Use `--digest markdown` or `--digest json` for a compact semantic digest instead of head/tail logs. Digest mode keeps status, exit code, truncation counts, runner failure facts, representative lines, redaction counts, and suggested next queries while preserving the wrapped command exit code. Wrapped commands time out after 600 seconds by default; tune this with `--timeout-seconds`.

### Sanitize search and diff output

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

The sanitizer reduces the chance that token-like, key-like, password-like, or sensitive path values are copied into Claude context.

### Audit local transcript usage

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files and JSONL records by default (`--max-file-bytes`, `--max-line-bytes`) and reports skipped counts, so a corrupt trace cannot dominate memory or hide scan gaps.

### Watch context and cache health in the statusline

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%` is the cache-read share of observed input-side tokens in the bounded transcript tail and stays hidden until at least one cache read is observed. `reuse X.Yx` is `cache_read / cache_creation` and is shown only when cache read is positive and cache creation is non-zero. The `⚠` marker appears when context usage reaches the warning threshold, defaulting to 80%; set `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90` to tune it for a project or shell.

### Run a repeatable benchmark

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json
```

The report compares successful baseline/variant runs by real tokens and `cost_usd + external_cost_usd`. Byte reductions are recorded as proxy evidence, not treated as proof of savings. If cost fields are zero or unavailable, the report can still mark token savings but will not claim shifted-cost savings. Claims are paired by matched successful tasks and downgraded when failure-rate guardrails regress.

## Future opportunities

The market around token-saving tools points to useful follow-up work, but these are **not shipped features** unless documented elsewhere:

- instruction-bloat scanning for large `AGENTS.md`, `CLAUDE.md`, and project rule files,
- cache-friendly prompt audits that flag frequently changing content near the front of prompts,
- ignore recommendation generation for files that should stay out of AI context,
- sample before/after benchmark reports for common Claude Code workflows.

## Repository layout

- `.claude-plugin/marketplace.json` — Claude Code marketplace manifest.
- `plugins/context-guard/` — installable Claude Code plugin package.
- `context-guard-kit/` — underlying Python/Bash helper tools.
- `docs/index.html` — static landing page for the project.
- `tests/` — regression tests for helper behavior.

## Local development

Run Claude Code with the plugin directory:

```bash
claude --plugin-dir ./plugins/context-guard
```

Test marketplace installation from the repository root:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

Plugin helper binaries are not added to `PATH` by default. For local testing, invoke them by full path:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

To use shorter commands during local development, add the plugin bin directory to your shell:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

## Release checks

Before publishing or merging release-sensitive changes, run both gates:

```bash
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

`prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` executes representative packaged entrypoints from `plugins/context-guard/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](docs/release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

Versioned release notes live in [CHANGELOG.md](CHANGELOG.md); the prepublish gate requires an entry matching the plugin manifest version before publishing.

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
