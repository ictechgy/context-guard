# ContextGuard

ContextGuard is a local-first context-hygiene toolkit for AI coding and tool agents. It ships as a Claude Code plugin first — install once, apply per project, reverse if needed. The same guardrails for noisy command output, large file reads, repeated failures, likely-secret values, and usage measurement extend to other agents through local helper commands and advisory brief-mode rule snippets.

- Korean documentation: [`README.ko.md`](README.ko.md)
- Static landing page: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([source](docs/index.html))

## TL;DR

Install and activation are separate. Installing ContextGuard only puts local helpers or Claude plugin skills in reach; configuration changes happen later through an explicit setup command.

| If you use... | Install | Activate |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` then `/plugin install context-guard@context-guard` | Run `/context-guard:setup` inside the project. |
| Codex CLI or any terminal-first agent | `npm install -g @ictechgy/context-guard` or one-shot `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --plan`, then rerun with `--yes`. |
| Other rule-file agents | npm/npx install above | `context-guard setup --agent gemini,cursor,windsurf,cline,copilot --scope project --with-init --plan`, then apply only the agents you want. |
| macOS/Homebrew users | planned release path: `brew tap ictechgy/contextguard && brew install context-guard` | Same `context-guard setup ...` commands after install. |

Common commands:

```bash
npm install -g @ictechgy/context-guard
npx @ictechgy/context-guard --version
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. User-level setup is opt-in, requires an explicit agent for writes, records backups/rollback metadata, and never runs during package installation.

ContextGuard is intentionally conservative about savings claims. It reduces common sources of context bloat and provides benchmark tooling so you can measure real before/after results on your own tasks. It does **not** promise a fixed token or cost reduction for every repository.

## Claude Code first, other agents too

ContextGuard ships as a Claude Code plugin, and that is still the fastest path to value. Once installed, the same local-first guardrails can be reused by other AI coding and tool agents through:

- **Local helper commands** (`context-guard-*`) that run as plain shell commands, independent of any specific agent.
- **Advisory brief-mode rule snippets** you install into an agent's own instruction file (`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot instructions, and similar rule files) and remove by deleting the marker-delimited block.
- **Dry-run cross-agent setup** that writes only local files, backs up before changing anything, and applies only with explicit approval.

Current setup surfaces:

| Agent or tool | ContextGuard surface |
| --- | --- |
| Claude Code | Native plugin setup for project-local hooks, deny rules, and statusline configuration. |
| OpenAI Codex CLI | Advisory `AGENTS.md` rule block plus optional project skill at `.agents/skills/context-guard/SKILL.md`. |
| Gemini CLI | Advisory `GEMINI.md` rule block. |
| Cursor | Advisory project-rule block, usually `.cursorrules`. |
| Windsurf | Advisory `.windsurf/rules/contextguard.md` rule block. |
| Cline | Advisory `.clinerules` rule block, with file/directory handling. |
| GitHub Copilot Coding Agent | Advisory `.github/copilot-instructions.md` rule block. |
| OpenCode, ForgeCode, or unknown agents | Manual shell-helper usage with local evidence; no automatic hooks. |

## How ContextGuard reduces token waste

ContextGuard does not make the model cheaper by itself. It reduces avoidable context before it reaches an AI coding agent, then gives you signals to measure whether that helped.

| Waste path | ContextGuard guardrail |
| --- | --- |
| Whole-file reads for one function | Suggest search, symbol slices, bounded outlines, and small line ranges before a full read. |
| Long test, build, search, or diff output | Trim output, emit structured digests, or store large logs locally and return compact receipts. |
| Repeated failing commands | Warn after repeated Bash failures so the agent changes strategy before more stale logs enter context. |
| Secret-like or noisy terminal output | Apply best-effort, pattern-based redaction for common credential patterns and sensitive-looking paths before output is copied into context. |
| Unknown token/cost hotspots | Surface statusline signals, transcript audits, and matched benchmark reports for before/after evidence. |
| Anthropic API requests that may miss prompt cache | `context-guard cost preflight` estimates input size, breakpoint-level cache risk, and low/mid/high cost ranges before a call; default mode warns only. |
| Volatile context before stable prompt prefixes | Audit bounded redacted prompt-segment hashes and flag likely cache-unfriendly prompt layouts without exposing raw prompt text. |
| Large tool/MCP catalogs for one narrow task | Rank a local tool catalog into a bounded top-k schema report while keeping full sanitized schemas retrievable from local receipts. |

## How it fits with caching and compression tools

ContextGuard is complementary to provider and semantic caches, and adjacent to prompt compression. It focuses on **not sending unnecessary files, logs, or output in the first place**.

| Tool category | Saves by | ContextGuard relationship |
| --- | --- | --- |
| Provider prompt/context caching | Reusing stable prompt prefixes. | Complementary; ContextGuard helps keep the changing tail of context smaller and cleaner, `context-guard-audit` can flag likely volatile prefix layouts, and `context-guard cost` can warn when an Anthropic request is likely to create/cache-write instead of read. |
| Semantic response cache | Reusing answers to identical or similar requests. | Complementary; ContextGuard does not serve cached AI answers. |
| Prompt/context compression | Shortening text that is already selected for the model. | Adjacent; ContextGuard trims and summarizes local output, but does not promise lossless semantic compression. |
| Experimental learned/multimodal/self-hosted techniques | Compressing prompts, reducing visual evidence, or optimizing self-hosted inference internals. | Tracked only in the experimental radar until matched benchmarks prove quality-preserving value; not a hosted API savings claim. |
| ContextGuard | Avoiding unnecessary files, logs, repeated failures, and noisy output before they enter agent context. | Local guardrails, reversible artifacts, and measurement. |

Related patterns that informed the design:

| Approach | What it emphasizes | ContextGuard relationship |
| --- | --- | --- |
| Compression-first | Shortening text already selected for the model, often with lossy transforms. | ContextGuard prefers local artifact storage with exact slice retrieval over lossy one-way compression; you can get the original back. |
| Terse-output rulesets across agents | Installing brief-mode output rules into many agents at once. | ContextGuard offers advisory brief-mode snippets and dry-run cross-agent setup — opt-in per project, no guaranteed savings claimed. |
| ContextGuard | Avoiding unnecessary files, logs, and output before they enter context, with conservative measurement. | Local guardrails, reversible artifacts and retrieval, and benchmark evidence you measure yourself. |

## Brief mode (advisory)

Brief mode is a set of agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving the evidence a reviewer needs: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels ship under [`plugins/context-guard/brief/`](plugins/context-guard/brief/): `lite`, `standard`, and `ultra`. Each level is a single marker-delimited block you install into an agent's rule/instruction file (for example `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions) and remove by deleting the block. See [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md).

## What to measure

When you need a savings claim, measure it on your own tasks:

- full-file reads versus symbol or line-range reads
- raw logs versus digest output or artifact receipts
- transcript hotspots reported by `context-guard-audit`, including `cache_friendliness` prompt-layout signals
- statusline `cache` / `reuse` as observed transcript/provider-cache signals, not savings caused by ContextGuard
- `context-guard cost preflight` estimates for Anthropic request JSON, followed by `context-guard cost observe` using provider usage fields (`cache_creation_input_tokens`, `cache_read_input_tokens`) after the call
- matched successful baseline/variant runs from `context-guard-bench`
- large tool/MCP catalogs versus `context-guard-tool-prune` top-k reports plus receipt retrieval
- optional experimental lanes in [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md), measured with the same matched-task benchmark gates before any savings claim

## What ContextGuard does not do

- It does not guarantee a fixed token or cost reduction.
- It does not send work to external AI providers to save model tokens.
- It does not mutate global Claude settings during install.
- It does not replace real before/after measurement when you need a savings claim.
- Local RAM/disk receipts can reduce what you send next, but they do **not** replace Anthropic's provider prompt cache or guarantee cache hits. Recheck Anthropic prompt-caching and pricing docs before release or billing claims: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.
- It does not ship learned compression, multimodal OCR/crop pruning, or self-hosted KV/latent inference optimization as runtime features; those remain gated experiments in the research radar.
- It does not alias the old `/claude-token-optimizer:*` Claude Code slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy local CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) still ship in `bin/` so existing automation can migrate gradually.

## Features

| Feature | What it helps with |
| --- | --- |
| Claude Code plugin skills | Guided setup, optimization, and transcript usage audits. |
| Project-local setup wizard | Applies recommended `.claude/settings.json` options without touching global settings. |
| Context hygiene scanner | Finds missing guardrails, noisy hooks, broad reads, large context files, secret-like files, excessive MCP servers, and expensive defaults. |
| Large-read guard and symbol reader | Nudges the agent toward `rg`, symbol reads, and small line ranges instead of full-file reads. |
| Output trimming and sanitizing | Keeps test, build, search, and diff output compact while redacting likely secrets before they enter agent context. |
| Local artifact store | Saves large sanitized logs outside the conversation and returns compact receipts or exact requested slices. |
| Anthropic cost guard | `context-guard cost preflight/observe/ledger/compile` estimates cache-risk and cost ranges, stores only keyed HMAC fingerprints, and stays passive unless `--enforce` is explicit. |
| Budgeted context packer | Assembles prioritized local file evidence into a hard byte-budgeted Markdown pack, and can suggest a build-compatible manifest from local query, diff, file, and sanitized output signals. |
| Tool/MCP schema pruner | Emits bounded top-k tool/schema advisory reports from local catalogs with compact receipts and full sanitized payload retrieval. |
| Conservative stdin compressor | Shrinks selected JSON, diffs, logs, search output, code, and prose with observed byte evidence and estimated token proxies. |
| Repeated-failure nudge | Warns after repeated Bash failures so the agent changes strategy before stale logs fill the context. |
| Statusline, audit, and benchmarks | Shows context/cache/cost signals, finds usage and cache-friendliness hotspots, and records conservative before/after evidence. |

Cost guard creates its local HMAC key automatically at `.context-guard/cost-ledger/hmac.key`. If you provision that file yourself, it must contain exactly one canonical URL-safe base64 32-byte key with required padding and no trailing newline or whitespace. Reports never emit the key or raw prompt text, and the local ledger does not replace Anthropic/provider prompt caching.

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

## Install with npm/npx

The npm package exposes a canonical `context-guard` command plus the backwards-compatible `context-guard-*` helper commands. Package installation is passive: there is no `postinstall` setup hook and no config write until you run `context-guard setup` yourself.

```bash
npm install -g @ictechgy/context-guard
context-guard --version
context-guard setup --agent codex --scope project --with-init --with-skill --plan
```

For a one-off run without global installation:

```bash
npx @ictechgy/context-guard setup --agent codex --scope project --with-init --with-skill --plan
npm exec @ictechgy/context-guard -- --version
```

Use `--scope project` for repository files such as `AGENTS.md` and `.agents/skills/...`. Use `--scope user` only when you intentionally want a user-level path; applying user scope requires `--yes` plus an explicit `--agent`, and supported writes record rollback metadata.

## Homebrew release path

Homebrew is documented as the macOS release path once formula publishing is wired to a verified release artifact:

```bash
brew tap ictechgy/contextguard
brew install context-guard
context-guard --version
```

Until the tap is published, use npm/npx or the Claude plugin install path above.

## Helper commands

Most users should start with `/context-guard:setup`. The helper commands below are useful for local testing, automation, or targeted debugging. The canonical command prefix is `context-guard-*`.

### Scan context hygiene

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

The scanner reports missing guardrails, noisy hooks, broad context paths, large or secret-like instruction/rule files across common AI-agent surfaces, and local context-exclusion recommendations for bulky or sensitive paths. `--top` caps both the reported context-like files and context-exclusion recommendations. Recommendations are heuristic/advisory unless they are emitted as Claude `permissions.deny` entries.

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

Artifact mode is for capture and retrieval. It stores sanitized output under `.context-guard/artifacts` by default and can still read legacy `.claude-token-optimizer/artifacts` receipts from before the rebrand. JSON receipts include line-numbered top-error receipts, duplicate-line groups, and sanitized bounded `suggested_queries` so an agent can fetch the smallest useful exact slice instead of replaying the full log. When a suggested `--lines START:END` query also includes `--max-lines`, that flag is only the returned-line cap for the selected range; it does not broaden the selector. Preserve the producer command's exit code yourself when using shell pipelines in release checks, or use `context-guard-trim-output -- ...` when exit-code preservation is the primary requirement.

### Build a budgeted context pack

```bash
./plugins/context-guard/bin/context-guard-pack suggest \
  --root . \
  --query "review failing tests" \
  --diff HEAD \
  --manifest-out suggested-pack.json \
  --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-pack build \
  --root . \
  --manifest suggested-pack.json \
  --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-pack slice --root . --path README.md --lines 1:40 --json
```

`context-guard-pack suggest` is an additive local-only planning step. It ranks candidate files and line ranges from `--query`, `--diff`, repeated `--files`, and optional `--output` / `--test-output` text files under `--root` after sanitizing those output signals, then writes a manifest that `build --manifest` can consume. It uses deterministic standard-library heuristics only: no network, model calls, embeddings, or provider-cost estimate. `context-guard-pack build` assembles prioritized local file evidence into a Markdown body whose rendered UTF-8 bytes stay within `--budget-bytes`. JSON output records included, partial, duplicate, unsafe, missing, and budget-omitted sources, writes a bounded local receipt under `.context-guard/packs`, and includes copy-pasteable `slice` commands for exact sanitized retrieval when the path/root are safe to display. If retrieval is unsafe, the pack and JSON metadata include `retrieval_omitted_reason` instead of a command. Byte counts are observed; token counts remain estimated `chars_div_4` proxies, not measured provider-token savings.

### Prune a tool/MCP catalog for a task

```bash
./plugins/context-guard/bin/context-guard-tool-prune select \
  --catalog tools.json \
  --query "review failing tests" \
  --top 5 --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-tool-prune get <receipt_id> --tool read_file --json
```

`context-guard-tool-prune` ranks a local tool or MCP catalog with deterministic lexical heuristics and emits a bounded top-k advisory report. Inline selected schemas respect an observed UTF-8 byte budget, and omitted or budget-skipped schemas remain recoverable from a compact local receipt plus a separate sanitized payload under `.context-guard/tool-prune`. This is advisory only: it does not mutate MCP configuration, and token counts remain estimated proxies rather than measured provider savings.

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

Use `--digest markdown` or `--digest json` for a compact semantic digest instead of head/tail logs. Digest mode keeps status, exit code, truncation counts, runner failure facts, a sanitized failure signature, duplicate-line groups, representative lines, redaction counts, and suggested next queries while preserving the wrapped command exit code. Wrapped commands time out after 600 seconds by default; tune this with `--timeout-seconds`.

### Sanitize search and diff output

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

The sanitizer reduces the chance that token-like, key-like, password-like, or sensitive path values are copied into agent context.

### Audit local transcript usage

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files and JSONL records by default (`--max-file-bytes`, `--max-line-bytes`) and reports skipped counts, so a corrupt trace cannot dominate memory or hide scan gaps. JSON output also includes `cache_friendliness`: a heuristic prompt-layout diagnostic built from bounded, redacted segment hashes. It can flag likely volatile content near the prompt prefix, but it does not print raw prompt text and may be `missing` or `partial` when transcript schemas do not expose allowlisted prompt text.

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

The report compares successful baseline/variant runs by real tokens and `cost_usd + external_cost_usd`. Byte reductions are recorded as proxy evidence, not treated as proof of savings. Token-savings claims require `primary_tokens_measured` on both sides of a matched task. `wall_time_seconds`, `provider_cached_tokens`, and `provider_cached_tokens_measured` are diagnostic telemetry, not proof of ContextGuard-caused token or cost savings. If cost fields are zero or unavailable, the report can still mark token savings but will not claim shifted-cost savings. Claims are paired by matched successful tasks and downgraded when failure-rate guardrails regress. CSV schemas are strict; after upgrading the benchmark helper, start a new `--csv` file or migrate the header named in the mismatch error. See [`docs/benchmark-report.example.json`](docs/benchmark-report.example.json) for a minimal report-shape example.

## What is not yet shipped

These are directions the project has noted, not committed features. Nothing here ships unless documented elsewhere in the repository.

- workflow-specific before/after benchmark report examples beyond the minimal report-shape fixture.
- learned prompt/context compression, multimodal crop/OCR or visual-token pruning, and self-hosted KV/latent inference optimizations. See the [experimental token-reduction radar](research/experimental-token-reduction-radar.md); these lanes require matched successful tasks, failure-rate guardrails, human-correction tracking, shifted-cost accounting, and provider-measured token/cost evidence before any hosted API savings claim.

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
