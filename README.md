# ContextGuard

ContextGuard is a local-first context-management toolkit for AI coding and tool-using agents. It starts with a Claude Code plugin: install it once, enable it explicitly per project, and roll it back when needed.

It trims noisy output, guides agents toward symbol-level reads, flags repeated failures, redacts secret-like patterns, and measures usage. The same guardrails are reusable by other agents through local helper commands and advisory brief-mode snippets.

- Korean documentation: [`README.ko.md`](README.ko.md)
- Static landing page: [GitHub Pages](https://ictechgy.github.io/context-guard/) ([source](docs/index.html))

## TL;DR

Installation and activation are deliberately separate. Installing ContextGuard only makes local helpers or Claude plugin skills available; it does not write configuration until you run an explicit setup command.

| If you use... | Install | Activate |
| --- | --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/context-guard` then `/plugin install context-guard@context-guard` | Run `/context-guard:setup` inside the project. |
| Codex CLI or any terminal-first agent | `npm install -g @ictechgy/context-guard` or one-shot `npx @ictechgy/context-guard ...` | `context-guard setup --agent codex --scope project --with-init --with-skill --plan`, then rerun with `--yes`. |
| Other rule-file agents | Use the npm/npx install path above. | `context-guard setup --agent gemini,cursor,windsurf,cline,copilot --scope project --with-init --plan`, then apply only the agents you want. |
| macOS/Homebrew users | Release path: `brew install ictechgy/tap/context-guard` | Same `context-guard setup ...` commands after install. |

Common commands:

```bash
npm install -g @ictechgy/context-guard
npx @ictechgy/context-guard --version
context-guard doctor --root . --json              # read-only health check; no changes made
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent claude --scope user --verify --json  # read-only user-scope check
context-guard setup --agent claude --scope user --plan
```

Project scope is the default. User-level setup is opt-in, requires an explicit agent for writes, records backups and rollback metadata, and never runs during package installation. Before applying setup, use `context-guard doctor` or `context-guard setup --verify` for a read-only health check. `doctor` reports next commands and makes no changes. Setup looks for bundled or checkout-local helpers first; it does not trust arbitrary `PATH` helpers unless you explicitly pass `--allow-path-helper-fallback` for a known-good install.

Distribution and helper trust boundaries are conservative too: npm exposes only canonical `context-guard`/`context-guard-*` bin links, legacy `claude-*` wrappers remain package files for path-based migration, command manifests are treated as literal data rather than executable Python, and the macOS visibility helper is discovered only from bundled/resource/executable-relative paths or an absolute explicit override with a minimal child environment. Current working directories, relative overrides, symlinked helpers, arbitrary `PATH`, and ambient shell environment are not trusted by default.

ContextGuard is intentionally conservative about savings claims. It reduces common sources of context bloat and provides benchmark tooling so you can measure before-and-after results on your own tasks. It does **not** promise a fixed token or cost reduction for every repository.

## Claude Code first, other agents too

ContextGuard ships as a Claude Code plugin first, which is still the fastest starting point for Claude users. After installation, the same local-first guardrails can be reused by other AI coding and tool-using agents through:

- **Local helper commands** (`context-guard-*`) that run as plain shell commands, independent of any specific agent.
- **Advisory brief-mode rule snippets** that you install into an agent's own instruction file (`AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot instructions, and similar rule files) and remove by deleting the marker-delimited block.
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

ContextGuard does not change model prices. It reduces avoidable context before it reaches an AI coding agent, then gives you signals to measure whether the change helped.

| Waste path | ContextGuard guardrail |
| --- | --- |
| Whole-file reads for one function | Suggest search, symbol slices, bounded outlines, and small line ranges before a full read. |
| Long test, build, search, or diff output | Trim output, emit structured digests, or store large logs locally and return compact receipts. |
| Repeated failing commands | Warn after repeated Bash failures so the agent changes strategy before more stale logs enter context. |
| Secret-like or noisy terminal output | Apply best-effort pattern-based redaction for common credential patterns and sensitive-looking paths before output is copied into context. |
| Unknown token/cost hotspots | Surface statusline signals, transcript audits, and matched benchmark reports for before/after evidence. |
| Anthropic API requests that may miss prompt cache | `context-guard cost preflight` estimates input size, breakpoint-level cache risk, and low/mid/high cost ranges before a call; default mode warns only. |
| Volatile context before stable prompt prefixes | Audit bounded redacted prompt-segment hashes and flag likely cache-unfriendly prompt layouts without exposing raw prompt text. |
| Large tool/MCP catalogs for one narrow task | Rank a local tool catalog into a bounded top-k schema report while keeping full sanitized schemas retrievable from local receipts. |

## How it fits with caching and compression tools

ContextGuard complements provider and semantic caches, and works alongside prompt compression. Its main job is simpler: **do not send unnecessary files, logs, or output in the first place**.

| Tool category | Saves by | ContextGuard relationship |
| --- | --- | --- |
| Provider prompt/context caching | Reusing stable prompt prefixes. | Complementary; ContextGuard helps keep the changing tail of context smaller and cleaner, `context-guard-audit` can flag likely volatile prefix layouts, and `context-guard cost` can warn when an Anthropic request is likely to cache-write instead of cache-read. |
| Semantic response cache | Reusing answers to identical or similar requests. | Complementary; ContextGuard does not serve cached AI answers. |
| Prompt/context compression | Shortening text that is already selected for the model. | Adjacent; ContextGuard trims and summarizes local output, but does not promise lossless semantic compression. |
| Experimental planners and local runtimes | Default-off and explicit-command-only; covers plan-only `image-context-pack` and `semantic-checkpoint` gates plus local-proxy plans/gate records and narrow local runtimes for caller-supplied context-diff, visual evidence-pack, learned-compression, and self-hosted metrics evidence. | `image-context-pack` and `semantic-checkpoint` are dry-run planning gates only: they do not emit replacements, call models/providers, proxy traffic, write files, or make hosted token/cost savings claims. `semantic-checkpoint` additionally requires exact context fallback/re-expand metadata, provenance review acknowledgement, provider-boundary acknowledgement, protected-zone denial, and missed-context notes before the JSON payload reports readiness. The local proxy `record` command starts no listener and forwards no traffic; `serve local-proxy` binds and forwards only literal loopback IPs for one bounded request; `--response-sandbox` can replace a safe UTF-8 upstream body with a compact local artifact rehydration envelope. Compressor/model execution, OCR/crop services, external forwarding, credential persistence, runtime checkpoint replacement, and hosted-savings claims stay out of scope until a separate evidence gate and future PR allow them. |
| ContextGuard | Avoiding unnecessary files, logs, repeated failures, and noisy output before they enter agent context. | Local guardrails, reversible artifacts, and measurement. |

Related patterns that informed the design:

| Approach | What it emphasizes | ContextGuard relationship |
| --- | --- | --- |
| Compression-first | Shortening text already selected for the model, often with lossy transforms. | ContextGuard prefers local artifact storage with exact slice retrieval over lossy one-way compression, so you can get the original back. |
| Terse-output rulesets across agents | Installing brief-mode output rules into many agents at once. | ContextGuard offers advisory brief-mode snippets and dry-run cross-agent setup — opt-in per project, no guaranteed savings claimed. |
| ContextGuard | Avoiding unnecessary files, logs, and output before they enter context, with conservative measurement. | Local guardrails, reversible artifacts and retrieval, plus benchmark evidence you measure yourself. |

## Brief mode (advisory)

Brief mode is a set of agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving reviewer evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee token or cost savings.

Three deterministic levels ship under [`plugins/context-guard/brief/`](plugins/context-guard/brief/): `lite`, `standard`, and `ultra`. Each level is a single marker-delimited block for an agent's rule/instruction file (for example `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions). Manage it through setup with `context-guard setup --agent codex --scope project --brief-mode standard --plan`, rerun with `--yes` to apply, and use `--brief-mode off` to remove the managed block. See [`plugins/context-guard/brief/README.md`](plugins/context-guard/brief/README.md).

## What to measure

If you need a savings claim, measure it on your own tasks:

- full-file reads versus symbol or line-range reads
- raw logs versus digest output or artifact receipts
- transcript hotspots reported by `context-guard-audit`, including `cache_friendliness` prompt-layout signals and `cache_layout_advice` experiment priorities
- statusline `cache` / `reuse` as observed transcript/provider-cache signals, not savings caused by ContextGuard
- `context-guard cost preflight` estimates for Anthropic request JSON, followed by `context-guard cost observe` using provider usage fields (`cache_creation_input_tokens`, `cache_read_input_tokens`) after the call
- static prompt/request cache layout checks from `context-guard-cache-score`, including optional user-supplied cache write/read multiplier amortization risk; its char/4 token estimates and warnings are advisory only until provider usage fields confirm real cache hits
- matched successful baseline/variant runs from `context-guard-bench`
- large tool/MCP catalogs versus `context-guard-tool-prune` top-k reports plus receipt retrieval
- optional experimental lanes in [`research/experimental-token-reduction-radar.md`](research/experimental-token-reduction-radar.md); fixture-only starters in [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) use the same matched-task benchmark gates before any savings claim

## What ContextGuard does not do

- It does not guarantee a fixed token or cost reduction.
- It does not send work to external AI providers to save model tokens.
- It does not mutate global Claude settings during install.
- It does not execute command manifests as code or trust arbitrary `PATH`/current-working-directory helpers during setup or packaged smoke checks.
- It does not replace real before/after measurement when you need a savings claim.
- Local RAM/disk receipts can help reduce what you send next, but they do **not** replace Anthropic's provider prompt cache or guarantee cache hits. Recheck Anthropic prompt-caching and pricing docs before release or billing claims: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.
- Experimental helpers are mostly dry-run checker/planner surfaces, including plan-only `image-context-pack` and `semantic-checkpoint` evaluation gates and a design-only external-forwarding opt-in gate. Explicit local runtimes exist only for caller-supplied context-diff replacement payloads, caller-supplied visual crop/OCR evidence packs, caller-supplied learned-compression prose candidates, self-hosted metrics JSONL sidecar records, local-proxy runtime-gate JSONL records, and one-shot `serve local-proxy` loopback forwarding with a private ready-file nonce, optional `--response-sandbox` compact artifact envelopes for safe UTF-8 responses, plus optional shifted-cost diagnostic JSONL rows for successful forwarded requests.
- ContextGuard does not ship learned/synthetic compressor execution, embeddings, rerankers, model calls, generated replacement text, screenshot capture, image cropping, OCR execution, image parsing, external OCR/image services, self-hosted KV/latent inference optimization beyond explicit local metrics recording, or broader proxy forwarding beyond literal-loopback, one-request HTTP forwarding with credential material blocked.
- It does not alias the old `/claude-token-optimizer:*` Claude Code slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy local CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) still ship as package files under `plugins/context-guard/bin/` so existing plugin-path automation can migrate gradually. npm global/`npx` bin links intentionally expose only the canonical `context-guard`/`context-guard-*` commands; call the legacy wrappers by package/plugin path if you still need them.

## Features

| Feature | What it helps with |
| --- | --- |
| Claude Code plugin skills | Guided setup, optimization, and transcript usage audits. |
| Project-local setup wizard | Applies recommended `.claude/settings.json` options without touching global settings. |
| Context management scanner | Finds missing guardrails, noisy hooks, broad reads, large context files, secret-like files, excessive MCP servers, and expensive defaults. |
| Structural-waste doctor | Opt-in local diagnostics for duplicate rules, stale imports, unused skill candidates, oversized tool schemas, and repeated read/tool-call loops. |
| Large-read guard and symbol reader | Nudges the agent toward `rg`, symbol reads, and small line ranges instead of full-file reads. |
| Output trimming and sanitizing | Keeps test, build, search, and diff output compact while redacting likely secrets before they enter agent context. |
| Declarative output filter | Opt-in JSON DSL for user-owned command filters with protected failure passthrough and validation before use. |
| Local artifact store | Saves large sanitized logs outside the conversation and returns compact receipts or exact requested slices. |
| Anthropic cost guard | `context-guard cost preflight/observe/ledger/compile` estimates cache risk and cost ranges. `context-guard route-advisor` summarizes local total-cost and batchability route candidates, stores only keyed HMAC fingerprints where a ledger is used, and stays passive unless `--enforce` is explicit. |
| Budgeted context packer | Assembles prioritized local file evidence into a byte-budgeted Markdown pack, can suggest a build-compatible manifest from local signals, adds `--explain` for compact local selection reasons plus bounded repo-map metadata, and adds opt-in `--adaptive-k` / `--symbol-memory` advisory metadata. |
| Tool/MCP schema pruner | Emits bounded top-k tool/schema advisory reports from local catalogs with compact receipts and full sanitized payload retrieval. |
| Conservative stdin compressor | Shrinks selected JSON, diffs, logs, search output, code, and prose with observed byte evidence and estimated token proxies; `--mode readable` adds an opt-in readable prose preview with exact fallback guidance. |
| Protected-zone policy receipts | Opt-in `context-guard-compress --protected-policy` and `context-guard cost compile` metadata mark code/diff/path/hash/JSON/literal zones as structural-only with exact retrieval guidance. |
| Repeated-failure nudge | Warns after repeated Bash failures so the agent changes strategy before stale logs fill the context. |
| Statusline, audit, and benchmarks | Shows context/cache/cost signals, finds usage and cache-friendliness hotspots, and records conservative before/after evidence. |

### Cost guard key provisioning

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

The npm package exposes a canonical `context-guard` command plus `context-guard-*` helper commands. Package installation is passive: there is no `postinstall` setup hook and no config write until you run `context-guard setup` yourself. npm global/`npx` bin links intentionally expose only canonical `context-guard`/`context-guard-*` commands; legacy `claude-*` wrapper files remain packaged for explicit path-based migration but are not advertised as executable bin aliases. If setup cannot find bundled or checkout-local helpers, `PATH` fallback remains disabled by default; use `--allow-path-helper-fallback` only for trusted helper directories after `context-guard doctor` or `setup --verify` confirms the plan.

```bash
npm install -g @ictechgy/context-guard
context-guard --version
context-guard doctor --root . --json
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
```

For a one-off run without global installation:

```bash
npx @ictechgy/context-guard setup --agent codex --scope project --with-init --with-skill --plan
npx @ictechgy/context-guard setup --agent codex --scope project --brief-mode standard --plan
npm exec @ictechgy/context-guard -- --version
```

Use `--scope project` for repository files such as `AGENTS.md` and `.agents/skills/...`. Use `--scope user` only when you intentionally want a user-level path; applying user scope requires `--yes` plus an explicit `--agent`, and supported writes record rollback metadata.

## Homebrew release path

Homebrew is available through the shared `ictechgy/tap` tap:

```bash
brew install ictechgy/tap/context-guard
context-guard --version
```

If you already tapped `ictechgy/tap`, `brew install context-guard` also works.

## Helper commands

Most users should start with `/context-guard:setup`. The helper commands below are useful for local testing, automation, or targeted debugging. The canonical command prefix is `context-guard-*`.

### Health check before setup

```bash
context-guard doctor --root . --json
context-guard setup --agent claude --scope user --verify --json
```

Both modes are read-only configuration checks. `doctor` reports recommended next commands, and `setup --verify` checks whether setup is complete without applying changes. With `--json`, the report is written to stdout.

### Scan context management

```bash
./plugins/context-guard/bin/context-guard-diet scan .
```

The scanner reports missing guardrails, noisy hooks, broad context paths, large or secret-like instruction/rule files across common AI-agent surfaces, and local context-exclusion recommendations for bulky or sensitive paths. `--top` caps both the reported context-like files and context-exclusion recommendations. Recommendations are heuristic/advisory unless they are emitted as Claude `permissions.deny` entries.

### Diagnose structural context waste

```bash
./plugins/context-guard/bin/context-guard-diet structural-waste . \
  --tool-catalog tools.json \
  --log-path .claude \
  --json
```

The structural-waste doctor is opt-in and read-only. It reuses the diet scanner's local safety model, then adds advisory findings for duplicate rule units, stale Python imports, unused skill candidates, excessive MCP/tool schema catalogs, and repeated file reads or duplicate tool calls from local JSON/JSONL logs. It does not edit files, disable tools, call the network, or print raw prompt/tool-input text; default output uses relative paths, hashed labels, and redacted secret-shaped path components. Treat low-confidence import/skill findings as review prompts, not deletion instructions.

### Read symbols instead of whole large files

```bash
./plugins/context-guard/bin/context-guard-read-symbol path/to/file.py TargetSymbol
```

The optional Read guard uses a progressive path for oversized files: search first, then symbol slices, then small line ranges. When possible, it also returns a bounded top-level outline. Repeated attempts to full-read the same oversized file get a deduplicated warning instead of repeating the same context-heavy path.

### Store and query large logs locally

```bash
long-command 2>&1 | ./plugins/context-guard/bin/context-guard-artifact store --command "long-command" --json
./plugins/context-guard/bin/context-guard-artifact search "ERROR" --json
./plugins/context-guard/bin/context-guard-artifact receipt <artifact_id> --json
./plugins/context-guard/bin/context-guard-artifact get <artifact_id> --lines 1:80
```

Artifact mode is for capture, sandbox search, and retrieval. It stores sanitized output under `.context-guard/artifacts` by default and can still read legacy `.claude-token-optimizer/artifacts` receipts from before the rebrand. JSON receipts include line-numbered top-error receipts, duplicate-line groups, sanitized bounded `suggested_queries`, and an `output_sandbox` envelope with a stable `contextguard-artifact:<id>` handle. Use `context-guard-artifact receipt <artifact_id> --json` to rehydrate metadata-only handles without returning content, then fetch the smallest useful exact slice instead of replaying the full log. `search` scans the local sanitized artifact sandbox by literal substring, returns capped match/context records, and includes `context-guard-artifact get ... --lines START:END` rehydration commands for omitted detail. For custom `--dir` values, raw private paths stay redacted by default; rerun with the same `--dir`, or pass `search --show-paths` when you explicitly want a directly executable local command. The search report is local-only and does not make hosted token/cost savings claims. When `--max-lines` accompanies a `--lines START:END` selector, it caps lines returned within that range; it does not expand the selector. Preserve the producer command's exit code yourself when using shell pipelines in release checks, or use `context-guard-trim-output -- ...` when exit-code preservation is the primary requirement.

### Build a budgeted context pack

```bash
./plugins/context-guard/bin/context-guard-pack auto \
  --root . \
  --query "review failing tests" \
  --diff HEAD \
  --manifest-out suggested-pack.json \
  --pack-out context-pack.md \
  --budget-bytes 12000 --json --explain --adaptive-k --symbol-memory
# Or run the two explicit steps:
./plugins/context-guard/bin/context-guard-pack suggest \
  --root . --query "review failing tests" --diff HEAD \
  --manifest-out suggested-pack.json --budget-bytes 12000 --json --adaptive-k --adaptive-k-policy recall
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json
# Optional diagnostic comparison against one exact private local receipt:
./plugins/context-guard/bin/context-guard-pack build \
  --root . --manifest suggested-pack.json --budget-bytes 12000 --json --no-artifact \
  --delta-from-pack-id 0123456789abcdef0123
./plugins/context-guard/bin/context-guard-pack slice --root . --path README.md --lines 1:40 --json
```

`context-guard-pack auto` is the one-command, local-only path: it runs the suggestion step and immediately builds the budgeted Markdown pack.

A few boundaries are intentional:

- Add `--explain` for compact deterministic local selection/build reasons in JSON or text output.
- `--explain` may include bounded `repo_map` metadata: sampled byte/token-proxy tree entries, category-only secret-risk counts, signature-first file hints, explain-only graph ranks, and exact `slice`/symbol retrieval hints.
- Explain metadata does not change the manifest, pack body, receipt, or byte budget. It does not use network/model/embedding calls, and token values remain local `chars_div_4` proxies rather than provider-token or savings claims.
- Add `--adaptive-k` to `suggest` or `auto` for advisory-only shrink/expand top-k metadata derived from local score distribution, byte-budget fit, and clamped score-mass recall/precision proxies. Use `--adaptive-k-policy balanced|recall|precision` plus optional `--adaptive-k-min-recall-proxy` / `--adaptive-k-min-precision-proxy` gates to choose a local recommendation policy; gate failures are metadata-only (`pass|failed`). The adaptive block includes capped selected/omitted evidence and structured source-verification hints, never applies the recommendation automatically, and does not change the manifest, pack body, receipt, or byte budget.
- Add `--symbol-memory` to `auto` for repo-map-derived symbol/graph advisory metadata with exact `slice` / `read-symbol` verification hints. It is source-verification guidance only and does not change the manifest, pack body, receipt, or byte budget.
- `--manifest-out` writes a build-compatible manifest; `--pack-out` saves the rendered pack.
- `context-guard-pack suggest` is the lower-level additive local-only planning step. It ranks candidate files and line ranges from `--query`, `--diff`, repeated `--files`, and optional sanitized `--output` / `--test-output` files under `--root`, then writes a manifest that `build --manifest` can consume.
- `context-guard-pack build` assembles prioritized local file evidence into a Markdown body whose rendered UTF-8 bytes stay within `--budget-bytes`. JSON output records included, partial, duplicate, unsafe, missing, and budget-omitted sources.
- Every build reports a `content_address` (`sha256:<digest>`) of the exact rendered pack bytes while retaining the legacy `pack_id`. On `build` or `auto`, opt-in `--delta-from-pack-id PACK_ID` reads only `.context-guard/packs/PACK_ID.json` and reports bounded, fail-soft `rolling_delta` diagnostics. It never changes selection, the pack body, `pack_id`, or default behavior, and it is not a provider token/cost savings claim.
- Bounded receipts are stored under `.context-guard/packs`. When path/root display is safe, JSON output includes copy-pasteable `slice` commands for exact sanitized retrieval; otherwise it records `retrieval_omitted_reason`.

The packer uses deterministic standard-library heuristics only: no network, model calls, embeddings, or provider-cost estimate. Byte counts are observed; token counts remain estimated `chars_div_4` proxies, not measured provider-token savings.

### Prune a tool/MCP catalog for a task

```bash
./plugins/context-guard/bin/context-guard-tool-prune select \
  --catalog tools.json \
  --query "review failing tests" \
  --top 5 --budget-bytes 12000 --json
./plugins/context-guard/bin/context-guard-tool-prune defer-report \
  --catalog tools.json \
  --query "review failing tests" \
  --core-top 3 --deferred-top 20 --json
./plugins/context-guard/bin/context-guard-tool-prune get <receipt_id> --tool read_file --json
```

`context-guard-tool-prune` ranks a local tool or MCP catalog with deterministic lexical heuristics and emits a bounded top-k advisory report. Inline selected schemas respect an observed UTF-8 byte budget, and omitted or budget-skipped schemas remain recoverable from a compact local receipt plus a separate sanitized payload under `.context-guard/tool-prune`. `defer-report` uses the same receipt path to split a catalog into core inline tools plus deferred tool stubs and namespace summaries, and reports gross deferred-schema plus net initial-report char/4 proxy accounting so you can see what moved out of the first prompt. This is advisory only: it does not mutate MCP configuration, does not configure native provider tool search, and token counts remain estimated proxies rather than measured provider savings.

### Score static prompt cacheability

```bash
./plugins/context-guard/bin/context-guard-cache-score --input prompt.json --provider openai --json
./plugins/context-guard/bin/context-guard cache-score --input prompt.txt --provider anthropic --json
```

`context-guard-cache-score` is a local static lint for prompt/request layout. It estimates total and cacheable-prefix size with a tokenizer-free char/4 proxy, warns about dynamic-looking values near the prefix, and records provider caveats for OpenAI, Anthropic, Gemini, or a generic threshold. Optional `--expected-reuses`, `--cache-write-multiplier`, and `--cache-read-multiplier` inputs add an advisory amortization-risk section using user-supplied economics only. It does not call providers, store raw prompts, estimate prices from bundled defaults, observe cache hits, or prove token/cost savings; verify real cache behavior with provider usage telemetry.

### Advise on total cost, batchability, and routing

```bash
./plugins/context-guard/bin/context-guard route-advisor --workload workload.json --json
./plugins/context-guard/bin/context-guard-cost route-advisor --feature batch_api=true --feature structured_outputs=true --json < workload.json
```

`context-guard route-advisor` is a local, passive advisor. It reads caller-supplied workload JSON, provider feature declarations, usage telemetry, and shifted external/local costs, then emits total-cost accounting, batchability blockers, and candidate routes such as batch API, prompt-cache prefix preservation, structured outputs, or cheaper-model evaluation. It does not start a queue, call providers, refresh pricing docs, or treat bundled provider feature knowledge as authoritative; unknown or caller-supplied features are marked recheck-required. Treat recommendations as candidates only. Hosted token or cost savings claims require matched successful tasks, non-inferior quality, and shifted-cost evidence.

### Compress selected local text conservatively

```bash
git diff | ./plugins/context-guard/bin/context-guard-compress --json
pytest -q 2>&1 | ./plugins/context-guard/bin/context-guard-compress --type log
cat evidence.txt | ./plugins/context-guard/bin/context-guard-compress --json --protected-policy
cat sanitized-prose.txt | ./plugins/context-guard/bin/context-guard-compress --json --type prose --mode readable
```

`context-guard-compress` classifies sanitized stdin as JSON, diff, log, search output, code, or prose, then applies deterministic reductions such as JSON compaction, diff context folding, duplicate log/search line collapse, and whitespace normalization. It never claims observed model-token savings; byte counts are observed, token counts are labeled as estimates, and lossy receipts point you back to `context-guard-artifact store` for exact retrieval.

Add `--protected-policy` when the input may contain semantic-sensitive zones such as code fences, diffs, identifiers, numeric constants, hashes, paths, stack frames, quoted strings, or JSON keys. The flag does not change default compressor behavior; it adds `protected_zone_policy` and `transform_policy` metadata that denies semantic/paraphrase rewrites, allows only structural transforms plus artifact retrieval, and stores only class/count policy metadata rather than raw protected spans.

Add `--mode readable` only for sanitized prose previews. It uses a deterministic sentence window, blocks prompt-like or high-risk protected signals, stores no raw protected spans, and marks exact fallback retrieval as required before edits or claims. It does not run learned compressors, models, embeddings, or rerankers.

### Trim or summarize command output

```bash
./plugins/context-guard/bin/context-guard-trim-output --max-lines 120 -- npm test
```

Use `--digest markdown` or `--digest json` for a compact semantic digest instead of head/tail logs. Digest mode keeps status, exit code, truncation counts, runner failure facts, a sanitized failure signature, duplicate-line groups, representative lines, redaction counts, and suggested next queries while preserving the wrapped command exit code. Add `--artifact-receipt` with digest mode when you want the exact sanitized full output stored locally as a `context-guard-artifact` receipt; keep the emitted `contextguard-artifact:<id>` handle in agent context and re-expand with the emitted `context-guard-artifact receipt/get/search ...` commands before relying on omitted details. Wrapped commands time out after 600 seconds by default; tune this with `--timeout-seconds`.

### Sanitize search and diff output

```bash
./plugins/context-guard/bin/context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
./plugins/context-guard/bin/context-guard-sanitize-output -- git diff
```

The sanitizer reduces the chance that token-like, key-like, password-like, or sensitive path values are copied into agent context.

### Apply an opt-in declarative output filter

```bash
cat > .context-guard/filter-dsl.json <<'JSON'
{
  "schema_version": "contextguard.filter-dsl.v1",
  "filters": [
    {
      "id": "git-status-short",
      "match": {"argv_prefix": ["git", "status", "--short"]},
      "include_regex": ["^[ MADRCU?!]"],
      "max_lines": 80
    }
  ]
}
JSON
./plugins/context-guard/bin/context-guard-filter validate --config .context-guard/filter-dsl.json
./plugins/context-guard/bin/context-guard-filter run --config .context-guard/filter-dsl.json -- git status --short
```

`context-guard-filter` is an opt-in local helper for user-owned JSON filter files; it does not install default filters or change hooks. Invalid configs, no-match commands, filtering errors, empty filtered output, and protected `git`/test/lint/`gh` command failures pass the original command stdout/stderr and exit code through. In filtered mode, line rules apply to combined stdout+stderr and write the filtered result to stdout; passthrough mode preserves stdout/stderr streams. `run --json-report` writes filter diagnostics to stderr so stdout remains command/filter output; protected nonzero passthrough suppresses that report to keep stderr raw. Treat filtered byte reductions as local presentation changes, not hosted token/cost savings claims.

### Audit local transcript usage

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --top 20 --recommend
```

The audit command skips oversized transcript files and JSONL records by default (`--max-file-bytes`, `--max-line-bytes`) and reports skipped counts. That keeps a corrupt trace from dominating memory or hiding scan gaps.

JSON output can include several evidence surfaces:

- `cache_friendliness` and [`cache_diagnostics`](docs/cache-diagnostics-schema.md): heuristic prompt-layout/cache-read diagnostics built from bounded usage fields, timestamped cache telemetry records, and redacted segment hashes.
- `cache_layout_advice`: ranked **checks/experiments** such as splitting long sessions or stabilizing early prompt prefixes, with observed issues kept separate from hypothesized or corroborated causes.
- `--feasibility-json` / [`mac_visibility`](docs/mac-visibility-feasibility-schema.md): a contract for local macOS-visible consumers. Only stable top-level fields are binding targets; `summary` is not a primary UI binding source.

These fields can flag likely volatile content near the prompt prefix, stable-prefix candidates, cache-miss hypotheses, and TTL/headroom evidence gaps. They do not print raw prompt text, do not prove provider cache hits, and may be `missing`, `partial`, `hypothesis`, or `unavailable` when transcript schemas do not expose enough evidence.

### Watch context and cache health in the statusline

```text
[Sonnet] repo | main | ctx 86% ⚠ | cost $0.123 | cache 80% | reuse 8.0x
```

`cache N%` is the cache-read share of observed input-side tokens in the bounded transcript tail and stays hidden until at least one cache read is observed. `reuse X.Yx` is `cache_read / cache_creation` and is shown only when cache read is positive and cache creation is non-zero. The `⚠` marker appears when context usage reaches the warning threshold, defaulting to 80%; set `CONTEXT_GUARD_STATUSLINE_CTX_WARN=90` to tune it for a project or shell.

### Run a repeatable benchmark

```bash
./plugins/context-guard/bin/context-guard-bench \
  --tasks bench/tasks.json --variants bench/variants.json --csv bench/results.csv \
  --ledger-jsonl bench/cost-shift.jsonl --report-json bench/report.json \
  --dashboard-md bench/dashboard.md
```

For deterministic local replay before a live provider run, add `--evidence-jsonl docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl` and, for the 12-task fixture, `--baseline-variant baseline_full_context_fixture`. Replay mode skips provider and `success_command` execution, writes the same CSV/report/dashboard surfaces, and marks synthetic/manual evidence as non-public-claim-eligible.

Read the report through its claim boundaries before writing any savings statement:

- Successful baseline/variant runs are compared by real tokens and `cost_usd + external_cost_usd`; byte reductions stay proxy evidence.
- Token-savings claims require `primary_tokens_measured` on both sides of a matched task.
- `matched_pair_evidence` links each successful task bucket to the transform, measurement availability, quality gate, and claim boundary.
- `default_matrix` classifies trimming, artifact escrow, tool pruning, cache advice, adaptive-k, and optional compression as `default-on`, `advisory`, `experimental`, or `reject/rework` from the same matched evidence. The matrix is report-only: it does not change runtime defaults or authorize hosted token/cost savings claims.
- `public_claim_readiness` is the authoritative release/public-claim gate. It remains false unless matched successful tasks, provider-measured primary tokens/cost, quality non-inferiority, shifted-cost accounting, explicit confidence/failure notes, and complete provider-export provenance all pass; unsupported hosted savings claims are forbidden when `claim_allowed` is false.
- `wall_time_seconds`, `provider_cached_tokens`, and `provider_cached_tokens_measured` are diagnostic telemetry, not proof of ContextGuard-caused token or cost savings.
- Optional `self_hosted_metrics` from provider payloads are stored as per-row JSONL ledger sidecars, kept out of CSV/report summaries, and must not be folded into hosted API token/cost savings claims.
- If cost fields are zero or unavailable, the report can still mark token savings but will not claim shifted-cost savings.
- CSV schemas are strict; after upgrading the benchmark helper, start a new `--csv` file or migrate the header named in the mismatch error.

See [`docs/benchmark-report.example.json`](docs/benchmark-report.example.json) for a minimal report-shape example, [`docs/benchmark-workflow-examples.md`](docs/benchmark-workflow-examples.md) for workflow-specific synthetic examples, and [`docs/experimental-benchmark-fixtures.md`](docs/experimental-benchmark-fixtures.md) for fixture-only experimental task/variant starters plus synthetic evidence replay.

### Manage experimental opt-ins

Experimental lanes are **default off**. The registry records project-local intent and metadata only; enabling an experiment does not activate stable runtime behavior by itself. Later helpers must still require explicit experimental flags before using these lanes.

```bash
context-guard experiments list
context-guard experiments status --json
context-guard experiments plan context-diff-compaction --json < change.diff
context-guard experiments emit context-diff-compaction --receipt-id <artifact-id> --reexpand-command "context-guard-artifact get <artifact-id> --full" --replacement-file compact-diff.txt --json < change.diff
context-guard experiments plan visual-crop-ocr --json --full-evidence-receipt <id> --crop-label <label> --crop-bounds 0,0,100,100 --image-size 800,600 --missed-context-note "outside crop omitted"
context-guard experiments emit visual-crop-ocr --json --full-evidence-receipt <id> --crop-label <label> --crop-bounds 0,0,100,100 --image-size 800,600 --ocr-text "visible text" --ocr-confidence 0.9 --ocr-error-note "glyph may be uncertain" --missed-context-note "outside crop omitted"
context-guard experiments plan image-context-pack --json --exact-text-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" --provider-boundary-ack --protected-zone-policy deny --missed-context-note "omitted text remains retrievable before any future image pack is used" --image-size 800,600 --packed-image-size 400,300
context-guard experiments plan semantic-checkpoint --json --goal "preserve current task state for review" --constraint "do not rewrite protected evidence" --decision "ship plan-only semantic-checkpoint gate first" --open-task "verify exact fallback before any checkpoint is used" --evidence-handle "roadmap=contextguard-artifact:0123456789abcdef" --missing-provenance-note "none known after review" --unresolved-question "which provenance handle fields become mandatory later" --exact-context-fallback-receipt 0123456789abcdef --reexpand-command "context-guard-artifact get 0123456789abcdef --full" --provider-boundary-ack --protected-zone-policy deny --missed-context-note "raw transcript remains retrievable before checkpoint metadata is used"
context-guard experiments plan proof-carrying-context --json --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","safe_range":{"kind":"lines","start":82,"end":85},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --protected-zone-policy deny
context-guard experiments verify proof-carrying-context --artifact-dir ./artifacts --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14","safe_range":{"kind":"lines","start":1,"end":1},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --json
context-guard experiments plan learned-compression --json --sanitized --trusted-source --exact-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" < sanitized-prose.txt
context-guard experiments emit learned-compression --json --sanitized --trusted-source --exact-fallback-receipt <id> --reexpand-command "context-guard-artifact get <id> --full" --replacement-file compact-prose.txt < sanitized-prose.txt
context-guard experiments plan self-hosted-metrics-ledger --json --latency-ms 123.5 --peak-memory-mb 2048 --quality-score 0.98
context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl .context-guard/self-hosted-metrics.jsonl --latency-ms 123.5 --peak-memory-mb 2048 --quality-score 0.98 --json
context-guard experiments plan local-proxy --json --bind-host 127.0.0.1 --target-host 127.0.0.1 --runtime-gate-ack
context-guard experiments plan local-proxy-external-forwarding --external-forwarding-intent --external-forwarding-design-ack --allow-host api.example.com --allow-scheme https --credential-redaction-policy strip-sensitive-headers --provider-evidence-boundary diagnostic-only-provider-measured-required --threat-model-note "Only user-owned HTTPS endpoint; sensitive headers are stripped before any future forwarding." --json
context-guard experiments record local-proxy-runtime-gate --ledger-jsonl .context-guard/local-proxy-gates.jsonl --bind-host 127.0.0.1 --target-host 127.0.0.1 --runtime-gate-ack --json
context-guard experiments serve local-proxy --bind-host 127.0.0.1 --bind-port 18080 --target-host 127.0.0.1 --target-port 18081 --runtime-gate-ack --forwarding-gate-ack --once --ready-file .context-guard/local-proxy-ready.json --response-sandbox --response-artifact-dir .context-guard/artifacts --diagnostic-ledger-jsonl .context-guard/local-proxy-diagnostics.jsonl --json
context-guard experiments enable output-receipt-trim --root .
context-guard experiments disable output-receipt-trim --root .
```

`plan image-context-pack` is intentionally plan-only and side-effect free: it emits deterministic JSON metadata, does not render or parse images, does not run OCR, does not store binary image artifacts, does not call providers or proxy traffic, and does not duplicate `visual-crop-ocr`. Any future omission of exact text must keep a verified exact text fallback, deny protected zones, record missed-context guardrails, and treat image/request byte reductions as proxy evidence until provider-measured matched tasks prove token/cost deltas.

`plan semantic-checkpoint` is also plan-only/eval-only. Its CLI flags are optional so incomplete plans can produce reviewer JSON, but missing readiness fields block the JSON payload until exact context fallback is present. Ready plans require a goal, exact fallback receipt, a local re-expand command shaped as `context-guard-artifact get <id> --full` or `context-guard artifact get <id> --full`, provider-boundary acknowledgement, protected-zone policy `deny`, missed-context notes, and provenance review notes. `--missing-provenance-note` may be a review acknowledgement such as `none known after review`. The gate has no `emit`, `record`, or `serve` runtime, no `context-guard-semantic-checkpoint` binary, no file writes, transcript or prompt edits, model/provider/network calls, replacement context, or hosted token/cost savings claim.

`plan proof-carrying-context` is a default-off plan-only proof-envelope metadata readiness gate. It accepts bounded repeatable inline JSON, validates syntax and defined consistency only, and keeps the caller-supplied timestamp without generating or comparing current time. Protected-zone policy is declared-only; range bounds, receipt storage, source content, SHA-256, timestamp freshness, and rehydration remain unchecked and are reported as warnings. The command reads no source/artifact/config/stdin content, writes no files, calls no model/provider/network/subprocess, generates or replaces no context (`candidate_replacement` stays `null`), exposes no `emit`/`record`/`serve` runtime or new binary, and permits no hosted token/cost savings claim without provider-measured matched successful tasks.

`verify proof-carrying-context` is the separate read-only local verifier. The documented fixture is the exact UTF-8 string `ContextGuard proof fixture\n` (27 bytes, one line), whose SHA-256 is `12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14`. Verification requires one explicit artifact directory, searches no fallback, follows no symlink, requires the directory to be owned by the effective user with mode `0700` and both receipt leaves with mode `0600`, and reads the whole bounded file only to verify receipt/proof hashes, byte/line counts, and range bounds; it never retrieves or echoes range content. Exit `0` means only those local bindings passed; exit `2` means verification failed. Timestamp freshness and protected-zone semantics remain unchecked, rehydrate commands are syntax/receipt checked but never executed, `candidate_replacement` remains `null`, and no replacement, omission, or hosted-savings claim is authorized.

The local-proxy examples are intentionally split by side effect:

- `plan local-proxy` produces advisory metadata only; it does not enable forwarding.
- `record local-proxy-runtime-gate` appends one localhost-only gate row and still starts no listener, forwards no traffic, persists no API keys, and makes no hosted-savings claim.
- `serve local-proxy` is the separate MVP. It requires both runtime and forwarding acknowledgements plus `--once`, a private `--ready-file` nonce handoff for the forwarding client, binds only a literal loopback IP, forwards only to a literal loopback IP target, blocks credential-bearing requests, uses byte/time limits, uses literal IPs instead of hostname DNS targets, does not persist API keys, and does not support external forwarding, CONNECT/TLS proxying, or hosted-savings claims. Optional `--response-sandbox` is a mediated response mode, not transparent forwarding: it artifacts only safe UTF-8 upstream response text and returns a compact JSON envelope with `contextguard-artifact:<id>` and rehydration commands; binary, sensitive, oversized, or blocked responses are not artifacted.
- With `--diagnostic-ledger-jsonl`, `serve` appends one shifted-cost diagnostic row only after a successful forwarded request. The row stores hashes/metadata rather than raw headers, request bodies, response bodies, or hosted-savings evidence.
- `plan local-proxy-external-forwarding` is a dry-run design gate only. It requires explicit external intent, design acknowledgement, HTTPS host allowlist, threat model notes, credential redaction policy, and provider-evidence boundary, but starts no listener, performs no DNS lookup, calls no external service, forwards no traffic, persists no credentials, and does not ship an external proxy forwarding runtime.

By default, project settings are stored in `.context-guard/experiments.json`. Use `--config <path>` only for an explicit project-local override. Experiment metadata includes risk level, gate requirements, explicit command/flag surfaces, and claim boundaries so hosted API token/cost savings are not claimed without provider-measured matched-task evidence. `experiments enable` records intent only; it does not run helpers, remove the need for their explicit flags, or permit replacing content without exact receipt/re-expand evidence.

Shipped experimental checker/planner surfaces, plus explicit local context-diff, visual evidence, learned-candidate, metrics, proxy-gate record runtimes, and the plan-only image-context-pack and semantic-checkpoint gates, are intentionally narrow:

| Planner/checker/runtime | What it emits | Hard boundary |
| --- | --- | --- |
| `context-diff-compaction` | Dry-run diff advice plus an explicit `emit ... --receipt-id ... --reexpand-command ...` runtime for caller-supplied compact replacements. | `plan` emits no replacement. `emit` requires reviewable hunks, exact local artifact re-expand metadata whose stored content matches the input diff, and a smaller caller-supplied replacement; ContextGuard does not generate semantic compression or support hosted token/cost savings claims. |
| `visual-crop-ocr` | Dry-run visual evidence advice plus an explicit `emit visual-crop-ocr` runtime for caller-supplied evidence packs. | `emit` requires a full visual evidence receipt, missed-context note, and complete user-supplied crop and/or OCR evidence; ContextGuard does not capture screenshots, crop images, run OCR, parse images, call external services, write files, or support hosted token/cost savings claims. |
| `image-context-pack` | Pxpipe-inspired dry-run plan metadata only for future image/context packing evaluation. | `plan` emits no image, replacement, evidence pack, binary artifact, ledger, listener, or proxy. It requires exact text fallback receipt/re-expand metadata before omitted text is used, protected-zone denial, missed-context notes, and an explicit provider boundary acknowledgement for provider/model measured matched-task evidence. `visual-crop-ocr` remains the caller-supplied visual evidence-pack surface; `image-context-pack` is not a duplicate emitter or verified exact binary/image fallback. |
| `semantic-checkpoint` | Plan-only/eval-only checkpoint readiness metadata for preserving task state during review. | `plan` emits deterministic JSON metadata only. CLI flags are optional, but readiness is blocked in JSON until exact context fallback, local re-expand metadata, provider-boundary acknowledgement, protected-zone denial, missed-context note, and provenance review note are present. `--missing-provenance-note` may be a review acknowledgement such as `none known after review`. It writes no files, edits no transcript or prompt, calls no model/provider/network, emits no replacement context, has no `emit`/`record`/`serve` runtime or new binary, and makes no hosted token/cost savings claim. |
| `proof-carrying-context` | Plan-only metadata readiness plus explicit read-only local receipt verification. | `plan` accepts at most 64 detailed inline JSON units without reading content. `verify` checks only one explicit private no-follow directory, strict receipt metadata, bounded whole-content bindings, range bounds, and command syntax without retrieving ranges or executing commands. Both keep `candidate_replacement: null`; neither grants replacement, omission, protected-zone, freshness, semantic-safety, or hosted-savings authority. |
| `learned-compression` | Deny-by-default policy checks plus an explicit `emit learned-compression` runtime for caller-supplied compact prose candidates with verified exact fallback content. | `emit` requires sanitized trusted prose, protected-signal denial, a verified local fallback artifact matching the input, and a smaller caller-supplied prose candidate; ContextGuard does not run compressors, embeddings, rerankers, model calls, subprocesses, external services, generated replacement text, or hosted savings claims. |
| `self-hosted-metrics-ledger` | Dry-run preview plus an explicit `record ... --ledger-jsonl` runtime for local/model-server latency, memory, quality, energy, throughput, and local-cost metrics. | The dry-run preview does not write a ledger; the explicit record command writes only local JSONL sidecars and still does not support hosted API token/cost savings claims. |
| `local-proxy` | Localhost-only advisory metadata, design-only `plan local-proxy-external-forwarding` review for future external forwarding, an explicit `record local-proxy-runtime-gate --ledger-jsonl` runtime for one local gate row, an explicit one-shot `serve local-proxy` loopback forwarding MVP, optional `--response-sandbox` compact artifact envelopes, and optional `--diagnostic-ledger-jsonl` shifted-cost diagnostics for successful forwarded requests. | `plan` writes no ledger. `record` writes only after localhost-only metadata and `--runtime-gate-ack`; it starts no listener, forwards no traffic, and performs no DNS lookup. `serve` additionally requires `--forwarding-gate-ack --once`, a private `--ready-file` nonce handoff, literal loopback bind/target IPs, nonzero ports, bounded bytes/timeouts, and credential-free requests; it performs no external forwarding, no CONNECT/TLS proxying, no API-key persistence, and no hosted-savings claim. `--response-sandbox` can store safe UTF-8 response text as a sanitized local artifact receipt and return a compact envelope with redacted rehydration command templates; it does not claim hosted token/cost savings. `--diagnostic-ledger-jsonl` writes only successful-forward diagnostics with no raw headers/bodies and no hosted-savings claim. `plan local-proxy-external-forwarding` emits threat-model/allowlist/redaction/provider-evidence design metadata only and still performs no DNS lookup, external service call, traffic forwarding, credential persistence, or hosted-savings claim. |

## What is not yet shipped

These are tracked directions, not committed features. Nothing here ships unless another repository document says it does.

ContextGuard does not yet ship:

- learned/synthetic compressor execution or generated replacement text beyond the caller-supplied learned candidate emitter
- generated crop/OCR or visual-token pruning runtime beyond the caller-supplied visual evidence-pack emitter
- generated image-context-pack renderers, binary/image artifact fallback, or pxpipe-style proxy/runtime beyond the plan-only evaluation gate
- semantic-checkpoint emit/record/serve runtime, replacement context, file-writing checkpoint store, transcript/prompt editing, provider/model/network-backed checkpointing, or a new `context-guard-semantic-checkpoint` binary
- self-hosted KV/latent optimization beyond explicit local metrics recording
- external, daemon, or credential-bearing proxy forwarding beyond the one-shot literal-loopback local proxy MVP

See the [experimental token-reduction radar](research/experimental-token-reduction-radar.md) and [fixture-only experimental benchmark starters](docs/experimental-benchmark-fixtures.md). Those lanes remain experimental/non-shipped under the later-roadmap gate until matched successful tasks, failure-rate guardrails, human-correction tracking, shifted-cost accounting, provider-measured token/cost evidence, and separate future PR gates justify any hosted API savings claim or broader runtime feature claim.

## Repository layout

- `.claude-plugin/marketplace.json` — Claude Code marketplace manifest.
- `plugins/context-guard/` — installable Claude Code plugin package.
- `context-guard-kit/` — checkout-local Python/Bash helper sources. npm packages ship synchronized `plugins/context-guard/bin` and `plugins/context-guard/lib` copies instead of duplicating this source tree.
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
./plugins/context-guard/bin/context-guard-setup --agent codex --brief-mode standard --plan
./plugins/context-guard/bin/context-guard-setup --yes
```

To use shorter commands during local development, add the plugin bin directory to your shell:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

Do not rely on `PATH` lookup for generated hooks by default. The setup wizard records explicit bundled or checkout-local helper paths; `--allow-path-helper-fallback` is only for trusted external installs and validates the resolved helper path, symlink state, and bounded identity probe before writing commands. The macOS app helper follows the same trust model: no launch-CWD discovery, no relative override paths, and no inherited ambient shell environment beyond the allowlisted values it needs to start.

## Release checks

Before publishing or merging release-sensitive changes, run the copy check and both gates:

```bash
python3 scripts/sync_plugin_copies.py --check
python3 scripts/prepublish_check.py
python3 scripts/release_smoke.py
```

When a helper under `context-guard-kit/` changes, run `python3 scripts/sync_plugin_copies.py --write` before the gates. `sync_plugin_copies.py --check` verifies the maintainer-facing exact-copy contract up front. npm packages intentionally ship only the synchronized plugin-local `plugins/context-guard/bin` entrypoints and `plugins/context-guard/lib` helpers to avoid duplicate implementation payloads, and the npm bin map intentionally omits legacy `claude-*` wrapper aliases. Command manifests are loaded as literal assignments for release and runtime checks; executable Python, imports, functions, or shadow manifests are rejected. `prepublish_check.py` verifies package invariants, synchronized plugin binaries, manifests, diagnostic redaction, and the regression suite. `release_smoke.py` executes representative packaged entrypoints from `plugins/context-guard/bin` in a temporary project so broken CLI wiring is caught before publish. See [docs/release-runbook.md](docs/release-runbook.md) for the full release workflow, evidence checklist, quad-review requirement, and rollback checklist.

Versioned release notes live in [CHANGELOG.md](CHANGELOG.md); the prepublish gate requires an entry matching the plugin manifest version before publishing.

### Experimental semantic-GC plan gate

`semantic-gc` is a default-off, deny-only, plan-review gate over a caller-declared graph. Default-off describes registry intent; the explicit plan CLI remains invocable and never enables omission or runtime action. Graph evaluation is suppressed when the complete envelope or topology is ambiguous. Unreachable nodes are review candidates, not proof of semantic irrelevance: omission and runtime action remain unauthorized. Candidate missed-context notes are untrusted. The planner does not read context/artifact content or verify provenance, fallback, providers, or hosted savings. Exit 0 means only `ready_for_plan_review`; it is never delete/omit authority.

context-guard experiments plan semantic-gc --json --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"root","references":[],"is_root":true,"protected_zone":false}' --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"orphan","references":[],"is_root":false,"protected_zone":false,"content_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provenance":{"source_label":"canonical-example","receipt_id":"0123456789abcdef"},"missed_context_note":"A reviewer could lose the orphaned rationale.","exact_fallback_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --human-review-ack --protected-zone-policy deny

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
