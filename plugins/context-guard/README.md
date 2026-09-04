# ContextGuard

ContextGuard is a local-first context management toolkit for AI coding and tool-using agents. It starts as a Claude Code plugin, then extends the same project-local guardrails to other agents through plain local helper commands and advisory brief-mode rule snippets.

Start with `/context-guard:setup`. Setup is explicit, project-local, and reversible: it merges recommended project settings, prints a read-only context management scan, does not mutate global Claude settings, and does not configure offloading to external AI services.

## Quickstart

```bash
/plugin marketplace add ictechgy/context-guard && /plugin install context-guard@context-guard   # Claude Code
/context-guard:setup          # applies the recommended project-local hooks after showing a plan
/context-guard:audit          # shows where your tokens went, by tool and per turn
```

npm users run `npx @ictechgy/context-guard setup --profile recommended --plan` then `--yes`.

## Token-waste paths it targets

ContextGuard is a local context management layer, not a provider prompt cache or semantic answer cache. Its helpers reduce avoidable context bloat before it enters an agent conversation: large file reads are steered toward search/symbol/line-range slices, long command output can be trimmed or digested, large logs can be stored as local artifact receipts, secret-like values are redacted on a best-effort basis, repeated Bash failures trigger a strategy nudge, cache-friendly prompt layout can be audited from bounded redacted segment hashes, and audit/benchmark evidence stays tied to your own tasks.

## Rebrand note

Claude Code does not alias the old `/claude-token-optimizer:*` plugin slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy `claude-*` wrapper names were removed in this release; use the `context-guard-*` names instead (migration: replace the prefix).

## Skills

After installation, use these skills inside Claude Code:

```text
/context-guard:setup
/context-guard:optimize
/context-guard:audit
```

| Skill | Purpose |
| --- | --- |
| `/context-guard:setup` | First-time project setup wizard. |
| `/context-guard:optimize` | Inspect and tune context guardrails. |
| `/context-guard:audit` | Audit local Claude transcript token/cost hotspots. |

## Helper commands and PATH

The canonical command is `context-guard`; backwards-compatible helper commands keep the `context-guard-*` prefix. Claude Code plugin skills can call the packaged helpers, but your normal shell may not automatically add the plugin `bin/` directory to `PATH`.

Setup records bundled or checkout-local helper paths by default. It does not fall back to arbitrary `PATH` helpers unless you explicitly pass `--allow-path-helper-fallback` for a trusted install; that fallback validates the canonical executable path and helper identity before use.

For Codex or other terminal-first agents, install the npm package or run it one-off with npx. Installation is passive and does not write configuration.

```bash
npm install -g @ictechgy/context-guard
context-guard doctor --root . --json  # read-only health check; no changes made
context-guard setup --agent codex --scope project --with-init --with-skill --plan
context-guard setup --agent codex --scope project --brief-mode standard --plan
npx @ictechgy/context-guard --version
```

The compact `bash_reference_v1` Bash-output route is intentionally not
available from this marketplace-plugin/source layout. It requires an exact
project-local npm installation of `@ictechgy/context-guard@0.13.0` and its
`@ictechgy/context-guard-receipt@0.4.0` dependency, then explicit
`setup --agent claude --scope project --bash-reference-v1`. Plugin setup keeps
legacy trimming and warns instead of installing a no-op reference flag. See the
repository distribution guide for activation, disablement, seven-day handle,
and preserved-state details.

From this repository root, run helpers by path:

```bash
./plugins/context-guard/bin/context-guard-setup --plan
./plugins/context-guard/bin/context-guard-diet scan . --json
```

For local development, add the plugin bin directory to your current shell:

```bash
export PATH="$PWD/plugins/context-guard/bin:$PATH"
context-guard-setup --plan
```

Common helpers:

```bash
context-guard-audit ~/.claude/projects --top 20 --recommend
context-guard-setup
context-guard-diet scan . --json
context-guard-diet structural-waste . --tool-catalog tools.json --log-path .claude --json
context-guard-artifact store --command "long-command" --json < large.log
context-guard-artifact search "ERROR" --json
context-guard-artifact receipt <artifact_id> --json
context-guard-artifact get <artifact_id> --lines 1:80
context-guard task-memory put --task issue-123 --source src/app.py --json < stable-context.txt
context-guard task-memory get <opaque_handle> --task issue-123 --source src/app.py --max-bytes 65536
context-guard-compress --json < large-output.txt
context-guard-compress --json --protected-policy < evidence.txt
context-guard-compress --json --type prose --mode readable < sanitized-prose.txt
context-guard cost preflight --request request.json --budget-krw 3000 --json
context-guard cost observe --usage usage.json --json
context-guard route-advisor --workload workload.json --json
context-guard cost advisory --workload advisory-workload.json --json
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-filter validate --config .context-guard/filter-dsl.json
context-guard-filter run --config .context-guard/filter-dsl.json -- git status --short
context-guard-pack auto --root . --query "review failing tests" --diff HEAD --manifest-out suggested-pack.json --pack-out context-pack.md --budget-bytes 12000 --json --explain --adaptive-k --adaptive-k-policy recall --symbol-memory
context-guard-pack auto --root . --files src/app.py --query "review entrypoint" --top 1 --budget-bytes 12000 --json --no-artifact --apply-symbol-memory
context-guard-pack auto --root . --query "review failing tests" --top 8 --budget-bytes 12000 --json --no-artifact --apply-adaptive-k
context-guard-pack build --root . --manifest suggested-pack.json --budget-bytes 12000 --json
context-guard-pack build --root . --manifest suggested-pack.json --budget-bytes 12000 --json --no-artifact --delta-from-pack-id 0123456789abcdef0123
context-guard-pack slice --root . --path README.md --lines 1:40 --json
context-guard-cache-score --input prompt.json --provider openai --json
context-guard cache-score --input prompt.txt --provider anthropic --json
context-guard-tool-prune select --catalog tools.json --query "review failing tests" --top 5 --budget-bytes 12000 --json
context-guard-tool-prune defer-report --catalog tools.json --query "review failing tests" --core-top 3 --deferred-top 20 --json
context-guard-tool-prune get <receipt_id> --tool read_file --json
context-guard-statusline
context-guard-statusline-merged
```

## What the helpers do

Every pack build includes a rendered-byte SHA-256 `content_address` without changing the legacy `pack_id`. `build` and `auto` accept opt-in `--delta-from-pack-id PACK_ID` for bounded, fail-soft diagnostics against exactly one private local receipt; `rolling_delta` is diagnostic-only, changes no selection or pack content, and is not a provider token/cost savings claim. Diagnostics are reported only in `--json` output or a stored artifact receipt; with `--no-artifact`, `--json` is required to report them, while legacy text stdout remains the exact pack body.

- **Setup wizard** merges `.claude/settings.json` instead of replacing it, then prints a read-only `context-guard-diet scan` summary. Use `context-guard doctor` or `context-guard setup --verify` for a read-only health check before applying setup; use `--no-diet-scan` when automation needs setup output without the post-apply scan. `PATH` helper fallback is default-off and requires `--allow-path-helper-fallback` plus identity validation.
- **Context management scanner** checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, large or secret-like agent rule files, and advisory context-exclusion recommendations for bulky/sensitive local paths. Its `--top` cap applies to both context-like files and context-exclusion recommendations.
- **Structural-waste doctor** is an opt-in read-only `context-guard-diet structural-waste` report for duplicate rule units, stale Python import candidates, unused skill candidates, excessive MCP/tool schema catalogs, and repeated file reads or duplicate tool calls in local JSON/JSONL logs. It does not mutate config, call the network, or print raw prompt/tool-input text; low-confidence import/skill findings are review prompts, not delete instructions.
- **Large-read guard and symbol reader** guide the agent from search to symbol slices to small line ranges before attempting a whole-file read. Supported source slices include Python, JavaScript/TypeScript, Go, and Rust.
- **Declarative output filter** validates user-owned JSON filter files outside package code and applies the first matching line filter only as an explicit `run --config ... -- <command>` wrapper. Invalid configs, no-match commands, filter errors, empty filtered output, and protected `git`/test/lint/`gh` command failures preserve original stdout/stderr and exit code. Filtered mode applies line rules to combined stdout+stderr and writes the filtered result to stdout; `--json-report` diagnostics go to stderr, except protected nonzero passthrough suppresses reports to keep stderr raw. It is local and opt-in, with no savings guarantee.
- **Artifact store** saves large sanitized command output under `.context-guard/artifacts` by default and returns compact receipts, local sandbox search results, or exact requested slices. JSON receipts include line-numbered top errors, duplicate-line groups, sanitized bounded suggested queries, and an `output_sandbox` envelope with a stable `contextguard-artifact:<id>` handle. `receipt <artifact_id> --json` rehydrates metadata-only handles without content. `search` scans sanitized local artifacts by literal substring, emits capped match/context records, and includes `get --lines START:END` rehydration commands without hosted token/cost savings claims. Custom `--dir` raw paths stay redacted by default; reuse the same `--dir` or opt into `search --show-paths` for a directly executable local command. In suggested `--lines START:END` queries, `--max-lines` is only the returned-line cap for that selected range, not a wider selector. `get`, `list`, and `search` can also read legacy `.claude-token-optimizer/artifacts` receipts.
- **Task memory** explicitly stores stable, secret-free task context in owner-private authenticated project storage. Opaque `contextguard-memory:` handles disclose neither paths nor content. Every bounded `get` revalidates the physical project, Git revision/worktree, task, source digests, expiry, modes, links, quotas, content digest, and authentication before writing content to stdout. It is provider-free and makes no token/cost savings guarantee.
- **Budgeted context packer** assembles prioritized local file evidence into a rendered byte-budgeted Markdown pack with included/partial/omitted source metadata, bounded `.context-guard/packs` receipts, exact sanitized `slice` commands when safe, and `retrieval_omitted_reason` when a path/root should not be echoed. The additive `auto` subcommand runs that recommendation and pack build in one step, and `auto --explain` adds compact deterministic local selection/build reasons without changing the manifest, pack body, receipt, or byte budget. JSON explain also includes bounded repo-map metadata: sampled byte/token-proxy tree entries, category-only secret-risk counts, signature-first hints, explain-only graph ranks, and exact `slice`/symbol retrieval hints. `suggest` remains available to rank local query, diff, explicit file, and sanitized output/test-output signals into a build-compatible manifest without network, model, embedding, or provider-cost calls. `suggest/auto --adaptive-k` adds advisory-only shrink/expand top-k metadata from local score distribution, byte-budget fit, and clamped score-mass recall/precision proxies. `--adaptive-k-policy balanced|recall|precision` plus optional recall/precision proxy gates selects the local recommendation policy; gate failures are metadata-only. The adaptive block includes capped selected/omitted evidence and structured source-verification hints, and it never applies the recommendation automatically or changes the manifest, pack body, receipt, or byte budget. `auto --symbol-memory` adds repo-map-derived symbol/graph advisory metadata with exact `slice`/`read-symbol` verification hints and still does not change selection or pack output. Explicit `auto --apply-symbol-memory` instead adds at most four safe direct import-neighbor slices, keeps explicit/query seeds at higher priority, excludes secret-risk neighbors, and rebuilds within the same byte budget while retaining exact fallback and a closed `graph_application` record. Token counts are estimated `chars_div_4` proxies, not measured provider-token savings.
- `auto --self-financing-selection` is the default-off composed path: Adaptive first, then task-matching Symbol slices, then bounded one-hop Graph neighbors under the frozen ordinary-pack byte ceiling. It never displaces caller/critical sources and records frozen identity, secret decision, byte delta, exact fallback, replacement removals, or an honest no-op for every candidate. It makes no provider savings claim.
- `auto --selection-plan --json` emits only a provider-free, read-only closed plan from the query, diff, output/log, symbol, and self-financing inputs. Save it explicitly and pass the same inputs with `--apply-selection-plan PATH` to apply it. Apply recomputes the plan and revalidates source identities before output; incomplete scans, secret-risk or scorer/private inputs, drift, unsafe output boundaries, and missing exact recovery fail closed.

```bash
context-guard-pack auto --root . --query "fix retry" --diff worktree --output logs/test.txt --json --selection-plan > selection-plan.json
context-guard-pack auto --root . --query "fix retry" --diff worktree --output logs/test.txt --json --apply-selection-plan selection-plan.json --no-artifact
```
- **Tool/MCP schema pruner** ranks local tool catalogs into bounded top-k advisory reports while preserving full sanitized schema fallback through compact receipts and payload integrity checks. `defer-report` additionally separates core inline tools from deferred stubs/namespaces and reports gross deferred-schema plus net initial-report char/4 proxy accounting; full schemas still must be retrieved before deferred tool use.
- **Applied adaptive breadth** is available only through explicit `auto --apply-adaptive-k`. It prunes heuristic-selected sources after local regression gates pass, always retains caller-declared file/output/test-output and diff sources, rebuilds within the same byte budget, and records `adaptive_k_application`; local proxies do not authorize provider-token or cost-savings claims.
- **Conservative compressor** classifies sanitized stdin as JSON, diff, log, search output, code, or prose and shrinks it with observed byte evidence plus estimated token proxies. Add `--protected-policy` for opt-in protected-zone class/count metadata that denies semantic rewrites for code fences, diffs, identifiers, numeric constants, hashes, paths, stack frames, quoted strings, and JSON keys while preserving exact-retrieval guidance. Add `--mode readable` only for sanitized prose previews: it uses deterministic sentence windows, blocks prompt-like/high-risk protected signals, stores no raw protected spans, and does not run learned compressors, models, embeddings, or rerankers.
- **Static cache-score lint plus Anthropic cost guard and route advisor** provides `context-guard-cache-score` for local prompt/request cache layout checks, with optional user-supplied cache write/read multiplier amortization risk, and `context-guard cost preflight/observe/ledger/compile` for passive pre-call estimates, provider-usage reconciliation, keyed-HMAC cache-risk history, and stable-prefix layout advice. `context-guard-receipt evaluate full-wire` compares a bounded canonical baseline/candidate request envelope under one canonical-byte ceiling, preserves selected JSON pointers and output-token budgets, and emits no request content. `context-guard route-advisor` is a local-only passive advisor for caller-supplied workload JSON, provider feature declarations, usage telemetry, and shifted external/local costs; it emits total-cost accounting, batchability blockers, and route candidates without starting a queue, calling providers, refreshing pricing docs, or treating provider feature knowledge as authoritative. It stores no raw prompt text, does not replace Anthropic/provider prompt caching, and its recommendations are not hosted token/cost savings claims without matched successful tasks, non-inferior quality evidence, and shifted-cost accounting.
- **Net-efficiency P0-P2 contracts** add local `net-efficiency`, `fanout-plan`,
  `prefix-plan`, `prune-plan`, and `shadow-policy` evaluation plus a task-scoped
  read-only `receipt_batch` MCP call. They remain provider-free and shadow-only,
  add no shell or network authority, and require quality-safe matched evidence.
- **Output trimmer** preserves the wrapped command exit code, trims long logs, and can emit `--digest markdown` or `--digest json` summaries with runner failure facts, sanitized failure signatures, duplicate-line groups, and suggested next queries. Add `--artifact-receipt` with digest mode to store the exact sanitized full output as a local artifact receipt; keep the `contextguard-artifact:<id>` handle and re-expand omitted slices with emitted `context-guard-artifact receipt/get/search ...` commands.
- **Sanitizer** redacts common credential patterns, private key blocks, auth headers, credential URLs, and sensitive-looking paths from search, diff, and log output.
- **Statusline** displays compact model/context/cost signals and, when transcript data is available, cache-read and cache-reuse signals.
- **Transcript audit** aggregates usage/cost/cache buckets, flags likely token hotspots, and exposes `cache_friendliness`, additive [`cache_diagnostics`](https://github.com/ictechgy/context-guard/blob/main/docs/cache-diagnostics-schema.md), and `cache_layout_advice` experiment priorities from bounded usage fields, timestamped cache telemetry records, and redacted segment hashes without printing raw prompt text or claiming provider-cache savings.
- **Repeated-failure nudge** warns after repeated Bash failures so the agent switches strategy instead of retrying the same context-heavy path.
- **Benchmark helper** records matched baseline/variant runs with real token and cost fields, separate byte-reduction proxy evidence, diagnostic `wall_time_seconds`, `provider_cached_tokens`, provider-cache availability telemetry, a report-level measurement-baseline contract, file-backed `variant_prompt_files`, and optional per-run `self_hosted_metrics` JSONL ledger sidecars that stay out of hosted API savings claims.

### Exact Claude Read surface

The installed guard is a Claude Code `PreToolUse` hook with matcher `Read`. When selected, setup removes only the exact legacy deny values `Read(./.env)` and `Read(./.env.*)` while preserving similar entries and their relative order. The hook checks bounded large-file ranges and denies root or nested paths whose basename begins `.env`, except the exact template names `.env.example`, `.env.sample`, and `.env.template`; ambiguous symlink paths fail closed. `Glob` can still list names. `Grep` and `Bash` can read file contents and are outside this hook. This is not universal `.env` or Bash protection.

The hook opens without following symlinks and revalidates identity, size, and modification time on that descriptor. Claude performs the actual `Read` with a separate open after the hook returns, so replacement during that post-hook window remains a documented TOCTOU limitation.

Cost guard creates its local HMAC key automatically at `.context-guard/cost-ledger/hmac.key`. If you provision that file yourself, it must contain exactly one canonical URL-safe base64 32-byte key with required padding and no trailing newline or whitespace. Reports never emit the key or raw prompt text, and the local ledger does not replace Anthropic/provider prompt caching.

## Brief mode (advisory)

Brief mode ships agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels — `lite`, `standard`, `ultra` — live under [`brief/`](brief/). Each is a single marker-delimited block for an agent's rule/instruction file (such as `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions). Use `context-guard setup --agent codex --scope project --brief-mode standard --plan`, apply with `--yes`, and remove with `--brief-mode off`. See [`brief/README.md`](brief/README.md).

## Quiet narration for Claude (advisory)

Quiet narration is a separate, default-off Claude-only rule that suppresses discretionary preambles, per-tool narration, filler, and repeated interim summaries while preserving approvals and decisions, blockers, failures, destructive or security warnings, required progress, the final result, changed files, and verification.

```bash
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --plan
context-guard setup --rules-only --agent claude --scope project --narration-mode quiet --yes
context-guard setup --rules-only --agent claude --scope project --narration-mode default --yes
```

The isolated operation manages only ContextGuard's narration span in project `CLAUDE.md`; it does not read or change settings, hooks, or other agents' files and cannot be combined with normal setup actions. The rule is best-effort, independent of final-answer brevity or reasoning depth, and Gate C makes no model-compliance or savings claim.

## Conservative claims

These helpers reduce common sources of context bloat, but they do not guarantee a fixed percentage savings. Use `context-guard-bench --ledger-jsonl ... --report-json ... --dashboard-md ...` when you need measured before/after evidence for your own tasks; add `--evidence-jsonl ...` only for deterministic local replay that remains non-claim-eligible unless provider-export provenance is complete; token-savings claims require `primary_tokens_measured` on both matched sides, and the report's `matched_pair_evidence` links each successful baseline/variant task bucket to the transform, quality gate, measurement availability, and claim boundary. The report's `default_matrix` classifies trimming, artifact escrow, tool pruning, cache advice, adaptive-k, and optional compression as `default-on`, `advisory`, `experimental`, or `reject/rework` from that evidence, but it is reporting-only and does not change runtime defaults or authorize hosted savings claims. The report's `public_claim_readiness` is the authoritative release/public-claim gate: matched successful tasks, provider-measured primary tokens/cost, quality non-inferiority, shifted-cost accounting, explicit confidence/failure notes, and complete provider-export provenance must all pass before `claim_allowed=true`; unsupported hosted savings claims are forbidden otherwise. Wall-time/provider-cache fields are diagnostic telemetry, not standalone savings proof. Audit `cache_friendliness`, [`cache_diagnostics`](https://github.com/ictechgy/context-guard/blob/main/docs/cache-diagnostics-schema.md), and `cache_layout_advice` findings are heuristic layout/cache-read signals and ranked checks/experiments with observed/inferred/hypothesis/unavailable boundaries, not billing authority or provider-cache proof. Benchmark CSV schemas are strict, so start a new CSV or migrate the header after helper upgrades. Workflow-specific synthetic examples live in [`docs/benchmark-workflow-examples.md`](https://github.com/ictechgy/context-guard/blob/main/docs/benchmark-workflow-examples.md), and fixture-only experimental task/variant starters live in [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md).

ContextGuard also does not send work to external AI providers to save model tokens. All helper commands run locally. Local RAM/disk receipts can reduce what you choose to send, but they do not replace a provider prompt cache. Before release or billing claims for Anthropic, recheck the official prompt-caching and pricing docs: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.

Future learned, multimodal, and self-hosted optimization ideas are tracked in [`research/experimental-token-reduction-radar.md`](https://github.com/ictechgy/context-guard/blob/main/research/experimental-token-reduction-radar.md), with fixture-only starters in [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md). That radar and those fixtures do not claim hosted API savings without provider-measured matched-task evidence; the shipped experimental surfaces and their boundaries are documented in [`docs/experiments.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experiments.md). The radar's later-roadmap gates keep neural/semantic compression, trust-tiered injection-aware compression, generated visual-token reduction, and broader local proxy forwarding constraints experimental/non-shipped until a separate future PR satisfies those gates.

## Experimental features

All experimental planners are off by default, plan-only, and documented in [`docs/experiments.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experiments.md).

Cross-agent rule snippets are advisory: the target agent may ignore them, so measure actual before/after behavior when you need a savings claim.

## Local MCP adapter

`context-guard mcp` and `context-guard-mcp` launch a dependency-free local stdio MCP child process. A process is isolated to one root and namespace and exposes only sanitized compression, sanitized exact artifact fallback, and local statistics. It has no HTTP, network, provider, model, or proxy integration and never mutates client configuration. Artifacts are inaccessible across namespaces; no hosted token/cost savings are claimed.

The installed Receipt companion can also be launched explicitly as
`context-guard-receipt-mcp --root /absolute/repository`. Its
`receipt_context` tool stores one explicitly eligible relative file or log as a
compact process-local exact reference when the conservative byte router finds
that beneficial, reuses the live reference, and reads exact slices of at most
65,536 bytes. Optional task scopes and explicit release provide process-local
context GC; content-free history stores only keyed digests and decisions.
`receipt_diagnose` exposes non-applying firewall/router and prefix-reuse
scout/surgeon advice. `receipt_pack` builds a caller-ordered bounded multi-file
pack only from prior `receipt_context` capabilities bound to the same required
task scope, while task-scoped
`receipt_tool_select` profiles reuse one stable catalog bundle and reject
drift. An explicit private `--state-dir` enables only the
authenticated advisory `receipt_twin`. It does not auto-register, intercept
prompts, persist capabilities across restart, call a provider, or make a hosted
savings claim.

## Local test before publishing

From the marketplace repository root:

```bash
claude --plugin-dir ./plugins/context-guard
```

Then run inside Claude Code:

```text
/context-guard:setup
```

Marketplace installation test:

```text
/plugin marketplace add ./
/plugin install context-guard@context-guard
```

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
