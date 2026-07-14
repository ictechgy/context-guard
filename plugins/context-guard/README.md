# ContextGuard

ContextGuard is a local-first context management toolkit for AI coding and tool-using agents. It starts as a Claude Code plugin, then extends the same project-local guardrails to other agents through plain local helper commands and advisory brief-mode rule snippets.

Start with `/context-guard:setup`. Setup is explicit, project-local, and reversible: it merges recommended project settings, prints a read-only context management scan, does not mutate global Claude settings, and does not configure offloading to external AI services.

## Token-waste paths it targets

ContextGuard is a local context management layer, not a provider prompt cache or semantic answer cache. Its helpers reduce avoidable context bloat before it enters an agent conversation: large file reads are steered toward search/symbol/line-range slices, long command output can be trimmed or digested, large logs can be stored as local artifact receipts, secret-like values are redacted on a best-effort basis, repeated Bash failures trigger a strategy nudge, cache-friendly prompt layout can be audited from bounded redacted segment hashes, and audit/benchmark evidence stays tied to your own tasks.

## Rebrand note

Claude Code does not alias the old `/claude-token-optimizer:*` plugin slash-command namespace. Use `/context-guard:*` after installing this plugin.

Legacy local CLI wrappers (`claude-token-*`, `claude-read-symbol`, `claude-trim-output`, and `claude-sanitize-output`) remain in `bin/` so existing automation can migrate gradually.

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
context-guard-compress --json < large-output.txt
context-guard-compress --json --protected-policy < evidence.txt
context-guard-compress --json --type prose --mode readable < sanitized-prose.txt
context-guard cost preflight --request request.json --budget-krw 3000 --json
context-guard cost observe --usage usage.json --json
context-guard route-advisor --workload workload.json --json
context-guard-trim-output --max-lines 120 -- npm test
context-guard-read-symbol path/to/file.py TargetSymbol
context-guard-sanitize-output -- rg -n "TOKEN|SECRET" .
context-guard-sanitize-output -- git diff
context-guard-filter validate --config .context-guard/filter-dsl.json
context-guard-filter run --config .context-guard/filter-dsl.json -- git status --short
context-guard-pack auto --root . --query "review failing tests" --diff HEAD --manifest-out suggested-pack.json --pack-out context-pack.md --budget-bytes 12000 --json --explain --adaptive-k --adaptive-k-policy recall --symbol-memory
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

Opt-in `build`/`auto --sketch-duplicate-veto` applies a rank-stable pre-budget gate to sanitized slices; `suggest` stays unchanged. Exact digest candidates are byte-confirmed. The approximate gate is sketch-set Jaccard over frozen Unicode-casefolded ordered five-token shingles: bottom 64 unique digests, minimum 12 on both sides, inclusive 0.90. Short sketches are exact-only. After 100,000 verified eligible pairs, the first skipped pair fails open and later work is digest-only. A winner may not render under the final budget, so use the omitted source's own exact retrieval before editing or relying on it. Only `sketch_duplicate_source`, standalone build/`auto.build` `sketch_duplicate_veto.comparison_cap_reached`, and flagged text `sketch_comparison_cap_reached=true|false` are observable, even when receipt storage fails. No fingerprint, match identity, overlap, score, provider token/cost savings claim is emitted; flag-off behavior is compatible.

- **Setup wizard** merges `.claude/settings.json` instead of replacing it, then prints a read-only `context-guard-diet scan` summary. Use `context-guard doctor` or `context-guard setup --verify` for a read-only health check before applying setup; use `--no-diet-scan` when automation needs setup output without the post-apply scan. `PATH` helper fallback is default-off and requires `--allow-path-helper-fallback` plus identity validation.
- **Context management scanner** checks missing `permissions.deny` guardrails, Bash trim hook/statusline setup, broad read allows, high default model/effort, many MCP servers, large or secret-like agent rule files, and advisory context-exclusion recommendations for bulky/sensitive local paths. Its `--top` cap applies to both context-like files and context-exclusion recommendations.
- **Structural-waste doctor** is an opt-in read-only `context-guard-diet structural-waste` report for duplicate rule units, stale Python import candidates, unused skill candidates, excessive MCP/tool schema catalogs, and repeated file reads or duplicate tool calls in local JSON/JSONL logs. It does not mutate config, call the network, or print raw prompt/tool-input text; low-confidence import/skill findings are review prompts, not delete instructions.
- **Large-read guard and symbol reader** guide the agent from search to symbol slices to small line ranges before attempting a whole-file read. Supported source slices include Python, JavaScript/TypeScript, Go, and Rust.
- **Declarative output filter** validates user-owned JSON filter files outside package code and applies the first matching line filter only as an explicit `run --config ... -- <command>` wrapper. Invalid configs, no-match commands, filter errors, empty filtered output, and protected `git`/test/lint/`gh` command failures preserve original stdout/stderr and exit code. Filtered mode applies line rules to combined stdout+stderr and writes the filtered result to stdout; `--json-report` diagnostics go to stderr, except protected nonzero passthrough suppresses reports to keep stderr raw. It is local and opt-in, with no savings guarantee.
- **Artifact store** saves large sanitized command output under `.context-guard/artifacts` by default and returns compact receipts, local sandbox search results, or exact requested slices. JSON receipts include line-numbered top errors, duplicate-line groups, sanitized bounded suggested queries, and an `output_sandbox` envelope with a stable `contextguard-artifact:<id>` handle. `receipt <artifact_id> --json` rehydrates metadata-only handles without content. `search` scans sanitized local artifacts by literal substring, emits capped match/context records, and includes `get --lines START:END` rehydration commands without hosted token/cost savings claims. Custom `--dir` raw paths stay redacted by default; reuse the same `--dir` or opt into `search --show-paths` for a directly executable local command. In suggested `--lines START:END` queries, `--max-lines` is only the returned-line cap for that selected range, not a wider selector. `get`, `list`, and `search` can also read legacy `.claude-token-optimizer/artifacts` receipts.
- **Budgeted context packer** assembles prioritized local file evidence into a rendered byte-budgeted Markdown pack with included/partial/omitted source metadata, bounded `.context-guard/packs` receipts, exact sanitized `slice` commands when safe, and `retrieval_omitted_reason` when a path/root should not be echoed. The additive `auto` subcommand runs that recommendation and pack build in one step, and `auto --explain` adds compact deterministic local selection/build reasons without changing the manifest, pack body, receipt, or byte budget. JSON explain also includes bounded repo-map metadata: sampled byte/token-proxy tree entries, category-only secret-risk counts, signature-first hints, explain-only graph ranks, and exact `slice`/symbol retrieval hints. `suggest` remains available to rank local query, diff, explicit file, and sanitized output/test-output signals into a build-compatible manifest without network, model, embedding, or provider-cost calls. `suggest/auto --adaptive-k` adds advisory-only shrink/expand top-k metadata from local score distribution, byte-budget fit, and clamped score-mass recall/precision proxies. `--adaptive-k-policy balanced|recall|precision` plus optional recall/precision proxy gates selects the local recommendation policy; gate failures are metadata-only. The adaptive block includes capped selected/omitted evidence and structured source-verification hints, and it never applies the recommendation automatically or changes the manifest, pack body, receipt, or byte budget. `auto --symbol-memory` adds repo-map-derived symbol/graph advisory metadata with exact `slice`/`read-symbol` verification hints and still does not change selection or pack output. Token counts are estimated `chars_div_4` proxies, not measured provider-token savings.
- **Tool/MCP schema pruner** ranks local tool catalogs into bounded top-k advisory reports while preserving full sanitized schema fallback through compact receipts and payload integrity checks. `defer-report` additionally separates core inline tools from deferred stubs/namespaces and reports gross deferred-schema plus net initial-report char/4 proxy accounting; full schemas still must be retrieved before deferred tool use.
- **Conservative compressor** classifies sanitized stdin as JSON, diff, log, search output, code, or prose and shrinks it with observed byte evidence plus estimated token proxies. Add `--protected-policy` for opt-in protected-zone class/count metadata that denies semantic rewrites for code fences, diffs, identifiers, numeric constants, hashes, paths, stack frames, quoted strings, and JSON keys while preserving exact-retrieval guidance. Add `--mode readable` only for sanitized prose previews: it uses deterministic sentence windows, blocks prompt-like/high-risk protected signals, stores no raw protected spans, and does not run learned compressors, models, embeddings, or rerankers.
- **Static cache-score lint plus Anthropic cost guard and route advisor** provides `context-guard-cache-score` for local prompt/request cache layout checks, with optional user-supplied cache write/read multiplier amortization risk, and `context-guard cost preflight/observe/ledger/compile` for passive pre-call estimates, provider-usage reconciliation, keyed-HMAC cache-risk history, and stable-prefix layout advice. `context-guard route-advisor` is a local-only passive advisor for caller-supplied workload JSON, provider feature declarations, usage telemetry, and shifted external/local costs; it emits total-cost accounting, batchability blockers, and route candidates without starting a queue, calling providers, refreshing pricing docs, or treating provider feature knowledge as authoritative. It stores no raw prompt text, does not replace Anthropic/provider prompt caching, and its recommendations are not hosted token/cost savings claims without matched successful tasks, non-inferior quality evidence, and shifted-cost accounting.
- **Output trimmer** preserves the wrapped command exit code, trims long logs, and can emit `--digest markdown` or `--digest json` summaries with runner failure facts, sanitized failure signatures, duplicate-line groups, and suggested next queries. Add `--artifact-receipt` with digest mode to store the exact sanitized full output as a local artifact receipt; keep the `contextguard-artifact:<id>` handle and re-expand omitted slices with emitted `context-guard-artifact receipt/get/search ...` commands.
- **Sanitizer** redacts common credential patterns, private key blocks, auth headers, credential URLs, and sensitive-looking paths from search, diff, and log output.
- **Statusline** displays compact model/context/cost signals and, when transcript data is available, cache-read and cache-reuse signals.
- **Transcript audit** aggregates usage/cost/cache buckets, flags likely token hotspots, and exposes `cache_friendliness`, additive [`cache_diagnostics`](https://github.com/ictechgy/context-guard/blob/main/docs/cache-diagnostics-schema.md), and `cache_layout_advice` experiment priorities from bounded usage fields, timestamped cache telemetry records, and redacted segment hashes without printing raw prompt text or claiming provider-cache savings.
- **Repeated-failure nudge** warns after repeated Bash failures so the agent switches strategy instead of retrying the same context-heavy path.
- **Benchmark helper** records matched baseline/variant runs with real token and cost fields, separate byte-reduction proxy evidence, diagnostic `wall_time_seconds`, `provider_cached_tokens`, provider-cache availability telemetry, a report-level measurement-baseline contract, file-backed `variant_prompt_files`, and optional per-run `self_hosted_metrics` JSONL ledger sidecars that stay out of hosted API savings claims.

Cost guard creates its local HMAC key automatically at `.context-guard/cost-ledger/hmac.key`. If you provision that file yourself, it must contain exactly one canonical URL-safe base64 32-byte key with required padding and no trailing newline or whitespace. Reports never emit the key or raw prompt text, and the local ledger does not replace Anthropic/provider prompt caching.

## Brief mode (advisory)

Brief mode ships agent-neutral, advisory rule snippets that ask a coding agent to cut filler while preserving evidence: file paths, commands, command output and errors, code blocks, verification status, changed files, known gaps, and caveats. It is best-effort guidance, not enforcement, and does **not** guarantee any token or cost savings.

Three deterministic levels — `lite`, `standard`, `ultra` — live under [`brief/`](brief/). Each is a single marker-delimited block for an agent's rule/instruction file (such as `AGENTS.md`, `CLAUDE.md`, a Cursor rules file, or Copilot instructions). Use `context-guard setup --agent codex --scope project --brief-mode standard --plan`, apply with `--yes`, and remove with `--brief-mode off`. See [`brief/README.md`](brief/README.md).

## Conservative claims

These helpers reduce common sources of context bloat, but they do not guarantee a fixed percentage savings. Use `context-guard-bench --ledger-jsonl ... --report-json ... --dashboard-md ...` when you need measured before/after evidence for your own tasks; add `--evidence-jsonl ...` only for deterministic local replay that remains non-claim-eligible unless provider-export provenance is complete; token-savings claims require `primary_tokens_measured` on both matched sides, and the report's `matched_pair_evidence` links each successful baseline/variant task bucket to the transform, quality gate, measurement availability, and claim boundary. The report's `default_matrix` classifies trimming, artifact escrow, tool pruning, cache advice, adaptive-k, and optional compression as `default-on`, `advisory`, `experimental`, or `reject/rework` from that evidence, but it is reporting-only and does not change runtime defaults or authorize hosted savings claims. The report's `public_claim_readiness` is the authoritative release/public-claim gate: matched successful tasks, provider-measured primary tokens/cost, quality non-inferiority, shifted-cost accounting, explicit confidence/failure notes, and complete provider-export provenance must all pass before `claim_allowed=true`; unsupported hosted savings claims are forbidden otherwise. Wall-time/provider-cache fields are diagnostic telemetry, not standalone savings proof. Audit `cache_friendliness`, [`cache_diagnostics`](https://github.com/ictechgy/context-guard/blob/main/docs/cache-diagnostics-schema.md), and `cache_layout_advice` findings are heuristic layout/cache-read signals and ranked checks/experiments with observed/inferred/hypothesis/unavailable boundaries, not billing authority or provider-cache proof. Benchmark CSV schemas are strict, so start a new CSV or migrate the header after helper upgrades. Workflow-specific synthetic examples live in [`docs/benchmark-workflow-examples.md`](https://github.com/ictechgy/context-guard/blob/main/docs/benchmark-workflow-examples.md), and fixture-only experimental task/variant starters live in [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md).

ContextGuard also does not send work to external AI providers to save model tokens. All helper commands run locally. Local RAM/disk receipts can reduce what you choose to send, but they do not replace a provider prompt cache. Before release or billing claims for Anthropic, recheck the official prompt-caching and pricing docs: https://docs.anthropic.com/en/build-with-claude/prompt-caching and https://platform.claude.com/docs/en/about-claude/pricing.

Future learned, multimodal, and self-hosted optimization ideas are tracked in [`research/experimental-token-reduction-radar.md`](https://github.com/ictechgy/context-guard/blob/main/research/experimental-token-reduction-radar.md), with fixture-only starters in [`docs/experimental-benchmark-fixtures.md`](https://github.com/ictechgy/context-guard/blob/main/docs/experimental-benchmark-fixtures.md). ContextGuard ships dry-run planners/checkers for a plan-only `image-context-pack` evaluation gate, local-proxy advisory plans, and design-only external-forwarding gates, plus narrow explicit local runtimes for caller-supplied context-diff replacement payloads, caller-supplied visual crop/OCR evidence packs, caller-supplied learned-compression prose candidates, self-hosted metrics JSONL sidecar records, local-proxy runtime-gate JSONL records, one-shot `serve local-proxy` loopback forwarding with a private ready-file nonce, optional `--response-sandbox` compact artifact envelopes for safe UTF-8 responses, and optional shifted-cost diagnostic JSONL rows for successful forwarded requests. Learned/synthetic compressor execution beyond the caller-supplied candidate emitter, embeddings, rerankers, model calls, generated replacement text, screenshot capture, image cropping, OCR execution, image parsing, external OCR/image services, output-file evidence writes, generated image-context-pack renderers, binary/image artifact fallback, pxpipe-style proxy/runtime, self-hosted KV/latent runtime optimization beyond explicit local metrics recording, and external/daemon/hostname-DNS, credential-bearing, or external proxy forwarding beyond literal-loopback one-request HTTP forwarding are not shipped. That radar and the fixtures do not claim hosted API savings without provider-measured matched-task evidence. The radar's later-roadmap gates also keep neural/semantic compression, trust-tiered injection-aware compression, generated visual-token reduction, and broader local proxy forwarding constraints experimental/non-shipped until a separate future PR satisfies those gates.

## Experimental opt-ins

Experimental lanes are default off. The registry is project-local metadata only; enabling an experiment records intent in `.context-guard/experiments.json` and does not activate stable runtime behavior by itself.

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

`image-context-pack` is a plan-only/dry-run gate for pxpipe-inspired image/context packing evaluation. It requires exact text artifact fallback, protected-zone denial, provider-boundary acknowledgement for provider-measured matched tasks, missed-context guardrails, and acknowledgement in the plan output that `visual-crop-ocr` is the existing caller-supplied visual evidence-pack surface. It does not render images, run OCR, call models/providers, proxy traffic, store binary artifacts, emit replacement evidence, or support hosted token/cost savings.

`semantic-checkpoint` is a plan-only/eval-only gate for reviewable task-state checkpoint planning. Its flags are optional at the CLI so incomplete dry runs can return JSON, but readiness remains blocked in the JSON payload until the plan includes a goal, exact fallback receipt, local re-expand command, provider-boundary acknowledgement, protected-zone policy `deny`, missed-context note, and provenance review note. `--missing-provenance-note` can be a review acknowledgement such as `none known after review`; allowed local re-expand shapes are `context-guard-artifact get <id> --full` and `context-guard artifact get <id> --full`. It has no `emit`, `record`, or `serve` runtime, no new `context-guard-semantic-checkpoint` binary, writes no files, edits no transcript or prompt, calls no model/provider/network, emits no replacement context, and makes no hosted token/cost savings claim.

`plan proof-carrying-context` is the default-off plan-only proof-envelope metadata readiness gate. It accepts bounded repeatable inline JSON and validates syntax/defined consistency only; caller timestamps are preserved without current-time generation or freshness checks. Protected-zone policy is declared-only, while range bounds, receipt storage, source content, SHA-256, timestamp freshness, and rehydration stay unchecked and visible as warnings. This plan command reads no source/artifact/config/stdin content, writes no files, invokes no model/provider/network/subprocess, generates or replaces no context (`candidate_replacement` is always `null`), exposes no `emit`/`record`/`serve` runtime or new binary, and makes no hosted token/cost savings claim without provider-measured matched successful tasks.

`verify proof-carrying-context` is the separate read-only local verifier. Its documented fixture is the exact UTF-8 string `ContextGuard proof fixture\n` (27 bytes, one line), SHA-256 `12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14`. It uses one explicit artifact directory, performs no fallback search, follows no symlink, and requires effective-user ownership plus directory mode `0700` and both receipt leaves with mode `0600`. It reads the complete bounded file for receipt/proof SHA, byte/line, and range-bounds verification but never retrieves or echoes range content. Exit `0` means only local bindings passed and exit `2` means verification failed; timestamp freshness and protected-zone semantics stay unchecked, rehydrate commands are syntax/receipt checked but never executed, `candidate_replacement` stays `null`, and no replacement, omission, or hosted-savings authority is granted.

Use `--config <path>` only for an explicit project-local override. Registry entries include risk, gate requirements, explicit command/flag surfaces, and claim boundaries; hosted API token/cost savings still require provider-measured matched-task evidence. The registry can discover existing explicit-flag experiments such as `context-guard-trim-output --digest ... --artifact-receipt` and `context-guard-compress --protected-policy`, run dry-run advisory planners such as `context-guard experiments plan context-diff-compaction`, `context-guard experiments plan visual-crop-ocr`, `context-guard experiments plan learned-compression`, `context-guard experiments plan semantic-checkpoint`, `context-guard experiments plan self-hosted-metrics-ledger`, `context-guard experiments plan local-proxy`, and design-only `context-guard experiments plan local-proxy-external-forwarding`, and run explicit local runtimes such as `context-guard experiments emit context-diff-compaction ...`, `context-guard experiments emit visual-crop-ocr ...`, `context-guard experiments emit learned-compression ...`, `context-guard experiments record self-hosted-metrics-ledger ...`, `context-guard experiments record local-proxy-runtime-gate ...`, `context-guard experiments serve local-proxy ...`, and successful-forward `context-guard experiments serve local-proxy --diagnostic-ledger-jsonl ...` diagnostics. The context-diff emit runtime only emits caller-supplied compact replacements when reviewable hunks, exact local artifact re-expand metadata whose stored content matches the input diff, and a smaller replacement are present; it does not generate semantic compression or permit hosted savings claims. The visual lane ships a dry-run planner plus an explicit local evidence-pack emitter: both use only caller-supplied full-evidence receipts, crop metadata, OCR text, confidence/error notes, and missed-context notes; screenshot capture, image cropping, OCR execution, image parsing, external OCR/image services, output-file writes, and hosted savings claims are not shipped. The learned-compression lane ships a deny-by-default dry-run policy check plus an explicit local candidate emitter for caller-supplied compact prose with verified exact fallback content: learned/synthetic compressor execution, embeddings, rerankers, model calls, subprocesses, external services, generated replacement text, and hosted savings claims are not shipped. The semantic-checkpoint lane ships only the plan/eval gate above: no runtime emit/record/serve surface, file-writing checkpoint store, transcript/prompt edit, provider/model/network-backed checkpointing, replacement context, new binary, or hosted savings claim is shipped. The self-hosted metrics planner emits a dry-run ledger-compatible preview for explicit local/model-server latency, memory, quality, energy, throughput, and local-cost metrics; the dry-run preview does not write a ledger, while `context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl ...` writes only local JSONL sidecars and still does not permit hosted API token/cost savings claims. The local-proxy planner emits localhost-only advisory metadata only, while `context-guard experiments record local-proxy-runtime-gate --ledger-jsonl ...` appends one local gate row only after localhost-only metadata and `--runtime-gate-ack`: it starts no listener, forwards no traffic, and performs no DNS lookup. `context-guard experiments serve local-proxy ...` is the separate forwarding MVP: it requires `--forwarding-gate-ack --once`, a private `--ready-file` nonce handoff, literal loopback bind/target IPs, no hostname DNS targets, nonzero ports, byte/time limits, and credential-free requests; it performs no external forwarding, no CONNECT/TLS proxying, no API-key persistence, and no hosted-savings claim. `--response-sandbox` can store safe UTF-8 response text as a sanitized local artifact receipt and return a compact envelope with redacted rehydration command templates; it does not claim hosted token/cost savings. `--diagnostic-ledger-jsonl` writes one shifted-cost diagnostic row only after a successful forwarded request, with no raw headers/bodies and no hosted-savings evidence. `plan local-proxy-external-forwarding` emits threat-model/allowlist/redaction/provider-evidence design metadata only and still starts no listener, performs no DNS lookup, calls no external service, forwards no traffic, persists no credentials, and does not ship an external proxy forwarding runtime. `experiments enable` records intent only; it does not run those helpers, remove the need for their explicit flags, or permit replacing content without exact receipt/re-expand evidence.

Cross-agent rule snippets are advisory: the target agent may ignore them, so measure actual before/after behavior when you need a savings claim.

## Local MCP adapter

`context-guard mcp` and `context-guard-mcp` launch a dependency-free local stdio MCP child process. A process is isolated to one root and namespace and exposes only sanitized compression, sanitized exact artifact fallback, and local statistics. It has no HTTP, network, provider, model, or proxy integration and never mutates client configuration. Artifacts are inaccessible across namespaces; no hosted token/cost savings are claimed.

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

### Experimental semantic-GC plan gate

`semantic-gc` is a default-off, deny-only, plan-review gate over a caller-declared graph. Default-off describes registry intent; the explicit plan CLI remains invocable and never enables omission or runtime action. Graph evaluation is suppressed when the complete envelope or topology is ambiguous. Unreachable nodes are review candidates, not proof of semantic irrelevance: omission and runtime action remain unauthorized. Candidate missed-context notes are untrusted. The planner does not read context/artifact content or verify provenance, fallback, providers, or hosted savings. Exit 0 means only `ready_for_plan_review`; it is never delete/omit authority.

context-guard experiments plan semantic-gc --json --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"root","references":[],"is_root":true,"protected_zone":false}' --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"orphan","references":[],"is_root":false,"protected_zone":false,"content_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provenance":{"source_label":"canonical-example","receipt_id":"0123456789abcdef"},"missed_context_note":"A reviewer could lose the orphaned rationale.","exact_fallback_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --human-review-ack --protected-zone-policy deny

`static-relevance` is a default-off compiler for bounded caller-supplied static evidence. Missing signals suppress all slices and review ordering; accepted empty edge lists are declarations, not verified observations. Built-in protected-path matches and explicit protected reasons are hard retention vetoes that move evidence first for human review only. This plan-review-only command does not scan or read any repository, does not invoke git, and does not invoke a parser, provider, network, or subprocess. Its deterministic review order does not authorize omission, deletion, deprioritization, replacement, or runtime action.

context-guard experiments plan static-relevance --json --relevance-unit-json '{"schema":"contextguard.static-relevance-unit.v1","unit_id":"src/cli.py::main","path":"src/cli.py","task_anchor":true,"protection_reasons":[],"symbol":{"name":"main","kind":"function","start_line":1,"end_line":40},"symbol_references":[],"dataflow_predecessors":[],"dataflow_successors":[],"git":{"blame_age_days":2,"blame_contributor_count":1,"path_change_count_90d":3}}' --protected-path-policy deny --provider-boundary-ack

## License

Copyright 2026 jinhongan. Licensed under the Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
