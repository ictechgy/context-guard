# Experimental Token-Reduction Radar

ContextGuard's shipped helpers reduce avoidable local context bloat before an AI coding agent sees it. This radar tracks **optional future experiments** that may reduce prompt size, multimodal payloads, or self-hosted inference overhead, but nothing here is a shipped runtime feature or a hosted API savings claim.

## Non-claims

- These lanes do **not** guarantee hosted API token or cost savings.
- Byte, image, OCR, or cache-memory reductions are proxy evidence until matched successful tasks show provider-measured token/cost improvement.
- Self-hosted KV-cache, attention, or latent optimizations are memory/latency techniques for inference stacks you control; they are **not hosted API token-savings claims** unless a provider reports token/cost deltas attributable to an integration.
- ContextGuard will not send work to external AI services just to reduce another model's tokens.

## Shared promotion gate

A lane can move from radar to shipped feature only when it satisfies the same evidence discipline used by [`benchmark-plan.md`](benchmark-plan.md):

1. **Matched successful tasks**: compare baseline and variant only on tasks that succeed in both conditions.
2. **Failure-rate guardrail**: use [`benchmark-plan.md`](benchmark-plan.md) as the source of truth for the threshold (`10%p`, i.e. 10 percentage points); downgrade or reject a technique if failure rate regresses by that amount or more.
3. **Human-correction tracking**: treat higher correction burden as a quality watch even when token counts fall.
4. **Shifted-cost accounting**: include external/subagent/local-service costs where the work moved elsewhere.
5. **Provider-measured evidence**: token or cost savings require measured primary token/cost fields, not only bytes saved.
6. **Privacy and reversibility**: local artifacts must be sanitized, bounded, and retrievable when lossy transforms are used.

## Later roadmap gates

The following ideas remain later-roadmap gates, not shipped runtime features. They may appear in research notes or fixture-only benchmark designs, but package descriptions, hero copy, and default helper behavior must not present them as available features or hosted API savings.

### Neural/semantic compression gate

Neural or semantic compression is allowed only behind an explicit experimental mode and only for already-sanitized, unprotected prose. It must deny protected zones, code, diffs, identifiers, paths, stack frames, numeric constants, hashes, quoted strings, JSON keys, prompt-like instructions, and any content that requires exact retrieval. A future PR must provide an exact retrieval fallback or local receipt handle before replacing text with a lossy semantic summary, and it must keep byte/token-proxy reductions separate from provider-measured token/cost evidence.

Promotion requires matched successful tasks, failure-rate and human-correction guardrails, shifted-cost accounting for any compressor or subagent work, and provider-measured primary token/cost data on both sides before any hosted API savings claim.

### Trust-tiered / injection-aware compression gate

Trust-tiered or injection-aware compression requires explicit trust labels for each input region, prompt-injection regression fixtures, and deny-by-default behavior for untrusted, instruction-bearing, user-supplied, or tool-output content. The safe default is structural selection, local artifact storage, and exact retrieval, not neural rewriting.

Future experiments must prove that injection-like text is not elevated into system/developer instructions, that untrusted content cannot change compression policy, and that regressions are benchmarked before a lane can be promoted.

### Reviewable context-diff compaction gate

Reviewable context-diff compaction must produce human-reviewable diffs plus stable exact handles for every omitted or transformed source. Local receipts and an audit trail must identify source paths or sanitized labels, byte ranges or line ranges when safe, transform policy, and exact re-expand commands. Lossy replacement is allowed only when the user can inspect the diff, retrieve the original, and see the bounded-loss disclosure.

No context-diff compaction may claim hosted token/cost savings from a smaller local diff alone; savings claims require the shared promotion gate and provider-measured matched-task evidence.

### Opt-in local proxy constraints gate

Local proxy constraints are opt-in and local-only. They must require explicit user enablement, document the local service boundary, state **no hidden external forwarding**, and record shifted-cost accounting for local services, subagents, model servers, or proxy infrastructure. Proxy byte reductions, cache hits, or local latency changes are diagnostic evidence only.

A future proxy-related PR must show configuration that keeps external forwarding disabled unless the user explicitly opts in, must preserve privacy/reversibility expectations, and must not convert local proxy metrics into hosted API token/cost savings without provider-measured evidence.


## Graduated local experiment — receipt-backed output trimming

`context-guard-trim-output --digest ... --artifact-receipt` is the first reversible local transform experiment promoted from this roadmap. It stores only sanitized command output in the existing local artifact store and emits exact re-expand commands for omitted details. It is opt-in, does not change default trimming behavior, and does not create a hosted API token/cost savings claim; benchmark reports must still use matched successful tasks and provider-measured primary token fields before reporting token savings.

The package-visible output-transform benchmark fixture is only a dry-run starter for this lane. The current benchmark runner has one `task.prompt` per task and variants only add `extra_args`, so a real A/B run must provide separate sanitized raw-output and digest-plus-receipt task evidence, or wait for a future runner-native preflight that can swap evidence before provider invocation.

## Graduated local experiment — protected-zone transform policy

`context-guard-compress --protected-policy` and `context-guard cost compile` now expose opt-in policy metadata for semantic-sensitive zones: code fences, diffs, identifiers, numeric constants, hashes, paths, stack frames, quoted strings, and JSON keys. The policy denies semantic/paraphrase rewrites, allows structural dedupe/window/truncate plus exact local retrieval, and keeps protected+volatile sections ordered by volatility rather than treating protection as provider-cache stability. This is a local guardrail and metadata layer only; it does not claim hosted token/cost savings or replace provider prompt caching.

## Lane 1 — Learned prompt/context compression

Candidate methods include LLMLingua/LongLLMLingua-style prompt compression, Selective Context-style pruning, gist-token or latent-context representations, and task-aware reranking before compression.

| Question | Gate |
| --- | --- |
| Why it could help | It may shorten text already selected for the model while preserving enough task evidence. |
| What it does not prove | A shorter prompt is not automatically a correct answer, lower total cost, or lower human-correction burden. |
| Hosted API claim boundary | Hosted token/cost savings may be claimed only after provider-measured matched-task evidence. |
| Minimum telemetry | input/output/cache tokens, cost, success, human corrections, external compressor cost, bytes before/after. |
| Promotion path | Start as an offline benchmark variant; promote only if quality and shifted-cost gates pass. |

Recommended first experiment: run a learned compressor only on already-sanitized context packs or artifact digests, never on raw secrets or unrecoverable source evidence.

## Lane 2 — Multimodal crop, OCR, and visual-token reduction

Candidate methods include screenshot cropping before upload, local OCR to replace screenshots with text when fidelity is sufficient, image tiling policies, visual-token pruning methods such as diversity or language-guided pruning, and task-specific region selection.

| Question | Gate |
| --- | --- |
| Why it could help | Many UI/debugging tasks need one region, one error message, or OCR text rather than a full high-resolution screenshot. |
| What it does not prove | Cropping/OCR can lose visual context; visual-token pruning usually applies inside specific multimodal model architectures. |
| Hosted API claim boundary | Claim hosted API savings only with provider-measured image/text token or cost evidence for matched successful tasks. |
| Minimum telemetry | image dimensions, crop area, OCR confidence/error notes, provider image/text token fields when available, success, corrections. |
| Promotion path | Start with local crop/OCR advice and benchmark fixtures; promote only when missed-visual-context regressions are bounded. |

Recommended first experiment: add a benchmark fixture comparing full screenshot review versus cropped/OCR evidence on tasks with known visual answers.

## Lane 3 — Self-hosted KV-cache, attention, and latent inference optimizations

Candidate methods include PyramidKV, ChunkKV, FastKV, RocketKV, KV quantization, attention sparsity, latent/gist memory, and model-server prefix/KV reuse. These are relevant when ContextGuard supports or documents self-hosted local inference stacks.

| Question | Gate |
| --- | --- |
| Why it could help | It may reduce memory, bandwidth, or latency for long-context inference you run yourself. |
| What it does not prove | It does not reduce hosted API prompt tokens just because local KV memory is smaller. |
| Hosted API claim boundary | Treat as self-hosted memory/latency only unless provider telemetry shows token/cost reduction. |
| Minimum telemetry | model/server, context length, KV memory, latency, throughput, quality metric, energy/cost if measured. |
| Promotion path | Keep as documentation until ContextGuard has a supported self-hosted integration and benchmark harness. |

Recommended first experiment: document how to record self-hosted latency/memory alongside ContextGuard's benchmark ledger without mixing it into hosted API token claims.

## Review checklist for future experiment PRs

- Does the PR state whether it affects hosted API prompt tokens, provider cache, local bytes, or self-hosted memory/latency?
- Does it include matched successful baseline/variant runs?
- Does it report failure rate, human corrections, and shifted cost?
- Does it avoid method-specific claims in package descriptions or hero copy until shipped?
- Does it preserve exact retrieval or clearly label lossy transforms?
- Does it keep local/private data local unless the user explicitly opts into a provider call?

## Current status

This radar is intentionally documentation-only. The shipped ContextGuard tools remain local context hygiene, artifact receipts, context packing, tool-schema pruning, transcript audit, statusline visibility, and benchmark evidence. Package-visible starter scaffolds live in [`../docs/experimental-benchmark-fixtures.md`](../docs/experimental-benchmark-fixtures.md). They are fixture-only synthetic task/variant examples and dry-run-only starters until prompts and success checks are replaced for a real experiment; they are not shipped runtime helpers, benchmark results, or hosted API savings evidence.
Future experiments must pass the gates above before becoming product features.
