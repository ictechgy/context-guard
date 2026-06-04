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
2. **Failure-rate guardrail**: downgrade or reject a technique if failure rate regresses by 10 percentage points or more.
3. **Human-correction tracking**: treat higher correction burden as a quality watch even when token counts fall.
4. **Shifted-cost accounting**: include external/subagent/local-service costs where the work moved elsewhere.
5. **Provider-measured evidence**: token or cost savings require measured primary token/cost fields, not only bytes saved.
6. **Privacy and reversibility**: local artifacts must be sanitized, bounded, and retrievable when lossy transforms are used.

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

This radar is intentionally documentation-only. The shipped ContextGuard tools remain local context hygiene, artifact receipts, context packing, tool-schema pruning, transcript audit, statusline visibility, and benchmark evidence. Future experiments must pass the gates above before becoming product features.
