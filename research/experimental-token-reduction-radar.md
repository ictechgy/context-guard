# Experimental Token-Reduction Radar

ContextGuard's shipped helpers reduce avoidable local context bloat before an AI coding agent sees it. This radar tracks **optional future experiments** plus narrow **graduated local experiments** such as the explicit context-diff, visual evidence-pack, plan-only image-context-pack and semantic-checkpoint gates, learned-candidate, self-hosted metrics, local proxy gate-record, and one-shot loopback local proxy forwarding runtimes. Later-roadmap lanes are not shipped runtime features, and nothing here is a hosted API savings claim.

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

Future PR checklist:
- [ ] Keep the feature behind an explicit experimental mode with no default runtime activation.
- [ ] Limit neural or semantic rewriting to already-sanitized unprotected prose only.
- [ ] Deny protected zones, code, diffs, identifiers, paths, stack frames, numeric constants, hashes, quoted strings, JSON keys, prompt-like instructions, and exact-retrieval-required evidence.
- [ ] Provide exact retrieval fallback or a local receipt handle before replacing text with any lossy semantic summary.
- [ ] Keep byte/token-proxy reductions separate from provider-measured matched successful task token/cost evidence.

Promotion requires matched successful tasks, failure-rate and human-correction guardrails, shifted-cost accounting for any compressor or subagent work, and provider-measured primary token/cost data on both sides before any hosted API savings claim.

### Trust-tiered / injection-aware compression gate

Trust-tiered or injection-aware compression requires explicit trust labels for each input region, prompt-injection regression fixtures, and deny-by-default behavior for untrusted, instruction-bearing, user-supplied, or tool-output content. The safe default is structural selection, local artifact storage, and exact retrieval, not neural rewriting.

Future experiments must prove that injection-like text is not elevated into system/developer instructions, that untrusted content cannot change compression policy, and that regressions are benchmarked before a lane can be promoted.

Future PR checklist:
- [ ] Require explicit trust labels for every input region before any compression policy is applied.
- [ ] Keep deny-by-default behavior for untrusted, instruction-bearing, user-supplied, and tool-output content.
- [ ] Include prompt-injection regression fixtures for instruction-like and policy-changing text.
- [ ] Prove untrusted content cannot change compression policy or become system/developer instructions.
- [ ] Benchmark regressions before promotion and prefer structural selection, local artifact storage, and exact retrieval by default.

### Reviewable context-diff compaction gate

Reviewable context-diff compaction must produce human-reviewable diffs plus stable exact handles for every omitted or transformed source. Local receipts and an audit trail must identify source paths or sanitized labels, byte ranges or line ranges when safe, transform policy, and exact re-expand commands. Lossy replacement is allowed only when the user can inspect the diff, retrieve the original, and see the bounded-loss disclosure.

No context-diff compaction may claim hosted token/cost savings from a smaller local diff alone; savings claims require the shared promotion gate and provider-measured matched-task evidence.

Future PR checklist:
- [ ] Produce human-reviewable diffs for every omitted or transformed source.
- [ ] Record stable exact handles, local receipts, and an audit trail before compaction output is used.
- [ ] Identify source paths or sanitized labels plus byte ranges or line ranges when safe.
- [ ] Emit exact re-expand commands and the transform policy for each compacted source.
- [ ] Show bounded-loss disclosure whenever lossy replacement is allowed.
- [ ] Make no hosted token/cost savings claim from a smaller local diff alone.


### Image-context-pack plan-only gate

`context-guard experiments plan image-context-pack` is a pxpipe-inspired, plan-only dry-run gate for evaluating whether future image/context packing is even safe to study. It is not a runtime feature: ContextGuard does not render images, run OCR, parse images, call models or providers, proxy traffic, store binary artifacts, write replacement evidence, or make hosted token/cost savings claims from this gate.

The gate requires explicit evaluation intent, exact text artifact fallback before any omitted text is relied on, protected-zone denial for code, diffs, identifiers, hashes, paths, numeric constants, JSON keys, stack frames, secrets, and prompt-like instructions, missed-context guardrails, and provider-measured matched successful tasks before any hosted savings claim. `visual-crop-ocr` remains the existing caller-supplied visual evidence-pack surface; its visual handles are not a verified exact binary/image fallback, and `image-context-pack` is not a duplicate visual evidence emitter.

Future PR checklist:
- [ ] Keep the lane plan-only and default off until a separate future runtime plan is approved.
- [ ] Require verified exact text fallback before any future image/context pack can replace omitted text.
- [ ] Deny protected-zone and prompt-like content rather than rendering or transforming it.
- [ ] Track missed-context review and human-correction evidence before promotion.
- [ ] Treat image/request byte reductions as proxy evidence until provider-measured matched tasks prove token/cost deltas.

### Opt-in local proxy constraints gate

Local proxy constraints are opt-in and local-only. The shipped gate recorder is record-only, and the shipped forwarding MVP is one-shot literal-loopback HTTP forwarding only; any broader proxy behavior must require explicit user enablement, document the local service boundary, state **no hidden external forwarding**, and record shifted-cost accounting for local services, subagents, model servers, or proxy infrastructure. Proxy byte reductions, cache hits, or local latency changes are diagnostic evidence only.

A future proxy-forwarding PR beyond the one-shot loopback MVP must show configuration that keeps external forwarding disabled unless the user explicitly opts in, must preserve privacy/reversibility expectations, and must not convert local proxy metrics into hosted API token/cost savings without provider-measured evidence. `context-guard experiments plan local-proxy-external-forwarding` is a design-only dry-run gate for that future work; it emits threat-model, HTTPS allowlist, credential-redaction, and provider-evidence-boundary metadata but starts no listener, performs no DNS lookup, calls no external service, forwards no traffic, persists no credentials, and does not ship external proxy forwarding runtime.

Future PR checklist:
- [ ] Keep explicit opt-in before any broader local proxy behavior is enabled; the shipped one-shot loopback MVP already requires explicit runtime and forwarding acknowledgements.
- [ ] Document the local-only service boundary and state no hidden external forwarding.
- [ ] Keep external forwarding disabled unless the user explicitly opts in.
- [ ] Preserve privacy and reversibility expectations for all proxy-managed data.
- [ ] Record shifted-cost accounting for local services, subagents, model servers, and proxy infrastructure.
- [ ] Make no hosted API token/cost savings claim from proxy byte reductions, cache hits, or local latency alone.


## Graduated local experiment — local proxy runtime-gate recorder and loopback forwarding MVP

`context-guard experiments record local-proxy-runtime-gate --ledger-jsonl ...` is the explicit local gate-row runtime promoted from the local proxy constraints gate. It appends one local JSONL gate row only after localhost-only bind/target/upstream metadata and explicit `--runtime-gate-ack` pass. It starts no listener, forwards no traffic, performs no DNS lookup, persists no API keys, calls no external services, and makes no hosted API token/cost savings claim.

`context-guard experiments serve local-proxy ...` is the separate one-shot forwarding MVP. It requires `--runtime-gate-ack --forwarding-gate-ack --once`, a private `--ready-file` nonce handoff, literal loopback bind and target IPs, nonzero bind/target ports, byte/time limits, and credential-free requests. It blocks Authorization/API-key/Cookie-like headers, supports no external forwarding, no CONNECT/TLS proxying, no API-key persistence, and no hosted API token/cost savings claim. With `--diagnostic-ledger-jsonl`, it can append one shifted-cost diagnostic row after a successful forwarded request; the row stores hashes/metadata only, not raw headers, request bodies, response bodies, credentials, or hosted-savings evidence.

Broader local proxy forwarding remains gated if it would use hostnames or non-loopback targets, run as a daemon, process credential-bearing traffic, call external services, persist secrets, or claim provider savings.

## Graduated local experiment — context-diff compaction emitter

`context-guard experiments emit context-diff-compaction --receipt-id ... --reexpand-command ...` is the explicit local runtime promoted from the reviewable context-diff gate. It does not generate semantic compression; the compact replacement must be supplied by the caller, the original diff must still contain reviewable hunks, and the exact re-expand command must be shaped as local artifact retrieval and the stored artifact content must match the input diff (`context-guard-artifact get <id> --full` or `context-guard artifact get <id> --full`). The emitted byte reduction is proxy evidence only and cannot support hosted API token/cost savings claims without the shared promotion gate.

Broader context-diff compaction remains gated if it would automatically generate replacements, execute re-expansion beyond local receipt-file verification, write replacement files, or claim provider savings.

## Graduated local experiment — visual crop/OCR evidence pack

`context-guard experiments emit visual-crop-ocr --full-evidence-receipt ...` is the explicit local runtime promoted from the multimodal crop/OCR lane. It emits only caller-supplied evidence packs: full visual evidence receipts, crop bounds/image-size metadata, OCR text, OCR confidence/error notes, and missed-context notes. It does not capture screenshots, crop images, parse images, run OCR, call external services, write evidence files, emit replacement evidence, or claim hosted visual/text token savings. Image area and OCR byte reductions are proxy evidence only until matched successful tasks include provider-measured image/text token or cost fields.

Broader visual-token reduction remains gated if it would generate crops, invoke OCR/image models, prune visual tokens inside model architectures, replace full evidence without review, or claim provider savings.

## Plan-only local experiment — image-context-pack gate

`context-guard experiments plan image-context-pack --json` is the plan-only control-plane marker for pxpipe-inspired image/context packing evaluation. It requires explicit provider-boundary acknowledgement, exact text fallback receipt/re-expand metadata, missed-context notes, and protected-zone denial before it can report `ready_for_plan_review`. It does not emit images, pack context, render PNGs, store binary/image artifacts, run OCR/image parsing/model calls, proxy traffic, write files, or change stable runtime behavior. Area or byte reductions in the plan are proxy-only diagnostics, not hosted token/cost savings evidence.

Future runtime work remains gated by verified exact text fallback, protected-zone denial, missed-context review, and provider-measured matched successful tasks. The existing `visual-crop-ocr` lane remains the caller-supplied visual evidence-pack surface and is not a verified exact binary/image fallback.

## Plan-only local experiment — semantic-checkpoint gate

`context-guard experiments plan semantic-checkpoint --json` is the plan-only/eval-only control-plane marker for reviewable task-state checkpoint planning. The canonical ready-state example is:

```bash
context-guard experiments plan semantic-checkpoint --json --goal "preserve current task state for review" --constraint "do not rewrite protected evidence" --decision "ship plan-only semantic-checkpoint gate first" --open-task "verify exact fallback before any checkpoint is used" --evidence-handle "roadmap=contextguard-artifact:0123456789abcdef" --missing-provenance-note "none known after review" --unresolved-question "which provenance handle fields become mandatory later" --exact-context-fallback-receipt 0123456789abcdef --reexpand-command "context-guard-artifact get 0123456789abcdef --full" --provider-boundary-ack --protected-zone-policy deny --missed-context-note "raw transcript remains retrievable before checkpoint metadata is used"
```

The CLI accepts these fields as optional so incomplete dry runs can still return reviewer JSON, but the JSON payload blocks readiness until the plan includes a goal, exact context fallback receipt, local re-expand command, provider-boundary acknowledgement, protected-zone policy `deny`, missed-context note, and provenance review note. `--missing-provenance-note` can be a review acknowledgement such as `none known after review`. Exact context fallback is required before any checkpoint metadata is used; allowed local artifact retrieval shapes are `context-guard-artifact get <id> --full` and `context-guard artifact get <id> --full`.

This gate has no `emit`, `record`, or `serve` runtime, no new `context-guard-semantic-checkpoint` binary, writes no files, edits no transcript or prompt, calls no model/provider/network, emits no replacement context, and makes no hosted token/cost savings claim. Future runtime work remains gated by complete provenance, exact fallback/re-expand verification, protected-zone denial, missed-context review, and provider-measured matched successful tasks.

## Plan-only local experiment — proof-carrying-context gate

`context-guard experiments plan proof-carrying-context --json` is a default-off proof-envelope metadata readiness gate. The canonical ready-state example is:

```bash
context-guard experiments plan proof-carrying-context --json --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","safe_range":{"kind":"lines","start":82,"end":85},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --protected-zone-policy deny
context-guard experiments verify proof-carrying-context --artifact-dir ./artifacts --proof-unit-json '{"source_label":"context-filesystem-roadmap","receipt_id":"0123456789abcdef","content_sha256":"12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14","safe_range":{"kind":"lines","start":1,"end":1},"captured_at":"2026-07-10T04:11:12Z","transform_policy":"safe_range_extract","rehydrate_command":"context-guard-artifact get 0123456789abcdef --full"}' --json
```

The gate accepts bounded repeatable inline JSON and validates metadata syntax plus defined cross-field/cross-unit consistency only. It preserves the caller-supplied timestamp without generating current time or checking freshness. Protected-zone policy is declared-only; range bounds, receipt storage, source content, SHA-256, timestamp freshness, and rehydration remain unchecked and are mandatory warnings rather than proof claims.

It reads no source/artifact/config/stdin content, writes no files, edits no prompt/transcript, calls no model/provider/network/subprocess, generates or replaces no context, always emits `candidate_replacement: null`, exposes no `emit`/`record`/`serve` runtime or new binary, and makes no hosted token/cost savings claim without provider-measured matched successful tasks. The separate verifier below adds bounded local evidence checks, not proof consumption or replacement authority.

The approved `context-guard experiments verify proof-carrying-context` surface is that separate read-only local verifier. Its documented fixture is the exact UTF-8 string `ContextGuard proof fixture\n` (27 bytes, one line), SHA-256 `12637068ee51f2ddfe27f1c00836a51cb54ba6a5cfca7f2301a4a45fbade2d14`. It requires one explicit artifact directory, searches no fallback, follows no symlink, and requires effective-user ownership with directory mode `0700` and both receipt leaves with mode `0600`. It performs a bounded whole-file read for receipt/proof SHA, byte/line, and range-bounds verification but never retrieves or echoes range content. Exit `0` means only local bindings passed; exit `2` means verification failed. Timestamp freshness and protected-zone semantics remain unchecked, rehydrate commands are syntax/receipt checked but never executed, `candidate_replacement` stays `null`, and no replacement, omission, or hosted-savings authority is granted.

## Graduated local experiment — learned-compression candidate emitter

`context-guard experiments emit learned-compression --exact-fallback-receipt ... --reexpand-command ...` is the explicit local runtime promoted from the learned-compression gate. It does not run learned compressors, embeddings, rerankers, model calls, subprocesses, or external services; the compact prose candidate must be supplied by the caller, both original and candidate text must pass the deny-by-default protected-signal scan, and the exact local fallback artifact content must match the input. The emitted byte reduction is proxy evidence only and cannot support hosted API token/cost savings claims without the shared promotion gate.

Broader learned/synthetic compression remains gated if it would generate replacement text, execute a compressor command, use embeddings/rerankers/model calls, compress protected or prompt-like content, or claim provider savings.

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

Candidate methods include screenshot cropping before upload, local OCR to replace screenshots with text when fidelity is sufficient, pxpipe-inspired image/context packing plans, image tiling policies, visual-token pruning methods such as diversity or language-guided pruning, and task-specific region selection.

| Question | Gate |
| --- | --- |
| Why it could help | Many UI/debugging tasks need one region, one error message, or OCR text rather than a full high-resolution screenshot. |
| What it does not prove | Cropping/OCR/image-context packing can lose visual or exact text context; visual-token pruning usually applies inside specific multimodal model architectures. |
| Hosted API claim boundary | Claim hosted API savings only with provider-measured image/text token or cost evidence for matched successful tasks. |
| Minimum telemetry | image dimensions, crop area or planned pack dimensions, OCR confidence/error notes when applicable, exact text fallback receipt verification, provider image/text token fields when available, success, corrections. |
| Promotion path | Start with local crop/OCR advice and benchmark fixtures; promote only when missed-visual-context regressions are bounded. |

Recommended first experiments: keep `image-context-pack` as plan-only metadata until exact text fallback verification and provider-measured matched-task fields exist; separately add benchmark fixtures comparing full screenshot review versus cropped/OCR evidence on tasks with known visual answers.

## Lane 3 — Self-hosted KV-cache, attention, and latent inference optimizations

Candidate methods include PyramidKV, ChunkKV, FastKV, RocketKV, KV quantization, attention sparsity, latent/gist memory, and model-server prefix/KV reuse. These are relevant when ContextGuard supports or documents self-hosted local inference stacks.

| Question | Gate |
| --- | --- |
| Why it could help | It may reduce memory, bandwidth, or latency for long-context inference you run yourself. |
| What it does not prove | It does not reduce hosted API prompt tokens just because local KV memory is smaller. |
| Hosted API claim boundary | Treat as self-hosted memory/latency only unless provider telemetry shows token/cost reduction. |
| Minimum telemetry | model/server, context length, KV memory, latency, throughput, quality metric, energy/cost if measured. |
| Promotion path | Start with explicit local metrics JSONL sidecars; broader KV/latent runtime optimization still waits for a supported self-hosted integration and benchmark harness. |

First local runtime experiment: `context-guard experiments record self-hosted-metrics-ledger --ledger-jsonl ...` can write self-hosted latency/memory/quality sidecar rows next to ContextGuard benchmark ledgers. These rows remain diagnostic local/self-hosted evidence and must not be mixed into hosted API token/cost claims.

## Review checklist for future experiment PRs

- Does the PR state whether it affects hosted API prompt tokens, provider cache, local bytes, or self-hosted memory/latency?
- Does it include matched successful baseline/variant runs?
- Does it report failure rate, human corrections, and shifted cost?
- Does it avoid method-specific claims in package descriptions or hero copy until shipped?
- Does it preserve exact retrieval or clearly label lossy transforms?
- Does it keep local/private data local unless the user explicitly opts into a provider call?

### Matched image-context-pack correction benchmark fixture

The package-visible image-context-pack benchmark fixture adds one deterministic matched task with a full sanitized textual baseline and a synthetic packed textual variant. The packed row admits that one qualifying context item was omitted initially, records one synthetic human correction, and keeps the missed-context disclosure plus an unverified full-text fallback narrative (`verified=false`). It does not treat successful completion after correction as proof that the initial pack was complete or quality-non-inferior.

The two replay rows label byte counts as sanitized textual UTF-8 proxies only, never image bytes or provider tokens. They use synthetic fixture provenance, unmeasured provider and shifted-cost fields, and explicit claim denial. No renderer/OCR/image-parser/provider/model/network/subprocess call, artifact read, replacement, or runtime is introduced; no hosted token/cost claim is allowed. Future promotion still requires verified exact fallback, protected-zone denial, matched successful provider measurements, correction and failure-rate guardrails, and shifted-cost accounting.

### Experimental semantic-GC plan gate

`semantic-gc` is a default-off, deny-only, plan-review gate over a caller-declared graph. Default-off describes registry intent; the explicit plan CLI remains invocable and never enables omission or runtime action. Graph evaluation is suppressed when the complete envelope or topology is ambiguous. Unreachable nodes are review candidates, not proof of semantic irrelevance: omission and runtime action remain unauthorized. Candidate missed-context notes are untrusted. The planner does not read context/artifact content or verify provenance, fallback, providers, or hosted savings. Exit 0 means only `ready_for_plan_review`; it is never delete/omit authority.

context-guard experiments plan semantic-gc --json --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"root","references":[],"is_root":true,"protected_zone":false}' --context-unit-json '{"schema":"contextguard.semantic-gc-unit.v1","unit_id":"orphan","references":[],"is_root":false,"protected_zone":false,"content_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","provenance":{"source_label":"canonical-example","receipt_id":"0123456789abcdef"},"missed_context_note":"A reviewer could lose the orphaned rationale.","exact_fallback_command":"context-guard-artifact get 0123456789abcdef --full"}' --provider-boundary-ack --human-review-ack --protected-zone-policy deny

`static-relevance` is a default-off compiler for bounded caller-supplied static evidence. Missing signals suppress all slices and review ordering; accepted empty edge lists are declarations, not verified observations. Built-in protected-path matches and explicit protected reasons are hard retention vetoes that move evidence first for human review only. This plan-review-only command does not scan or read any repository, does not invoke git, and does not invoke a parser, provider, network, or subprocess. Its deterministic review order does not authorize omission, deletion, deprioritization, replacement, or runtime action.

context-guard experiments plan static-relevance --json --relevance-unit-json '{"schema":"contextguard.static-relevance-unit.v1","unit_id":"src/cli.py::main","path":"src/cli.py","task_anchor":true,"protection_reasons":[],"symbol":{"name":"main","kind":"function","start_line":1,"end_line":40},"symbol_references":[],"dataflow_predecessors":[],"dataflow_successors":[],"git":{"blame_age_days":2,"blame_contributor_count":1,"path_change_count_90d":3}}' --protected-path-policy deny --provider-boundary-ack

## Current status

This radar is intentionally conservative. The shipped ContextGuard tools remain local context hygiene, artifact receipts, context packing, tool-schema pruning, transcript audit, statusline visibility, benchmark evidence, plus the explicitly gated local context-diff emitter, visual crop/OCR evidence-pack emitter, plan-only image-context-pack dry-run gate, plan-only/eval-only semantic-checkpoint gate, plan-only semantic-GC review gate, learned-compression candidate emitter, and self-hosted metrics sidecar recorder described above. Package-visible starter scaffolds live in [`../docs/experimental-benchmark-fixtures.md`](../docs/experimental-benchmark-fixtures.md). They are fixture-only synthetic task/variant examples and dry-run-only starters until prompts and success checks are replaced for a real experiment; they are not shipped runtime helpers, benchmark results, or hosted API savings evidence.
Future experiments must pass the gates above before becoming product features.
