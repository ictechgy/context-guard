# Experimental benchmark fixtures

These fixtures are **fixture-only** starter scaffolds for future image-context-pack, visual/OCR, learned-compression, reversible output-transform, and token-savings roadmap experiments. They are **synthetic**, package-visible examples for `context-guard-bench` task and variant shapes; they are **not shipped benchmark results**, not image packing/OCR/compression implementations, not cache/tool-deferral implementations, and not hosted API savings claims.

Use them when designing an experiment that starts from ContextGuard's existing benchmark discipline:

1. Run `context-guard-bench --tasks ... --variants ... --csv ... --dry-run` first to validate command shape. Dry-run output confirms only the argv shape; it is not benchmark evidence.
   Unchanged fixture files are dry-run-only starters: before any non-dry-run benchmark, replace the placeholder prompts and replace the failing placeholder `success_command` with an explicit success check or documented manual correction/evaluation workflow.
2. Replace the placeholder prompts with sanitized project tasks and run baseline plus variant on the same task set.
3. Compare only **matched successful tasks**.
4. Record the **failure-rate guardrail**, **human corrections**, and **shifted-cost accounting** for work moved to local tools, subagents, artifact stores, OCR tools, or compressors.
5. Treat byte counts, image dimensions, OCR confidence, and local compressor ratios as proxy evidence. Real token/cost claims require **provider-measured** primary token/cost fields on both sides.
6. Keep private screenshots, raw secrets, and external service endpoints out of fixture files.

## Local replay evidence

`context-guard-bench --evidence-jsonl <path>` can replay pre-recorded run evidence into the normal CSV/report pipeline without invoking `claude` or any task `success_command`. Pair it with `--report-json` and `--dashboard-md` to regenerate a deterministic local dashboard:

```bash
context-guard-bench \
  --tasks docs/benchmark-fixtures/token-savings-12task.tasks.example.json \
  --variants docs/benchmark-fixtures/token-savings-12task.variants.example.json \
  --evidence-jsonl docs/benchmark-fixtures/token-savings-12task.evidence.example.jsonl \
  --csv /tmp/contextguard-token-savings.csv \
  --report-json /tmp/contextguard-token-savings.report.json \
  --dashboard-md /tmp/contextguard-token-savings.dashboard.md \
  --baseline-variant baseline_full_context_fixture
```

The included token-savings evidence file is deliberately `synthetic_fixture` provenance. It validates replay/dashboard mechanics and byte-proxy reporting only: replay forces synthetic/manual rows to `primary_tokens_measured=false` and `cost_measured=false`, so it is not public hosted API token/cost savings evidence even when token-looking numbers are present. A public claim still requires matched successful tasks, provider-export provenance, provider-measured primary tokens/cost, quality non-inferiority, and shifted-cost accounting.

## Runner-native variant prompt files

`context-guard-bench` supports optional file-backed `variant_prompt_files` in task fixtures. The map is keyed by variant name and lets a single logical task swap sanitized prompt evidence per variant, for example a baseline raw-output prompt versus a digest plus artifact receipt prompt. Prompt files are resolved relative to the task JSON, must be relative paths, and are read with the same no-follow/symlink-safe posture as task and variant fixtures.

This runner-native swap only proves command shape and prompt selection until the user supplies real sanitized tasks, success checks, and provider telemetry. It does **not** make dry-run output, artifact receipts, byte counts, or digest metadata into token/cost savings evidence. For real non-dry-run output-transform experiments, keep task IDs matched across baseline and digest variants and require provider-measured primary token/cost fields on matched successful tasks before making any comparison claim.

## Optional image-context evaluation profile

`context-guard-bench` supports an optional, versioned evaluation profile for image-context-pack replays. A task opts in with `"evaluation_profile": "contextguard.bench.image-context-pack-evaluation.v1"`, and every evidence row for that task repeats the same value plus an `evaluation_controls` block. Absence means today's generic behavior: a fixture, report, or workflow that does not opt in acquires no new required field and no changed claim decision.

The profile is **evaluation-only**. It makes imported image-context evidence machine-reviewable; it adds no image renderer, OCR engine, image parser, provider client or SDK, credential handling, network access, proxy, daemon, subprocess transformer, automatic context omission, replacement runtime, or hosted savings claim. **Operators own the real work**: provider runs, images, credentials, and corpus selection stay with you. The runner only validates the evidence you import, and only against local, bounded checks.

`evaluation_controls` carries bounded, typed fields:

- `prompt_evidence` — SHA-256 of the selected variant prompt file plus a sanitized source label. The runner recomputes the hash with the existing no-follow bounded reader and compares it.
- `source_omission` — whether any source text was omitted or transformed for this variant.
- `exact_text_fallback` — receipt ID, content SHA-256, exact local retrieval command, and a bounded projection of one imported proof-verifier result. Required when `source_omission.present=true`. The runner labels this `imported_local_verifier_attestation`: it checks that the record is internally consistent and binds the same receipt/hash/command, but it does **not** authenticate who produced the record and does **not** reread the artifact.
- `protected_zone_review` — `deny` policy, explicit review completion, zero included protected or prompt-like regions, reviewer/source label, and a review note. This is a human/tool attestation, not semantic proof.
- `missed_context_review` — completion flag, presence flag, bounded summary, and correction-required flag.
- `human_correction` — count and bounded reason; the count must equal the existing top-level `corrections` field.
- `provider_usage` and `shifted_cost` — measurement flags that must agree with the generic normalized fields. Lane metadata can never upgrade an unmeasured value into a measured one.
- `control_provenance` — bounded local verifier/review identifiers, kept separate from provider-export provenance.

Every string, array, and nested block is bounded, and unknown keys are rejected for v1 so a typo cannot become a false pass. Schema evolution requires a new profile version.

### Rejected before write versus accepted and blocked

Evidence that cannot be interpreted safely or unambiguously is **rejected before anything is written** — no CSV, ledger, report, dashboard, or lock sidecar is created. Evidence that is well-formed but negative is **accepted and scored as blocked**, so a reviewer can still read why it failed.

| Evidence condition | Outcome |
| --- | --- |
| Missing control block; wrong type, oversize, unknown v1 key or version; task/row profile mismatch; duplicate, mixed, or partial profile batch | rejected before write |
| `--resume`, or a pre-existing non-empty CSV, for a profiled replay | rejected before write |
| Missing or unsafe prompt mapping, or a prompt SHA mismatch | rejected before write |
| Correction counts or measurement flags that contradict the generic fields | rejected before write |
| A fallback record that claims verification while its own schema, status, blockers, replacement, receipt, hash, or command fields contradict that claim | rejected before write |
| Explicitly unverified or failed fallback; non-`deny`, incomplete, or unknown protected-zone review; reported missed context; explicitly unmeasured provider or shifted cost; correction-burden or failure-rate regression | accepted, lane blocked |

Errors are bounded and redacted: raw prompts, prompt paths, artifact directories, receipt contents, and secret-shaped values are never echoed. In v1 a profiled replay requires a fresh empty CSV and a complete baseline/candidate batch. Incremental replay is deliberately given up so profile context cannot silently vanish from a resumed or pre-existing report.

### Status ceiling

A profiled report exposes `evaluation_profiles.image_context_pack` with `status: blocked` or `status: ready_for_bounded_pilot_review`.

**`ready_for_bounded_pilot_review` is the ceiling, and it is not an achievement.** It is not promotion, not runtime authority, not quality proof, and not a hosted API token/cost savings claim. It means only that the imported evidence was complete and internally consistent enough to justify a bounded human pilot review.

For any profiled report the runner clamps every public-authority surface: `evaluation_only=true`, `promotion_authority=false`, `public_claim_allowed=false`, top-level `public_claim_eligible=false`, `public_claim_status` and legacy `claim_status` set to the stable non-candidate value `image_context_pack_evaluation_only_not_public_claim`, generic `public_claim_readiness.claim_allowed=false`, and profiled matched-pair `token_savings_claim_allowed` and `shifted_cost_claim_allowed` false. Pre-clamp measurements survive only in explicitly non-authoritative fields such as `raw_metric_claim_status`. The report also carries a `sample_adequacy` observation with matched counts and `policy_status: not_defined_for_promotion`: this feature defines no sample-size or promotion threshold, and a future consensus decision must.

## Included fixture sets

| Fixture set | Task file | Variant file | Evidence replay file | Intended future experiment |
| --- | --- | --- | --- | --- |
| Matched image-context-pack correction | [`benchmark-fixtures/image-context-pack.tasks.example.json`](benchmark-fixtures/image-context-pack.tasks.example.json) | [`benchmark-fixtures/image-context-pack.variants.example.json`](benchmark-fixtures/image-context-pack.variants.example.json) | [`benchmark-fixtures/image-context-pack.evidence.example.jsonl`](benchmark-fixtures/image-context-pack.evidence.example.jsonl) | Replay one full sanitized textual baseline against one synthetic packed textual variant that succeeds only after one recorded human correction, without turning byte proxies into a hosted claim. |
| Visual/OCR evidence | [`benchmark-fixtures/visual-ocr.tasks.example.json`](benchmark-fixtures/visual-ocr.tasks.example.json) | [`benchmark-fixtures/visual-ocr.variants.example.json`](benchmark-fixtures/visual-ocr.variants.example.json) | n/a | Compare full visual evidence against cropped or OCR-derived evidence after the user supplies sanitized textual evidence, missed-context notes, crop/OCR telemetry, and provider telemetry. |
| Learned compression | [`benchmark-fixtures/learned-compression.tasks.example.json`](benchmark-fixtures/learned-compression.tasks.example.json) | [`benchmark-fixtures/learned-compression.variants.example.json`](benchmark-fixtures/learned-compression.variants.example.json) | n/a | Compare sanitized baseline context packs against a fixture-only compressed digest candidate after exact retrieval or receipt fallback, quality gates, and shifted costs are measured. |
| Reversible output transform | [`benchmark-fixtures/output-transform.tasks.example.json`](benchmark-fixtures/output-transform.tasks.example.json) | [`benchmark-fixtures/output-transform.variants.example.json`](benchmark-fixtures/output-transform.variants.example.json) | n/a | Compare raw sanitized command output against a digest plus artifact receipt after variant prompt files, success checks, and provider telemetry are supplied. |
| Token-savings 12-task roadmap | [`benchmark-fixtures/token-savings-12task.tasks.example.json`](benchmark-fixtures/token-savings-12task.tasks.example.json) | [`benchmark-fixtures/token-savings-12task.variants.example.json`](benchmark-fixtures/token-savings-12task.variants.example.json) | [`benchmark-fixtures/token-savings-12task.evidence.example.jsonl`](benchmark-fixtures/token-savings-12task.evidence.example.jsonl) | Exercise a canonical 12-task spread for bugfix, exploration, review, log analysis, migration, docs, refactor, performance, telemetry, cache layout, tool-schema deferral, and artifact receipt experiments after real success commands and provider telemetry are supplied. |

## Matched image-context-pack correction fixture notes

The image-context-pack fixture is a deterministic replay over one task and two variants. The baseline supplies full sanitized textual evidence. The packed variant explicitly records that qualifying context was omitted at first, then records one **synthetic human correction** and retains the missed-context disclosure. Its full-text fallback is narrative/shape only and remains `verified=false`; the fixture does not retrieve an artifact or prove that the initial pack was complete.

Both rows are plan-only, use protected-zone deny, and describe byte counts only as sanitized textual UTF-8 proxies—not image bytes or provider tokens. The fixture performs no renderer, OCR, image-parser, provider, model, network, or subprocess call; ships no replacement or runtime; and makes no hosted claim. A successful synthetic replay after one correction does not establish quality non-inferiority, token savings, or cost savings.

The fixture opts into the image-context evaluation profile described above, so its known-negative evidence exercises the blocked path rather than the rejection path: the unverified fallback (`verified=false`) and the one recorded correction produce an explicitly **blocked** lane score with stable blocker IDs, not a parse failure and not a claim. It is a worked example of what negative-but-reviewable evidence looks like. Because it is provider-unmeasured synthetic evidence, it cannot reach `ready_for_bounded_pilot_review` no matter how its nested metadata is written.

## Visual/OCR fixture notes

The visual/OCR fixtures describe sanitized textual visual evidence only and now demonstrate `variant_prompt_files` for full visual evidence versus cropped/OCR-derived evidence. They do not include image assets, crop images, run OCR, prune visual tokens, or call a model. Future experiments should record image dimensions, crop area, visible area, omitted or missed context, OCR confidence/error notes, full visual fallback conditions, provider image/text token telemetry when available, task success, corrections, and any external/local processing cost.

## Learned-compression fixture notes

The learned-compression fixtures describe already-sanitized context-pack or artifact-digest comparisons and now demonstrate `variant_prompt_files` for baseline context-pack evidence versus a fixture-only compressed digest candidate. ContextGuard ships `context-guard experiments plan learned-compression` only as a deny-by-default dry-run checker for sanitized trusted prose plus exact fallback handles. It does not invoke or ship LLMLingua-style, gist-token, latent-context, embedding, reranking, model-call, or replacement-generation implementations. Future experiments must follow a sanitized evidence only rule, keep protected evidence exact or receipt-retrievable, forbid semantic rewrites of identifiers, numeric constants, hashes, paths, quoted strings, stack frames, JSON keys, code fences, and diff zones, and record bytes before/after, primary provider tokens, cost, success, corrections, compressor latency, and external cost.

## Reversible output-transform fixture notes

The output-transform fixtures describe already-sanitized command output comparisons and now demonstrate `variant_prompt_files` for raw sanitized output versus digest plus artifact receipt prompt evidence. They do not execute `context-guard-trim-output`, store artifacts, call `context-guard-artifact`, or invoke a provider. Future experiments should compare raw sanitized output against `--digest` output plus an `--artifact-receipt`, verify the receipt's exact re-expand command retrieves the omitted sanitized lines, and record bytes before/after, primary provider tokens, cost, success, corrections, artifact-store usage, and any external/local processing cost.

## Token-savings 12-task roadmap fixture notes

The token-savings 12-task fixtures are a canonical **fixture-only** spread for roadmap-level A/B design. They demonstrate `variant_prompt_files` for a baseline full-context prompt versus a ContextGuard advisory-foundations prompt that may later include cache layout lint, core-vs-deferred tool schemas, artifact receipts, and claim-safe telemetry. They do not execute `context-guard-cache-score`, `context-guard-tool-prune`, or any provider call. The companion `token-savings-12task.evidence.example.jsonl` lets users replay deterministic synthetic rows into CSV/report/dashboard outputs while preserving the same non-claim boundary.

For real non-dry-run experiments, replace every placeholder `success_command`, keep task IDs matched across baseline and candidate variants, and require provider-measured primary token/cost data before interpreting `tokens_per_successful_task`, `total_cost_with_shift_usd`, or `external_cost_usd`. Cache predictions, char/4 token proxies, local latency, and byte reductions remain diagnostic proxy evidence unless the generated report contains matched successful task evidence and stays within the 10%p failure-rate guardrail.

## Safe wording

Use language like:

> This synthetic fixture validates benchmark task/variant shape only. A real claim needs provider-measured token/cost data for matched successful baseline and variant tasks, plus failure-rate, correction, and shifted-cost guardrails.

Avoid language that presents dry-run output, bytes saved, OCR text, artifact receipts, exact re-expand handles, or compressor ratios as hosted API token/cost savings evidence.
