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
