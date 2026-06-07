# Experimental benchmark fixtures

These fixtures are **fixture-only** starter scaffolds for future visual/OCR and learned-compression experiments. They are **synthetic**, package-visible examples for `context-guard-bench` task and variant shapes; they are **not a shipped runtime feature**, not an OCR/compression implementation, and not a hosted API savings claim.

Use them when designing an experiment that starts from ContextGuard's existing benchmark discipline:

1. Run `context-guard-bench --tasks ... --variants ... --csv ... --dry-run` first to validate command shape. Dry-run output confirms only the argv shape; it is not benchmark evidence.
2. Replace the placeholder prompts with sanitized project tasks and run baseline plus variant on the same task set.
3. Compare only **matched successful tasks**.
4. Record the **failure-rate guardrail**, **human corrections**, and **shifted-cost accounting** for work moved to local tools, subagents, artifact stores, OCR tools, or compressors.
5. Treat byte counts, image dimensions, OCR confidence, and local compressor ratios as proxy evidence. Real token/cost claims require **provider-measured** primary token/cost fields on both sides.
6. Keep private screenshots, raw secrets, and external service endpoints out of fixture files.

## Included fixture sets

| Fixture set | Task file | Variant file | Intended future experiment |
| --- | --- | --- | --- |
| Visual/OCR evidence | [`benchmark-fixtures/visual-ocr.tasks.example.json`](benchmark-fixtures/visual-ocr.tasks.example.json) | [`benchmark-fixtures/visual-ocr.variants.example.json`](benchmark-fixtures/visual-ocr.variants.example.json) | Compare full visual evidence against cropped or OCR-derived evidence after the user supplies sanitized artifacts and provider telemetry. |
| Learned compression | [`benchmark-fixtures/learned-compression.tasks.example.json`](benchmark-fixtures/learned-compression.tasks.example.json) | [`benchmark-fixtures/learned-compression.variants.example.json`](benchmark-fixtures/learned-compression.variants.example.json) | Compare baseline context packs or artifact digests against a future learned-compression candidate after quality gates and shifted costs are measured. |

## Visual/OCR fixture notes

The visual/OCR fixtures describe placeholder evidence only. They do not crop images, run OCR, prune visual tokens, or call a model. Future experiments should record image dimensions, crop area, OCR confidence/error notes, provider image/text token telemetry when available, task success, corrections, and any external/local processing cost.

## Learned-compression fixture notes

The learned-compression fixtures describe already-sanitized context-pack or artifact-digest comparisons. They do not invoke LLMLingua-style, gist-token, latent-context, or reranking implementations. Future experiments should preserve exact retrieval for lossy transforms where possible and record bytes before/after, primary provider tokens, cost, success, corrections, compressor latency, and external cost.

## Safe wording

Use language like:

> This synthetic fixture validates benchmark task/variant shape only. A real claim needs provider-measured token/cost data for matched successful baseline and variant tasks, plus failure-rate, correction, and shifted-cost guardrails.

Avoid language that presents dry-run output, bytes saved, OCR text, or compressor ratios as hosted API token/cost savings evidence.
