# Experimental benchmark fixtures

These fixtures are **fixture-only** starter scaffolds for future visual/OCR, learned-compression, and reversible output-transform experiments. They are **synthetic**, package-visible examples for `context-guard-bench` task and variant shapes; they are **not shipped benchmark results**, not OCR/compression implementations, and not hosted API savings claims.

Use them when designing an experiment that starts from ContextGuard's existing benchmark discipline:

1. Run `context-guard-bench --tasks ... --variants ... --csv ... --dry-run` first to validate command shape. Dry-run output confirms only the argv shape; it is not benchmark evidence.
   Unchanged fixture files are dry-run-only starters: before any non-dry-run benchmark, replace the placeholder prompts and replace the failing placeholder `success_command` with an explicit success check or documented manual correction/evaluation workflow.
2. Replace the placeholder prompts with sanitized project tasks and run baseline plus variant on the same task set.
3. Compare only **matched successful tasks**.
4. Record the **failure-rate guardrail**, **human corrections**, and **shifted-cost accounting** for work moved to local tools, subagents, artifact stores, OCR tools, or compressors.
5. Treat byte counts, image dimensions, OCR confidence, and local compressor ratios as proxy evidence. Real token/cost claims require **provider-measured** primary token/cost fields on both sides.
6. Keep private screenshots, raw secrets, and external service endpoints out of fixture files.

## Runner-native variant prompt files

`context-guard-bench` supports optional file-backed `variant_prompt_files` in task fixtures. The map is keyed by variant name and lets a single logical task swap sanitized prompt evidence per variant, for example a baseline raw-output prompt versus a digest plus artifact receipt prompt. Prompt files are resolved relative to the task JSON, must be relative paths, and are read with the same no-follow/symlink-safe posture as task and variant fixtures.

This runner-native swap only proves command shape and prompt selection until the user supplies real sanitized tasks, success checks, and provider telemetry. It does **not** make dry-run output, artifact receipts, byte counts, or digest metadata into token/cost savings evidence. For real non-dry-run output-transform experiments, keep task IDs matched across baseline and digest variants and require provider-measured primary token/cost fields on matched successful tasks before making any comparison claim.

## Included fixture sets

| Fixture set | Task file | Variant file | Intended future experiment |
| --- | --- | --- | --- |
| Visual/OCR evidence | [`benchmark-fixtures/visual-ocr.tasks.example.json`](benchmark-fixtures/visual-ocr.tasks.example.json) | [`benchmark-fixtures/visual-ocr.variants.example.json`](benchmark-fixtures/visual-ocr.variants.example.json) | Compare full visual evidence against cropped or OCR-derived evidence after the user supplies sanitized textual evidence, missed-context notes, crop/OCR telemetry, and provider telemetry. |
| Learned compression | [`benchmark-fixtures/learned-compression.tasks.example.json`](benchmark-fixtures/learned-compression.tasks.example.json) | [`benchmark-fixtures/learned-compression.variants.example.json`](benchmark-fixtures/learned-compression.variants.example.json) | Compare sanitized baseline context packs against a fixture-only compressed digest candidate after exact retrieval or receipt fallback, quality gates, and shifted costs are measured. |
| Reversible output transform | [`benchmark-fixtures/output-transform.tasks.example.json`](benchmark-fixtures/output-transform.tasks.example.json) | [`benchmark-fixtures/output-transform.variants.example.json`](benchmark-fixtures/output-transform.variants.example.json) | Compare raw sanitized command output against a digest plus artifact receipt after variant prompt files, success checks, and provider telemetry are supplied. |

## Visual/OCR fixture notes

The visual/OCR fixtures describe sanitized textual visual evidence only and now demonstrate `variant_prompt_files` for full visual evidence versus cropped/OCR-derived evidence. They do not include image assets, crop images, run OCR, prune visual tokens, or call a model. Future experiments should record image dimensions, crop area, visible area, omitted or missed context, OCR confidence/error notes, full visual fallback conditions, provider image/text token telemetry when available, task success, corrections, and any external/local processing cost.

## Learned-compression fixture notes

The learned-compression fixtures describe already-sanitized context-pack or artifact-digest comparisons and now demonstrate `variant_prompt_files` for baseline context-pack evidence versus a fixture-only compressed digest candidate. ContextGuard ships `context-guard experiments plan learned-compression` only as a deny-by-default dry-run checker for sanitized trusted prose plus exact fallback handles. It does not invoke or ship LLMLingua-style, gist-token, latent-context, embedding, reranking, model-call, or replacement-generation implementations. Future experiments must follow a sanitized evidence only rule, keep protected evidence exact or receipt-retrievable, forbid semantic rewrites of identifiers, numeric constants, hashes, paths, quoted strings, stack frames, JSON keys, code fences, and diff zones, and record bytes before/after, primary provider tokens, cost, success, corrections, compressor latency, and external cost.

## Reversible output-transform fixture notes

The output-transform fixtures describe already-sanitized command output comparisons and now demonstrate `variant_prompt_files` for raw sanitized output versus digest plus artifact receipt prompt evidence. They do not execute `context-guard-trim-output`, store artifacts, call `context-guard-artifact`, or invoke a provider. Future experiments should compare raw sanitized output against `--digest` output plus an `--artifact-receipt`, verify the receipt's exact re-expand command retrieves the omitted sanitized lines, and record bytes before/after, primary provider tokens, cost, success, corrections, artifact-store usage, and any external/local processing cost.

## Safe wording

Use language like:

> This synthetic fixture validates benchmark task/variant shape only. A real claim needs provider-measured token/cost data for matched successful baseline and variant tasks, plus failure-rate, correction, and shifted-cost guardrails.

Avoid language that presents dry-run output, bytes saved, OCR text, artifact receipts, exact re-expand handles, or compressor ratios as hosted API token/cost savings evidence.
