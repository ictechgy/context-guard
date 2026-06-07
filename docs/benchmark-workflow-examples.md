# Workflow benchmark examples

These examples show how to read `context-guard-bench` reports for common ContextGuard workflows. They are **synthetic report-shape examples**, not benchmark results for every repository.

Use them to decide what evidence a workflow has and what it does **not** prove:

- matched successful tasks are the comparison basis;
- provider-measured primary token/cost fields are required for token/cost savings claims;
- byte reductions and `chars_div_4` token proxies are local proxy evidence;
- provider cached-token fields are diagnostic telemetry and must stay separate from token-reduction claims;
- wall time, human corrections, and shifted external costs are quality/cost guardrails, not standalone savings proof.

## Example fixtures

| Workflow example | What it demonstrates | Claim boundary |
| --- | --- | --- |
| [`benchmark-workflows/context-pack-byte-proxy.example.json`](benchmark-workflows/context-pack-byte-proxy.example.json) | `context-guard-pack auto` can reduce selected local bytes and inferred token proxies. | No hosted API token-savings claim because primary provider token fields are unavailable. |
| [`benchmark-workflows/provider-cache-telemetry.example.json`](benchmark-workflows/provider-cache-telemetry.example.json) | Cache-layout diagnostics can coincide with observed provider cached-token telemetry. | Provider-cache telemetry is not proof that ContextGuard reduced prompt tokens or cost. |
| [`benchmark-workflows/measured-token-workflow.example.json`](benchmark-workflows/measured-token-workflow.example.json) | A matched successful task pair with measured primary tokens may expose `token_savings_pct`. | The percentage is sample report data only, not a general savings promise; real claims require your own matched successful task runs and quality gates. |

## How to use the examples

1. Run your own benchmark with `context-guard-bench --tasks ... --variants ... --csv ... --report-json ...`.
2. Compare your report's `claim_status`, `summary_by_variant`, and `comparisons[].quality_gate` to the examples.
3. Treat `comparisons[].quality_gate != "pass"` as a warning to inspect failures, correction burden, and unmatched tasks before discussing savings.
4. Keep byte-proxy, provider-cache, wall-time, and shifted-cost evidence in separate language from provider-measured token/cost claims. Provider-cache telemetry is not independent savings proof.

## Safe wording

Use language like:

> In this matched successful task set, primary token telemetry was observed for both variants and the report shows `token_savings_pct` for the optimized variant. Byte reductions and provider-cache fields are diagnostic context, not independent savings proof.

Avoid language like:

> ContextGuard guarantees this workflow will save tokens or cost.

The fixtures intentionally use full `context-guard-bench-report-v1` shapes so tests can catch schema drift and overclaim wording.

For task/variant starter fixtures rather than full report-shape examples, see [`experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md). Those files are fixture-only and synthetic dry-run-only starters until users replace the placeholder prompts and success checks; they are not shipped OCR, visual-token, or learned-compression runtime features, and real claims still require provider-measured matched successful tasks plus failure-rate, correction, and shifted-cost guardrails.
