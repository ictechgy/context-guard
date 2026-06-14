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
| [`benchmark-workflows/self-hosted-metrics-ledger.example.jsonl`](benchmark-workflows/self-hosted-metrics-ledger.example.jsonl) | A run-evidence JSONL row can carry explicit local/model-server latency, peak-memory, and quality sidecar metrics. | Self-hosted metrics are not hosted API token/cost telemetry and do not change report savings math. |

## How to use the examples

1. Run your own benchmark with `context-guard-bench --tasks ... --variants ... --csv ... --report-json ...`.
2. Compare your report's `claim_status`, `summary_by_variant`, and `comparisons[].quality_gate` to the examples.
3. Treat `comparisons[].quality_gate != "pass"` as a warning to inspect failures, correction burden, and unmatched tasks before discussing savings.
4. Keep byte-proxy, provider-cache, wall-time, and shifted-cost evidence in separate language from provider-measured token/cost claims. Provider-cache telemetry is not independent savings proof.
5. Keep self-hosted local/model-server latency, memory, and quality metrics in the run-evidence ledger sidecar; do not fold them into hosted API token/cost savings claims unless provider-measured matched-task evidence separately supports that claim.
6. For deterministic local replay, add `--evidence-jsonl ... --dashboard-md ...`. Synthetic/manual replay evidence regenerates CSV/report/dashboard artifacts, but the report is marked `replay_only_not_public_claim` or `unknown_mixed_csv` unless every report row has complete provider-export provenance.

## Safe wording

Use language like:

> In this matched successful task set, primary token telemetry was observed for both variants and the report shows `token_savings_pct` for the optimized variant. Byte reductions and provider-cache fields are diagnostic context, not independent savings proof.

Avoid language like:

> ContextGuard guarantees this workflow will save tokens or cost.

The `.example.json` fixtures intentionally use full `context-guard-bench-report-v1` shapes so tests can catch schema drift and overclaim wording.

The self-hosted metrics example is a JSONL run-evidence sidecar, not a full report shape. Its fields are additive ledger evidence only: `latency_ms`, `peak_memory_mb`, and normalized `quality_score` describe local/model-server behavior and leave hosted API report calculations unchanged. Use `context-guard experiments plan self-hosted-metrics-ledger --json ...` only as a dry-run ledger-preview checker for explicit metrics; it does not write the benchmark ledger.

For task/variant starter fixtures rather than full report-shape examples, see [`experimental-benchmark-fixtures.md`](experimental-benchmark-fixtures.md). Those files are fixture-only and synthetic dry-run-only starters until users replace the placeholder prompts and success checks; they are not shipped OCR, visual-token, learned-compression, or output-transform benchmark results, and real claims still require provider-measured matched successful tasks plus failure-rate, correction, and shifted-cost guardrails.

The token-savings 12-task starter also includes [`benchmark-fixtures/token-savings-12task.evidence.example.jsonl`](benchmark-fixtures/token-savings-12task.evidence.example.jsonl) for `context-guard-bench --evidence-jsonl` replay. That file is synthetic local replay evidence, not provider-measured savings proof; use it to validate dashboards and claim-boundary handling before collecting real provider exports.
