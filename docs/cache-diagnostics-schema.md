# ContextGuard `cache_diagnostics` schema

`cache_diagnostics` is the nested diagnostic object emitted by `context-guard-audit --json` and by top-level `cache_diagnostics` in `context-guard-audit --feasibility-json`. The committed schema file, [`cache-diagnostics.schema.json`](cache-diagnostics.schema.json), describes that nested object only; it is not the full CLI response envelope.

The object is for GUI and external consumers that need stable cache-read, prefix-layout, TTL-evidence, and headroom-boundary fields without scraping prose. It is a local transcript diagnostic contract, not a billing source, not provider telemetry verification, and not a token or cost savings promise. It does not guarantee savings, does not prove provider cache hits, and does not infer live headroom.

`context-guard-audit` also emits a top-level sibling `cache_layout_advice` object. That sibling is intentionally separate from `cache_diagnostics`: diagnostics stay evidence-oriented, while advice ranks checks and experiments such as session splitting, prefix stabilization, and context-diet scans. Advice distinguishes an `observed_issue` from `hypothesized_causes`, `corroborated_causes`, and `next_checks`; without diet or structural evidence, volatile prefix positions should be presented as hypotheses to check, not confirmed root causes.

## Files

- [`cache-diagnostics.schema.json`](cache-diagnostics.schema.json) — JSON Schema 2020-12-style reference for the nested `cache_diagnostics` object.
- [`cache-diagnostics.example.json`](cache-diagnostics.example.json) — focused example generated from a synthetic timestamped transcript through `context-guard-audit --json`.

## Output surfaces

### `context-guard-audit --json`

The legacy audit JSON includes top-level `cache_diagnostics` beside `cache_metrics`, `cache_friendliness`, and the separate `cache_layout_advice` advice object.

### `context-guard-audit --feasibility-json`

The feasibility JSON includes top-level `cache_diagnostics` and `cache_layout_advice`, and lists both in `consumer_contract.stable_top_level_fields`. GUI consumers should prefer the top-level feasibility field when available and use `summary.cache_diagnostics` only for legacy compatibility.

## Top-level fields

| Field | Meaning | Consumer note |
| --- | --- | --- |
| `schema_version` | Stable version string, currently `contextguard.cache-diagnostics.v1`. | Treat unknown versions as compatible only after checking docs. |
| `status` | Overall diagnostic availability: `available`, `partial`, or `missing`. | `partial` means skipped/capped evidence or partial prompt-layout confidence. |
| `confidence` | Overall confidence: `hypothesis`, `partial`, or `unavailable` for current v1 output. | Do not present `hypothesis` as observed provider truth. |
| `evidence` | Overall evidence class: `inferred` or `unavailable`. | Cache fields may be observed inside nested observations. |
| `heuristic` | Always `true` for v1. | UI should label these as local heuristics. |
| `observations` | Observed cache field counts and token totals. | Distinguishes missing cache fields from observed zero values. |
| `derived_ratios` | Inferred ratios such as cache-read share and reuse ratio. | Ratios are formulas over transcript fields. |
| `stable_prefix_candidates` | Redacted segment positions that appear stable across samples. | Never contains raw prompt text. |
| `dynamic_prefix_breakers` | Redacted segment positions that appear volatile near the prefix. | Use as prompt-layout guidance only. |
| `cache_miss_hypotheses` | Ordered local hypotheses for missing or weak cache reads. | Small, conservative list; not root-cause proof. |
| `ttl_diagnostics` | Timestamped cache telemetry interval evidence and TTL caveats. | Positive timestamped records bound local observations only. |
| `headroom_diagnostics` | Historical-scan headroom boundary. | Live headroom requires `live_statusline_snapshot`. |
| `caveats` | User-facing caveats for evidence limits. | Preserve these when presenting summaries. |

## Evidence vocabulary

- `observed`: a field was present in the local transcript scan.
- `inferred`: a value was derived from local transcript fields or redacted prompt segment hashes.
- `hypothesis`: a plausible local interpretation that still needs corroboration.
- `partial`: some scan evidence was skipped, capped, overlapping, or otherwise incomplete.
- `unavailable`: the scan does not contain enough evidence to expose the metric.

## TTL diagnostics

`ttl_diagnostics` documents timestamped cache telemetry fields:

- `timestamped_cache_record_count`: transcript records that had timestamps and cache telemetry fields.
- `positive_timestamped_cache_record_count`: timestamped cache telemetry records with positive cache read or cache creation token counts.
- `timestamped_cache_record_span_seconds`: span between the first and last positive timestamped cache telemetry records, or `null` when fewer than two positive records exist.
- `interval_basis`: always `positive_timestamped_cache_records` for v1.
- `candidate`: one of `within-5m`, `between-5m-and-1h`, `beyond-1h`, or `null`.
- `status`, `evidence`, and `confidence`: no stronger than `hypothesis` / `inferred` for timestamp-derived intervals.

Positive timestamped cache telemetry records are local interval evidence. They do not prove provider TTL state, provider cache hits, invoices, or token/cost savings.

## Headroom diagnostics

Historical transcript scans do not carry live context-window state. `headroom_diagnostics` therefore keeps headroom `missing`/`unavailable`, sets `historical_total_tokens_are_not_headroom: true`, and names `live_statusline_snapshot` as the required observation.

## GUI binding guidance

1. Bind to `schema_version` and tolerate future additive fields only after reviewing the schema docs.
2. Display `status`, `confidence`, `evidence`, and `heuristic` near any cache recommendation.
3. Separate observed token telemetry under `observations.cache_fields` from inferred ratios and hypotheses.
4. Preserve TTL/headroom caveats in UI copy.
5. Hide provider-cache or headroom widgets when evidence is `unavailable` instead of treating missing data as zero.

## Claim boundaries

`cache_diagnostics` and the sibling `cache_layout_advice` can help users reorganize prompts, find volatile prefix segments, and identify missing evidence or next checks. They do not guarantee savings, do not verify provider cache state, are not billing authority, do not prove provider cache hits, and do not infer live headroom from historical token totals.
