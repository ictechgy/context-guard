# ContextGuard Mac Visibility Data Availability Spike

This note records the gated path for a future macOS-visible ContextGuard surface. Do **not** build a full Mac GUI first. The first implementation step is to prove which Claude Code token/cache/cost/context signals can be extracted locally and safely.

## Decision gate

1. Produce a local feasibility report from Claude Code transcript JSON/JSONL files.
2. Use that report as the only contract for any xbar, Raycast, menu-bar, or SwiftUI prototype.
3. Build a Mac-visible prototype only when the report shows the needed metrics as `available` or acceptable `partial` with clear caveats.

## Command

```bash
./plugins/context-guard/bin/context-guard-audit ~/.claude/projects --feasibility-json --recommend
```

The report is local-only. It scans transcript files, redacts/labels paths and commands by default, and does not contact external services.

## Stable contract reference

The package-visible contract source is [`../docs/mac-visibility-feasibility-schema.md`](../docs/mac-visibility-feasibility-schema.md), with an abridged example at [`../docs/mac-visibility-feasibility.example.json`](../docs/mac-visibility-feasibility.example.json). The current full feasibility envelope is `contextguard.metric-feasibility.v1.3`; the macOS binding/index is top-level `mac_visibility` with nested `schema_version: contextguard.mac-visibility.v1`.

GUI prototypes should bind to `consumer_contract.stable_top_level_fields` and `mac_visibility.bind_to_top_level_fields`. `summary` remains diagnostic legacy audit payload for troubleshooting/backward compatibility and must not drive primary UI cards.

The `mac_visibility.primary_cards` contract currently defines pre-GUI cards for source freshness, scan integrity, token totals, cache-read share/reuse ratio, observed transcript cost, context availability, headroom availability, and cache layout advice. Context/headroom cards stay `missing` unless a future surface provides `live_statusline_snapshot`; historical transcript totals are not remaining-token or live headroom observations.

## Product caveats

- Use “cache-read share” and “reuse ratio” rather than billing-authoritative “cache hit rate”.
- Treat cost values as observed transcript fields, not invoices.
- Hide or soften UI sections for metrics whose availability is `missing`.
- If the feasibility report is not useful, improve local instrumentation before building a GUI.
