# macOS visibility feasibility contract

`context-guard-audit --feasibility-json` emits a local, pre-GUI contract for future macOS-visible surfaces such as a menu-bar app, xbar item, Raycast command, or SwiftUI prototype. It is a transcript-scan contract, not a GUI implementation and not a live daemon.

The full feasibility envelope is versioned as `contextguard.metric-feasibility.v1.3`. The macOS binding/index inside that envelope is the top-level `mac_visibility` object with nested `schema_version: contextguard.mac-visibility.v1`.

## Contract boundary

- `mac_visibility` is a thin index over stable top-level feasibility fields. It does not recompute totals and does not read diagnostic `summary`.
- GUI or menu-bar consumers should bind only to fields listed in `consumer_contract.stable_top_level_fields` and `mac_visibility.bind_to_top_level_fields`.
- `summary` is diagnostic/backward-compatible payload only. It may be shown in a debug panel, but it must not drive primary cards.
- Historical transcript scans do not include live context-window state. Context and headroom cards stay `missing` until a future surface provides `live_statusline_snapshot`.
- Values are local transcript observations. They are not invoice-grade billing records, do not prove provider cache hits, and do not guarantee token or cost savings.

## Stable `mac_visibility` keys

| Key | Meaning |
| --- | --- |
| `schema_version` | Nested contract version: `contextguard.mac-visibility.v1`. |
| `surface_kind` | Local surface family; currently `local_macos_visibility_contract`. |
| `readiness.status` | One of `ready`, `partial`, or `missing`, derived from token availability and scan integrity. |
| `bind_to_top_level_fields` | Stable top-level fields primary consumers may use. |
| `diagnostic_only_fields` | Fields that must not drive primary UI; currently `summary`. |
| `primary_cards` | Ordered card descriptors with `id`, `title`, `status`, and `binding_paths`. |
| `missing_live_observations` | Required live observations that transcript scans cannot provide. |
| `claim_boundaries` | Copy-safe caveats for UI labels and docs. |
| `redaction_required` | Always `true` for default GUI/menu-bar presentation. |

## Card IDs and binding paths

`primary_cards[*].binding_paths` use dotted paths inside the feasibility envelope. Current card IDs are:

1. `source_freshness` → `source_kind`, `source_freshness.status`, `source_freshness.generated_at`
2. `scan_integrity` → scan completeness and skipped counts
3. `token_totals` → `totals.total_tokens` and `totals.tokens.*`
4. `cache_reuse` → `totals.cache_read_share`, `totals.cache_reuse_ratio`, `metric_availability.cache`
5. `observed_cost` → `totals.cost_usd_observed`, `metric_availability.cost`
6. `context_availability` → `context_availability`, `metric_availability.context`
7. `headroom_availability` → `headroom_availability`, `cache_diagnostics.headroom_diagnostics`
8. `cache_layout_advice` → `cache_layout_advice`, `cache_friendliness`, `cache_diagnostics.dynamic_prefix_breakers`

When a card includes `required_observation: live_statusline_snapshot`, consumers should show an unavailable or setup state rather than treating the value as zero.

## Example

See [`mac-visibility-feasibility.example.json`](mac-visibility-feasibility.example.json) for an abridged feasibility envelope. It keeps `summary` out of primary bindings and demonstrates the missing live context/headroom boundary.

## Verification guidance

For a local fixture:

```bash
context-guard-audit ./fixtures/transcripts --feasibility-json --recommend
```

Then verify:

- `schema_version == "contextguard.metric-feasibility.v1.3"`
- `consumer_contract.stable_top_level_fields` contains `mac_visibility`
- `mac_visibility.diagnostic_only_fields` contains `summary`
- no `primary_cards[*].binding_paths` entry starts with `summary`
- `missing_live_observations[*].required_observation` names `live_statusline_snapshot` when context/headroom are missing
