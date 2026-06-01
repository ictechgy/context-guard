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

## Sample redacted JSON shape

This example is illustrative, not normative. The exact contract source is the live `--feasibility-json` output. GUI prototypes should bind to the stable top-level fields listed in `consumer_contract.stable_top_level_fields`; `summary` is diagnostic legacy audit payload for troubleshooting/backward compatibility.

```json
{
  "schema_version": "contextguard.metric-feasibility.v1",
  "producer": "context-guard-audit",
  "generated_at": "2026-05-31T13:45:00Z",
  "consumer_contract": {
    "stable_top_level_fields": [
      "schema_version",
      "producer",
      "generated_at",
      "source_kind",
      "source_freshness",
      "scan_integrity",
      "metric_availability",
      "metric_caveats",
      "redaction_mode",
      "context_availability",
      "totals"
    ],
    "diagnostic_fields": ["summary"],
    "summary_contract": "summary is the legacy audit JSON payload for diagnostics and backward compatibility; new GUI prototypes should bind to stable top-level feasibility fields first."
  },
  "source_kind": "historical_transcript_scan",
  "source_freshness": {
    "status": "snapshot_at_scan_time",
    "live": false,
    "generated_at": "2026-05-31T13:45:00Z",
    "description": "Local transcript files were scanned when this report was generated; this is not a live statusline snapshot."
  },
  "scan_integrity": {
    "status": "complete",
    "files_scanned": 4,
    "records_scanned": 120,
    "skipped_files": 0,
    "skipped_records": 0,
    "parse_error_count": 0,
    "complete": true
  },
  "metric_availability": {
    "tokens": {"status": "available"},
    "cache": {
      "status": "available",
      "present_fields": {"cache_read": 12, "cache_creation": 8},
      "zero_values_observed": {"cache_read": false, "cache_creation": false}
    },
    "cost": {"status": "available", "present_count": 6},
    "context": {"status": "missing", "reason": "Transcript scans do not include live Claude Code context_window data."}
  },
  "metric_caveats": [
    "Values are observed from local Claude Code transcript JSON/JSONL fields and are not official billing records.",
    "cache-read share is cache_read / (input + cache_read + cache_creation), not a provider billing hit-rate."
  ],
  "redaction_mode": {
    "paths": "basename_plus_stable_hash_by_default",
    "commands": "command_category_plus_stable_hash_by_default",
    "secret_like_values": "pattern_redacted",
    "raw_path_and_command_flags": ["--show-paths", "--show-commands"]
  },
  "context_availability": {"status": "missing"},
  "totals": {
    "total_tokens": 123456,
    "tokens": {"input": 10000, "output": 4000, "cache_read": 90000, "cache_creation": 19456},
    "cost_usd_observed": 0.42,
    "cache_read_share": 0.753,
    "cache_reuse_ratio": 4.63
  },
  "summary": {"diagnostic": "legacy audit JSON payload omitted here for brevity"}
}
```

## Product caveats

- Use “cache-read share” and “reuse ratio” rather than billing-authoritative “cache hit rate”.
- Treat cost values as observed transcript fields, not invoices.
- Hide or soften UI sections for metrics whose availability is `missing`.
- If the feasibility report is not useful, improve local instrumentation before building a GUI.
