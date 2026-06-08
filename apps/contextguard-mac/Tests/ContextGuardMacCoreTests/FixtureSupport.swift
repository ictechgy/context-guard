import Foundation
@testable import ContextGuardMacCore

func feasibilityFixture(
    schemaVersion: String = "contextguard.metric-feasibility.v1",
    scanStatus: String = "complete",
    cacheStatus: String = "available",
    costStatus: String = "available",
    contextStatus: String = "missing",
    cacheReuseRatio: String = "4.0",
    observedCost: String = "0.1234",
    includeSummary: Bool = true
) -> String {
    let summary = includeSummary ? #", "summary": {"misleading": "debug only", "cache_metrics": {"cache_read_tokens": 999999}}"# : ""
    return #"""
    {
      "schema_version": "\#(schemaVersion)",
      "producer": "context-guard-audit",
      "generated_at": "2026-06-01T02:02:12Z",
      "consumer_contract": {
        "stable_top_level_fields": ["schema_version", "producer", "generated_at", "source_kind", "source_freshness", "scan_integrity", "metric_availability", "metric_caveats", "redaction_mode", "context_availability", "headroom_availability", "mac_visibility", "totals"],
        "diagnostic_fields": ["summary"],
        "summary_contract": "summary is diagnostic"
      },
      "source_kind": "historical_transcript_scan",
      "source_freshness": {"status": "snapshot_at_scan_time", "live": false, "generated_at": "2026-06-01T02:02:12Z", "description": "not live"},
      "scan_integrity": {"status": "\#(scanStatus)", "files_scanned": 1, "records_scanned": 1, "skipped_files": 0, "skipped_records": 0, "parse_error_count": 0, "complete": true},
      "metric_availability": {
        "tokens": {"status": "available", "present_fields": {"input": 1, "output": 1, "cache_read": 1, "cache_creation": 1}},
        "cache": {"status": "\#(cacheStatus)", "present_fields": {"cache_read": 1, "cache_creation": 1}, "zero_values_observed": {"cache_read": false, "cache_creation": false}},
        "cost": {"status": "\#(costStatus)", "present_count": 1, "observed_cost_usd": 0.1234},
        "context": {"status": "\#(contextStatus)", "reason": "Transcript scans do not include live Claude Code context_window data."},
        "input": {"status": "available", "present_count": 1},
        "output": {"status": "available", "present_count": 1}
      },
      "metric_caveats": [
        "Values are observed from local Claude Code transcript JSON/JSONL fields and are not official billing records.",
        "cache-read share is cache_read / (input + cache_read + cache_creation), not a provider billing hit-rate."
      ],
      "redaction_mode": {"paths": "basename_plus_stable_hash_by_default", "commands": "command_category_plus_stable_hash_by_default", "secret_like_values": "pattern_redacted", "raw_path_and_command_flags": ["--show-paths", "--show-commands"]},
      "context_availability": {"status": "\#(contextStatus)", "reason": "Transcript scans do not include live Claude Code context_window data."},
      "headroom_availability": {"status": "missing", "evidence": "unavailable", "observable_via": "live_statusline_snapshot"},
      "mac_visibility": {"schema_version": "contextguard.mac-visibility.v1", "surface_kind": "local_macos_visibility_contract", "readiness": {"status": "ready", "reason": "Transcript token totals are available and the scan completed within configured limits."}, "bind_to_top_level_fields": ["source_kind", "source_freshness", "scan_integrity", "metric_availability", "metric_caveats", "redaction_mode", "context_availability", "headroom_availability", "totals"], "diagnostic_only_fields": ["summary"], "primary_cards": [], "missing_live_observations": [{"id": "live_headroom", "required_observation": "live_statusline_snapshot"}], "claim_boundaries": ["Local transcript observations are not invoice-grade billing records."], "redaction_required": true},
      "totals": {"total_tokens": 1150, "tokens": {"input": 100, "output": 50, "cache_read": 800, "cache_creation": 200}, "cost_usd_observed": \#(observedCost), "cache_read_share": 0.7272727272727273, "cache_reuse_ratio": \#(cacheReuseRatio)}
      \#(summary)
    }
    """#
}

func decodeFixture(_ json: String = feasibilityFixture()) throws -> FeasibilityReport {
    try JSONDecoder().decode(FeasibilityReport.self, from: Data(json.utf8))
}
