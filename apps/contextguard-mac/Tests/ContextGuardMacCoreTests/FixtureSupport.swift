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
    includeAdditiveVisibilityFields: Bool = true,
    includeSummary: Bool = true
) -> String {
    let summary = includeSummary ? #", "summary": {"misleading": "debug only", "cache_metrics": {"cache_read_tokens": 999999}}"# : ""
    let stableTopLevelFields = includeAdditiveVisibilityFields
        ? #"["schema_version", "producer", "generated_at", "source_kind", "source_freshness", "scan_integrity", "metric_availability", "metric_caveats", "redaction_mode", "context_availability", "headroom_availability", "cache_friendliness", "cache_diagnostics", "cache_layout_advice", "mac_visibility", "totals"]"#
        : #"["schema_version", "producer", "generated_at", "source_kind", "source_freshness", "scan_integrity", "metric_availability", "metric_caveats", "redaction_mode", "context_availability", "totals"]"#
    let additiveVisibilityFields = includeAdditiveVisibilityFields ? #"""
,
      "headroom_availability": {"status": "missing", "evidence": "unavailable", "observable_via": "live_statusline_snapshot"},
      "cache_friendliness": {"status": "\#(cacheStatus)", "score": 0.82, "summary": "Fixture cache shape only."},
      "cache_diagnostics": {"status": "\#(cacheStatus)", "headroom_diagnostics": {"status": "missing", "reason": "Historical transcript totals are not live headroom observations."}, "dynamic_prefix_breakers": []},
      "cache_layout_advice": {"status": "\#(cacheStatus)", "summary": "Fixture cache advice only.", "recommendations": []},
      "mac_visibility": {
        "schema_version": "contextguard.mac-visibility.v1",
        "surface_kind": "local_macos_visibility_contract",
        "readiness": {"status": "ready", "reason": "Transcript token totals are available and the scan completed within configured limits."},
        "bind_to_top_level_fields": ["source_kind", "source_freshness", "scan_integrity", "metric_availability", "metric_caveats", "redaction_mode", "context_availability", "headroom_availability", "cache_friendliness", "cache_diagnostics", "cache_layout_advice", "totals"],
        "diagnostic_only_fields": ["summary"],
        "primary_cards": [
          {"id": "source_freshness", "title": "Source freshness", "status": "available", "binding_paths": ["source_kind", "source_freshness.status", "source_freshness.generated_at"]},
          {"id": "scan_integrity", "title": "Scan integrity", "status": "\#(scanStatus)", "binding_paths": ["scan_integrity.status", "scan_integrity.files_scanned", "scan_integrity.records_scanned", "scan_integrity.skipped_files", "scan_integrity.skipped_records"]},
          {"id": "token_totals", "title": "Token totals", "status": "available", "binding_paths": ["totals.total_tokens", "totals.tokens.input", "totals.tokens.output", "totals.tokens.cache_read", "totals.tokens.cache_creation"]},
          {"id": "cache_reuse", "title": "Cache-read share and reuse ratio", "status": "\#(cacheStatus)", "binding_paths": ["totals.cache_read_share", "totals.cache_reuse_ratio", "metric_availability.cache"]},
          {"id": "observed_cost", "title": "Observed transcript cost", "status": "\#(costStatus)", "binding_paths": ["totals.cost_usd_observed", "metric_availability.cost"]},
          {"id": "context_availability", "title": "Context availability", "status": "\#(contextStatus)", "binding_paths": ["context_availability", "metric_availability.context"], "required_observation": "live_statusline_snapshot"},
          {"id": "headroom_availability", "title": "Headroom availability", "status": "missing", "binding_paths": ["headroom_availability", "cache_diagnostics.headroom_diagnostics"], "required_observation": "live_statusline_snapshot"},
          {"id": "cache_layout_advice", "title": "Cache layout advice", "status": "\#(cacheStatus)", "binding_paths": ["cache_layout_advice", "cache_friendliness", "cache_diagnostics.dynamic_prefix_breakers"]}
        ],
        "missing_live_observations": [
          {"id": "live_context_window", "required_observation": "live_statusline_snapshot", "affects": ["context_availability", "metric_availability.context"], "reason": "Historical transcript scans do not include live Claude Code context_window data."},
          {"id": "live_headroom", "required_observation": "live_statusline_snapshot", "affects": ["headroom_availability", "cache_diagnostics.headroom_diagnostics"], "reason": "Historical transcript totals are not remaining-token or live headroom observations."}
        ],
        "claim_boundaries": [
          "Local transcript observations are not invoice-grade billing records.",
          "Provider cache fields are telemetry, not ContextGuard-caused token reduction and do not prove provider cache hits.",
          "Historical transcript totals do not infer live context headroom or remaining tokens.",
          "This contract does not guarantee token or cost savings."
        ],
        "redaction_required": true
      }
"""# : ""
    return #"""
    {
      "schema_version": "\#(schemaVersion)",
      "producer": "context-guard-audit",
      "generated_at": "2026-06-01T02:02:12Z",
      "consumer_contract": {
        "stable_top_level_fields": \#(stableTopLevelFields),
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
      "context_availability": {"status": "\#(contextStatus)", "reason": "Transcript scans do not include live Claude Code context_window data."}\#(additiveVisibilityFields),
      "totals": {"total_tokens": 1150, "tokens": {"input": 100, "output": 50, "cache_read": 800, "cache_creation": 200}, "cost_usd_observed": \#(observedCost), "cache_read_share": 0.7272727272727273, "cache_reuse_ratio": \#(cacheReuseRatio)}
      \#(summary)
    }
    """#
}

func decodeFixture(_ json: String = feasibilityFixture()) throws -> FeasibilityReport {
    try JSONDecoder().decode(FeasibilityReport.self, from: Data(json.utf8))
}
