import XCTest
@testable import ContextGuardMacCore

final class FeasibilityReportTests: XCTestCase {
    func testDecodesStableTopLevelFields() throws {
        let report = try decodeFixture()
        try report.validateSupportedSchema()

        XCTAssertEqual(report.schemaVersion, contextGuardFeasibilitySchemaVersion)
        XCTAssertEqual(report.producer, "context-guard-audit")
        XCTAssertEqual(report.sourceKind, "historical_transcript_scan")
        XCTAssertFalse(report.sourceFreshness.live)
        XCTAssertEqual(report.scanIntegrity.status, "complete")
        XCTAssertEqual(report.metricAvailability.cache?.status, "available")
        XCTAssertEqual(report.metricAvailability.cost?.observedCostUSD, 0.1234)
        XCTAssertEqual(report.contextAvailability.status, "missing")
        XCTAssertEqual(report.headroomAvailability?.status, "missing")
        XCTAssertEqual(report.cacheFriendliness?.status, "available")
        XCTAssertEqual(report.cacheFriendliness?.score, 0.82)
        XCTAssertEqual(report.cacheDiagnostics?.status, "available")
        XCTAssertEqual(report.cacheDiagnostics?.headroomDiagnostics?.status, "missing")
        XCTAssertEqual(report.cacheLayoutAdvice?.status, "available")
        XCTAssertEqual(report.cacheLayoutAdvice?.summary, "Fixture cache advice only.")
        XCTAssertEqual(report.totals.tokens.input, 100)
        XCTAssertEqual(report.totals.tokens.output, 50)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
        XCTAssertEqual(report.totals.tokens.cacheCreation, 200)
        XCTAssertEqual(report.totals.cacheReadShare ?? -1, 800.0 / 1100.0, accuracy: 0.000001)
        XCTAssertEqual(report.totals.cacheReuseRatio ?? -1, 4.0, accuracy: 0.000001)
        XCTAssertTrue(report.diagnosticSummaryPresent)
    }

    func testUnsupportedSchemaIsRejected() throws {
        let report = try decodeFixture(feasibilityFixture(schemaVersion: "contextguard.metric-feasibility.v999"))
        XCTAssertThrowsError(try report.validateSupportedSchema()) { error in
            XCTAssertEqual(error as? FeasibilityReportError, .unsupportedSchema("contextguard.metric-feasibility.v999"))
        }
    }

    func testAdditiveMinorSchemaIsAccepted() throws {
        let report = try decodeFixture(feasibilityFixture(schemaVersion: contextGuardLatestFeasibilitySchemaVersion))

        XCTAssertEqual(report.schemaVersion, contextGuardLatestFeasibilitySchemaVersion)
        XCTAssertNoThrow(try report.validateSupportedSchema())
    }

    func testHistoricalAdditiveSchemasRemainAccepted() throws {
        for schema in [
            contextGuardFeasibilitySchemaVersion,
            "contextguard.metric-feasibility.v1.1",
            "contextguard.metric-feasibility.v1.2",
            contextGuardLatestFeasibilitySchemaVersion
        ] {
            let report = try decodeFixture(feasibilityFixture(schemaVersion: schema))

            XCTAssertEqual(report.schemaVersion, schema)
            XCTAssertNoThrow(try report.validateSupportedSchema())
        }
    }

    func testHistoricalPayloadWithoutAdditiveVisibilityFieldsStillDecodes() throws {
        let report = try decodeFixture(feasibilityFixture(
            schemaVersion: "contextguard.metric-feasibility.v1.2",
            includeAdditiveVisibilityFields: false
        ))

        XCTAssertEqual(report.schemaVersion, "contextguard.metric-feasibility.v1.2")
        XCTAssertNoThrow(try report.validateSupportedSchema())
        XCTAssertNil(report.headroomAvailability)
        XCTAssertNil(report.cacheFriendliness)
        XCTAssertNil(report.cacheDiagnostics)
        XCTAssertNil(report.cacheLayoutAdvice)
        XCTAssertNil(report.macVisibility)
    }

    func testDecodesProducerAlignedMacVisibilityContract() throws {
        let report = try decodeFixture(feasibilityFixture(schemaVersion: contextGuardLatestFeasibilitySchemaVersion))
        let stableFields = report.consumerContract?.stableTopLevelFields ?? []

        XCTAssertTrue(stableFields.contains("cache_friendliness"))
        XCTAssertTrue(stableFields.contains("cache_diagnostics"))
        XCTAssertTrue(stableFields.contains("cache_layout_advice"))
        XCTAssertTrue(stableFields.contains("mac_visibility"))
        XCTAssertEqual(report.headroomAvailability?.observableVia, "live_statusline_snapshot")
        XCTAssertEqual(report.cacheFriendliness?.summary, "Fixture cache shape only.")
        XCTAssertEqual(report.cacheDiagnostics?.headroomDiagnostics?.reason, "Historical transcript totals are not live headroom observations.")
        XCTAssertEqual(report.cacheLayoutAdvice?.recommendations, [])

        let macVisibility = try XCTUnwrap(report.macVisibility)
        XCTAssertEqual(macVisibility.schemaVersion, "contextguard.mac-visibility.v1")
        XCTAssertEqual(macVisibility.surfaceKind, "local_macos_visibility_contract")
        XCTAssertEqual(macVisibility.readiness.status, "ready")
        XCTAssertEqual(macVisibility.diagnosticOnlyFields, ["summary"])
        XCTAssertTrue(macVisibility.redactionRequired)
        XCTAssertTrue(macVisibility.bindToTopLevelFields.contains("cache_friendliness"))
        XCTAssertTrue(macVisibility.bindToTopLevelFields.contains("cache_diagnostics"))
        XCTAssertTrue(macVisibility.bindToTopLevelFields.contains("cache_layout_advice"))
        XCTAssertFalse(macVisibility.bindToTopLevelFields.contains("summary"))

        XCTAssertEqual(
            macVisibility.primaryCards.map(\.id),
            [
                "source_freshness",
                "scan_integrity",
                "token_totals",
                "cache_reuse",
                "observed_cost",
                "context_availability",
                "headroom_availability",
                "cache_layout_advice"
            ]
        )
        let headroomObservation = try XCTUnwrap(macVisibility.missingLiveObservations.first { $0.id == "live_headroom" })
        XCTAssertEqual(headroomObservation.requiredObservation, "live_statusline_snapshot")
        XCTAssertTrue(headroomObservation.affects.contains("headroom_availability"))
        XCTAssertTrue(headroomObservation.reason?.contains("not remaining-token") ?? false)
        XCTAssertTrue(macVisibility.claimBoundaries.contains("Historical transcript totals do not infer live context headroom or remaining tokens."))
        XCTAssertTrue(macVisibility.claimBoundaries.contains("This contract does not guarantee token or cost savings."))
    }

    func testMissingSummaryStillDecodesPrimaryContract() throws {
        let report = try decodeFixture(feasibilityFixture(includeSummary: false))
        XCTAssertFalse(report.diagnosticSummaryPresent)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
    }
}
