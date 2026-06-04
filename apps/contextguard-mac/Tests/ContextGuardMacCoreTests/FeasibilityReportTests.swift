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

        XCTAssertEqual(report.schemaVersion, "contextguard.metric-feasibility.v1.1")
        XCTAssertNoThrow(try report.validateSupportedSchema())
    }

    func testMissingSummaryStillDecodesPrimaryContract() throws {
        let report = try decodeFixture(feasibilityFixture(includeSummary: false))
        XCTAssertFalse(report.diagnosticSummaryPresent)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
    }
}
