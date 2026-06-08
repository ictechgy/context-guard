import XCTest
@testable import ContextGuardMacCore

final class VisibilityViewModelTests: XCTestCase {
    func testSnapshotDisplaysContractMetricsWithApprovedLanguage() throws {
        let snapshot = VisibilityViewModel.snapshot(report: try decodeFixture())

        XCTAssertEqual(snapshot.statusTitle, "CG")
        XCTAssertEqual(snapshot.severity, VisibilitySeverity.ready)
        XCTAssertTrue(snapshot.sourceMessage.contains("not a live statusline signal"))
        XCTAssertTrue(snapshot.contextMessage.contains("Transcript scans do not include live Claude Code context"))
        XCTAssertTrue(snapshot.cards.contains(MetricCard(title: "Cache-read share", value: "72.7%", detail: "cache_read / (input + cache_read + cache_creation)", isAvailable: true)))
        XCTAssertTrue(snapshot.cards.contains(MetricCard(title: "Reuse ratio", value: "4.00×", detail: "cache_read / cache_creation", isAvailable: true)))
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Observed cost" && $0.value == "$0.1234" && ($0.detail?.contains("not invoice-grade billing") ?? false) })
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Headroom availability" && $0.value == "missing" && ($0.detail?.contains("live_statusline_snapshot") ?? false) })
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Cache layout advice" && $0.value == "available" && ($0.detail?.contains("Fixture cache advice only") ?? false) })
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Cache layout advice" && ($0.detail?.contains("Cache-friendliness score: 0.82") ?? false) })
        XCTAssertFalse(snapshot.cards.contains { $0.title.lowercased().contains("hit rate") })
        XCTAssertTrue(snapshot.caveats.contains("Historical transcript totals do not infer live context headroom or remaining tokens."))
        XCTAssertTrue(snapshot.caveats.contains("This contract does not guarantee token or cost savings."))
    }

    func testPartialScanChangesStatusButStillRendersValues() throws {
        var json = feasibilityFixture(scanStatus: "partial")
        json = json.replacingOccurrences(of: #""skipped_records": 0"#, with: #""skipped_records": 2"#)
        let snapshot = VisibilityViewModel.snapshot(report: try decodeFixture(json))

        XCTAssertEqual(snapshot.statusTitle, "CG partial")
        XCTAssertEqual(snapshot.severity, VisibilitySeverity.partial)
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Scan integrity" && ($0.detail?.contains("skipped records 2") ?? false) })
    }

    func testNilReuseRatioIsUndefinedNotZero() throws {
        let report = try decodeFixture(feasibilityFixture(cacheReuseRatio: "null"))
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertTrue(snapshot.cards.contains(MetricCard(title: "Reuse ratio", value: "Undefined", detail: "cache_read / cache_creation", isAvailable: false)))
        XCTAssertFalse(snapshot.cards.contains { $0.title == "Reuse ratio" && $0.value == "0%" })
    }

    func testSummaryDoesNotDrivePrimarySnapshot() throws {
        let withSummary = VisibilityViewModel.snapshot(report: try decodeFixture(feasibilityFixture(includeSummary: true)))
        let withoutSummary = VisibilityViewModel.snapshot(report: try decodeFixture(feasibilityFixture(includeSummary: false)))

        XCTAssertEqual(withSummary, withoutSummary)
    }

    func testSetupAndErrorStatesAreActionable() {
        let setup = VisibilityViewModel.setup(defaultDirectory: nil)
        XCTAssertEqual(setup.statusTitle, "CG setup")
        XCTAssertTrue(setup.sourceMessage.contains("Choose"))

        let error = VisibilityViewModel.error(AuditCLIAdapterError.executableNotFound)
        XCTAssertEqual(error.statusTitle, "CG ⚠")
        XCTAssertTrue(error.sourceMessage.contains("context-guard-audit"))
    }
}
