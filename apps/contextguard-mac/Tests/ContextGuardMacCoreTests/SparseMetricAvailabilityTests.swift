import XCTest
@testable import ContextGuardMacCore

final class SparseMetricAvailabilityTests: XCTestCase {
    func testMissingTokenMetricDoesNotRenderAggregateZero() throws {
        let report = try decodeFixture(allTokensMissingFixture())
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertEqual(
            card(in: snapshot, titled: "Total tokens"),
            MetricCard(
                title: "Total tokens",
                value: "Unavailable",
                detail: "input + output + cache read + cache creation",
                isAvailable: false
            )
        )
    }

    func testUnknownTokenAvailabilityStatusFailsClosed() throws {
        let report = try decodeFixture(unknownTokenStatusFixture())
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertEqual(card(in: snapshot, titled: "Total tokens")?.value, "Unavailable")
        XCTAssertEqual(card(in: snapshot, titled: "Total tokens")?.isAvailable, false)
        XCTAssertEqual(card(in: snapshot, titled: "Cache read")?.value, "Unavailable")
        XCTAssertEqual(card(in: snapshot, titled: "Cache read")?.isAvailable, false)
    }

    func testSparseProducerTokenFixtureDoesNotRenderUnobservedBucketsAsZero() throws {
        let report = try decodeFixture(sparseProducerTokenFixture())
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertNil(report.totals.tokens.input)
        XCTAssertNil(report.totals.tokens.output)
        XCTAssertNil(report.totals.tokens.cacheCreation)
        XCTAssertEqual(card(in: snapshot, titled: "Total tokens")?.value, "1,150")
        XCTAssertEqual(card(in: snapshot, titled: "Input"), MetricCard(title: "Input", value: "Unavailable", isAvailable: false))
        XCTAssertEqual(card(in: snapshot, titled: "Output"), MetricCard(title: "Output", value: "Unavailable", isAvailable: false))
        XCTAssertEqual(card(in: snapshot, titled: "Cache read"), MetricCard(title: "Cache read", value: "800", detail: "Availability: partial (cache_read: 1)", isAvailable: true))
        XCTAssertEqual(card(in: snapshot, titled: "Cache creation")?.isAvailable, false)
        XCTAssertEqual(card(in: snapshot, titled: "Cache creation")?.value, "Unavailable")
    }

    func testProducerPresenceMapPreservesAnObservedZeroBucket() throws {
        let report = try decodeFixture(observedZeroTokenFixture())
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertNil(report.totals.tokens.input)
        XCTAssertEqual(report.metricAvailability.tokens?.presentFields["input"], 1)
        XCTAssertEqual(card(in: snapshot, titled: "Input"), MetricCard(title: "Input", value: "0", isAvailable: true))
    }

    func testExplicitZeroBucketRemainsAvailable() throws {
        let report = try decodeFixture(explicitZeroTokenFixture())
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertEqual(report.totals.tokens.input, 0)
        XCTAssertEqual(card(in: snapshot, titled: "Input"), MetricCard(title: "Input", value: "0", isAvailable: true))
    }

    func testHistoricalFixtureWithFullTokenBucketsRemainsVisible() throws {
        let report = try decodeFixture(feasibilityFixture(
            schemaVersion: "contextguard.metric-feasibility.v1.2",
            includeAdditiveVisibilityFields: false
        ))
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertEqual(card(in: snapshot, titled: "Input"), MetricCard(title: "Input", value: "100", isAvailable: true))
        XCTAssertEqual(card(in: snapshot, titled: "Output"), MetricCard(title: "Output", value: "50", isAvailable: true))
        XCTAssertEqual(card(in: snapshot, titled: "Cache creation"), MetricCard(title: "Cache creation", value: "200", isAvailable: true))
    }

    private func card(in snapshot: VisibilitySnapshot, titled title: String) -> MetricCard? {
        snapshot.cards.first { $0.title == title }
    }
}

private func sparseProducerTokenFixture() -> String {
    let full = feasibilityFixture()
    return full
        .replacingOccurrences(
            of: #""tokens": {"status": "available", "present_fields": {"input": 1, "output": 1, "cache_read": 1, "cache_creation": 1}}"#,
            with: #""tokens": {"status": "available", "present_fields": {"cache_read": 1}}"#
        )
        .replacingOccurrences(
            of: #""cache": {"status": "available", "present_fields": {"cache_read": 1, "cache_creation": 1}, "zero_values_observed": {"cache_read": false, "cache_creation": false}}"#,
            with: #""cache": {"status": "partial", "present_fields": {"cache_read": 1}, "zero_values_observed": {"cache_read": false}}"#
        )
        .replacingOccurrences(
            of: #""tokens": {"input": 100, "output": 50, "cache_read": 800, "cache_creation": 200}"#,
            with: #""tokens": {"cache_read": 800}"#
        )
}

private func allTokensMissingFixture() -> String {
    sparseProducerTokenFixture()
        .replacingOccurrences(
            of: #""tokens": {"status": "available", "present_fields": {"cache_read": 1}}"#,
            with: #""tokens": {"status": "missing", "present_fields": {}}"#
        )
        .replacingOccurrences(
            of: #""tokens": {"cache_read": 800}"#,
            with: #""tokens": {}"#
        )
        .replacingOccurrences(
            of: #""total_tokens": 1150"#,
            with: #""total_tokens": 0"#
        )
}

private func unknownTokenStatusFixture() -> String {
    sparseProducerTokenFixture()
        .replacingOccurrences(
            of: #""tokens": {"status": "available", "present_fields": {"cache_read": 1}}"#,
            with: #""tokens": {"status": "future_status", "present_fields": {"cache_read": 1}}"#
        )
}

private func observedZeroTokenFixture() -> String {
    sparseProducerTokenFixture()
        .replacingOccurrences(
            of: #""tokens": {"status": "available", "present_fields": {"cache_read": 1}}"#,
            with: #""tokens": {"status": "partial", "present_fields": {"input": 1, "cache_read": 1}}"#
        )
}

private func explicitZeroTokenFixture() -> String {
    observedZeroTokenFixture()
        .replacingOccurrences(
            of: #""tokens": {"cache_read": 800}"#,
            with: #""tokens": {"input": 0, "cache_read": 800}"#
        )
}
