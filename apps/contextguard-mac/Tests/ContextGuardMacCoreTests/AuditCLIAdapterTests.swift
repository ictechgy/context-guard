import XCTest
@testable import ContextGuardMacCore

final class AuditCLIAdapterTests: XCTestCase {
    func testFallbackCLIProducesDecodedReport() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        let report = try adapter.loadReport(transcriptDirectory: temp)

        XCTAssertEqual(report.schemaVersion, contextGuardFeasibilitySchemaVersion)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
    }

    func testPathResolutionPrefersPathBeforeFallback() throws {
        let temp = try temporaryDirectory()
        let pathDir = temp.appendingPathComponent("path-bin", isDirectory: true)
        let fallbackDir = temp.appendingPathComponent("fallback-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: pathDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fallbackDir, withIntermediateDirectories: true)
        let pathHelper = try writeHelper(in: pathDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture(observedCost: "0.1111"))\nJSON\n")
        let fallbackHelper = try writeHelper(in: fallbackDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture(observedCost: "9.9999"))\nJSON\n")
        XCTAssertEqual(pathHelper.lastPathComponent, "context-guard-audit")

        let adapter = AuditCLIAdapter(fallbackExecutableURL: fallbackHelper, timeout: 2, environment: ["PATH": pathDir.path])
        let report = try adapter.loadReport(transcriptDirectory: temp)

        XCTAssertEqual(report.totals.costUSDObserved ?? -1, 0.1111, accuracy: 0.000001)
    }

    func testExecutableNotFoundIsActionable() throws {
        let adapter = AuditCLIAdapter(timeout: 1, environment: ["PATH": ""])
        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .executableNotFound)
        }
    }

    func testInvalidJSONIsReported() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "echo 'not json'\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.loadReport(transcriptDirectory: temp)) { error in
            guard case AuditCLIAdapterError.invalidJSON = error else {
                return XCTFail("expected invalidJSON, got \(error)")
            }
        }
    }

    func testNonZeroExitIncludesBoundedStderr() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "echo 'boom' >&2\nexit 7\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .nonZeroExit(7, stderr: "boom\n"))
        }
    }

    func testTimeoutDoesNotHang() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/sleep 2\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 0.1, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .timedOut(0.1))
        }
    }

    func testUnsupportedSchemaFromCLIIsRejected() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/cat <<'JSON'\n\(feasibilityFixture(schemaVersion: "contextguard.metric-feasibility.v999"))\nJSON\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.loadReport(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .unsupportedSchema("contextguard.metric-feasibility.v999"))
        }
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("contextguard-mac-tests-")
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func writeHelper(in directory: URL, body: String) throws -> URL {
        let helper = directory.appendingPathComponent("context-guard-audit")
        try ("#!/bin/sh\n" + body).write(to: helper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
        return helper
    }
}
