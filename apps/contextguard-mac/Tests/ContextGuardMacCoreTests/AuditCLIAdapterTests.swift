import XCTest
@testable import ContextGuardMacCore

private enum ProducerGoldenTestError: Error {
    case missingRepoLocalAuditExecutable
    case missingPython3
}

final class AuditCLIAdapterTests: XCTestCase {
    func testFallbackCLIProducesDecodedReport() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        let report = try adapter.loadReport(transcriptDirectory: temp)

        XCTAssertEqual(report.schemaVersion, contextGuardFeasibilitySchemaVersion)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
    }

    func testPathResolutionIgnoresPathShadowAndUsesFallback() throws {
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

        XCTAssertEqual(report.totals.costUSDObserved ?? -1, 9.9999, accuracy: 0.000001)
    }

    func testPathOnlyExecutableIsNotResolved() throws {
        let temp = try temporaryDirectory()
        let pathDir = temp.appendingPathComponent("path-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: pathDir, withIntermediateDirectories: true)
        _ = try writeHelper(in: pathDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")

        let adapter = AuditCLIAdapter(timeout: 1, environment: ["PATH": pathDir.path])

        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .executableNotFound)
        }
    }

    func testDefaultExecutableDiscoveryUsesAnchorsOutsideCurrentDirectory() throws {
        let temp = try temporaryDirectory()
        let repo = temp.appendingPathComponent("repo", isDirectory: true)
        let pluginBin = repo.appendingPathComponent("plugins/context-guard/bin", isDirectory: true)
        let appBuild = repo.appendingPathComponent("apps/contextguard-mac/.build/debug", isDirectory: true)
        let outside = temp.appendingPathComponent("outside", isDirectory: true)
        try FileManager.default.createDirectory(at: pluginBin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: appBuild, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        let helper = try writeHelper(in: pluginBin, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let previous = FileManager.default.currentDirectoryPath
        XCTAssertTrue(FileManager.default.changeCurrentDirectoryPath(outside.path))
        defer { XCTAssertTrue(FileManager.default.changeCurrentDirectoryPath(previous)) }

        let discovered = AuditCLIAdapter.defaultTrustedAuditExecutable(
            searchAnchors: [appBuild.appendingPathComponent("ContextGuardMac")],
            environment: [:]
        )

        XCTAssertEqual(discovered?.resolvingSymlinksInPath().path, helper.resolvingSymlinksInPath().path)
    }


    func testDefaultExecutableDiscoveryIgnoresCurrentWorkingDirectory() throws {
        let temp = try temporaryDirectory()
        let maliciousBin = temp.appendingPathComponent("plugins/context-guard/bin", isDirectory: true)
        try FileManager.default.createDirectory(at: maliciousBin, withIntermediateDirectories: true)
        let malicious = try writeHelper(in: maliciousBin, body: "echo malicious-cwd-helper\n")
        let previous = FileManager.default.currentDirectoryPath
        XCTAssertTrue(FileManager.default.changeCurrentDirectoryPath(temp.path))
        defer { XCTAssertTrue(FileManager.default.changeCurrentDirectoryPath(previous)) }

        let discovered = AuditCLIAdapter.defaultTrustedAuditExecutable(environment: [:])

        XCTAssertNotEqual(discovered?.resolvingSymlinksInPath().path, malicious.resolvingSymlinksInPath().path)
    }

    func testDefaultExecutableDiscoveryRejectsUnvalidatedEnvironmentOverride() throws {
        let temp = try temporaryDirectory()
        let realDir = temp.appendingPathComponent("real-bin", isDirectory: true)
        let linkDir = temp.appendingPathComponent("link-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: linkDir, withIntermediateDirectories: true)
        let helper = try writeHelper(in: realDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let link = linkDir.appendingPathComponent("context-guard-audit")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: helper)

        let discovered = AuditCLIAdapter.defaultTrustedAuditExecutable(
            searchAnchors: [],
            environment: [AuditCLIAdapter.explicitAuditExecutableEnvironmentKey: link.path]
        )

        XCTAssertNil(discovered)
    }

    func testExecutableNotFoundIsActionable() throws {
        let adapter = AuditCLIAdapter(timeout: 1, environment: ["PATH": ""])
        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .executableNotFound)
        }
    }

    func testRelativePathEntriesAreIgnoredDuringExecutableResolution() throws {
        let temp = try temporaryDirectory()
        let relativeBin = temp.appendingPathComponent("relative-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: relativeBin, withIntermediateDirectories: true)
        _ = try writeHelper(in: relativeBin, body: "echo should-not-resolve\n")

        let adapter = AuditCLIAdapter(timeout: 1, environment: ["PATH": "relative-bin"])

        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .executableNotFound)
        }
    }

    func testFallbackDirectoryIsRejectedAsExecutable() throws {
        let temp = try temporaryDirectory()
        let adapter = AuditCLIAdapter(fallbackExecutableURL: temp, timeout: 1, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .fallbackNotExecutable(temp.path))
        }
    }

    func testFallbackSymlinkLeafIsRejectedAsExecutable() throws {
        let temp = try temporaryDirectory()
        let realDir = temp.appendingPathComponent("real-bin", isDirectory: true)
        let linkDir = temp.appendingPathComponent("link-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: linkDir, withIntermediateDirectories: true)
        let realHelper = try writeHelper(in: realDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let link = linkDir.appendingPathComponent("context-guard-audit")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: realHelper)

        let adapter = AuditCLIAdapter(fallbackExecutableURL: link, timeout: 1, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .fallbackNotExecutable(link.path))
        }
    }

    func testFallbackSymlinkParentIsRejectedAsExecutable() throws {
        let temp = try temporaryDirectory()
        let realDir = temp.appendingPathComponent("real-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: realDir, withIntermediateDirectories: true)
        _ = try writeHelper(in: realDir, body: "/bin/cat <<'JSON'\n\(feasibilityFixture())\nJSON\n")
        let linkedParent = temp.appendingPathComponent("linked-bin", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: realDir)
        let fallback = linkedParent.appendingPathComponent("context-guard-audit")

        let adapter = AuditCLIAdapter(fallbackExecutableURL: fallback, timeout: 1, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.resolveExecutable()) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .fallbackNotExecutable(fallback.path))
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
        let stderrPayload = String(repeating: "x", count: 200_000)
        let stderrFile = temp.appendingPathComponent("stderr.txt")
        try stderrPayload.write(to: stderrFile, atomically: true, encoding: .utf8)
        let helper = try writeHelper(in: temp, body: "/bin/cat \(shellSingleQuoted(stderrFile.path)) >&2\nexit 7\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            guard case AuditCLIAdapterError.nonZeroExit(7, let stderr) = error else {
                return XCTFail("expected nonZeroExit, got \(error)")
            }
            XCTAssertLessThan(stderr.count, stderrPayload.count)
            XCTAssertLessThanOrEqual(stderr.count, 4_000)
            XCTAssertTrue(stderr.hasSuffix("...[truncated]"))
        }
    }

    func testStdoutOutputOverCapFailsClosed() throws {
        let temp = try temporaryDirectory()
        let payload = String(repeating: "x", count: 2_048)
        let payloadFile = temp.appendingPathComponent("too-large-stdout.txt")
        try payload.write(to: payloadFile, atomically: true, encoding: .utf8)
        let helper = try writeHelper(in: temp, body: "/bin/cat \(shellSingleQuoted(payloadFile.path))\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, maxOutputBytes: 128, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .outputTooLarge("stdout", limit: 128))
        }
    }

    func testStderrOutputOverCapFailsClosed() throws {
        let temp = try temporaryDirectory()
        let payload = String(repeating: "x", count: 2_048)
        let payloadFile = temp.appendingPathComponent("too-large-stderr.txt")
        try payload.write(to: payloadFile, atomically: true, encoding: .utf8)
        let helper = try writeHelper(in: temp, body: "/bin/cat \(shellSingleQuoted(payloadFile.path)) >&2\nexit 7\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, maxOutputBytes: 128, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .outputTooLarge("stderr", limit: 128))
        }
    }

    func testRunRawDrainsLargeStdoutWhileProcessIsRunning() throws {
        let temp = try temporaryDirectory()
        let payload = String(repeating: "x", count: 200_000)
        let payloadFile = temp.appendingPathComponent("large-output.txt")
        try payload.write(to: payloadFile, atomically: true, encoding: .utf8)
        let helper = try writeHelper(in: temp, body: "/bin/cat \(shellSingleQuoted(payloadFile.path))\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        let output = try adapter.runRaw(transcriptDirectory: temp)

        XCTAssertEqual(output.count, payload.count)
    }

    func testTemporaryOutputDirectoryIsPrivateWorkingDirectory() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/usr/bin/stat -f '%Lp' .\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        let mode = try adapter.runRaw(transcriptDirectory: temp).trimmingCharacters(in: .whitespacesAndNewlines)

        XCTAssertEqual(mode, "700")
    }

    func testTimeoutDoesNotHang() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/sleep 2\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 0.1, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .timedOut(0.1))
        }
    }

    func testTimeoutDoesNotHangWhenProcessIgnoresTerminate() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "trap '' TERM\n/bin/sleep 5\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 0.1, environment: ["PATH": ""])
        let start = Date()

        XCTAssertThrowsError(try adapter.runRaw(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .timedOut(0.1))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    func testUnsupportedSchemaFromCLIIsRejected() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/cat <<'JSON'\n\(feasibilityFixture(schemaVersion: "contextguard.metric-feasibility.v999"))\nJSON\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        XCTAssertThrowsError(try adapter.loadReport(transcriptDirectory: temp)) { error in
            XCTAssertEqual(error as? AuditCLIAdapterError, .unsupportedSchema("contextguard.metric-feasibility.v999"))
        }
    }

    func testAdditiveMinorSchemaFromCLIIsAccepted() throws {
        let temp = try temporaryDirectory()
        let helper = try writeHelper(in: temp, body: "/bin/cat <<'JSON'\n\(feasibilityFixture(schemaVersion: contextGuardLatestFeasibilitySchemaVersion))\nJSON\n")
        let adapter = AuditCLIAdapter(fallbackExecutableURL: helper, timeout: 2, environment: ["PATH": ""])

        let report = try adapter.loadReport(transcriptDirectory: temp)

        XCTAssertEqual(report.schemaVersion, contextGuardLatestFeasibilitySchemaVersion)
        XCTAssertEqual(report.totals.tokens.cacheRead, 800)
    }

    func testRepoProducerFeasibilityJSONDecodesMacVisibilityContract() throws {
        let temp = try temporaryDirectory()
        let sample = temp.appendingPathComponent("session.jsonl")
        try """
        {"timestamp":"2026-06-08T12:00:00Z","message":{"model":"claude-sonnet-test","role":"user","content":[{"type":"text","text":"Stable policy\\nStable workflow\\nRun-specific evidence"}],"usage":{"input_tokens":100,"output_tokens":50,"cache_read_input_tokens":800,"cache_creation_input_tokens":200}},"total_cost_usd":0.1234}

        """.write(to: sample, atomically: true, encoding: .utf8)
        let adapter = AuditCLIAdapter(
            fallbackExecutableURL: try repoLocalAuditExecutable(),
            timeout: 5,
            environment: ["PATH": try pythonOnlyPATH(in: temp)]
        )

        let report = try adapter.loadReport(transcriptDirectory: temp)
        let snapshot = VisibilityViewModel.snapshot(report: report)

        XCTAssertEqual(report.schemaVersion, contextGuardLatestFeasibilitySchemaVersion)
        XCTAssertEqual(report.cacheFriendliness?.status, "partial")
        XCTAssertEqual(report.cacheDiagnostics?.status, "partial")
        XCTAssertEqual(report.cacheLayoutAdvice?.status, "partial")
        XCTAssertEqual(report.macVisibility?.primaryCards.map(\.id).contains("cache_layout_advice"), true)
        XCTAssertTrue(snapshot.cards.contains { $0.title == "Cache layout advice" && $0.value == "partial" })
        XCTAssertTrue(snapshot.caveats.contains("This contract does not guarantee token or cost savings."))
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("contextguard-mac-tests-")
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directory)
        }
        return directory
    }

    private func writeHelper(in directory: URL, body: String) throws -> URL {
        let helper = directory.appendingPathComponent("context-guard-audit")
        try ("#!/bin/sh\n" + body).write(to: helper, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
        return helper
    }

    private func repoLocalAuditExecutable() throws -> URL {
        let fileURL = URL(fileURLWithPath: #filePath)
        var current = fileURL.deletingLastPathComponent()
        for _ in 0..<10 {
            let candidate = current.appendingPathComponent("plugins/context-guard/bin/context-guard-audit")
            if FileManager.default.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
            current.deleteLastPathComponent()
        }
        throw ProducerGoldenTestError.missingRepoLocalAuditExecutable
    }

    private func pythonOnlyPATH(in directory: URL) throws -> String {
        let python = [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
        ].first { FileManager.default.isExecutableFile(atPath: $0) }
        guard let python else {
            throw ProducerGoldenTestError.missingPython3
        }
        let bin = directory.appendingPathComponent("python-bin", isDirectory: true)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            at: bin.appendingPathComponent("python3"),
            withDestinationURL: URL(fileURLWithPath: python)
        )
        return bin.path
    }

    private func shellSingleQuoted(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}
