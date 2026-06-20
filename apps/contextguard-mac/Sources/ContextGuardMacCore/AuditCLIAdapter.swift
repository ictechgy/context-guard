import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum AuditCLIAdapterError: Error, Equatable, LocalizedError {
    case executableNotFound
    case fallbackNotExecutable(String)
    case timedOut(TimeInterval)
    case outputTooLarge(String, limit: Int)
    case nonZeroExit(Int32, stderr: String)
    case invalidUTF8
    case invalidJSON(String)
    case unsupportedSchema(String)

    public var errorDescription: String? {
        switch self {
        case .executableNotFound:
            return "No trusted context-guard-audit executable fallback is configured."
        case .fallbackNotExecutable(let path):
            return "Configured context-guard-audit fallback is not executable: \(path)"
        case .timedOut(let timeout):
            return "context-guard-audit timed out after \(timeout) seconds."
        case .outputTooLarge(let stream, let limit):
            return "context-guard-audit \(stream) exceeded \(limit) bytes."
        case .nonZeroExit(let code, let stderr):
            return "context-guard-audit exited with status \(code): \(stderr)"
        case .invalidUTF8:
            return "context-guard-audit emitted non-UTF-8 output."
        case .invalidJSON(let message):
            return "context-guard-audit emitted invalid feasibility JSON: \(message)"
        case .unsupportedSchema(let schema):
            return "Unsupported ContextGuard feasibility schema: \(schema)"
        }
    }
}

public struct AuditCLIAdapter {
    public static let trustedExecutablePATH = "/usr/bin:/bin:/usr/sbin:/sbin"
    public static let explicitAuditExecutableEnvironmentKey = "CONTEXT_GUARD_MAC_AUDIT_EXECUTABLE"

    public var fallbackExecutableURL: URL?
    public var timeout: TimeInterval
    public var maxOutputBytes: Int
    public var environment: [String: String]
    public var fileManager: FileManager

    public init(
        fallbackExecutableURL: URL? = nil,
        timeout: TimeInterval = 30,
        maxOutputBytes: Int = 1_000_000,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) {
        self.fallbackExecutableURL = fallbackExecutableURL
        self.timeout = timeout
        self.maxOutputBytes = max(1, maxOutputBytes)
        self.environment = environment
        self.fileManager = fileManager
    }

    public static func defaultTrustedAuditExecutable(
        searchAnchors: [URL]? = nil,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) -> URL? {
        if let explicit = environment[explicitAuditExecutableEnvironmentKey]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !explicit.isEmpty {
            return validatedFallback(URL(fileURLWithPath: explicit), fileManager: fileManager)
        }

        let anchors = searchAnchors ?? defaultSearchAnchors(fileManager: fileManager)
        var seen = Set<String>()
        for anchor in anchors {
            for candidate in auditExecutableCandidates(near: anchor) {
                let key = candidate.standardizedFileURL.path
                guard seen.insert(key).inserted else { continue }
                if let executable = validatedFallback(candidate, fileManager: fileManager) {
                    return executable
                }
            }
        }
        return nil
    }

    private static func defaultSearchAnchors(fileManager: FileManager) -> [URL] {
        var anchors: [URL] = [
            URL(fileURLWithPath: fileManager.currentDirectoryPath, isDirectory: true),
            URL(fileURLWithPath: #filePath),
        ]
        if let executableURL = Bundle.main.executableURL {
            anchors.append(executableURL)
        }
        if let resourceURL = Bundle.main.resourceURL {
            anchors.append(resourceURL)
        }
        return anchors
    }

    private static func auditExecutableCandidates(near anchor: URL) -> [URL] {
        var candidates: [URL] = []
        var current = (anchor.hasDirectoryPath ? anchor : anchor.deletingLastPathComponent()).standardizedFileURL
        for _ in 0..<12 {
            candidates.append(current.appendingPathComponent("plugins/context-guard/bin/context-guard-audit"))
            candidates.append(current.appendingPathComponent("../../plugins/context-guard/bin/context-guard-audit").standardizedFileURL)
            let parent = current.deletingLastPathComponent()
            if parent.path == current.path {
                break
            }
            current = parent
        }
        return candidates
    }

    private static func validatedFallback(_ url: URL, fileManager: FileManager) -> URL? {
        AuditCLIAdapter(fallbackExecutableURL: url, fileManager: fileManager).validatedExecutable(url)
    }

    public func resolveExecutable() throws -> URL {
        if let fallbackExecutableURL {
            if let executable = validatedExecutable(fallbackExecutableURL) {
                return executable
            }
            throw AuditCLIAdapterError.fallbackNotExecutable(fallbackExecutableURL.path)
        }

        throw AuditCLIAdapterError.executableNotFound
    }

    public func loadReport(transcriptDirectory: URL, includeRecommendations: Bool = true) throws -> FeasibilityReport {
        let raw = try runRaw(transcriptDirectory: transcriptDirectory, includeRecommendations: includeRecommendations)
        let data = Data(raw.utf8)
        do {
            let report = try JSONDecoder().decode(FeasibilityReport.self, from: data)
            try report.validateSupportedSchema()
            return report
        } catch FeasibilityReportError.unsupportedSchema(let schema) {
            throw AuditCLIAdapterError.unsupportedSchema(schema)
        } catch {
            throw AuditCLIAdapterError.invalidJSON(error.localizedDescription)
        }
    }

    public func runRaw(transcriptDirectory: URL, includeRecommendations: Bool = true) throws -> String {
        let executableURL = try resolveExecutable()
        let outputDirectory = try makeTemporaryOutputDirectory()
        defer { try? fileManager.removeItem(at: outputDirectory) }
        let stdoutURL = outputDirectory.appendingPathComponent("stdout.json")
        let stderrURL = outputDirectory.appendingPathComponent("stderr.txt")
        fileManager.createFile(atPath: stdoutURL.path, contents: nil)
        fileManager.createFile(atPath: stderrURL.path, contents: nil)
        let stdoutHandle = try FileHandle(forWritingTo: stdoutURL)
        let stderrHandle = try FileHandle(forWritingTo: stderrURL)
        defer {
            try? stdoutHandle.close()
            try? stderrHandle.close()
        }

        let process = Process()
        process.executableURL = executableURL
        process.arguments = [transcriptDirectory.path, "--feasibility-json"] + (includeRecommendations ? ["--recommend"] : [])
        process.environment = trustedProcessEnvironment()
        process.currentDirectoryURL = outputDirectory
        process.standardOutput = stdoutHandle
        process.standardError = stderrHandle

        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            if try outputFileExceedsLimit(stdoutURL) {
                terminate(process)
                throw AuditCLIAdapterError.outputTooLarge("stdout", limit: maxOutputBytes)
            }
            if try outputFileExceedsLimit(stderrURL) {
                terminate(process)
                throw AuditCLIAdapterError.outputTooLarge("stderr", limit: maxOutputBytes)
            }
            Thread.sleep(forTimeInterval: 0.02)
        }

        if process.isRunning {
            terminate(process)
            throw AuditCLIAdapterError.timedOut(timeout)
        }

        try stdoutHandle.close()
        try stderrHandle.close()
        let stdoutRead = try cappedData(contentsOf: stdoutURL)
        let stderrRead = try cappedData(contentsOf: stderrURL)
        if stdoutRead.truncated {
            throw AuditCLIAdapterError.outputTooLarge("stdout", limit: maxOutputBytes)
        }
        if stderrRead.truncated {
            throw AuditCLIAdapterError.outputTooLarge("stderr", limit: maxOutputBytes)
        }
        let stdoutData = stdoutRead.data
        let stderrData = stderrRead.data
        guard let stdoutText = String(data: stdoutData, encoding: .utf8) else {
            throw AuditCLIAdapterError.invalidUTF8
        }
        let stderrText = String(data: stderrData, encoding: .utf8) ?? ""

        guard process.terminationStatus == 0 else {
            throw AuditCLIAdapterError.nonZeroExit(process.terminationStatus, stderr: bounded(stderrText))
        }
        return stdoutText
    }

    private func makeTemporaryOutputDirectory() throws -> URL {
        let directory = fileManager.temporaryDirectory
            .appendingPathComponent("contextguard-audit-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        return directory
    }

    private func terminate(_ process: Process) {
        process.terminate()
        let deadline = Date().addingTimeInterval(0.5)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
#if canImport(Darwin)
        if process.isRunning {
            kill(process.processIdentifier, SIGKILL)
        }
#endif
        let killDeadline = Date().addingTimeInterval(0.5)
        while process.isRunning && Date() < killDeadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if !process.isRunning {
            process.waitUntilExit()
        }
    }

    private func validatedExecutable(_ url: URL) -> URL? {
        let standardized = normalizeAllowedFirstAbsoluteSymlink(url.standardizedFileURL)
        guard standardized.isFileURL, standardized.path.hasPrefix("/") else {
            return nil
        }
        guard !pathContainsSymlink(standardized) else {
            return nil
        }
        guard let attributes = try? fileManager.attributesOfItem(atPath: standardized.path),
              attributes[.type] as? FileAttributeType == .typeRegular else {
            return nil
        }
        guard fileManager.isExecutableFile(atPath: standardized.path) else {
            return nil
        }
        return standardized
    }

    private func normalizeAllowedFirstAbsoluteSymlink(_ url: URL) -> URL {
        let components = url.standardizedFileURL.pathComponents
        guard components.count >= 3, components[0] == "/" else {
            return url.standardizedFileURL
        }
        let expectedTargets = [
            "tmp": "/private/tmp",
            "var": "/private/var",
        ]
        let first = components[1]
        guard let expected = expectedTargets[first] else {
            return url.standardizedFileURL
        }
        let link = URL(fileURLWithPath: "/").appendingPathComponent(first)
        guard let destination = try? fileManager.destinationOfSymbolicLink(atPath: link.path) else {
            return url.standardizedFileURL
        }
        let target: URL
        if destination.hasPrefix("/") {
            target = URL(fileURLWithPath: destination)
        } else {
            target = URL(fileURLWithPath: "/").appendingPathComponent(destination)
        }
        guard target.path == expected else {
            return url.standardizedFileURL
        }
        var normalized = URL(fileURLWithPath: expected, isDirectory: true)
        for component in components.dropFirst(2) {
            normalized.appendPathComponent(component)
        }
        return normalized
    }

    private func pathContainsSymlink(_ url: URL) -> Bool {
        let components = url.pathComponents
        guard !components.isEmpty else {
            return true
        }
        var current = components[0] == "/" ? URL(fileURLWithPath: "/", isDirectory: true) : URL(fileURLWithPath: components[0])
        for component in components.dropFirst() {
            current.appendPathComponent(component)
            if (try? fileManager.destinationOfSymbolicLink(atPath: current.path)) != nil {
                return true
            }
        }
        return false
    }

    private func trustedProcessEnvironment() -> [String: String] {
        var result = environment
        result["PATH"] = Self.trustedExecutablePATH
        return result
    }

    private func outputFileExceedsLimit(_ url: URL) throws -> Bool {
        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber else {
            return false
        }
        return size.intValue > maxOutputBytes
    }

    private func cappedData(contentsOf url: URL) throws -> (data: Data, truncated: Bool) {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maxOutputBytes + 1) ?? Data()
        if data.count > maxOutputBytes {
            return (Data(data.prefix(maxOutputBytes)), true)
        }
        return (data, false)
    }

    private func bounded(_ value: String, limit: Int = 4_000) -> String {
        if value.count <= limit {
            return value
        }
        let end = value.index(value.startIndex, offsetBy: max(0, limit - 15))
        return String(value[..<end]) + "...[truncated]"
    }
}
