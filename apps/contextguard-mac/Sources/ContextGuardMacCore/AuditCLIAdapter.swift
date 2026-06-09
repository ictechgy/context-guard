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
            return "context-guard-audit was not found in PATH and no executable fallback is configured."
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

    public func resolveExecutable() throws -> URL {
        if let pathValue = environment["PATH"] {
            for entry in pathValue.split(separator: ":", omittingEmptySubsequences: true) {
                let entryPath = String(entry)
                guard entryPath.hasPrefix("/") else {
                    continue
                }
                let candidate = URL(fileURLWithPath: entryPath, isDirectory: true).appendingPathComponent("context-guard-audit")
                if let executable = validatedExecutable(candidate) {
                    return executable
                }
            }
        }

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
        process.environment = environment
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
        guard url.isFileURL, url.path.hasPrefix("/") else {
            return nil
        }
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
            return nil
        }
        guard fileManager.isExecutableFile(atPath: url.path) else {
            return nil
        }
        let resolved = url.resolvingSymlinksInPath()
        guard fileManager.isExecutableFile(atPath: resolved.path) else {
            return nil
        }
        return resolved
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
