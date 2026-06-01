import Foundation

public enum DefaultTranscriptLocator {
    public static func defaultClaudeProjectsDirectory(fileManager: FileManager = .default) -> URL? {
        let candidate = fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent(".claude", isDirectory: true)
            .appendingPathComponent("projects", isDirectory: true)
        var isDirectory = ObjCBool(false)
        guard fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return nil
        }
        return candidate
    }
}
