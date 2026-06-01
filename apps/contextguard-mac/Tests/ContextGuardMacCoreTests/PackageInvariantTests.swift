import XCTest

final class PackageInvariantTests: XCTestCase {
    func testPrototypeSourceIsOutsidePluginPackage() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let packageRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .standardizedFileURL
        let repoRoot = packageRoot
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .standardizedFileURL
        let pluginRoot = repoRoot
            .appendingPathComponent("plugins/context-guard", isDirectory: true)
            .standardizedFileURL

        XCTAssertTrue(FileManager.default.fileExists(atPath: pluginRoot.path), "expected repo plugin package at \(pluginRoot.path)")
        XCTAssertFalse(isDescendant(packageRoot, of: pluginRoot), "prototype package must not live under the plugin package")
        XCTAssertFalse(isDescendant(pluginRoot, of: packageRoot), "plugin package must not live under the prototype package")

        guard let enumerator = FileManager.default.enumerator(at: packageRoot, includingPropertiesForKeys: nil) else {
            return XCTFail("could not enumerate prototype package at \(packageRoot.path)")
        }

        var visitedCount = 0
        while let file = enumerator.nextObject() as? URL {
            visitedCount += 1
            let relativeComponents = relativePathComponents(from: packageRoot, to: file)
            XCTAssertFalse(
                containsPluginPackagePath(relativeComponents),
                "prototype package must not contain a nested plugin package path: \(relativeComponents.joined(separator: "/"))"
            )
        }
        XCTAssertGreaterThan(visitedCount, 0, "prototype package invariant check must not pass vacuously")
    }

    private func isDescendant(_ child: URL, of parent: URL) -> Bool {
        let childComponents = child.standardizedFileURL.pathComponents
        let parentComponents = parent.standardizedFileURL.pathComponents
        guard childComponents.count >= parentComponents.count else { return false }
        return Array(childComponents.prefix(parentComponents.count)) == parentComponents
    }

    private func relativePathComponents(from root: URL, to file: URL) -> [String] {
        let rootComponents = root.standardizedFileURL.pathComponents
        let fileComponents = file.standardizedFileURL.pathComponents
        guard fileComponents.count >= rootComponents.count,
              Array(fileComponents.prefix(rootComponents.count)) == rootComponents else {
            return fileComponents
        }
        return Array(fileComponents.dropFirst(rootComponents.count))
    }

    private func containsPluginPackagePath(_ components: [String]) -> Bool {
        for index in components.indices.dropLast() {
            if components[index] == "plugins", components[components.index(after: index)] == "context-guard" {
                return true
            }
        }
        return false
    }
}
