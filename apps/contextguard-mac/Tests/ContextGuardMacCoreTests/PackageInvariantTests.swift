import XCTest

final class PackageInvariantTests: XCTestCase {
    func testPrototypeSourceIsOutsidePluginPackage() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        XCTAssertFalse(testFile.path.contains("/plugins/context-guard/"))

        let packageRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let enumerator = FileManager.default.enumerator(at: packageRoot, includingPropertiesForKeys: nil)
        while let file = enumerator?.nextObject() as? URL {
            XCTAssertFalse(file.path.contains("/plugins/context-guard/"), "prototype file must stay outside plugin package: \(file.path)")
        }
    }
}
