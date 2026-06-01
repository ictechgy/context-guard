// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ContextGuardMac",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "ContextGuardMac", targets: ["ContextGuardMac"])
    ],
    targets: [
        .target(name: "ContextGuardMacCore"),
        .executableTarget(
            name: "ContextGuardMac",
            dependencies: ["ContextGuardMacCore"]
        ),
        .testTarget(
            name: "ContextGuardMacCoreTests",
            dependencies: ["ContextGuardMacCore"]
        )
    ]
)
