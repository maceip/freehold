// swift-tools-version: 5.9
// Freehold iOS - Swift Package

import PackageDescription

let package = Package(
    name: "Freehold",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "FreeholdClient",
            targets: ["FreeholdClient"]
        ),
    ],
    dependencies: [],
    targets: [
        // FFI bindings (C library wrapper)
        .systemLibrary(
            name: "FreeholdFFI",
            path: "FreeholdFFI/include",
            pkgConfig: nil,
            providers: []
        ),

        // Swift client library
        .target(
            name: "FreeholdClient",
            dependencies: ["FreeholdFFI"],
            path: "Freehold",
            exclude: [
                "FreeholdApp.swift", // App entry point not needed for library
                "Frameworks",
                "Assets.xcassets",
                "Info.plist"
            ],
            sources: [
                "FreeholdClient.swift",
                "VPNManager.swift"
            ]
        ),

        // Tests
        .testTarget(
            name: "FreeholdClientTests",
            dependencies: ["FreeholdClient"],
            path: "Tests"
        ),
    ]
)
