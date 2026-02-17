// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "FreeholdWSClientApp",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "FreeholdWSClient", targets: ["FreeholdWSClient"]),
    ],
    targets: [
        // Rust static library (built by build-rust.sh → XCFramework)
        .binaryTarget(
            name: "FreeholdWSClientLib",
            path: "build/FreeholdWSClient.xcframework"
        ),

        // System module that exposes the C header to Swift
        .systemLibrary(
            name: "FreeholdWSClient",
            path: "FreeholdWSClient/include"
        ),
    ]
)
