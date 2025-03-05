// swift-tools-version: 6.0

import PackageDescription

/// SFrame Package Description.
public let package = Package(
    name: "swift-sframe",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "SFrame",
            targets: ["SFrame"])
    ],
    dependencies: [
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.58.2"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "4.0.0")
    ],
    targets: [
        .target(
            name: "SFrame",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto")
            ],
            plugins: [
                .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLintPlugins")
            ]),
        .testTarget(
            name: "SFrameTests",
            dependencies: ["SFrame"],
            resources: [.process("rfc_vectors.json")],
            plugins: [
                .plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLintPlugins")
            ])
    ]
)
