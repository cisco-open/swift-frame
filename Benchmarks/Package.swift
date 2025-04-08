// swift-tools-version: 6.0

import PackageDescription

/// SFrame Benchmarks.
public let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(name: "swift-sframe", path: ".."),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.11.1")
    ],
    targets: [
        .executableTarget(
            name: "SFrameBenchmark",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "SFrame", package: "swift-sframe")
            ],
            path: "SFrameBenchmark",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        )
    ]
)
