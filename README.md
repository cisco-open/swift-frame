<!--
SPDX-FileCopyrightText: 2025 Cisco

SPDX-License-Identifier: Apache-2.0
-->

# S(wift)Frame

Pure Swift implementation of [SFrame (RFC9605)](https://datatracker.ietf.org/doc/rfc9605/).

> [!CAUTION]
> This library only implements the basic SFrame operations, and none of the application requirements as set out in [Section 9](https://www.rfc-editor.org/rfc/rfc9605.html#section-9). It is the consumer's responsibility to adhere to these requirements in order to operate securely.

## Features

The built in [`SwiftCrypto`](https://github.com/apple/swift-crypto) provider allows a dependency-less experience on Apple platforms via `CryptoKit` when using GCM mode ciphers. On Linux, or when using CTR mode ciphers, `SwiftCrypto` provides a `CryptoKit` compatible API using `BoringSSL`.

Extensible crypto provider interface through `CryptoProvider`.

Support for RFC declared cipher suites and test vectors.

## Install

To use `swift-frame` in your project, add it as a dependency to your `Package.swift` like so:

```swift
dependencies: [
    .package(url: "https://github.com/cisco-open/swift-frame.git", from: "1.0.0")
],
```

and include it in a target like:

```swift
targets: [
    .target(
        name: "SFrame",
        dependencies: [
            .product(name: "SFrame", package: "swift-frame"),
        ]
    )
]
```

To build and test locally, you invoke Swift in the usual way:

```bash
swift build
swift test
```

## TODO

- Performance & benchmarking.
- Consider an option to remove the `SwiftCrypto` dependency when Apple && GCM-only is okay.

## Usage

`Tests/SFrameTests/Example.swift` has test validated example usage.
