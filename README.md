# S(wift)Frame

Pure Swift implementation of [SFrame (RFC9605)](https://datatracker.ietf.org/doc/rfc9605/).

> [!CAUTION]
> This library only implements the basic SFrame operations, and none of the application requirements as set out in [Section 9](https://www.rfc-editor.org/rfc/rfc9605.html#section-9). It is the consumer's responsibility to adhere to these requirements in order to operate securely.

## Features

Built in [`SwiftCrypto`](https://github.com/apple/swift-crypto) bindings for `CryptoKit` on Apple platforms and `BoringSSL` fallback on Linux.

Extensible crypto provider interface through `CryptoProvider`.

Support for RFC declared cipher suites and test vectors.

## TODO

- MLS Context support.
- Performance & benchmarking.

## Usage

`Tests/SFrameTests/Example.swift` has test validated example usage.