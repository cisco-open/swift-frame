// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Benchmark
import Crypto
import Foundation
import SFrame

internal let benchmarks: @Sendable () -> Void = { // swiftlint:disable:this closure_body_length
    Benchmark("Serialize Headers") { benchmark in
        var headers: [Header] = []
        var datas: [Data] = []
        for _ in benchmark.scaledIterations {
            headers.append(.init(keyId: .random(in: 0..<KeyId.max), counter: .random(in: 0..<Counter.max)))
            datas.append(.init(capacity: 17))
        }

        benchmark.startMeasurement()
        for index in benchmark.scaledIterations {
            blackHole(headers[index].encode(into: &datas[index]))
        }
    }

    Benchmark("Deserialize Headers") { benchmark in
        var datas: [Data] = []
        for _ in benchmark.scaledIterations {
            let header = Header(keyId: .random(in: 0..<KeyId.max), counter: .random(in: 0..<Counter.max))
            var data = Data(capacity: 17)
            header.encode(into: &data)
            datas.append(data)
        }

        benchmark.startMeasurement()
        for index in benchmark.scaledIterations {
            var read = 0
            try blackHole(Header(from: datas[index], read: &read))
        }
    }

    for suite in registry {
        let kid: KeyId = 1_234
        let key = SymmetricKey(size: SymmetricKeySize(bitCount: suite.value.nk * 8))
        let plain = Data("PLAIN TEXT".utf8)
        let metadata = Data("METADATA".utf8)

        Benchmark("Protect", configuration: .init(tags: ["suite": "\(suite.key)"])) { benchmark in
            let provider = SwiftCryptoProvider(suite: suite.value)
            let sframe = Context(provider: provider)
            try sframe.addKey(kid, key: key, usage: .encrypt)
            benchmark.startMeasurement()
            try blackHole(sframe.protect(kid, plaintext: plain, metadata: metadata))
        }

        Benchmark("Unprotect", configuration: .init(tags: ["suite": "\(suite.key)"])) { benchmark in
            let provider = SwiftCryptoProvider(suite: suite.value)
            let sframe = Context(provider: provider)
            try sframe.addKey(kid, key: key, usage: .encrypt)
            let encrypted = try sframe.protect(kid, plaintext: plain, metadata: metadata)
            let decryptContext = Context(provider: provider)
            try decryptContext.addKey(kid, key: key, usage: .decrypt)
            benchmark.startMeasurement()
            blackHole(try decryptContext.unprotect(ciphertext: encrypted, metadata: metadata))
        }
    }
}
