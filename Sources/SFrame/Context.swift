// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

private protocol KeyContext {
    var key: SymmetricKey { get }
    var salt: ContiguousBytes { get }
}

private struct SendKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
    private(set) var counter: Counter

    mutating func increment() {
        self.counter += 1
    }
}

private struct ReceiveKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
}

/// SFrame Implementation.
public class Context: SFrame {
    private var sendKeys: [KeyId: SendKeyContext] = [:]
    private var recvKeys: [KeyId: ReceiveKeyContext] = [:]
    private let crypto: any CryptoProvider

    public init(provider: some CryptoProvider) {
        self.crypto = provider
    }

    public func addKey(_ keyId: KeyId, key: SymmetricKey, usage: KeyUsage) throws {
        // Check for existing.
        if usage == .encrypt && self.recvKeys[keyId] != nil ||
            usage == .decrypt && self.sendKeys[keyId] != nil {
            throw SFrameError.existingKey
        }

        let derived = try key.sframeDerive(keyId: keyId,
                                           provider: self.crypto)
        switch usage {
        case .encrypt:
            self.sendKeys[keyId] = .init(key: derived.key, salt: derived.salt, counter: 0)

        case .decrypt:
            self.recvKeys[keyId] = .init(key: derived.key, salt: derived.salt)
        }
    }

    public func protect(_ keyId: KeyId, plaintext: Data, metadata: Data?) throws -> Data {
        // Ensure we have a matching encryption key.
        guard var context = self.sendKeys[keyId] else {
            throw SFrameError.missingKey
        }

        // Derive the nonce.
        let nonceBytes = try self.formNonce(counter: context.counter, salt: context.salt)

        // Prepare the header & aad.
        let header = Header(keyId: keyId, counter: context.counter)
        var aad = Data()
        header.encode(into: &aad)
        if let metadata {
            aad.append(metadata)
        }

        // Seal.
        let sealedBox = try self.crypto.seal(plainText: plaintext,
                                             using: context.key,
                                             nonce: .init(nonceBytes),
                                             authenticating: aad)
        context.increment()
        self.sendKeys[keyId] = context
        let cipherText = Ciphertext(header: header,
                                    encrypted: sealedBox.encrypted,
                                    authenticationTag: sealedBox.authTag)
        let maxHeaderSize = 17
        var data = Data(capacity: sealedBox.encrypted.count + sealedBox.authTag.count + maxHeaderSize)
        cipherText.encode(into: &data)
        return data
    }

    public func unprotect(ciphertext: Data, metadata: Data?) throws -> Data {
        // Decode the constituant parts.
        var read = 0
        let ciphertext = try Ciphertext(tagLength: self.crypto.suite.nt, from: ciphertext, read: &read)

        // Ensure we have a matching decryption key.
        guard let context = self.recvKeys[ciphertext.header.keyId] else {
            throw SFrameError.missingKey
        }

        let nonce = try self.formNonce(counter: ciphertext.header.counter, salt: context.salt)
        var result = Data()
        ciphertext.header.encode(into: &result)
        if let metadata {
            result.append(metadata)
        }
        let aad = result
        let sealedBox = SealedDataBox(authTag: ciphertext.authenticationTag,
                                      encrypted: ciphertext.encrypted,
                                      nonceBytes: nonce)
        return try self.crypto.open(box: sealedBox, using: context.key, authenticating: aad)
    }

    private func formNonce(counter: Counter, salt: some ContiguousBytes) throws(DataError) -> Data {
        let nonce = Data(contiguousNoCopy: salt)
        precondition(nonce.count == self.crypto.suite.nn)
        var counterData = Data(count: self.crypto.suite.nn)
        withUnsafeBytes(of: counter.bigEndian) { bytes in
            let size = MemoryLayout<Counter>.size
            let offset = self.crypto.suite.nn - size
            counterData.replaceSubrange(offset..<nonce.count, with: bytes)
        }
        return try nonce ^ counterData
    }
}
