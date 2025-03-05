import Crypto
import Foundation

private protocol KeyContext {
    var key: SymmetricKey { get }
    var salt: ContiguousBytes { get }
}

private struct SendKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
    let counter: Counter

    static func incrementing(_ context: Self) -> Self {
        .init(key: context.key,
              salt: context.salt,
              counter: context.counter + 1)
    }
}

private struct ReceiveKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
}

public class Context: SFrame {
    private var keys: [KeyId: KeyContext] = [:]
    private let crypto: any CryptoProvider

    public init(provider: any CryptoProvider) {
        self.crypto = provider
    }

    public func addSendKey(_ keyId: KeyId, key: SymmetricKey, currentCounter: Counter = 0) throws {
        guard self.keys[keyId] == nil else {
            throw SFrameError.invalidKeyId
        }
        let derived = try key.sframeDerive(keyId: keyId,
                                           provider: self.crypto)
        self.keys[keyId] = SendKeyContext(key: derived.key,
                                          salt: derived.salt,
                                          counter: currentCounter)
    }

    public func addReceiveKey(_ keyId: KeyId, key: SymmetricKey) throws {
        guard self.keys[keyId] == nil else {
            throw SFrameError.invalidKeyId
        }
        let derived = try key.sframeDerive(keyId: keyId,
                                           provider: self.crypto)
        self.keys[keyId] = ReceiveKeyContext(key: derived.key, salt: derived.salt)
    }

    public func encrypt(_ keyId: KeyId, metadata: Data?, plaintext: Data) throws -> Data {
        // Ensure we have a matching encryption key.
        guard let context = self.keys[keyId],
              let sendContext = context as? SendKeyContext else {
            throw SFrameError.invalidKeyId
        }

        // Derive the nonce.
        let nonceBytes = try self.formNonce(counter: sendContext.counter, salt: sendContext.salt)

        // Prepare the header & aad.
        let header = Header(keyId: keyId, counter: sendContext.counter)
        var aad = Data()
        try header.encode(into: &aad)
        if let metadata {
            aad.append(metadata)
        }

        // Seal.
        let sealedBox = try self.crypto.seal(plainText: plaintext,
                                             using: sendContext.key,
                                             nonce: .init(nonceBytes),
                                             authenticating: aad)
        self.keys[keyId] = SendKeyContext.incrementing(sendContext)
        let cipherText = CipherText(header: header,
                                    encrypted: sealedBox.encrypted,
                                    authenticationTag: sealedBox.authTag)
        var data = Data(capacity: sealedBox.encrypted.count + sealedBox.authTag.count + 16)
        try cipherText.encode(into: &data)
        return data
    }

    public func decrypt(metadata: Data, ciphertext: Data) throws -> Data {
        // Decode the constituant parts.
        var read = 0
        let ciphertext = try CipherText(tagLength: self.crypto.suite.nt, from: ciphertext, read: &read)

        // Ensure we have a matching decryption key.
        guard let context = self.keys[ciphertext.header.keyId],
              context is ReceiveKeyContext else {
            throw SFrameError.invalidKeyId
        }

        let nonce = try self.formNonce(counter: ciphertext.header.counter, salt: context.salt)
        var result = Data()
        try ciphertext.header.encode(into: &result)
        result.append(metadata)
        let aad = result
        let sealedBox = SealedDataBox(authTag: ciphertext.authenticationTag,
                                      encrypted: ciphertext.encrypted,
                                      nonceBytes: nonce)
        return try self.crypto.open(box: sealedBox, using: context.key, authenticating: aad)
    }

    private func formNonce(counter: Counter, salt: some ContiguousBytes) throws -> Data {
        let nonce = Data(contiguousNoCopy: salt)
        guard nonce.count == self.crypto.suite.nn else {
            throw SFrameError.badParameter
        }
        var counterData = Data(count: self.crypto.suite.nn)
        withUnsafeBytes(of: counter.bigEndian) { bytes in
            let size = MemoryLayout<Counter>.size
            let offset = self.crypto.suite.nn - size
            counterData.replaceSubrange(offset..<nonce.count, with: bytes)
        }
        return try nonce ^ counterData
    }
}
