import Crypto
import Foundation
import SFrame
import Testing

private func makeSFrame(_ suite: UInt32) throws -> SFrame {
    // Prepare.
    guard let supported = CipherSuites(rawValue: suite),
          let resolvedSuite = registry[supported] else {
        throw TestError.unsupportedCipherSuite
    }
    return Context(provider: SwiftCryptoProvider(suite: resolvedSuite))
}

private struct SFrameVectorTests {
    @Test("Encrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorEncrypt(_ vector: SFrameVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addKey(vector.kid, key: baseKey, usage: .encrypt)
        // Spin up to the vector's counter value.
        for _ in 0..<vector.ctr {
            _ = try sframe.encrypt(vector.kid, plaintext: .init(), metadata: vector.metadata)
        }
        let cipherText = try sframe.encrypt(vector.kid, plaintext: vector.plainText, metadata: vector.metadata)
        #expect(cipherText == vector.cipherText)
    }

    @Test("Decrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorDecrypt(_ vector: SFrameVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addKey(vector.kid, key: baseKey, usage: .decrypt)
        let decrypted = try sframe.decrypt(ciphertext: vector.cipherText, metadata: vector.metadata)
        #expect(decrypted == vector.plainText)
    }
}

private struct SFrameTests {
    @Test("Key Misuse - Missing")
    func testEncryptBadKid() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        #expect(performing: {
            try sframe.encrypt(0, plaintext: .init(), metadata: nil)
        }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
    }

    @Test("Key Misuse - Existing")
    func testExistingKey() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        let keyId: KeyId = 1
        try sframe.addKey(keyId, key: .init(size: .bits128), usage: .encrypt)
        #expect(performing: {
            try sframe.addKey(keyId, key: .init(size: .bits128), usage: .encrypt)
        }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
    }

    @Test("Key Misuse - Encrypt with decrypt")
    func testEncryptWithDecryptKey() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        let keyId: KeyId = 1
        try sframe.addKey(keyId, key: .init(size: .bits128), usage: .decrypt)
        #expect(performing: {
            try sframe.encrypt(keyId, plaintext: .init(), metadata: nil)
        }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
    }

    @Test("Key Misuse - Decrypt with encrypt")
    func testDecryptWithEncryptKey() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)

        // Get some real cipher text.
        let setupKeyId: KeyId = 1
        try sframe.addKey(setupKeyId, key: .init(size: .bits128), usage: .encrypt)
        let cipherText = try sframe.encrypt(setupKeyId, plaintext: Data([1]), metadata: nil)

        // This is the test.
        let keyId: KeyId = 2
        try sframe.addKey(keyId, key: .init(size: .bits128), usage: .encrypt)
        #expect(performing: {
            try sframe.decrypt(ciphertext: cipherText, metadata: nil)
        }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
    }
}
