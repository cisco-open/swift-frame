import Crypto
import Foundation
@testable import SFrame
import Testing

@Test("Missing KID Throws")
internal func testEncryptBadKid() throws {
    let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
    let provider = SwiftCryptoProvider<SHA256>(suite: suite)
    let sframe = Context(provider: provider)
    #expect(performing: {
        try sframe.encrypt(0, metadata: nil, plaintext: .init())
    }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
}

private func makeSFrame(_ suite: UInt32) -> SFrame? {
    // Prepare.
    let factory = SwiftCryptoProviderFactory()
    var provider: (any CryptoProvider)?
    withKnownIssue("Unsupported Cipher Suite: \(suite)", isIntermittent: true) {
        guard let supported = CipherSuites(rawValue: suite),
              let resolvedSuite = registry[supported] else { return }
        provider = try factory.create(suite: resolvedSuite)
    }
    return provider != nil ? Context(provider: provider!) : nil // swiftlint:disable:this force_unwrapping
}

@Test("SFrame Encrypt", arguments: Fixtures.testVectors.sframe)
internal func testSFrameVectorEncrypt(_ vector: SFrameVector) throws {
    guard var sframe = makeSFrame(vector.cipherSuite) else {
        return
    }
    let baseKey = SymmetricKey(data: vector.baseKey)
    try sframe.addSendKey(vector.kid, key: baseKey, currentCounter: vector.ctr)
    let cipherText = try sframe.encrypt(vector.kid, metadata: vector.metadata, plaintext: vector.plainText)
    var encoded = Data()
    try cipherText.encode(into: &encoded)
    #expect(encoded == vector.cipherText)
}

@Test("SFrame Decrypt", arguments: Fixtures.testVectors.sframe)
internal func testSFrameVectorDecrypt(_ vector: SFrameVector) throws {
    guard var sframe = makeSFrame(vector.cipherSuite) else {
        return
    }
    let baseKey = SymmetricKey(data: vector.baseKey)
    try sframe.addReceiveKey(vector.kid, key: baseKey)
    let decrypted = try sframe.decrypt(metadata: vector.metadata, ciphertext: vector.cipherText)
    #expect(decrypted == vector.plainText)
}
