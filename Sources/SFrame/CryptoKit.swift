import CryptoKit
import Foundation

public enum CryptoKitProviderFactoryError: Error {
    case unsupportedCipherSuite
}

/// Provides CryptoKit functionality for a cipher suite.
public struct CryptoKitProviderFactory {
    /// Create a CryptoKit SFrame provider for the given cipher suite.
    /// - Parameter suite: The cipher suite to use.
    /// - Returns: A CryptoKit SFrame provider.
    public func create(suite: CipherSuite) throws -> any CryptoProvider {
        let sframeDeclared = CipherSuites(rawValue: suite.identifier)
        guard let sframeDeclared else {
            throw CryptoKitProviderFactoryError.unsupportedCipherSuite
        }
        switch sframeDeclared {
        case .aes_128_ctr_hmac_sha256_32,
                .aes_128_ctr_hmac_sha256_64,
                .aes_128_ctr_hmac_sha256_80:
            throw CryptoKitProviderFactoryError.unsupportedCipherSuite

        case .aes_128_gcm_sha256_128:
            return CryptoKitProvider<SHA256>(suite: suite)

        case .aes_256_gcm_sha512_128:
            return CryptoKitProvider<SHA512>(suite: suite)
        }
    }
}

extension AES.GCM.SealedBox: SealedBox {
    public var authTag: Data { self.tag }
    public var encrypted: Data { self.ciphertext }
    public var nonceBytes: Data { .init(self.nonce) }

    internal init(_ box: SealedBox) throws {
        try self.init(nonce: .init(data: box.nonceBytes), ciphertext: box.encrypted, tag: box.authTag)
    }
}

public struct CryptoKitProvider<Hash: HashFunction>: CryptoProvider {
    public let suite: CipherSuite

    public func seal(plainText: Data, using: SymmetricKey, nonce: Data, authenticating: Data) throws -> any SealedBox {
        try AES.GCM.seal(plainText, using: using, nonce: .init(data: nonce), authenticating: authenticating)
    }

    public func open(box: any SealedBox, using: SymmetricKey, authenticating: Data) throws -> Data {
        try AES.GCM.open(.init(box), using: using, authenticating: authenticating)
    }

    public func hkdfExpand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) -> SymmetricKey {
        HKDF<Hash>.expand(pseudoRandomKey: pseudoRandomKey, info: info, outputByteCount: outputByteCount)
    }

    public func hkdfExtract(inputKeyMaterial: SymmetricKey, salt: Data?) -> HashedAuthenticationCode<Hash> {
        HKDF<Hash>.extract(inputKeyMaterial: inputKeyMaterial, salt: salt)
    }
}
