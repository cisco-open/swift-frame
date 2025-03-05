// swiftlint:disable identifier_name

/// SFrame cipher suites by registered identifier.
public enum CipherSuites: CipherSuiteIdentifier, Sendable {
    case aes_128_ctr_hmac_sha256_80 = 1
    case aes_128_ctr_hmac_sha256_64 = 2
    case aes_128_ctr_hmac_sha256_32 = 3
    case aes_128_gcm_sha256_128 = 4
    case aes_256_gcm_sha512_128 = 5
}

/// Represents a cipher suite.
public struct CipherSuite: Sendable {
    // SFrame Cipher Suite Registry Identifier.
    public let identifier: CipherSuiteIdentifier
    /// Size of the hash function output.
    public let nh: Int
    /// Compound AEAD key size, if applicable.
    public let nka: Int?
    /// Size of the encryption key.
    public let nk: Int
    /// Size of the nonce.
    public let nn: Int
    /// Size of the authentication tag.
    public let nt: Int
}
// swiftlint:enable identifier_name

/// SFrame Cipher Suite Registry.
public let registry: [CipherSuites: CipherSuite] = [
    .aes_128_ctr_hmac_sha256_80: .init(identifier: 1, nh: 32, nka: 16, nk: 48, nn: 12, nt: 10),
    .aes_128_ctr_hmac_sha256_64: .init(identifier: 2, nh: 32, nka: 16, nk: 48, nn: 12, nt: 8),
    .aes_128_ctr_hmac_sha256_32: .init(identifier: 3, nh: 32, nka: 16, nk: 48, nn: 12, nt: 4),
    .aes_128_gcm_sha256_128: .init(identifier: 4, nh: 64, nka: nil, nk: 16, nn: 12, nt: 16),
    .aes_256_gcm_sha512_128: .init(identifier: 5, nh: 64, nka: nil, nk: 32, nn: 12, nt: 16)
]
