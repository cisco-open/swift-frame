import Crypto
import Foundation

extension SymmetricKey {
    private static let keyLabelPrefix = "SFrame 1.0 Secret key "
    private static let saltLabelPrefix = "SFrame 1.0 Secret salt "

    /// Perform the SFrame key derivation on this base key.
    /// - Parameter keyId: The base key's identifier.
    /// - Parameter provider: Crypto operation provider.
    /// - Parameter cipherSuite: The cipher suite to use.
    /// - Returns: The derived key and salt.
    internal func sframeDerive(keyId: KeyId,
                               provider: some CryptoProvider) throws -> (key: SymmetricKey, salt: SymmetricKey) {
        // Get secret.
        let secret = try SymmetricKey(data: provider.hkdfExtract(inputKeyMaterial: self, salt: .none))

        // Derive Key.
        let keyLabel = try self.buildKeyLabel(Self.keyLabelPrefix, keyId: keyId, cipherSuite: provider.suite)
        let key = try provider.hkdfExpand(pseudoRandomKey: secret, info: keyLabel, outputByteCount: provider.suite.nk)

        // Derive Salt.
        let saltLabel = try self.buildKeyLabel(Self.saltLabelPrefix, keyId: keyId, cipherSuite: provider.suite)
        let salt = try provider.hkdfExpand(pseudoRandomKey: secret, info: saltLabel, outputByteCount: provider.suite.nn)
        return (key: key, salt: salt)
    }

    private func buildKeyLabel(_ label: String, keyId: KeyId, cipherSuite: CipherSuite) throws -> Data {
        guard var data = label.data(using: .utf8) else {
            throw SFrameError.badLabel
        }
        data.append(Swift.withUnsafeBytes(of: keyId.bigEndian) { Data($0) })
        data.append(Swift.withUnsafeBytes(of: UInt16(cipherSuite.identifier).bigEndian) { Data($0) })
        return data
    }
}
