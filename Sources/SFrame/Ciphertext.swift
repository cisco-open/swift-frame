// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SFrame Encryption Result.
internal struct Ciphertext {
    /// SFrame Header.
    internal let header: Header
    /// The encrypted payload.
    internal let encrypted: Data
    /// The authentication tag.
    internal let authenticationTag: Data

    internal init(header: Header, encrypted: Data, authenticationTag: Data) {
        self.header = header
        self.encrypted = encrypted
        self.authenticationTag = authenticationTag
    }

    /// Decode an SFrame CipherText from its wire format.
    /// - Parameters:
    ///  - tagLength: The length of the authentication tag.
    ///  - data: The encoded data.
    ///  - read: The running offset read from data, in bytes.
    internal init(tagLength: Int, from data: Data, read: inout Int) throws(SFrameError) {
        self.header = try .init(from: data, read: &read)
        guard data.count - read >= tagLength else {
            throw SFrameError.malformedCipherText
        }
        self.encrypted = data[read..<(data.count - tagLength)]
        read += self.encrypted.count
        self.authenticationTag = data[read..<data.count]
        read += self.authenticationTag.count
    }

    /// Encode the SFrame CipherText into its wire format.
    /// - Parameter data: The data to encode into.
    internal func encode(into data: inout Data) {
        self.header.encode(into: &data)
        data.append(self.encrypted)
        data.append(self.authenticationTag)
    }
}
