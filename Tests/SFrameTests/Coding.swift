// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
@testable import SFrame
import Testing

private struct CodingTests {
    @Test("Header", arguments: Fixtures.testVectors.header)
    private func testHeaderCoding(_ serialized: HeaderTestVector) throws {
        // Deserialize the kid & ctr into a header, ensure they match.
        let header = Header(serialized: serialized)
        #expect(header.keyId == serialized.kid)
        #expect(header.counter == serialized.ctr)

        // Encode the deserialized header, ensure it matches the serialized header bytes.
        var encoded = Data()
        header.encode(into: &encoded)
        #expect(encoded == serialized.encoded)

        // Decode the serialized header, ensure it matches the constructed header.
        var read = 0
        let decoded = try Header(from: encoded, read: &read)
        #expect(decoded == header)
    }

    @Test("Bad Header")
    func testBadHeader() {
        let data = Data()
        var read = 0
        #expect(throws: SFrameError.malformedCipherText) {
            try Header(from: data, read: &read)
        }

        let badData = Data([0xFF])
        read = 0
        #expect(throws: SFrameError.malformedCipherText) {
            try Header(from: badData, read: &read)
        }
    }

    @Test("CipherText")
    func testCipherTextCoding() throws {
        // Make an example CipherText.
        let header = Header(keyId: 1234, counter: 5678) // swiftlint:disable:this number_separator
        let encrypted = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let tag = Data([0xBA, 0xDC, 0x0F, 0xFE])
        let cipherText = Ciphertext(header: header, encrypted: encrypted, authenticationTag: tag)

        // Encode it.
        var encoded = Data()
        cipherText.encode(into: &encoded)

        // Ensure encoded header data matches.
        var expected = Data()
        header.encode(into: &expected)
        let encodedHeader = encoded[..<expected.count]
        #expect(encodedHeader == expected)

        // Then encrypted data matches.
        var offset = encodedHeader.count
        let encryptedRange = encoded[offset..<offset + encrypted.count]
        #expect(encryptedRange == encrypted)
        offset += encrypted.count

        // Then the auth tag matches.
        let tagRange = encoded.advanced(by: offset)
        #expect(tagRange == tag)

        // And backwards.
        var ctOffset = 0
        let decoded = try Ciphertext(tagLength: tag.count, from: encoded, read: &ctOffset)
        #expect(decoded.header == header)
        #expect(decoded.encrypted == encrypted)
        #expect(decoded.authenticationTag == tag)
    }
}

extension Header {
    internal init(serialized: HeaderTestVector) {
        let kid = serialized.kid
        let ctr = serialized.ctr
        self.init(keyId: kid, counter: ctr)
    }
}

extension Header: Equatable {
    public static func == (lhs: Header, rhs: Header) -> Bool {
        lhs.keyId == rhs.keyId && lhs.counter == rhs.counter
    }
}
