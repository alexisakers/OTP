/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
import Foundation
@testable import OTP

/**
 * Tests the Key URI decoder.
 */

class OTPKeyURIDecoderTests: XCTestCase {

    /**
     * Tests decoding the information label of barcodes.
     */

    func testDecodingLabel() {

        let label1 = "alice@gmail.com"
        let decodedLabel1 = OTPKeyURIDecoder.decodeLabel(label1)
        XCTAssertEqual(decodedLabel1?.accountName, "alice@gmail.com")
        XCTAssertNil(decodedLabel1?.issuerPrefix)

        let label2 = "Example:alice@gmail.com"
        let decodedLabel2 = OTPKeyURIDecoder.decodeLabel(label2)
        XCTAssertEqual(decodedLabel2?.accountName, "alice@gmail.com")
        XCTAssertEqual(decodedLabel2?.issuerPrefix, "Example")

        let label3 = "Provider1:Alice%20Smith"
        let decodedLabel3 = OTPKeyURIDecoder.decodeLabel(label3)
        XCTAssertEqual(decodedLabel3?.accountName, "Alice Smith")
        XCTAssertEqual(decodedLabel3?.issuerPrefix, "Provider1")

        let label4 = "Big%20Corporation%3A%20alice%40bigco.com"
        let decodedLabel4 = OTPKeyURIDecoder.decodeLabel(label4)
        XCTAssertEqual(decodedLabel4?.accountName, "alice@bigco.com")
        XCTAssertEqual(decodedLabel4?.issuerPrefix, "Big Corporation")

    }

    /**
     * Tests parsing valid URIs.
     */

    func testParsingValidURIs() {

        // TOTP

        let totpSimpleURI = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

        guard let totpSimpleKey = OTPKeyURIDecoder.decodeURI(totpSimpleURI) else {
            XCTFail("Could not decode simple TOTP URI.")
            return
        }

        XCTAssertEqual(totpSimpleKey.accountName, "alice@google.com")
        XCTAssertEqual(totpSimpleKey.issuerPrefix, "Example")
        XCTAssertEqual(totpSimpleKey.issuer, "Example")
        XCTAssertEqual(totpSimpleKey.algorithm, .sha1)
        XCTAssertEqual(totpSimpleKey.counter, 0)
        XCTAssertEqual(totpSimpleKey.digits, 6)
        XCTAssertEqual(totpSimpleKey.mode, .totp)
        XCTAssertEqual(totpSimpleKey.period, 30)
        XCTAssertEqual(totpSimpleKey.sharedSecret, "48656C6C6F21DEADBEEF")

        let totpCompleteURI = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=15"

        guard let totpCompleteKey = OTPKeyURIDecoder.decodeURI(totpCompleteURI) else {
            XCTFail("Could not decode complete TOTP URI.")
            return
        }

        XCTAssertEqual(totpCompleteKey.accountName, "john.doe@email.com")
        XCTAssertEqual(totpCompleteKey.issuerPrefix, "ACME Co")
        XCTAssertEqual(totpCompleteKey.issuer, "ACME Co")
        XCTAssertEqual(totpCompleteKey.algorithm, .sha256)
        XCTAssertEqual(totpCompleteKey.counter, 0)
        XCTAssertEqual(totpCompleteKey.digits, 8)
        XCTAssertEqual(totpCompleteKey.mode, .totp)
        XCTAssertEqual(totpCompleteKey.period, 15)
        XCTAssertEqual(totpCompleteKey.sharedSecret, "3DC6CAA4824A6D288767B2331E20B43166CB85D9")

        // HOTP

        let hotpSimpleURI = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=2"

        guard let hotpSimpleKey = OTPKeyURIDecoder.decodeURI(hotpSimpleURI) else {
            XCTFail("Could not decode simple HOTP URI.")
            return
        }

        XCTAssertEqual(hotpSimpleKey.accountName, "alice@google.com")
        XCTAssertEqual(hotpSimpleKey.issuerPrefix, "Example")
        XCTAssertEqual(hotpSimpleKey.issuer, "Example")
        XCTAssertEqual(hotpSimpleKey.algorithm, .sha1)
        XCTAssertEqual(hotpSimpleKey.counter, 2)
        XCTAssertEqual(hotpSimpleKey.digits, 6)
        XCTAssertEqual(hotpSimpleKey.mode, .hotp)
        XCTAssertEqual(hotpSimpleKey.period, 30)
        XCTAssertEqual(hotpSimpleKey.sharedSecret, "48656C6C6F21DEADBEEF")

    }

    /**
     * Tests parsing invalid URIs.
     */

    func testParsingInvalidURIs() {

        let notAnURI = OTPKeyURIDecoder.decodeURI("hello,world\0")
        XCTAssertNil(notAnURI)

        let wrongScheme = OTPKeyURIDecoder.decodeURI("https://www.apple.com/")
        XCTAssertNil(wrongScheme)

        let noHost = OTPKeyURIDecoder.decodeURI("otpauth://")
        XCTAssertNil(noHost)

        let noQuery = OTPKeyURIDecoder.decodeURI("otpauth://totp/label")
        XCTAssertNil(noQuery)

        let invalidMode = OTPKeyURIDecoder.decodeURI("otpauth://otp/label?secret=abc")
        XCTAssertNil(invalidMode)

        let colonContainingLabel = OTPKeyURIDecoder.decodeURI("otpauth://totp/prefix:username:alexis?secret=abc")
        XCTAssertNil(colonContainingLabel)

        let missingSecret = OTPKeyURIDecoder.decodeURI("otpauth://totp/prefix:username?key=abc")
        XCTAssertNil(missingSecret)

        let missingCounter = OTPKeyURIDecoder.decodeURI("otpauth://hotp/prefix:username?secret=JBSWY3DPEHPK3PXP")
        XCTAssertNil(missingCounter)

    }

}
