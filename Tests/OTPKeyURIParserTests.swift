/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
import Foundation
@testable import OTP

/**
 * Tests the Key URI parser.
 */

class OTPKeyURIParserTests: XCTestCase {

    /**
     * Tests parsing the information label of barcodes.
     */

    func testParsingLabel() {

        let label1 = "alice@gmail.com"
        let parsedLabel1 = OTPKeyURIParser.parseLabel(label1)
        XCTAssertEqual(parsedLabel1?.accountName, "alice@gmail.com")
        XCTAssertNil(parsedLabel1?.issuerPrefix)

        let label2 = "Example:alice@gmail.com"
        let parsedLabel2 = OTPKeyURIParser.parseLabel(label2)
        XCTAssertEqual(parsedLabel2?.accountName, "alice@gmail.com")
        XCTAssertEqual(parsedLabel2?.issuerPrefix, "Example")

        let label3 = "Provider1:Alice%20Smith"
        let parsedLabel3 = OTPKeyURIParser.parseLabel(label3)
        XCTAssertEqual(parsedLabel3?.accountName, "Alice Smith")
        XCTAssertEqual(parsedLabel3?.issuerPrefix, "Provider1")

        let label4 = "Big%20Corporation%3A%20alice%40bigco.com"
        let parsedLabel4 = OTPKeyURIParser.parseLabel(label4)
        XCTAssertEqual(parsedLabel4?.accountName, "alice@bigco.com")
        XCTAssertEqual(parsedLabel4?.issuerPrefix, "Big Corporation")

    }

    /**
     * Tests parsing valid URIs.
     */

    func testParsingValidURIs() {

        // TOTP

        let totpSimpleURI = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"

        guard let totpSimpleKey = OTPKeyURIParser.parseURI(totpSimpleURI) else {
            XCTFail("Could not parse simple TOTP URI.")
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

        guard let totpCompleteKey = OTPKeyURIParser.parseURI(totpCompleteURI) else {
            XCTFail("Could not parse simple TOTP URI.")
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

        guard let hotpSimpleKey = OTPKeyURIParser.parseURI(hotpSimpleURI) else {
            XCTFail("Could not parse simple HOTP URI.")
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

        let notAnURI = OTPKeyURIParser.parseURI("hello,world\0")
        XCTAssertNil(notAnURI)

        let wrongScheme = OTPKeyURIParser.parseURI("https://www.apple.com/")
        XCTAssertNil(wrongScheme)

        let noHost = OTPKeyURIParser.parseURI("otpauth://")
        XCTAssertNil(noHost)

        let noQuery = OTPKeyURIParser.parseURI("otpauth://totp/label")
        XCTAssertNil(noQuery)

        let invalidMode = OTPKeyURIParser.parseURI("otpauth://otp/label?secret=abc")
        XCTAssertNil(invalidMode)

        let colonContainingLabel = OTPKeyURIParser.parseURI("otpauth://totp/prefix:username:alexis?secret=abc")
        XCTAssertNil(colonContainingLabel)

        let missingSecret = OTPKeyURIParser.parseURI("otpauth://totp/prefix:username?key=abc")
        XCTAssertNil(missingSecret)

        let missingCounter = OTPKeyURIParser.parseURI("otpauth://hotp/prefix:username?secret=JBSWY3DPEHPK3PXP")
        XCTAssertNil(missingCounter)

    }

}
