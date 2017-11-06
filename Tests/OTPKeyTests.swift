/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
import Foundation
@testable import OTP

/**
 * Tests the key class.
 */

class OTPKeyTests: XCTestCase {

    /**
     * Tests making an HOTP request.
     */

    func testMakeHOTPRequest() {

        let sharedSecret: Data = "3ca9daa58a6b4b043a380cdc026f8413ca0138cd895ae3cd03feb97f13ab33bc"
        let key = OTPKey(mode: .hotp, accountName: "alexaubry", issuerPrefix: "GitHub", sharedSecret: sharedSecret)
        key.counter = 6
        key.digits = 8

        let request = key.makeOTPRequest(currentTime: Date().timeIntervalSince1970)

        switch request {
        case .hotp:

            XCTAssertEqual(request.codeLength, 8)
            XCTAssertEqual(request.hmac, .sha1)
            XCTAssertEqual(request.movingFactor, "0000000000000006")
            XCTAssertEqual(request.sharedSecret, sharedSecret)

        default:
            XCTFail("Expected a OTPGenerationRequest.hotp value.")
        }

    }

    func testMakeTOTPRequest() {

        // Initial Request

        let sharedSecret: Data = "3ca9daa58a6b4b043a380cdc026f8413ca0138cd895ae3cd03feb97f13ab33bc"
        let key = OTPKey(mode: .totp, accountName: "alexaubry", issuerPrefix: "GitHub", sharedSecret: sharedSecret)
        key.counter = 6
        key.digits = 4
        key.algorithm = .sha512
        key.initialTime = 1000
        key.period = 15

        let currentTime = Date().timeIntervalSince1970
        let request = key.makeOTPRequest(currentTime: currentTime)

        let timeFactor = floor((currentTime - key.initialTime) / key.period)
        let expectedMovingFactor = OTPGenerationRequest.makeMovingFactorBytes(with: UInt64(timeFactor))

        switch request {
        case .totp:

            XCTAssertEqual(request.codeLength, 4)
            XCTAssertEqual(request.hmac, .sha512)
            XCTAssertEqual(request.movingFactor, expectedMovingFactor)
            XCTAssertEqual(request.sharedSecret, sharedSecret)

        default:
            XCTFail("Expected a OTPGenerationRequest.totp value.")
        }

        // Change Algorithm

        key.algorithm = .sha256
        let sha256Request = key.makeOTPRequest(currentTime: currentTime)

        key.algorithm = .sha1
        let sha1Request = key.makeOTPRequest(currentTime: currentTime)

        switch request {
        case .totp:
            XCTAssertEqual(sha256Request.hmac, .sha256)
            XCTAssertEqual(sha256Request.movingFactor, expectedMovingFactor)
            XCTAssertEqual(sha256Request.sharedSecret, sharedSecret)

            XCTAssertEqual(sha1Request.hmac, .sha1)
            XCTAssertEqual(sha1Request.movingFactor, expectedMovingFactor)
            XCTAssertEqual(sha1Request.sharedSecret, sharedSecret)

        default:
            XCTFail("Expected a OTPGenerationRequest.totp value.")
        }


    }

}
