/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
@testable import OTP

/**
 * Tests the OTP generation APIs.
 */

class OTPGenerationTests: XCTestCase {

    // MARK: - Requests

    /**
     * Tests that HOTP requests are correctly configured.
     */

    func testHOTPRequestValues() {

        let request = OTPGenerationRequest.hotp(counter: 1, sharedSecret: "a2", codeLength: 8)
        XCTAssertEqual(request.movingFactor, "0000000000000001")
        XCTAssertEqual(request.sharedSecret, "a2")
        XCTAssertEqual(request.codeLength, 8)
        XCTAssertEqual(request.hmac, .sha1)

    }

    /**
     * Tests that TOTP requests are correctly configured.
     */

    func testTOTPRequestValues() {

        let totpVectors = OTPTestSuite.totp()

        for totpVector in totpVectors {

            let request = totpVector.makeRequest()

            XCTAssertEqual(request.movingFactor, totpVector.movingFactor)
            XCTAssertEqual(request.sharedSecret, totpVector.sharedSecret)
            XCTAssertEqual(request.codeLength, totpVector.codeLength)
            XCTAssertEqual(request.hmac, totpVector.hmac)

        }

    }

    // MARK: - Generation

    /**
     * Tests that the moving factor is correctly authenticated with HMAC.
     */

    func testMovingFactorHMAC() {

        let testHashes = OTPTestSuite.movingFactorHash()

        for testHash in testHashes {
            let digest = OTPGenerator.authenticate(testHash.0)
            XCTAssertEqual(digest, testHash.1)
        }

    }

    /**
     * Tests the truncation method.
     */

    func testTruncation() {

        let truncationVectors = OTPTestSuite.truncation()

        for truncationVector in truncationVectors {
            let truncatedDigest = OTPGenerator.truncateDigest(truncationVector.1, length: truncationVector.0)
            XCTAssertEqual(truncatedDigest, truncationVector.2)
        }

    }

    /**
     * Tests generating TOTPs.
     */

    func testTOTP() {

        let totpVectors = OTPTestSuite.totp()

        for totpVector in totpVectors {

            let request = totpVector.makeRequest()
            let code = OTPGenerator.generateCode(for: request)

            let hash = OTPGenerator.authenticate(request)
            XCTAssertEqual(hash, totpVector.expectedHash)

            XCTAssertEqual(code, totpVector.expectedTOTP)

        }

    }

}
