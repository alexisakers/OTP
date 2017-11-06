/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import XCTest
import Foundation
@testable import OTP

/**
 * Tests the Key URI encoder.
 */

class OTPKeyURIEncoderTests: XCTestCase {

    func testEncodeURI() {

        let key = OTPKey(mode: .totp, accountName: "john.doe@email.com", issuerPrefix: "ACME Co", sharedSecret: "3DC6CAA4824A6D288767B2331E20B43166CB85D9")
        key.issuer = "ACME Co"
        key.algorithm = .sha256

        guard let encodedURI = OTPKeyURIEncoder.encodeKey(key) else {
            XCTFail("Could not encode TOTP URI.")
            return
        }

        let expectedURI = "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=6&period=30"

        let components = URLComponents(string: encodedURI)!
        let expectedComponents = URLComponents(string: expectedURI)!

        let queryItems = Set<URLQueryItem>(components.queryItems!.map {
            URLQueryItem(name: $0.name, value: $0.value?.removingPercentEncoding) })

        let expectedQueryItems = Set<URLQueryItem>(expectedComponents.queryItems!)

        XCTAssertEqual(components.scheme, expectedComponents.scheme)
        XCTAssertEqual(components.host, expectedComponents.host)
        XCTAssertEqual(components.path.removingPercentEncoding, expectedComponents.path)
        XCTAssertEqual(queryItems, expectedQueryItems)

    }

}
