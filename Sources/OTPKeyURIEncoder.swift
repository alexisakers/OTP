/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation

/**
 * Encodes OTP keys in the google-authenticator URI format.
 */

public enum OTPKeyURIEncoder {

    /**
     * Encodes the specified OTP key in the google-authenticator URI format.
     *
     * - parameter key: The OTP key to encode.
     * - returns: The google-authenticator URI-encoded representation of the key, suitable for QR code generation.
     */

    public static func encodeKey(_ key: OTPKey) -> String? {

        var uriComponents = URLComponents()
        uriComponents.scheme = "otpauth"
        uriComponents.host = key.mode.rawValue

        // Label

        var label = key.accountName

        if let issuerPrefix = key.issuerPrefix {
            label = issuerPrefix + ":" + label
        } else if let issuer = key.issuer {
            label = issuer + ":" + label
        }

        guard let path = label.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            return nil
        }

        uriComponents.path = "/\(path)"

        // Query Parameters

        var queryItems = [URLQueryItem]()
        queryItems["secret"] = key.sharedSecret.base32EncodedString

        queryItems["digits"] = String(key.digits)

        if let issuer = key.issuer {
            queryItems["issuer"] = issuer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        }

        if key.mode == .totp {
            queryItems["algorithm"] = key.algorithm.rawValue
            queryItems["period"] = String(Int(key.period))
        }

        if key.mode == .hotp {
            queryItems["counter"] = String(key.counter)
        }

        // Export

        uriComponents.queryItems = queryItems
        return uriComponents.string

    }

}
