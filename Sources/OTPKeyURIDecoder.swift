/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation

/**
 * Decodes OTP key URIs, in the google-authenticator format.
 */

public enum OTPKeyURIDecoder {

    /**
     * Decodes an OTP key URI encoded in the google-authenticator format.
     *
     * - parameter stringValue: The key URI to decode.
     * - returns: The decoded key, or `nil` if the URI is not valid.
     */

    public static func decodeURI(_ stringValue: String) -> OTPKey? {

        // Context

        guard let urlComponents = URLComponents(string: stringValue) else {
            return nil
        }

        guard urlComponents.scheme == "otpauth" else {
            return nil
        }

        guard let host = urlComponents.host, host.count > 0 else {
            return nil
        }

        var path = urlComponents.path

        while path.first == "/" {
            path.removeFirst()
        }

        guard let queryItems = urlComponents.queryItems else {
            return nil
        }

        // Decoding

        guard let mode = OTPKey.Mode(rawValue: host) else {
            return nil
        }

        guard let label = decodeLabel(path) else {
            return nil
        }

        guard let secret = extractSecret(from: queryItems) else {
            return nil
        }

        let key = OTPKey(mode: mode, accountName: label.accountName, issuerPrefix: label.issuerPrefix, sharedSecret: secret)

        if mode == .hotp {

            guard let counter = extractCounter(from: queryItems) else {
                return nil
            }

            key.counter = counter

        }

        configureKey(key, with: queryItems)
        return key

    }

    /**
     * Decodes the label section of a Key URI.
     */

    static func decodeLabel(_ labelString: String) -> (accountName: String, issuerPrefix: String?)? {

        guard let decodedString = labelString.removingPercentEncoding else {
            return nil
        }

        print(decodedString)

        let labelComponents = decodedString.components(separatedBy: ":")

        if labelComponents.count == 1 {
            return (labelComponents[0], nil)
        }

        if labelComponents.count == 2 {

            let issuerPrefix = labelComponents[0]
            var accountName = labelComponents[1]

            while accountName.first == " " {
                accountName.removeFirst()
            }

            return (accountName, issuerPrefix)

        }

        return nil

    }

    /**
     * Extracts the secret from the query items.
     */

    static func extractSecret(from queryItems: [URLQueryItem]) -> Data? {

        guard let secret = queryItems["secret"] else {
            return nil
        }

        return secret.base32DecodedData

    }

    /**
     * Extracts the counter from the query items.
     */

    static func extractCounter(from queryItems: [URLQueryItem]) -> UInt64? {

        guard let counter = queryItems["counter"] else {
            return nil
        }

        return UInt64(counter)

    }

    /**
     * Configures the optional parameters of the key.
     *
     * - parameter key: The key to configure.
     * - parameter queryItems: The query items containing the details.
     */

    static func configureKey(_ key: OTPKey, with queryItems: [URLQueryItem]) {

        key.issuer = queryItems["issuer"]?.removingPercentEncoding

        if let rawAlgorithm = queryItems["algorithm"], let alg = OTPKey.Algorithm(rawValue: rawAlgorithm) {
            key.algorithm = alg
        }

        if let rawDigits = queryItems["digits"], let digits = Int(rawDigits) {
            key.digits = digits
        }

        if let rawPeriod = queryItems["period"], let period = TimeInterval(rawPeriod) {
            key.period = period
        }

    }

}

// MARK: - OTP+URLQueryItem

extension Array where Element == URLQueryItem {

    /**
     * Get and set the value for the given query item name.
     */

    subscript(name: String) -> String? {
        get {
            return first(where: { $0.name == name })?.value
        }
        set {
            let item = URLQueryItem(name: name, value: newValue)
            append(item)
        }
    }

}
