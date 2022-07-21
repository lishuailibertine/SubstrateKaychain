//
//  File.swift
//  
//
//  Created by li shuai on 2021/8/31.
//

import Foundation
import Sr25519
import BIP39swift
import CryptoSwift

public typealias SubstrateKeychainRandom = Sr25519SecureRandom

extension Mnemonic {
    public func substrate_seed(password: String = "") -> [UInt8] {
        let salt = Array(("mnemonic"+password).utf8)
        return try! PKCS5.PBKDF2(password: self.entropy, salt: salt, iterations: 2048, keyLength: 64, variant: HMAC.Variant.sha512).calculate()
    }
}

public protocol KeyPair {
    var rawPubKey: Data { get }
    var raw: Data { get }
    var seed: Data? {get}
    init()
    init(phrase: String, password: String?) throws
    init(seed: Data) throws
    init(raw: Data) throws
    init(secretKey: Data) throws
    func sign(message: Data) -> Data
    func verify(message: Data, signature: Data) -> Bool
    
    static var seedLength: Int { get }
}
