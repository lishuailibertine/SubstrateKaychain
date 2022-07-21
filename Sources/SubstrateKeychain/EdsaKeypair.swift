//
//  File.swift
//  
//
//  Created by li shuai on 2021/8/31.
//

import Foundation
import CSecp256k1
import BIP39swift
import ScaleCodec

public struct EcdsaKeyPair {
    public let privateData: [UInt8]
    public let publicKey: secp256k1_pubkey
    public let publicRaw: Data
    
    public init(privKey: [UInt8]) throws {
        guard Self._context.verify(privKey: privKey) else {
            throw KeyPairError.native(error: .badPrivateKey)
        }
        let pub = try Self._context.toPublicKey(privKey: privKey)
        let raw = try Data(Self._context.serialize(pubKey: pub, compressed: true))
        self.publicKey = pub
        self.privateData = privKey
        self.publicRaw = raw
    }
    
    fileprivate static let _context = Secp256k1Context()
}
extension EcdsaKeyPair: KeyPair {
    public var seed: Data? {
        Data(privateData)
    }
    public var rawPubKey: Data { publicRaw }
    public var raw: Data { Data(privateData) + rawPubKey }

    public init(phrase: String, password: String? = nil) throws {
        let mnemonic: Mnemonic
        do {
            mnemonic = try Mnemonic(mnemonic: phrase, wordlist: .english)
        } catch {
            throw KeyPairError(error: error)
        }
        let seed = mnemonic.substrate_seed(password: password ?? "")
        try self.init(seed: Data(seed))
    }
    
    public init(seed: Data) throws {
        guard seed.count >= Secp256k1Context.privKeySize else {
            throw KeyPairError.input(error: .seed)
        }
        try self.init(privKey: Array(seed.prefix(Secp256k1Context.privKeySize)))
    }
    
    public init(raw: Data) throws {
        guard raw.count == (Secp256k1Context.privKeySize + Secp256k1Context.compressedPubKeySize) else {
            throw KeyPairError.native(error: .badPrivateKey)
        }
        try self.init(privKey: Array(raw[0..<Secp256k1Context.privKeySize]))
    }
    public init(secretkey: Data) throws{
        guard secretkey.count == Secp256k1Context.privKeySize else {
            throw KeyPairError.native(error: .badPrivateKey)
        }
        try self.init(privKey: Array(secretkey[0..<Secp256k1Context.privKeySize]))
    }
    public init() {
        try! self.init(seed: Data(SubstrateKeychainRandom.bytes(count: Secp256k1Context.privKeySize)))
    }
    
    public func sign(message: Data) -> Data {
        let hash = HBlake2b256.hasher.hash(data: message)
        let signature = try! Self._context.sign(hash: Array(hash), privKey: self.privateData)
        return try! Data(Self._context.serialize(signature: signature))
    }
    
    public func verify(message: Data, signature: Data) -> Bool {
        guard let sig = try? Self._context.signature(from: Array(signature)) else {
            return false
        }
        let hash = HBlake2b256.hasher.hash(data: message)
        return Self._context.verify(signature: sig, hash: Array(hash), pubKey: self.publicKey)
    }
    
    public static var seedLength: Int = Secp256k1Context.privKeySize
}
extension EcdsaKeyPair: KeyDerivable {
    public func derive(path: [PathComponent]) throws -> EcdsaKeyPair {
        let priv = try path.reduce(privateData) { (secret, cmp) in
            guard cmp.isHard else { throw KeyPairError.derive(error: .softDeriveIsNotSupported) }
            let encoder = SCALE.default.encoder()
            try encoder.encode("Secp256k1HDKD")
            try encoder.encode(Data(secret), .fixed(UInt(Secp256k1Context.privKeySize)))
            try encoder.encode(cmp.bytes, .fixed(UInt(PathComponent.size)))
            let hash = HBlake2b256.hasher.hash(data: encoder.output)
            return Array(hash.prefix(Secp256k1Context.privKeySize))
        }
        
        return try Self(privKey: priv)
    }
}
