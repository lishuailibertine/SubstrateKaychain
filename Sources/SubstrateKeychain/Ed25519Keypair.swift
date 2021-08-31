//
//  File.swift
//  
//
//  Created by li shuai on 2021/8/31.
//

import Foundation
import Bip39
import ScaleCodec
import Ed25519
import Sr25519

public typealias EDKeyPair = Ed25519.Ed25519KeyPair
public typealias EDSeed = Ed25519.Ed25519Seed
public typealias EDSignature = Ed25519.Ed25519Signature
public typealias EDPublicKey = Ed25519.Ed25519PublicKey

public struct Ed25519KeyPair {
    public let keyPair: EDKeyPair
    public var edSeed: EDSeed? = nil
    private init(keyPair: EDKeyPair) {
        self.keyPair = keyPair
    }
    fileprivate static func convertError<T>(_ cb: () throws -> T) throws -> T {
        do {
            return try cb()
        } catch let e as Ed25519Error {
            switch e {
            case .badKeyPairLength:
                throw KeyPairError.native(error: .badPrivateKey)
            case .badPrivateKeyLength:
                throw KeyPairError.input(error: .privateKey)
            case .badPublicKeyLength:
                throw KeyPairError.input(error: .publicKey)
            case .badSeedLength:
                throw KeyPairError.input(error: .seed)
            case .badSignatureLength:
                throw KeyPairError.input(error: .signature)
            }
        } catch {
            throw KeyPairError(error: error)
        }
    }
}
extension Ed25519KeyPair: KeyPair {
    public var seed: Data? {
        edSeed?.raw
    }
    public var rawPubKey: Data { keyPair.publicKey.raw }
    public var raw: Data { keyPair.raw }
 
    public init(phrase: String, password: String? = nil) throws {
        let mnemonic = try Self.convertError {
            try Mnemonic(mnemonic: phrase.components(separatedBy: " "))
        }
        let seed = mnemonic.substrate_seed(password: password ?? "")
        try self.init(seed: Data(seed))
    }
    
    public init(seed: Data) throws {
        let kpSeed = try Self.convertError {
            try EDSeed(raw: seed.prefix(EDSeed.size))
        }
        self.init(keyPair: EDKeyPair(seed: kpSeed))
        self.edSeed = kpSeed
    }
    
    public init() {
        try! self.init(seed: Data(SubstrateKeychainRandom.bytes(count: EDSeed.size)))
    }
    
    public init(raw: Data) throws {
        let kp = try Self.convertError {
            try EDKeyPair(raw: raw)
        }
        self.init(keyPair: kp)
    }
    
    public func sign(message: Data) -> Data {
        return keyPair.sign(message: message).raw
    }
    
    public func verify(message: Data, signature: Data) -> Bool {
        guard let sig = try? EDSignature(raw: signature) else {
            return false
        }
        return keyPair.verify(message: message, signature: sig)
    }
    
    public static var seedLength: Int = EDSeed.size
}

extension Ed25519KeyPair: KeyDerivable {
    public func derive(path: [PathComponent]) throws -> Ed25519KeyPair {
        let kp = try path.reduce(keyPair) { (pair, cmp) in
            guard cmp.isHard else { throw KeyPairError.derive(error: .softDeriveIsNotSupported) }
            let encoder = SCALE.default.encoder()
            try encoder.encode("Ed25519HDKD")
            try encoder.encode(keyPair.privateRaw, .fixed(UInt(EDKeyPair.secretSize)))
            try encoder.encode(cmp.bytes, .fixed(UInt(PathComponent.size)))
            let hash = HBlake2b256.hasher.hash(data: encoder.output)
            let seed = try Self.convertError { try EDSeed(raw: hash) }
            return EDKeyPair(seed: seed)
        }
        return Self(keyPair: kp)
    }
}
