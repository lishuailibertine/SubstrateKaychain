//
//  File.swift
//  
//
//  Created by li shuai on 2021/8/31.
//

import Foundation
import Sr25519
import Bip39
import ScaleCodec

public typealias SRKeyPair = Sr25519.Sr25519KeyPair
public typealias SRSeed = Sr25519.Sr25519Seed
public typealias SRSignature = Sr25519.Sr25519Signature
public typealias SRChainCode = Sr25519.Sr25519ChainCode
public typealias SRPublicKey = Sr25519.Sr25519PublicKey

public struct Sr25519KeyPair {
    public let keyPair: SRKeyPair
    public var srSeed: SRSeed? = nil
    public init(keyPair: SRKeyPair) {
        self.keyPair = keyPair
    }
    fileprivate static func convertError<T>(_ cb: () throws -> T) throws -> T {
        do {
            return try cb()
        } catch let e as Sr25519Error {
            switch e {
            case .badChainCodeLength:
                throw KeyPairError.derive(error: .badComponentSize)
            case .badKeyPairLength:
                throw KeyPairError.native(error: .badPrivateKey)
            case .badPublicKeyLength:
                throw KeyPairError.input(error: .publicKey)
            case .badSeedLength:
                throw KeyPairError.input(error: .seed)
            case .badSignatureLength, .badVrfSignatureLength:
                throw KeyPairError.input(error: .signature)
            case .badVrfThresholdLength:
                throw KeyPairError.input(error: .threshold)
            case .vrfError:
                throw KeyPairError.native(error: .internal)
            }
        } catch {
            throw KeyPairError(error: error)
        }
    }
}
extension Sr25519KeyPair: KeyPair {
    public var raw: Data { keyPair.raw }
    public var rawPubKey: Data { keyPair.publicKey.raw }
    public var seed: Data? {srSeed?.raw}
    public init(phrase: String, password: String? = nil) throws {
        let mnemonic = try Self.convertError {
            try Mnemonic(mnemonic: phrase.components(separatedBy: " "), wordlist: .english)
        }
        let seed = mnemonic.substrate_seed(password: password ?? "")
        try self.init(seed: Data(seed))
    }
    
    public init(seed: Data) throws {
        let kpSeed = try Self.convertError {
            try SRSeed(raw: seed.prefix(SRSeed.size))
        }
        let kp = try Self.convertError {
             SRKeyPair(seed: kpSeed)
        }
        self.init(keyPair: kp)
        self.srSeed = kpSeed
    }
    
    public init(raw: Data) throws {
        let kp = try Self.convertError {
            try SRKeyPair(raw: raw)
        }
        self.init(keyPair: kp)
    }
    
    public init() {
        try! self.init(seed: Data(SubstrateKeychainRandom.bytes(count: SRSeed.size)))
    }
    public func sign(message: Data) -> Data {
        return keyPair.sign(message: message).raw
    }
    
    public func verify(message: Data, signature: Data) -> Bool {
        guard let sig = try? SRSignature(raw: signature) else {
            return false
        }
        return keyPair.verify(message: message, signature: sig)
    }
    
    public static var seedLength: Int = SRSeed.size
}

extension Sr25519KeyPair: KeyDerivable {
    public func derive(path: [PathComponent]) throws -> Sr25519KeyPair {
        let kp = try path.reduce(keyPair) { (pair, cmp) in
            let chainCode = try Self.convertError { try SRChainCode(raw: cmp.bytes) }
            return pair.derive(chainCode: chainCode, hard: cmp.isHard)
        }
        return Self(keyPair: kp)
    }
}
