//
//  Mnemonic.swift
//
//
//  Created by Yehor Popovych on 10.05.2021.
//

import Foundation
import UncommonCrypto
import BIP39swift

public struct Mnemonic: Equatable, Hashable {
    public enum Error: Swift.Error {
        case invalidMnemonic
        case invalidStrengthSize
        case invalidEntropy
    }
    
    public let entropy: [UInt8]
    
    public init(strength: Int = 128) throws {
        guard strength >= 32, strength <= 256, strength % 32 == 0 else {
            throw Error.invalidStrengthSize
        }
        try self.init(entropy: SecureRandom.bytes(size: strength / 8))
    }
    
    public init(mnemonic: String, wordlist: BIP39Language = .english) throws {
        try self.init(entropy: Self.toEntropy(mnemonic, wordlist: wordlist))
    }
    
    public init(entropy: [UInt8]) throws {
        guard entropy.count > 0, entropy.count <= 32, entropy.count % 4 == 0 else {
            throw Error.invalidEntropy
        }
        self.entropy = entropy
    }
    
    // Generate Mnemonic Phrase
    public func mnemonic(wordlist: BIP39Language = .english) -> [String] {
        return try! Self.toMnemonic(entropy, wordlist: wordlist)
    }
    // Check is mnemonic phrase valid
    public static func isValid(phrase: String, wordlist: BIP39Language = .english) -> Bool {
        do {
            let _ = try Self.toEntropy(phrase, wordlist: wordlist)
            return true
        } catch {
            return false
        }
    }
    
    // Entropy Bytes -> Mnemonic Phrase
    public static func toMnemonic(_ entropy: [UInt8], wordlist: BIP39Language = .english) throws -> [String] {
        
        guard let mnemonics = BIP39.generateMnemonicsFromEntropy(entropy: Data(entropy), language: wordlist) else {
            throw Error.invalidEntropy
        }
        let wordList = mnemonics.components(separatedBy: " ")
        return wordList
    }
    
    // Mnemonic Phrase -> Entropy Bytes
    public static func toEntropy(_ phrase: String, wordlist: BIP39Language = .english) throws -> [UInt8] {
        
        guard let entropy = BIP39.mnemonicsToEntropy(phrase, language: wordlist) else {
            throw Error.invalidMnemonic
        }
        return [UInt8](entropy)
    }
}
