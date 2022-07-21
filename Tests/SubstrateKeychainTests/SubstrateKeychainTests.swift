import XCTest
@testable import SubstrateKeychain

final class SubstrateKeychainTests: XCTestCase {
    func testExample() throws {
        let keypair1 = Sr25519KeyPair()
        
        let keyPair2 = try Sr25519KeyPair(raw: keypair1.raw)
        XCTAssertEqual(keypair1.raw, keyPair2.raw)
        XCTAssertEqual(keypair1.rawPubKey, keyPair2.rawPubKey)
        
        let keyPair3 = try Sr25519KeyPair(secretKey: keypair1.raw[0..<64])
        XCTAssertEqual(keypair1.raw, keyPair3.raw)
        XCTAssertEqual(keypair1.rawPubKey, keyPair3.rawPubKey)
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
