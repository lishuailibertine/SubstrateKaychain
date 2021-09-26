// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SubstrateKeychain",
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "SubstrateKeychain",
            targets: ["SubstrateKeychain"]),
    ],
    dependencies: [
        .package(name:"Sr25519",url: "https://github.com/lishuailibertine/Sr25519.swift.git", from: "0.1.5"),
        .package(name:"xxHash-Swift",url: "https://github.com/lishuailibertine/xxHash-Swift.git", from: "1.1.1"),
        .package(name:"Blake2",url: "https://github.com/tesseract-one/Blake2.swift.git", from: "0.1.2"),
        .package(name:"swift-scale-codec",url: "https://github.com/tesseract-one/swift-scale-codec.git", from: "0.2.0"),
        .package(name:"BIP39swift", url: "https://github.com/mathwallet/BIP39swift", from: "1.0.0"),
        .package(name:"Secp256k1Swift", url: "https://github.com/mathwallet/Secp256k1Swift", from: "1.2.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SubstrateKeychain",
            dependencies: ["Sr25519",.product(name: "Ed25519", package: "Sr25519"),"Secp256k1Swift","BIP39swift",.product(name: "ScaleCodec", package: "swift-scale-codec"),"xxHash-Swift","Blake2"]),
        .testTarget(
            name: "SubstrateKeychainTests",
            dependencies: ["SubstrateKeychain"]),
    ]
)
