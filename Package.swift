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
        .package(name:"xxHash-Swift",url: "https://github.com/daisuke-t-jp/xxHash-Swift.git", from: "1.1.0"),
        .package(name:"Blake2",url: "https://github.com/tesseract-one/Blake2.swift.git", from: "0.1.2"),
        .package(name:"swift-scale-codec",url: "https://github.com/tesseract-one/swift-scale-codec.git", from: "0.2.0"),
        .package(name:"Sr25519",url: "https://github.com/tesseract-one/Sr25519.swift.git", from: "0.1.3"),
        .package(name:"CSecp256k1",url: "https://github.com/tesseract-one/CSecp256k1.swift.git", from: "0.1.0"),
        .package(name: "Bip39", url: "https://github.com/tesseract-one/Bip39.swift", from: "0.1.1")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "SubstrateKeychain",
            dependencies: ["Sr25519","CSecp256k1","Bip39",.product(name: "ScaleCodec", package: "swift-scale-codec"),.product(name: "Ed25519", package: "Sr25519"),"xxHash-Swift","Blake2"]),
        .testTarget(
            name: "SubstrateKeychainTests",
            dependencies: ["SubstrateKeychain"]),
    ]
)
