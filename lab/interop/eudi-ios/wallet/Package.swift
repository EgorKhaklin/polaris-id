// swift-tools-version: 6.2
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// A wallet on the EU reference OpenID4VP library for iOS (eudi-lib-ios-openid4vp-swift), to present
// to polaris-oid4vp. The two EU libraries are pinned to the exact versions the EUDI iOS wallet kit
// 0.54.5 pins. The two helpers the wallet also imports are named with the ranges the EU libraries
// themselves ask for. Package.resolved pins every package to a commit.
import PackageDescription

let package = Package(
  name: "polaris-eudi-ios-wallet",
  platforms: [.macOS(.v14)],
  dependencies: [
    .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vp-swift.git", exact: "0.43.2"),
    .package(url: "https://github.com/eu-digital-identity-wallet/eudi-lib-sdjwt-swift.git", exact: "0.14.7"),
    .package(url: "https://github.com/beatt83/jose-swift.git", from: "6.0.5"),
    .package(url: "https://github.com/SwiftyJSON/SwiftyJSON.git", from: "5.0.1"),
  ],
  targets: [
    .executableTarget(
      name: "polaris-eudi-ios-wallet",
      dependencies: [
        .product(name: "OpenID4VP", package: "eudi-lib-ios-openid4vp-swift"),
        .product(name: "eudi-lib-sdjwt-swift", package: "eudi-lib-sdjwt-swift"),
        .product(name: "jose-swift", package: "jose-swift"),
        .product(name: "SwiftyJSON", package: "SwiftyJSON"),
      ],
      path: "Sources/Wallet"
    )
  ]
)
