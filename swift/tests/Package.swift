// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "BedrockForeignTestPackage",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "Bedrock",
            targets: ["Bedrock"]),
    ],
    targets: [
        .target(
            name: "Bedrock",
            dependencies: ["BedrockFFI"],
            path: "Sources/Bedrock"
        ),
        .binaryTarget(
            name: "BedrockFFI",
            path: "../Bedrock.xcframework"
        ),
        .testTarget(
            name: "BedrockTests",
            dependencies: ["Bedrock"],
            path: "Tests/BedrockTests"
        )
    ]
) 