#!/bin/bash
set -e

# Creates a Swift package of the `Bedrock` library for local development.
# This script builds the library and sets up the proper structure for importing
# via Swift Package Manager using a local file:// URL.
# All artifacts are placed in swift/local_build to keep the repo clean.

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_PATH="$PROJECT_ROOT_PATH/swift" # The base path for the Swift build
LOCAL_BUILD_PATH="$BASE_PATH/local_build" # Local build artifacts directory
FRAMEWORK="Bedrock.xcframework"

echo "Building $FRAMEWORK for local iOS development"

# Clean up previous builds
rm -rf "$LOCAL_BUILD_PATH"

# Create the local build directory
mkdir -p "$LOCAL_BUILD_PATH"

echo "Running core Swift build..."

# Call the main build script with local build directory
bash "$BASE_PATH/build_swift.sh" "$LOCAL_BUILD_PATH"

echo "Creating Package.swift for local development..."

# Create Package.swift for local development
cat > $LOCAL_BUILD_PATH/Package.swift << EOF
// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Bedrock",
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
            path: "Bedrock.xcframework"
        )
    ]
)
EOF

echo ""
echo "✅ Swift package built successfully!"
echo ""
echo "📦 Package location: $LOCAL_BUILD_PATH"
echo ""
echo "To use this package in your iOS app:"
echo "1. In Xcode, go to File → Add Package Dependencies..."
echo "2. Click 'Add Local...' and select the local_build directory: $LOCAL_BUILD_PATH"
echo "3. Or add it to your Package.swift dependencies:"
echo "   .package(path: \"$LOCAL_BUILD_PATH\")"
echo ""
echo "The package exports the 'Bedrock' library that you can import in your Swift code." 