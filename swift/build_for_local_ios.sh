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
PACKAGE_NAME="bedrock"
SWIFT_SOURCES_DIR="$LOCAL_BUILD_PATH/Sources/Bedrock"
SWIFT_HEADERS_DIR="$LOCAL_BUILD_PATH/ios_build/Headers/Bedrock"

echo "Building $FRAMEWORK for local iOS development"

# Clean up previous builds
rm -rf "$LOCAL_BUILD_PATH"

# Create necessary directories
mkdir -p "$LOCAL_BUILD_PATH/ios_build/bindings"
mkdir -p "$LOCAL_BUILD_PATH/ios_build/target/universal-ios-sim/release"
mkdir -p "$SWIFT_SOURCES_DIR"
mkdir -p "$SWIFT_HEADERS_DIR"

echo "Building Rust packages for iOS targets..."

export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"

# Build for all iOS targets
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios-sim --release
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios --release
cargo build --package $PACKAGE_NAME --target x86_64-apple-ios --release

echo "Rust packages built. Combining simulator targets into universal binary..."

# Create universal binary for simulators
lipo -create target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.a \
  target/x86_64-apple-ios/release/lib${PACKAGE_NAME}.a \
  -output $LOCAL_BUILD_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

lipo -info $LOCAL_BUILD_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

echo "Generating Swift bindings..."

# Generate Swift bindings using uniffi
cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir $LOCAL_BUILD_PATH/ios_build/bindings

# Move generated Swift file to Sources directory
mv $LOCAL_BUILD_PATH/ios_build/bindings/${PACKAGE_NAME}.swift ${SWIFT_SOURCES_DIR}/

# Move headers
mv $LOCAL_BUILD_PATH/ios_build/bindings/${PACKAGE_NAME}FFI.h $SWIFT_HEADERS_DIR/
cat $LOCAL_BUILD_PATH/ios_build/bindings/${PACKAGE_NAME}FFI.modulemap > $SWIFT_HEADERS_DIR/module.modulemap

echo "Creating XCFramework..."

# Create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/lib${PACKAGE_NAME}.a -headers $LOCAL_BUILD_PATH/ios_build/Headers \
  -library $LOCAL_BUILD_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a -headers $LOCAL_BUILD_PATH/ios_build/Headers \
  -output $LOCAL_BUILD_PATH/$FRAMEWORK

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

# Clean up intermediate build files
rm -rf $LOCAL_BUILD_PATH/ios_build

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