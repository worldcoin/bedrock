#!/bin/bash
set -e

# Creates a Swift build of the `Bedrock` library.
# This script is intended to be run in a GitHub Actions workflow.
# When a release is created, the output is committed to the github.com/worldcoin/bedrock-swift repo.

BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK="Bedrock.xcframework"
PACKAGE_NAME="bedrock"
SWIFT_SOURCES_DIR="Sources/Bedrock"
SWIFT_HEADERS_DIR="$BASE_PATH/ios_build/Headers/Bedrock"

echo "Building $FRAMEWORK"

rm -rf $BASE_PATH/ios_build
rm -rf $BASE_PATH/$FRAMEWORK
mkdir -p $BASE_PATH/ios_build/bindings
mkdir -p $BASE_PATH/ios_build/target/universal-ios-sim/release
mkdir -p $BASE_PATH/$SWIFT_SOURCES_DIR
mkdir -p $SWIFT_HEADERS_DIR


export IPHONEOS_DEPLOYMENT_TARGET="13.0"
export RUSTFLAGS="-C link-arg=-Wl,-application_extension"
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios-sim --release
cargo build --package $PACKAGE_NAME --target aarch64-apple-ios --release
cargo build --package $PACKAGE_NAME --target x86_64-apple-ios --release

echo "Rust packages built. Combining into a single binary."

lipo -create target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.a \
  target/x86_64-apple-ios/release/lib${PACKAGE_NAME}.a \
  -output $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

lipo -info $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a

echo "Generating Swift bindings."

cargo run -p uniffi-bindgen generate \
  target/aarch64-apple-ios-sim/release/lib${PACKAGE_NAME}.dylib \
  --library \
  --language swift \
  --no-format \
  --out-dir $BASE_PATH/ios_build/bindings

mv $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}.swift ${BASE_PATH}/${SWIFT_SOURCES_DIR}

mv $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}FFI.h $SWIFT_HEADERS_DIR

cat $BASE_PATH/ios_build/bindings/${PACKAGE_NAME}FFI.modulemap > $SWIFT_HEADERS_DIR/module.modulemap

echo "Creating $FRAMEWORK."

xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/lib${PACKAGE_NAME}.a -headers $BASE_PATH/ios_build/Headers \
  -library $BASE_PATH/ios_build/target/universal-ios-sim/release/lib${PACKAGE_NAME}.a -headers $BASE_PATH/ios_build/Headers \
  -output $BASE_PATH/$FRAMEWORK

rm -rf $BASE_PATH/ios_build
