#!/usr/bin/env bash
set -euo pipefail

# Creates Kotlin/JNA bindings for the `bedrock` library and places them in the
# Gradle test module found in `test_android/`.
# This script mirrors the behaviour of `build_swift.sh` for Kotlin/JVM.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_TEST_DIR="$ROOT_DIR/test_android"
JAVA_SRC_DIR="$ANDROID_TEST_DIR/src/main/java"
LIBS_DIR="$ANDROID_TEST_DIR/libs"

# Clean previous artefacts
rm -rf "$JAVA_SRC_DIR" "$LIBS_DIR"
mkdir -p "$JAVA_SRC_DIR" "$LIBS_DIR"

echo "🟢 Building Rust cdylib for host platform"
cargo build --package bedrock --release

# Determine the correct library file extension and copy it
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    LIB_FILE="$ROOT_DIR/target/release/libbedrock.dylib"
    cp "$LIB_FILE" "$LIBS_DIR/"
    echo "📦 Copied libbedrock.dylib for macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    LIB_FILE="$ROOT_DIR/target/release/libbedrock.so"
    cp "$LIB_FILE" "$LIBS_DIR/"
    echo "📦 Copied libbedrock.so for Linux"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Generate Kotlin bindings using UniFFI
echo "🟡 Generating Kotlin bindings via uniffi-bindgen"
cargo run -p uniffi-bindgen -- generate \
  "$LIB_FILE" \
  --language kotlin \
  --library \
  --out-dir "$JAVA_SRC_DIR"

echo "✅ Kotlin bindings written to $JAVA_SRC_DIR" 