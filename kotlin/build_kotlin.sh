#!/usr/bin/env bash
set -euo pipefail

# Creates Kotlin/JNA bindings for the `bedrock` library and places them in the
# This script mirrors the behavior of `build_swift.sh` for Kotlin/JVM.

PROJECT_ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLIN_DIR="$PROJECT_ROOT_PATH/kotlin"
JAVA_SRC_DIR="$KOTLIN_DIR/bedrock-android/src/main/java"
LIBS_DIR="$KOTLIN_DIR/libs"

# Clean previous artifacts
rm -rf "$JAVA_SRC_DIR" "$LIBS_DIR"
mkdir -p "$JAVA_SRC_DIR" "$LIBS_DIR"

echo "🟢 Building Rust cdylib for host platform"
cargo build --package bedrock --release

# Determine the correct library file extension and copy it
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    LIB_FILE="$PROJECT_ROOT_PATH/target/release/libbedrock.dylib"
    cp "$LIB_FILE" "$LIBS_DIR/"
    echo "📦 Copied libbedrock.dylib for macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    LIB_FILE="$PROJECT_ROOT_PATH/target/release/libbedrock.so"
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