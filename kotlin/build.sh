#!/bin/bash
set -euo pipefail

echo "Building Bedrock Android SDK..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANDROID_DIR="$SCRIPT_DIR/bedrock-android"
JAVA_SRC_DIR="$ANDROID_DIR/src/main/java"
JNI_DIR="$ANDROID_DIR/src/main/jniLibs"

rm -rf "$JNI_DIR" "$JAVA_SRC_DIR/uniffi"
mkdir -p "$JNI_DIR"/{arm64-v8a,armeabi-v7a,x86_64,x86}

echo "Building for aarch64-linux-android..."
cross build -p bedrock --release --target=aarch64-linux-android

echo "Building for armv7-linux-androideabi..."
cross build -p bedrock --release --target=armv7-linux-androideabi

echo "Building for x86_64-linux-android..."
cross build -p bedrock --release --target=x86_64-linux-android

echo "Building for i686-linux-android..."
cross build -p bedrock --release --target=i686-linux-android

echo "Copying native libraries..."
cp "$ROOT_DIR/target/aarch64-linux-android/release/libbedrock.so" "$JNI_DIR/arm64-v8a/libbedrock.so"
cp "$ROOT_DIR/target/armv7-linux-androideabi/release/libbedrock.so" "$JNI_DIR/armeabi-v7a/libbedrock.so"
cp "$ROOT_DIR/target/x86_64-linux-android/release/libbedrock.so" "$JNI_DIR/x86_64/libbedrock.so"
cp "$ROOT_DIR/target/i686-linux-android/release/libbedrock.so" "$JNI_DIR/x86/libbedrock.so"

echo "Generating Kotlin bindings..."
cargo run --locked \
  -p uniffi-bindgen generate \
  "$JNI_DIR/arm64-v8a/libbedrock.so" \
  --library \
  --language kotlin \
  --no-format \
  --out-dir "$JAVA_SRC_DIR"

echo "✅ Android build complete!"
