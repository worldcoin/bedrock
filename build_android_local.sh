#!/bin/bash
set -euo pipefail

echo "Building Bedrock Android SDK for local development..."

# Default to the caller's standard Rust homes; callers can still override these explicitly.
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"

if [ -z "${1:-}" ]; then
    echo "Error: Version parameter is required"
    echo "Usage: ./build_android_local.sh <version>"
    echo "Example: ./build_android_local.sh 0.2.10-SNAPSHOT"
    exit 1
fi

VERSION="$1"
echo "Using version: $VERSION"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTLIN_DIR="$SCRIPT_DIR/kotlin"

ensure_gradle_wrapper() {
    if [ -x "$KOTLIN_DIR/gradlew" ]; then
        return
    fi

    local gradle_version="${GRADLE_VERSION:-8.13}"
    local dist_url="https://services.gradle.org/distributions/gradle-${gradle_version}-bin.zip"
    local tmp_dir=""
    local zip_path=""
    local unzip_dir=""

    echo "Gradle wrapper missing, bootstrapping Gradle ${gradle_version}..."
    tmp_dir="$(mktemp -d)"
    zip_path="$tmp_dir/gradle-${gradle_version}.zip"
    unzip_dir="$tmp_dir/unzip"

    curl -sSL "$dist_url" -o "$zip_path"
    mkdir -p "$unzip_dir"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "$zip_path" -d "$unzip_dir"
    else
        (cd "$unzip_dir" && jar xvf "$zip_path" >/dev/null)
    fi

    "$unzip_dir/gradle-${gradle_version}/bin/gradle" -p "$KOTLIN_DIR" wrapper --gradle-version "$gradle_version"
    rm -rf "$tmp_dir"
}

ensure_gradle_wrapper

echo "Building Bedrock SDK..."
"$KOTLIN_DIR/build.sh"

echo "Publishing to Maven Local..."
"$KOTLIN_DIR/gradlew" --no-daemon -p "$KOTLIN_DIR" :bedrock-android:publishToMavenLocal -PversionName="$VERSION"

echo ""
echo "✅ Successfully published $VERSION to Maven Local!"
echo "Published to: ~/.m2/repository/com/toolsforhumanity/bedrock/$VERSION/"
echo ""
echo "To use in your project:"
echo "  implementation 'com.toolsforhumanity:bedrock:$VERSION'"
