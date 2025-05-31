#!/usr/bin/env bash
set -euo pipefail

echo "========================================="
echo "Running Kotlin/JVM Tests"
echo "========================================="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

# Set JAVA_HOME if not already set (for CI environments)
if [ -z "${JAVA_HOME:-}" ]; then
  if [ -d "/opt/homebrew/Cellar/openjdk@17" ]; then
    # macOS with Homebrew - find latest 17.x version
    LATEST_JDK=$(ls -v /opt/homebrew/Cellar/openjdk@17 | grep "^17\." | tail -n 1)
    if [ -n "$LATEST_JDK" ]; then
      export JAVA_HOME="/opt/homebrew/Cellar/openjdk@17/$LATEST_JDK/libexec/openjdk.jdk/Contents/Home"
      echo "🔧 Set JAVA_HOME to: $JAVA_HOME"
    else
      echo "⚠️  No OpenJDK 17.x found in Homebrew"
    fi
  elif command -v java >/dev/null 2>&1; then
    # Try to find JAVA_HOME from java command
    JAVA_PATH=$(which java)
    export JAVA_HOME=$(dirname $(dirname $(readlink -f $JAVA_PATH)))
    echo "🔧 Detected JAVA_HOME: $JAVA_HOME"
  else
    echo "⚠️  JAVA_HOME not set and Java not found in PATH"
  fi
fi

# --------------------------------------------------
# Step 1: Build Rust + Kotlin bindings
# --------------------------------------------------

echo "🔨 Step 1: Building Kotlin bindings with build_kotlin.sh"
"$ROOT_DIR/kotlin/build_kotlin.sh"

echo "✅ Kotlin bindings built"

# --------------------------------------------------
# Step 2: Run unit tests via Gradle
# --------------------------------------------------

cd "$ROOT_DIR/kotlin"

# Generate Gradle wrapper if missing (use host gradle)
if [ ! -f "gradlew" ]; then
  echo "Gradle wrapper missing, generating..."
  if ! command -v gradle &> /dev/null; then
    echo "Gradle is required but not installed. Aborting." >&2
    exit 1
  fi
  gradle wrapper --gradle-version 8.7
fi

"$ROOT_DIR/kotlin/gradlew" --no-daemon test