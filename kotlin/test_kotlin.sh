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

echo ""
echo "🧪 Running Kotlin tests with verbose output..."
echo ""

# Run tests with verbose output (HTML reports disabled in build.gradle)
./gradlew --no-daemon test --info --continue

echo ""
echo "📊 Test Results Summary:"
echo "========================"

# Show test results if they exist
if [ -d "build/test-results/test" ]; then
  echo "✅ Test results found in: build/test-results/test"
  
  # Count test results
  TOTAL_TESTS=$(find build/test-results/test -name "*.xml" -exec grep -l "testcase" {} \; | wc -l | tr -d ' ')
  if [ "$TOTAL_TESTS" -gt 0 ]; then
    echo "📋 Total test files: $TOTAL_TESTS"
    
    # Show basic stats from XML files
    PASSED=$(find build/test-results/test -name "*.xml" -exec grep -o "tests=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    FAILURES=$(find build/test-results/test -name "*.xml" -exec grep -o "failures=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    ERRORS=$(find build/test-results/test -name "*.xml" -exec grep -o "errors=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    
    echo "✅ Tests passed: $PASSED"
    echo "❌ Tests failed: $FAILURES"
    echo "⚠️  Test errors: $ERRORS"
  fi
else
  echo "⚠️  No test results found"
fi 