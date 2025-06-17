#!/usr/bin/env bash
set -euo pipefail

rm -rf bedrock-tests/build/test-results

echo "========================================="
echo "Running Kotlin/JVM Tests"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

# Set JAVA_HOME if not already set (for CI environments)
if [ -z "${JAVA_HOME:-}" ]; then
  if [ -d "/opt/homebrew/Cellar/openjdk@17" ]; then
    # macOS with Homebrew - find latest 17.x version
    LATEST_JDK=$(ls -v /opt/homebrew/Cellar/openjdk@17 | grep "^17\." | tail -n 1)
    if [ -n "$LATEST_JDK" ]; then
      export JAVA_HOME="/opt/homebrew/Cellar/openjdk@17/$LATEST_JDK/libexec/openjdk.jdk/Contents/Home"
      echo -e "${BLUE}🔧 Set JAVA_HOME to: $JAVA_HOME${NC}"
    else
      echo -e "${YELLOW}⚠️  No OpenJDK 17.x found in Homebrew${NC}"
    fi
  elif command -v java >/dev/null 2>&1; then
    # Try to find JAVA_HOME from java command
    JAVA_PATH=$(which java)
    export JAVA_HOME=$(dirname $(dirname $(readlink -f $JAVA_PATH)))
    echo -e "${BLUE}🔧 Detected JAVA_HOME: $JAVA_HOME${NC}"
  else
    echo -e "${YELLOW}⚠️  JAVA_HOME not set and Java not found in PATH${NC}"
  fi
fi

echo -e "${BLUE}🔨 Step 1: Building Kotlin bindings with build_kotlin.sh${NC}"
"$ROOT_DIR/kotlin/build_kotlin.sh"

echo -e "${GREEN}✅ Kotlin bindings built${NC}"

echo -e "${BLUE}📦 Step 2: Setting up Gradle test environment${NC}"
cd "$ROOT_DIR/kotlin"

# Generate Gradle wrapper if missing (use host gradle)
if [ ! -f "gradlew" ]; then
  echo "Gradle wrapper missing, generating..."
  if ! command -v gradle &> /dev/null; then
    echo -e "${RED}✗ Gradle is required but not installed. Aborting.${NC}" >&2
    exit 1
  fi
  gradle wrapper --gradle-version 8.7 # same version as in publish-release.yml
fi
echo -e "${GREEN}✅ Gradle test environment ready${NC}"

echo ""
echo -e "${BLUE}🧪 Step 3: Running Kotlin tests with verbose output...${NC}"
echo ""

# Run tests with verbose output (HTML reports disabled in build.gradle)
./gradlew --no-daemon bedrock-tests:test --info --continue

echo ""
echo "📊 Test Results Summary:"
echo "========================"

# Show test results if they exist
if [ -d "bedrock-tests/build/test-results/test" ]; then
  echo "✅ Test results found in: bedrock-tests/build/test-results/test"
  
  # Count test results
  TOTAL_TESTS=$(find bedrock-tests/build/test-results/test -name "*.xml" -exec grep -l "testcase" {} \; | wc -l | tr -d ' ')
  if [ "$TOTAL_TESTS" -gt 0 ]; then
    echo "📋 Total test files: $TOTAL_TESTS"
    
    # Show basic stats from XML files
    PASSED=$(find bedrock-tests/build/test-results/test -name "*.xml" -exec grep -o "tests=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    FAILURES=$(find bedrock-tests/build/test-results/test -name "*.xml" -exec grep -o "failures=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    ERRORS=$(find bedrock-tests/build/test-results/test -name "*.xml" -exec grep -o "errors=\"[0-9]*\"" {} \; | cut -d'"' -f2 | awk '{sum+=$1} END {print sum+0}')
    
    echo "✅ Tests passed: $PASSED"
    echo "❌ Tests failed: $FAILURES"
    echo "⚠️  Test errors: $ERRORS"
    
    # Check for failures and show appropriate message
    if [ "$FAILURES" -gt 0 ] || [ "$ERRORS" -gt 0 ]; then
      echo ""
      echo -e "${YELLOW}⚠️ Some tests failed${NC}"
      exit 1
    else
      echo ""
      echo -e "${GREEN}🎉 All tests passed!${NC}"
      exit 0
    fi
  fi
else
  echo "⚠️  No test results found"
  echo ""
  echo -e "${RED}✗ Could not determine test results${NC}"
  exit 1
fi 