#!/bin/bash
set -e

echo "========================================="
echo "Running Swift Tests"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Base paths
BASE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_PATH="$BASE_PATH/tests"
SOURCES_PATH_NAME="/Sources/Bedrock/"

echo -e "${BLUE}Step 1: Building XCFramework with build_swift.sh${NC}"
# Run the existing build_swift.sh script
bash "$BASE_PATH/build_swift.sh"

# Check if the XCFramework was created
if [ ! -d "$BASE_PATH/Bedrock.xcframework" ]; then
    echo -e "${RED}✗ Failed to build XCFramework${NC}"
    exit 1
fi
echo -e "${GREEN}✓ XCFramework built successfully${NC}"

echo -e "${BLUE}Step 2: Copying generated Swift files to package${NC}"
# Ensure the destination directory exists
mkdir -p "$TESTS_PATH/$SOURCES_PATH_NAME"

# Copy the generated Swift file to the package
if [ -f "$BASE_PATH/$SOURCES_PATH_NAME/bedrock.swift" ]; then
    cp "$BASE_PATH/$SOURCES_PATH_NAME/bedrock.swift" "$TESTS_PATH/$SOURCES_PATH_NAME"
    echo -e "${GREEN}✓ Swift bindings copied to package${NC}"
else
    echo -e "${RED}✗ Could not find generated Swift bindings${NC}"
    exit 1
fi

echo -e "${BLUE}Step 3: Running Swift tests${NC}"

# Clean any previous build artifacts
rm -rf .build
rm -rf ~/Library/Developer/Xcode/DerivedData/BedrockForeignTestPackage-*

# Find an available iPhone simulator
SIMULATOR_ID=$(xcrun simctl list devices available | grep "iPhone 14" | head -1 | grep -o "[0-9A-F\-]*" | tail -1)

if [ -z "$SIMULATOR_ID" ]; then
    # Try any available iPhone
    SIMULATOR_ID=$(xcrun simctl list devices available | grep "iPhone" | head -1 | grep -o "[0-9A-F\-]*" | tail -1)
fi

if [ -z "$SIMULATOR_ID" ]; then
    echo -e "${RED}✗ No iPhone simulator available${NC}"
    exit 1
fi

echo "Using simulator ID: $SIMULATOR_ID"

cd "$TESTS_PATH"

# Run tests using xcodebuild for iOS simulator with more explicit settings
echo "Running tests on iOS Simulator..."
xcodebuild test \
  -scheme BedrockForeignTestPackage \
  -destination "platform=iOS Simulator,id=$SIMULATOR_ID" \
  -sdk iphonesimulator \
  CODE_SIGNING_ALLOWED=NO \
  2>&1 | tee test_output.log | grep -E "(Test Suite|Test Case|passed|failed|executed)" || true

# Check if tests passed by examining the output
if grep -q "failed" test_output.log; then
    echo -e "\n${YELLOW}⚠️ Some tests failed${NC}"
    # Show failed tests
    grep -E "(failed|error:)" test_output.log || true
    rm -f test_output.log
    exit 1
elif grep -q "Test Suite.*passed" test_output.log; then
    echo -e "\n${GREEN}🎉 All tests passed!${NC}"
    rm -f test_output.log
    exit 0
else
    echo -e "\n${RED}✗ Could not determine test results${NC}"
    echo "Full output:"
    cat test_output.log
    rm -f test_output.log
    exit 1
fi 