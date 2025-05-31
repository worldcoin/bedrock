# 🐦‍🔥 Swift for Bedrock

This folder contains all relevant support files for Bedrock to work in Swift:

1. Script to cross-compile and build Swift bindings.
2. **Foreign Tests**. Unit tests for Swift (`/tests` folder). Foreign unit tests run the XCTest suite on iOS simulator using `xcodebuild`.

### Building the Swift Bindings

To build the Swift bindings run:

```bash
    # run from the root project directory
    ./swift/build_swift.sh
```

### Running Foreign Tests for Swift

```bash
    # run from the root project directory
    ./swift/test_swift.sh
```
