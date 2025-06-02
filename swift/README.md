# 🐦‍🔥 Swift for Bedrock

This folder contains all relevant support files for Bedrock to work in Swift:

1. Script to cross-compile and build Swift bindings.
2. Script to build Swift package for local development.
3. Foreign tests. Unit tests for Swift (`/tests` folder). Foreign unit tests run the XCTest suite on iOS simulator using `xcodebuild`.

### Building the Swift Bindings

To build the Swift project for release/distribution:

```bash
    # run from the root project directory
    ./swift/build_swift.sh
```

### Building for Local iOS Development

To build a Swift package that can be imported locally via Swift Package Manager:

```bash
    # run from the root project directory
    ./swift/build_for_local_ios.sh
```

This creates a complete Swift package in the `swift/local_build/` directory that you can import in your iOS project:

### Integration via Package.swift

Add the local package to your Package.swift dependencies:

```swift
dependencies: [
    .package(name: "Bedrock", path: "../../../bedrock/swift/local_build"),
    // ... other dependencies
],
```

Then add it to specific targets that need bedrock functionality:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "Bedrock", package: "Bedrock"),
        // ... other dependencies
    ]
),
```

### Running foreign tests for Swift

```bash
    # run from the root project directory
    ./swift/test_swift.sh
```
