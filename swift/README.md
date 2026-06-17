# 🐦‍🔥 Swift for Bedrock

This folder contains support files for Bedrock's Swift bindings:

1. The generated Swift sources and `Bedrock.xcframework` (regenerated on every build).
2. Foreign tests in `tests/` — XCTest suite run on the iOS simulator via `xcodebuild`.

All build tasks are exposed as subcommands of `cargo xtask swift` (see `xtask/`):

### Build the Swift bindings for release/distribution

```bash
cargo xtask swift build
```

### Build a local Swift package for iOS app development

```bash
cargo xtask swift local
```

Produces a `file://`-installable package in `swift/local_build/bedrock-swift/`. Add it
to your consumer `Package.swift`:

```swift
dependencies: [
    .package(name: "Bedrock", path: "../../../bedrock/swift/local_build/bedrock-swift"),
],
```

To automatically rewrite a consumer project's `Package.swift` to point at the local
build, set `CONSUMER_PATH` (or pass `--consumer-path`) and run:

```bash
cargo xtask swift link-local
```

### Run the foreign Swift tests

```bash
cargo xtask swift test
```
