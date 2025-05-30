# bedrock

Foundational library which powers World App's crypto wallet.

## Error Handling

Uses `#[bedrock_error]` macro for unified error handling across modules:

- **Strongly typed errors**: Specific variants for known error cases
- **Generic errors**: Flexible `anyhow::Error` variant for complex error chains
- **Auto-generated**: Automatic `From` implementations and context support

## Swift Bindings

### Building (`build_swift.sh`)

Generates Swift bindings and creates an XCFramework for iOS:

- Builds Rust library for iOS targets (device + simulator)
- Generates Swift bindings using UniFFI
- Packages everything into `Bedrock.xcframework`

### Testing (`run_swift_tests.sh`)

Runs Swift unit tests against the generated bindings:

- Executes `build_swift.sh` to generate the framework
- Copies Swift bindings to test package at `test_ios/BedrockPackage`
- Runs XCTest suite on iOS simulator using `xcodebuild`
