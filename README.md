# bedrock

Foundational library which powers World App's crypto wallet.

## Dependencies

### Building and Testing

- **Rust toolchain** (stable) - for building the core library
- **UniFFI** - for generating language bindings (included as workspace dependency)

### Swift Bindings

- **Xcode** (macOS only) - for building XCFramework and running iOS simulator tests
- **iOS Simulator** - automatically detected by `run_swift_tests.sh`

### Kotlin Bindings

- **Java 17+** - required for Gradle and Kotlin compilation
- **Gradle** - automatically installed via wrapper if missing
- **JNA 5.12.0** - automatically downloaded as Gradle dependency for native library access

### Platform Support

- **macOS** - supports both Swift and Kotlin testing
- **Linux** - supports Kotlin testing (CI environment)
- **Windows** - not currently tested

## Kotlin Bindings

### Building (`build_kotlin.sh`)

Generates Kotlin/JNA bindings for JVM:

- Builds Rust library for host platform (macOS/Linux)
- Generates Kotlin bindings using UniFFI
- Copies shared library and bindings to `test_android/` Gradle module

### Testing (`run_kotlin_tests.sh`)

Runs Kotlin unit tests against the generated bindings:

- Executes `build_kotlin.sh` to generate bindings and native library
- Auto-detects Java installation (or uses Homebrew OpenJDK on macOS)
- Runs JUnit test suite via Gradle wrapper

## CI/CD

Both Swift and Kotlin tests run automatically in GitHub Actions:

- Swift tests: `macos-latest` with iOS simulator
- Kotlin tests: `ubuntu-latest` with OpenJDK
- Rust tests: `ubuntu-latest` with Foundry for Ethereum testing

## Local Development & Contributing

Review our [CONTRIBUTING](CONTRIBUTING.md) guide. Including details on how to run this project locally.

## 🐦‍🔥 Swift Bindings

Bedrock ships with foreign bindings for native Swift. All details can be found in the [/swift](./swift/README.md) folder.
