# 🧬 Kotlin for Bedrock

This folder contains all relevant support files for Bedrock to work in Kotlin:

1. Script to cross-compile and build Kotlin bindings.
2. **Foreign Tests**. Unit tests for Kotlin (`src/test/java/bedrock/` folder). Foreign unit tests run the JUnit test suite via Gradle wrapper.

### Building the Kotlin Project

To build the Kotlin project run:

```bash
    # run from the root project directory
    ./kotlin/build_kotlin.sh
```

### Running Foreign Tests for Kotlin

```bash
    # run from the root project directory
    ./swift/test_kotlin.sh
```


### Kotlin Project Structure

The Kotlin project has two members:
- `bedrock-android`: The main bedrock library with foreign bindings for Kotlin.
- `bedrock-tests`: Unit tests to assert the Kotlin bindings behave as intended (called "Foreign Tests"). These tests are not bundled with the library.