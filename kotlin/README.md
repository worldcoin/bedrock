# 🧬 Kotlin for Bedrock

This folder contains all relevant support files for Bedrock to work in Kotlin. **Foreign Tests** are located in `bedrock-tests/src/test/kotlin/bedrock/` folder.

All build tasks are exposed as subcommands of `cargo xtask kotlin` (see `xtask/`):

### Build the Android bindings for release/distribution

```bash
cargo xtask kotlin build
```

### Run the foreign Kotlin tests

```bash
cargo xtask kotlin test
```

Builds a host-platform cdylib (so the JVM can load it via JNA) and runs the JUnit suite through the Gradle wrapper.

### Publish a local build to Maven Local

```bash
cargo xtask kotlin local --version 0.2.10-SNAPSHOT
```

Builds the Android bindings and runs `publishToMavenLocal`, making the artifact
available to a consumer project:

```kotlin
implementation("com.toolsforhumanity:bedrock:0.2.10-SNAPSHOT")
```

### Kotlin Project Structure

The Kotlin project has two members:
- `bedrock-android`: The main bedrock library with foreign bindings for Kotlin.
- `bedrock-tests`: Unit tests to assert the Kotlin bindings behave as intended (called "Foreign Tests"). These tests are not bundled with the library.
