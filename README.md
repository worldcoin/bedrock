# bedrock

Foundational library which powers World App's crypto wallet.

## 🧱 Local Development & Contributing

Review our [CONTRIBUTING](CONTRIBUTING.md) guide. Including details on how to run this project locally.

## 🐦‍🔥 Swift Bindings

Bedrock ships with foreign bindings for native Swift. All details can be found in the [/swift](./swift/README.md) folder.

## 🧬 Kotlin Bindings

Bedrock ships with foreign bindings for native Kotlin. All details can be found in the [/kotlin](./kotlin/README.md) folder.

## 🌍 Global Configuration

Bedrock provides a global configuration system for managing environment settings across your application.

### Initialization

Initialize the global configuration once at app startup:

**Swift:**

```swift
@_exported import Bedrock
Bedrock.setConfig(environment: .staging)
// or
import Bedrock
setConfig(environment: .staging)
```

**Kotlin:**

```kotlin
uniffi.bedrock.setConfig(BedrockEnvironment.STAGING)
```

## 🛠️ Error Handling & Logging Tooling

Each module should implement its own error enum. See [tooling_tests](/bedrock/src/primitives/tooling_tests.rs) for example references.

### `#[bedrock_error]` Macro

Automatically enhances error enums with UniFFI compatibility and `anyhow` integration:

```rust
#[bedrock_error]
pub enum MyError {
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed { code: u32 },
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout { seconds: u32 },
    // Generic variant added automatically for anyhow integration
}
```

**Features:**

- Auto-derives `Debug`, `thiserror::Error`, `uniffi::Error`
- Adds `Generic { message: String }` variant automatically
- Implements `From<anyhow::Error>` for seamless error conversion
- Provides helper methods like `from_anyhow_result()` and `from_anyhow_result_with_prefix()`

### `#[bedrock_export]` Macro

Wraps `#[uniffi::export]` with automatic logging context injection:

```rust
#[bedrock_export]
impl MyStruct {
    pub fn some_method(&self) -> String {
        // LogContext automatically set to "MyStruct"
        info!("This will be prefixed with [Bedrock][MyStruct]");
        "result".to_string()
    }
}
```

**Features:**

- Automatically injects `LogContext::new("StructName")` at the start of every public method
- Works with any `impl` block for structs or traits
- Maintains all original `#[uniffi::export]` functionality

### Context-Aware Logging

Simplified logging macros that automatically use the current context:

```rust
use bedrock::{trace, debug, info, warn, error};

// In a bedrock_export impl, logs will be automatically prefixed
info!("User authenticated successfully");  // Logs: [Bedrock][MyStruct] User authenticated successfully
debug!("Processing data: {}", value);       // Logs: [Bedrock][MyStruct] Processing data: 42
```

**Available macros:** `trace!`, `debug!`, `info!`, `warn!`, `error!`

### Manual Context Management

For fine-grained control over logging context:

```rust
use bedrock::logger::LogContext;

{
    let _bedrock_logger_ctx = LogContext::new("CustomContext");
    info!("This message has custom context");  // Logs: [Bedrock][CustomContext] This message has custom context
} // Context automatically cleared when _bedrock_logger_ctx is dropped
```
