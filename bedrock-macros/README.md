# `bedrock_sol!` Macro

The `bedrock_sol!` macro is a powerful procedural macro that extends `alloy::sol!` with automatic generation of unparsed struct variants for foreign language bindings (Swift and Kotlin).

## Overview

This macro:

1. **Forwards everything to `alloy::sol!`** - maintaining full compatibility with existing Solidity type definitions
2. **Generates unparsed versions** - creates `Unparsed{StructName}` variants with all String fields for foreign language consumption
3. **Provides automatic conversion** - implements `TryFrom<Unparsed{StructName}>` for seamless conversion from unparsed to typed structs

## Usage

### Basic Syntax

```rust
use bedrock::bedrock_sol;

bedrock_sol! {
    #[derive(serde::Serialize)]
    #[unparsed]
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    #[unparsed]
    struct PermitTransferFrom {
        TokenPermissions permitted;
        address spender;
        uint256 nonce;
        uint256 deadline;
    }
}
```

### What Gets Generated

The above example generates:

#### 1. Original Sol Structs (via `alloy::sol!`)

- `TokenPermissions` with typed fields (`Address`, `U256`)
- `PermitTransferFrom` with typed fields

#### 2. Unparsed Variants (for Foreign Languages)

```rust
/// For Swift & Kotlin usage only.
#[derive(uniffi::Record, Debug, Clone)]
pub struct UnparsedTokenPermissions {
    /// Solidity type: `address`
    pub token: String,
    /// Solidity type: `uint256`
    pub amount: String,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct UnparsedPermitTransferFrom {
    pub permitted: UnparsedTokenPermissions,
    /// Solidity type: `address`
    pub spender: String,
    /// Solidity type: `uint256`
    pub nonce: String,
    /// Solidity type: `uint256`
    pub deadline: String,
}
```

#### 3. Conversion Implementations

```rust
impl TryFrom<UnparsedTokenPermissions> for TokenPermissions {
    type Error = crate::smart_account::SafeSmartAccountError;

    fn try_from(value: UnparsedTokenPermissions) -> Result<Self, Self::Error> {
        Ok(Self {
            token: <alloy::primitives::Address as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.token, "token")?,
            amount: <alloy::primitives::U256 as crate::primitives::ParseFromForeignBinding>::parse_from_ffi(&value.amount, "amount")?,
        })
    }
}
```

## Type Mapping

### Primitive Types

Solidity primitive types are converted to `String` in unparsed variants:

| Solidity Type | Unparsed Type | Parsed Type                  |
| ------------- | ------------- | ---------------------------- |
| `address`     | `String`      | `alloy::primitives::Address` |
| `uint256`     | `String`      | `alloy::primitives::U256`    |
| `uint128`     | `String`      | `alloy::primitives::U128`    |
| `bytes`       | `String`      | `alloy::primitives::Bytes`   |
| ...           | `String`      | (respective alloy types)     |

### Nested Structs

When a field references another struct that's also marked with `#[unparsed]`, the unparsed variant uses the corresponding unparsed struct type:

```rust
bedrock_sol! {
    #[unparsed]
    struct Child {
        uint256 value;
    }

    #[unparsed]
    struct Parent {
        Child nested;
        address owner;
    }
}
```

## Foreign Language Usage

### Swift Example

```swift
// Create unparsed struct with string values
let unparsedPermissions = UnparsedTokenPermissions(
    token: "0x1234567890abcdef1234567890abcdef12345678",
    amount: "1000000000000000000"
)

// Convert to typed struct for processing
let typedPermissions = try TokenPermissions.from(unparsed: unparsedPermissions)
```

### Kotlin Example

```kotlin
// Create unparsed struct with string values
val unparsedPermissions = UnparsedTokenPermissions(
    token = "0x1234567890abcdef1234567890abcdef12345678",
    amount = "1000000000000000000"
)

// Convert to typed struct for processing
val typedPermissions = TokenPermissions.from(unparsedPermissions)
```

## Benefits

1. **Type Safety**: Foreign languages get strongly-typed structs while maintaining string-based input flexibility
2. **Error Handling**: Automatic validation and detailed error messages during conversion
3. **Documentation**: Each string field includes Solidity type information in comments
4. **Maintainability**: Single source of truth - update the `bedrock_sol!` definition and both typed and unparsed variants update automatically

## Error Handling

Conversion failures return detailed `SafeSmartAccountError::InvalidInput` errors with:

- **Attribute name**: Which field failed to parse
- **Error message**: Specific parsing failure details

```rust
// Example error for invalid address
SafeSmartAccountError::InvalidInput {
    attribute: "token",
    message: "failed to parse: invalid address checksum"
}
```

## Best Practices

1. **Mark only necessary structs**: Only add `#[unparsed]` to structs that need foreign language bindings
2. **Document your structs**: Doc comments on original structs are preserved in unparsed variants
3. **Use descriptive field names**: Field names become part of the foreign language API
4. **Validate early**: Convert from unparsed to typed structs as early as possible in your processing pipeline
