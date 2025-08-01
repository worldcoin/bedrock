# `bedrock_sol!` Macro

The `bedrock_sol!` macro is a procedural macro that extends `alloy::sol!` with automatic generation of unparsed struct variants for foreign language bindings (Swift and Kotlin).

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
    #[unparsed(TokenPermissions, PermitTransferFrom)]

    #[derive(serde::Serialize)]
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    #[derive(serde::Serialize)]
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

When a field references another struct that's also marked for unparsed generation, the unparsed variant uses the corresponding unparsed struct type:

```rust
bedrock_sol! {
    #[unparsed(Parent, Child)]

    struct Child {
        uint256 value;
    }

    struct Parent {
        Child nested;
        address owner;
    }
}
```
