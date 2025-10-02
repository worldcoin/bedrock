use alloy::primitives::Bytes;
use alloy::{primitives::Address, signers::Signature};
use ruint::aliases::{U128, U256};

use crate::bedrock_export;
use std::fmt::Display;
use std::str::FromStr;

// Re-export HTTP client types for external use
pub use http_client::{AuthenticatedHttpClient, HttpError, HttpMethod};

/// The prefix for Bedrock-generated transactions.
pub static BEDROCK_NONCE_PREFIX_CONST: &[u8; 5] = b"bdrck";

/// The prefix for PBHTX-generated transactions.
#[allow(dead_code)]
pub static PBH_NONCE_PREFIX_CONST: &[u8; 5] = b"pbhtx";

// Serde helper functions for skip_serializing_if

/// Helper function to check if an `Address` is zero for serde `skip_serializing_if`
#[must_use]
pub fn is_zero_address(addr: &Address) -> bool {
    addr.is_zero()
}

/// Helper function to check if `Bytes` is empty for serde `skip_serializing_if`
#[must_use]
pub fn is_empty_bytes(bytes: &Bytes) -> bool {
    bytes.is_empty()
}

/// Helper function to check if `u128` is zero for serde `skip_serializing_if`
#[must_use]
pub const fn is_zero_u128(value: &u128) -> bool {
    *value == 0
}

/// Helper function to check if `U256` is zero for serde `skip_serializing_if`
#[must_use]
pub fn is_zero_u256(value: &U256) -> bool {
    value.is_zero()
}

/// Provides an interface for interacting with Ethereum addresses for foreign code.
pub mod address;

/// Introduces logging functionality that can be integrated with foreign language bindings.
pub mod logger;

/// Introduces global configuration for Bedrock operations.
pub mod config;

/// Introduces filesystem functionality with automatic path prefixing for each exported struct.
pub mod filesystem;

/// Introduces authenticated HTTP client functionality that native applications must implement for bedrock.
pub mod http_client;

/// Introduces test elements to ensure tooling (logging and error handling) is working as expected.
/// The elements in this module are only used in Foreign Tests and are not available in built binaries.
#[cfg(feature = "tooling_tests")]
pub mod tooling_tests;

/// Contract interfaces and data structures for ERC-4337 account abstraction
pub mod contracts;

/// Supported blockchain networks for Bedrock operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u32)]
pub enum Network {
    /// Ethereum (chain ID: 1)
    Ethereum = 1,
    /// Optimism (chain ID: 10)
    Optimism = 10,
    /// World Chain (chain ID: 480)
    WorldChain = 480,
}

impl Network {
    /// Returns the network name for RPC endpoint construction
    #[must_use]
    pub const fn network_name(&self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::Optimism => "optimism",
            Self::WorldChain => "worldchain",
        }
    }

    /// Returns the display name for the network
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::Optimism => "Optimism",
            Self::WorldChain => "World Chain",
        }
    }
}

impl Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// A wrapper around hex-encoded bytes (may or may not be a number).
///
/// This is used to ensure that the hex string is properly formatted and the output is always prefixed with "0x".
/// Ensures consistency in expected output format.
///
/// # Examples
/// ```
/// use bedrock::primitives::HexEncodedData;
/// let hex_string = HexEncodedData::new("0x1234567890abcdef");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
pub struct HexEncodedData(String);

#[bedrock_export]
impl HexEncodedData {
    /// Initializes a new `HexEncodedData` from a hex string.
    ///
    /// # Arguments
    /// * `s` - The hex string to initialize the `HexEncodedData` from. May or may not be prefixed with "0x".
    ///
    /// # Errors
    /// - `PrimitiveError::InvalidHexString` if the provided string is not validly encoded hex data.
    #[uniffi::constructor]
    pub fn new(s: &str) -> Result<Self, PrimitiveError> {
        let s = s.trim_start_matches("0x");
        hex::decode(s).map_err(|_| PrimitiveError::InvalidHexString(s.to_string()))?;
        Ok(Self(format!("0x{s}")))
    }

    /// Returns the wrapped hex string as a String. Re-wraps `Display` trait for foreign code.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        self.0.to_string()
    }

    /// Converts the wrapped hex string into a `Bytes` struct.
    ///
    /// # Errors
    /// - `PrimitiveError::Generic` in the unexpected case that the hex string is not validly encoded hex data.
    ///     This should never happen as this is verified on initialization.
    pub fn to_vec(&self) -> Result<Vec<u8>, PrimitiveError> {
        hex::decode(self.0.trim_start_matches("0x")).map_err(|_| {
            PrimitiveError::Generic {
                message: "unexpected error in HexEncodedData::to_vec".to_string(),
            }
        })
    }
}

impl HexEncodedData {
    /// Returns the wrapped hex string as a &str.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for HexEncodedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<HexEncodedData> for String {
    fn from(hex_encoded_string: HexEncodedData) -> Self {
        hex_encoded_string.0
    }
}

impl TryFrom<String> for HexEncodedData {
    type Error = PrimitiveError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl TryFrom<&str> for HexEncodedData {
    type Error = PrimitiveError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<Signature> for HexEncodedData {
    fn from(signature: Signature) -> Self {
        Self(signature.to_string())
    }
}

/// Represents primitive errors on Bedrock. These errors may not be called **from** FFI.
#[crate::bedrock_error]
pub enum PrimitiveError {
    /// The provided string is not validly encoded hex data.
    #[error("invalid hex string: {0}")]
    InvalidHexString(String),
    /// A provided raw input could not be parsed, is incorrectly formatted, incorrectly encoded or otherwise invalid.
    #[error("invalid input on {attribute}: {message}")]
    InvalidInput {
        /// The name of the attribute that was invalid.
        attribute: String,
        /// Explicit failure message for the attribute validation.
        message: String,
    },
}

/// A trait for parsing primitive types from foreign bindings.
///
/// This trait is used to parse primitive types from foreign provided values. For example, parsing
/// a stringified address into an `Address` type.
///
/// # Examples
/// ```rust,ignore
/// let address = Address::parse_from_ffi("0x1234567890abcdef", "address");
/// ```
///
/// # Errors
/// - `PrimitiveError::InvalidInput` if the provided string is not a valid address.
pub(crate) trait ParseFromForeignBinding {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError>
    where
        Self: Sized;
}

impl ParseFromForeignBinding for Address {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        Self::from_str(s).map_err(|e| PrimitiveError::InvalidInput {
            attribute: attr.to_string(),
            message: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for U256 {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        Self::from_str(s).map_err(|e| PrimitiveError::InvalidInput {
            attribute: attr.to_string(),
            message: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for u128 {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        let number = U128::from_str(s).map_err(|e| PrimitiveError::InvalidInput {
            attribute: attr.to_string(),
            message: e.to_string(),
        })?;

        // This is safe because we know the number is within the range of u128
        Ok(number.to::<Self>())
    }
}

impl ParseFromForeignBinding for Bytes {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        let raw = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(raw)
            .map(Self::from)
            .map_err(|e| PrimitiveError::InvalidInput {
                attribute: attr.to_string(),
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encoded_string() {
        let hex_string = HexEncodedData::new("0x1234567890abcdef").unwrap();

        assert_eq!(hex_string.to_hex_string(), "0x1234567890abcdef".to_string());
    }

    #[test]
    fn test_hex_encoded_string_invalid() {
        let hex_string = HexEncodedData::new("0xg1234");

        assert!(hex_string.is_err());
        assert_eq!(
            hex_string.err().unwrap().to_string(),
            "invalid hex string: g1234".to_string()
        );
    }
}
