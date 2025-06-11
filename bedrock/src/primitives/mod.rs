use alloy::primitives::Bytes;
use alloy::{primitives::Address, signers::Signature};
use ruint::aliases::{U128, U256};

use crate::bedrock_export;
use std::fmt::Display;
use std::str::FromStr;

/// Introduces logging functionality that can be integrated with foreign language bindings.
pub mod logger;

/// Introduces global configuration for Bedrock operations.
pub mod config;

/// Introduces test elements to ensure tooling (logging and error handling) is working as expected.
/// The elements in this module are only used in Foreign Tests and are not available in built binaries.
#[cfg(feature = "tooling_tests")]
pub mod tooling_tests;

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
        attribute: &'static str,
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
            attribute: attr,
            message: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for U256 {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        Self::from_str(s).map_err(|e| PrimitiveError::InvalidInput {
            attribute: attr,
            message: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for U128 {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        Self::from_str(s).map_err(|e| PrimitiveError::InvalidInput {
            attribute: attr,
            message: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for Bytes {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, PrimitiveError> {
        let raw = s.strip_prefix("0x").unwrap_or(s);
        hex::decode(raw)
            .map(Self::from)
            .map_err(|e| PrimitiveError::InvalidInput {
                attribute: attr,
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
