use std::fmt::Display;

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

#[uniffi::export]
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

/// Represents primitive errors on Bedrock. These errors may not be called **from** FFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PrimitiveError {
    /// The provided string is not validly encoded hex data.
    #[error("invalid hex string: {0}")]
    InvalidHexString(String),
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
