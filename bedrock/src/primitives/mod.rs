/// A wrapper around a hex-encoded string.
///
/// This is used to ensure that the hex string is properly formatted and it's always prefixed with "0x".
/// Ensures consistency in expected output.
///
/// # Examples
/// ```
/// use bedrock::primitives::HexEncodedString;
/// let hex_string = HexEncodedString::new("0x1234567890abcdef".to_string());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object)]
pub struct HexEncodedString(String);

#[uniffi::export]
impl HexEncodedString {
    /// Initializes a new `HexEncodedString` from a hex string.
    ///
    /// # Arguments
    /// * `s` - The hex string to initialize the `HexEncodedString` from. May or may not be prefixed with "0x".
    ///
    /// # Errors
    /// - `PrimitiveError::InvalidHexString` if the provided string is not validly encoded hex data.
    #[uniffi::constructor]
    pub fn new(s: String) -> Result<Self, PrimitiveError> {
        let mut s = s;

        if s.starts_with("0x") {
            s = s[2..].to_string();
        }

        hex::decode(&s).map_err(|_| PrimitiveError::InvalidHexString(s.clone()))?;

        Ok(Self(format!("0x{}", s)))
    }

    /// Returns the wrapped hex string as a string.
    pub fn as_string(&self) -> String {
        self.0.clone()
    }
}

impl From<HexEncodedString> for String {
    fn from(hex_encoded_string: HexEncodedString) -> Self {
        hex_encoded_string.0
    }
}

impl From<String> for HexEncodedString {
    fn from(s: String) -> Self {
        Self::new(s).unwrap()
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
        let hex_string =
            HexEncodedString::new("0x1234567890abcdef".to_string()).unwrap();

        assert_eq!(hex_string.as_string(), "0x1234567890abcdef".to_string());
    }

    #[test]
    fn test_hex_encoded_string_invalid() {
        let hex_string = HexEncodedString::new("0xg1234".to_string());

        assert!(hex_string.is_err());
        assert_eq!(
            hex_string.err().unwrap().to_string(),
            "invalid hex string: g1234".to_string()
        );
    }
}
