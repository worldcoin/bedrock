use bedrock_macros::{bedrock_error, bedrock_export};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Errors that can occur when working with the secure module.
#[bedrock_error]
pub enum SecureError {
    /// The provided input is likely not an actual `RootKey`. It is malformed or not the right format.
    #[error("failed to parse key")]
    KeyParseError,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "version", content = "key")]
enum VersionedKey {
    V0(String),
    V1([u8; 32]),
}

impl Zeroize for VersionedKey {
    fn zeroize(&mut self) {
        match self {
            Self::V0(key) => key.zeroize(),
            Self::V1(key) => key.zeroize(),
        }
    }
}

#[derive(uniffi::Object)]
pub struct RootKey {
    key: SecretBox<VersionedKey>,
}

#[bedrock_export]
impl RootKey {
    /// Initialize RootKey from JSON string
    #[uniffi::constructor]
    pub fn from_json(json_str: &str) -> Result<Self, SecureError> {
        let versioned_key: VersionedKey =
            serde_json::from_str(json_str).map_err(|_| SecureError::KeyParseError)?;

        Ok(Self {
            key: SecretBox::new(Box::new(versioned_key)),
        })
    }

    /// Serialize RootKey to JSON string
    pub fn to_json(&self) -> Result<String, SecureError> {
        serde_json::to_string(self.key.expose_secret())
            .map_err(|_| SecureError::KeyParseError)
    }
}
