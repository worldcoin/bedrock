use bedrock_macros::{bedrock_error, bedrock_export};
#[cfg(test)]
use rand::RngCore as _;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

const KEY_LENGTH: usize = 32;
type KeyType = [u8; KEY_LENGTH];

/// Errors that can occur when working with the secure module.
#[bedrock_error]
pub enum RootKeyError {
    /// The provided input is likely not an actual `RootKey`. It is malformed or not the right format.
    #[error("failed to parse key")]
    KeyParseError,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "version", content = "key")]
enum VersionedKey {
    V0(String),
    #[serde(
        serialize_with = "serialize_key_as_hex",
        deserialize_with = "deserialize_key_from_hex"
    )]
    V1(KeyType),
}

impl Zeroize for VersionedKey {
    fn zeroize(&mut self) {
        match self {
            Self::V0(key) => key.zeroize(),
            Self::V1(key) => key.zeroize(),
        }
    }
}

fn serialize_key_as_hex<S>(key: &KeyType, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = hex::encode(key);
    serializer.serialize_str(&hex_string)
}

fn deserialize_key_from_hex<'de, D>(deserializer: D) -> Result<KeyType, D::Error>
where
    D: Deserializer<'de>,
{
    let mut s = String::deserialize(deserializer)?;

    let mut decoded_key = hex::decode(&s).map_err(serde::de::Error::custom)?;

    if decoded_key.len() != KEY_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Key length must be {KEY_LENGTH} bytes",
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&decoded_key);

    s.zeroize();
    decoded_key.zeroize();

    Ok(key)
}

/// The `RootKey` is a 32-byte secret key from which other keys are derived for use throughout World App.
///
/// Debug trait is safe because the key is stored in a `SecretBox`.
#[derive(uniffi::Object, Debug)]
pub struct RootKey {
    inner: SecretBox<VersionedKey>,
}

#[bedrock_export]
impl RootKey {
    /// Initialize an existing `RootKey` from a JSON string
    #[uniffi::constructor]
    pub fn from_json(json_str: &str) -> Result<Self, RootKeyError> {
        // no need to zeroize `key` because it's moved into the `SecretBox`
        let key: VersionedKey =
            serde_json::from_str(json_str).map_err(|_| RootKeyError::KeyParseError)?;

        Ok(Self {
            inner: SecretBox::new(Box::new(key)),
        })
    }

    pub fn is_v0(&self) -> bool {
        matches!(self.inner.expose_secret(), VersionedKey::V0(_))
    }
}

impl Clone for RootKey {
    fn clone(&self) -> Self {
        let inner = self.inner.expose_secret().clone();
        Self {
            inner: SecretBox::new(Box::new(inner)),
        }
    }
}

impl PartialEq for RootKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.expose_secret() == other.inner.expose_secret()
    }
}

impl Eq for RootKey {}

/// Internal implementation for `RootKey` (methods not exposed to foreign bindings)
impl RootKey {
    /// Decodes the key from serialized format.
    pub fn decode(encoded_key: String) -> Self {
        // Try JSON first (expects a VersionedKey JSON object)
        if let Ok(versioned) = serde_json::from_str::<VersionedKey>(&encoded_key) {
            return Self {
                inner: SecretBox::new(Box::new(versioned)),
            };
        }

        // Fallback: treat as V0 hex string
        Self {
            inner: SecretBox::new(Box::new(VersionedKey::V0(encoded_key))),
        }
    }

    /// Decodes the key from `JSON` serialized format.
    ///
    /// This function does not allow the key to be in the raw hex format, like regular `decode`.
    /// Even if it is a `v0` key, it has to be serialized in `JSON` format (for example, after `.encode()`).
    ///
    /// This function can be used in cases where `OxideKey` is decoded regularly (for `v0` or `v1`) and then
    /// re-encoded to full `JSON` format. For example, backup service parses the key from `HEX`/`JSON`
    /// on enrollment (using regular `decode`) and then re-encodes it to JSON format for storage.
    /// When recovery is happening, we know the key is in JSON format, so we can use this function
    /// to decode it at the recovery time.
    pub fn decode_from_json_enforced(encoded_key: &str) -> Result<Self, RootKeyError> {
        let versioned = serde_json::from_str::<VersionedKey>(encoded_key)
            .map_err(|_| RootKeyError::KeyParseError)?;
        Ok(Self {
            inner: SecretBox::new(Box::new(versioned)),
        })
    }

    /// Encodes the key as JSON.
    pub fn encode(&self) -> Result<String, RootKeyError> {
        serde_json::to_string(self.inner.expose_secret()).map_err(|_| {
            RootKeyError::Generic {
                message: "Failed to serialize key".to_string(),
            }
        })
    }

    /// Generate a new random V1 `RootKey`.
    #[must_use]
    #[cfg(test)]
    pub fn new_random() -> Self {
        let mut key = [0u8; KEY_LENGTH];
        rand::thread_rng().fill_bytes(&mut key);
        Self {
            inner: SecretBox::new(Box::new(VersionedKey::V1(key))),
        }
    }

    /// Serializes a `RootKey` to a JSON string.
    ///
    /// # Warning
    ///
    /// This method exports the secret key. Use cautiously.
    #[allow(dead_code)] // TODO: usage coming soon
    pub fn danger_to_json(&self) -> Result<String, RootKeyError> {
        serde_json::to_string(self.inner.expose_secret()).map_err(|_| {
            RootKeyError::Generic {
                message: "Failed to serialize key".to_string(),
            }
        })
    }
}

#[cfg(test)]
mod test;
