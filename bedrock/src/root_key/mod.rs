use bedrock_macros::{bedrock_error, bedrock_export};
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

/// Internal implementation for `RootKey` (methods not exposed to foreign bindings)
impl RootKey {
    /// Encode the `RootKey` into a JSON string representation.
    ///
    /// The returned string is a JSON object with the shape {"version":"V0|V1","key":"<hex-or-string>"}.
    // pub fn encode(&self) -> Result<String, RootKeyError> {
    //     serde_json::to_string(self.inner.expose_secret()).map_err(|_| {
    //         RootKeyError::Generic {
    //             message: "Failed to serialize key".to_string(),
    //         }
    //     })
    // }

    /// Decode a `RootKey` from either a hex string (V0) or a JSON string (V0/V1).
    ///
    /// This is a compatibility shim for legacy call sites that previously accepted
    /// multiple formats. It never fails; if parsing as JSON fails and the input is
    /// not valid hex, it will keep the original string as a V0 value.
    #[must_use]
    pub fn decode(input: String) -> Self {
        // Try JSON first
        if let Ok(key) = serde_json::from_str::<VersionedKey>(&input) {
            return Self {
                inner: SecretBox::new(Box::new(key)),
            };
        }

        // Preserve as-is in V0 for compatibility (validation performed elsewhere)
        Self {
            inner: SecretBox::new(Box::new(VersionedKey::V0(input))),
        }
    }

    /// Strictly decode from a JSON string; returns an error if the input is not JSON or invalid.
    pub fn decode_from_json_enforced(json_str: &str) -> Result<Self, RootKeyError> {
        let key: VersionedKey =
            serde_json::from_str(json_str).map_err(|_| RootKeyError::KeyParseError)?;

        // Additional enforcement for V0: ensure it is valid hex of correct length
        if let VersionedKey::V0(ref s) = key {
            let decoded = hex::decode(s).map_err(|_| RootKeyError::KeyParseError)?;
            if decoded.len() != KEY_LENGTH {
                return Err(RootKeyError::KeyParseError);
            }
        }

        Ok(Self {
            inner: SecretBox::new(Box::new(key)),
        })
    }

    /// Generate a new random V1 `RootKey`.
    #[must_use]
    #[allow(dead_code)]
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

#[cfg(test)]
mod test;
