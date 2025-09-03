use bedrock_macros::{bedrock_error, bedrock_export};
use rand::{rngs::OsRng, TryRngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
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

#[derive(Serialize, Deserialize)]
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

    let mut decoded_key = hex::decode(&s).map_err(|e| {
        s.zeroize();
        serde::de::Error::custom(e)
    })?;
    s.zeroize();

    if decoded_key.len() != KEY_LENGTH {
        decoded_key.zeroize();
        return Err(serde::de::Error::custom(format!(
            "Key length must be {KEY_LENGTH} bytes",
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&decoded_key);

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
    /// Generates a new random `RootKey` using the system CSPRNG.
    ///
    /// # Panics
    /// Will panic if there is an error with the CSPRNG. This terminates the app.
    #[uniffi::constructor]
    pub fn new_random() -> Self {
        let mut buf = [0u8; KEY_LENGTH];
        OsRng
            .try_fill_bytes(&mut buf)
            .expect("Fatal CSPRNG error: unable to initialize new RootKey");
        let inner = SecretBox::new(Box::new(VersionedKey::V1(buf)));
        buf.zeroize();
        Self { inner }
    }

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

    pub fn is_equal_to(&self, other: &Self) -> bool {
        let self_secret = self.inner.expose_secret();
        let other_secret = other.inner.expose_secret();

        match (self_secret, other_secret) {
            (VersionedKey::V0(self_secret), VersionedKey::V0(other_secret)) => {
                self_secret.as_bytes().ct_eq(other_secret.as_bytes()).into()
            }
            (VersionedKey::V1(self_secret), VersionedKey::V1(other_secret)) => {
                self_secret.ct_eq(other_secret).into()
            }
            _ => false,
        }
    }
}

impl PartialEq for RootKey {
    fn eq(&self, other: &Self) -> bool {
        self.is_equal_to(other)
    }
}

/// Internal implementation for `RootKey` (methods not exposed to foreign bindings)
impl RootKey {
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
