use bedrock_macros::{bedrock_error, bedrock_export};
use dryoc::kdf::Kdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEY_LENGTH: usize = 32;
type KeyType = [u8; KEY_LENGTH];

/// Errors that can occur when working with the secure module.
#[bedrock_error]
pub enum RootKeyError {
    /// The provided input is likely not an actual `RootKey`. It is malformed or not the right format.
    #[error("failed to parse key")]
    KeyParseError,
    /// Key derivation unexpectedly fail
    #[error("key derivation failure: {0}")]
    KeyDerivation(String),
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
#[derive(uniffi::Object, Debug, Zeroize, ZeroizeOnDrop)]
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

    /// Returns `true` if the `RootKey` is a version 0 key.
    pub fn is_v0(&self) -> bool {
        matches!(self.inner.expose_secret(), VersionedKey::V0(_))
    }

    /// Returns `true` if the provided `RootKey`s are equal by comparing internally the underlying secrets.
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
    const CONTEXT: [u8; 8] = *b"OXIDEKEY";

    /// Serializes a `RootKey` to a JSON string.
    ///
    /// # Warning
    ///
    /// This method exports the secret key. Use cautiously.
    pub fn danger_to_json(&self) -> Result<String, RootKeyError> {
        serde_json::to_string(self.inner.expose_secret()).map_err(|_| {
            RootKeyError::Generic {
                error_message: "Failed to serialize key".to_string(),
            }
        })
    }

    /// Derives a subkey from the `RootKey` given `subkey_id` using blake2b-based KDF.
    fn derive_subkey(
        &self,
        subkey_id: u64,
    ) -> Result<SecretBox<KeyType>, RootKeyError> {
        let mut base_key_material = match self.inner.expose_secret() {
            VersionedKey::V0(key) => {
                Self::internal_parse_key_v0(key).expose_secret().to_owned()
            }
            VersionedKey::V1(key) => key.to_owned(),
        };

        let mut key = Kdf::from_parts(base_key_material, Self::CONTEXT);
        base_key_material.zeroize();

        let mut subkey: [u8; 32] = key
            .derive_subkey(subkey_id)
            .map_err(|e| RootKeyError::KeyDerivation(e.to_string()))?;

        let secret_box = SecretBox::new(Box::new(subkey));
        subkey.zeroize();
        key.zeroize();
        Ok(secret_box)
    }

    /// Handling for legacy V0 keys to be able to use them with KDF.
    fn internal_parse_key_v0(encoded_key: &str) -> SecretBox<KeyType> {
        let mut hasher = Sha256::new();
        hasher.update(encoded_key);
        let mut key_bytes: [u8; KEY_LENGTH] = hasher.finalize().into();

        let secret_box = SecretBox::new(Box::new(key_bytes));
        key_bytes.zeroize();
        secret_box
    }
}

/// Subkey ID. Namespace used for the Backup ID.
const BACKUP_SUBKEY_ID: u64 = 0x100;

/// Public key derivation implementations. These are not considered secret and may be exposed. They are also exposed
/// to foreign bindings.
///
/// Note these values are not returned in a `SecretBox`.
#[bedrock_export]
impl RootKey {
    /// Key derivation. "Public" value.
    ///
    /// Derives the deterministic public backup account ID to uniquely identify a backup for an account.
    ///
    /// This is used to ensure that only a single backup can exist per account, otherwise this could lead
    /// to race conditions and undefined behavior with the backup (including user confusion).
    ///
    /// # Errors
    /// No errors are generally expected, but key derivation may unexpectedly fail.
    pub fn derive_public_backup_account_id(&self) -> Result<String, RootKeyError> {
        let mut subkey: SecretBox<[u8; 32]> =
            Self::derive_subkey(self, BACKUP_SUBKEY_ID)?;
        let backup_id = blake3::keyed_hash(subkey.expose_secret(), b"public");
        subkey.zeroize();
        Ok(format!("backup_account_{}", backup_id.to_hex()))
    }
}

#[cfg(test)]
mod test;
