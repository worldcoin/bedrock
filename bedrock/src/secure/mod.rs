use bedrock_macros::{bedrock_error, bedrock_export};
use dryoc::kdf::Kdf;
use rand::{rngs::OsRng, RngCore};
use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

const CONTEXT: [u8; 8] = *b"OXIDEKEY";
const ETHEREUM_KEY_ID: u64 = 0x00;
const ROTATED_ETHEREUM_KEY_ID: u64 = 0x01;
const WORLDID_KEY_ID: u64 = 0x10;
const ORB_ENCRYPTION_KEY_ID: u64 = 0x20;
const MARBLE_SEED_KEY_ID: u64 = 0x30;
const DOCUMENT_PCP_KEY_ID: u64 = 0x40;
const WORLDCHAT_BACKUP_KEY_ID: u64 = 0x50;
const WORLD_CHAT_PUSH_ID_KEY_ID: u64 = 0x60;
const KEY_LENGTH: usize = 32;
const ROTATED_ETHEREUM_KEY_SALT: &str = "ethereum_key_rotated_";
const MARBLE_SEED_SALT: &str = "world_id_card_marble_b9dcc41bf41_";

type Key = [u8; KEY_LENGTH];

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "version", content = "key")]
enum VersionedKey {
    V0(String),
    #[serde(
        serialize_with = "serialize_key_as_hex",
        deserialize_with = "deserialize_key_from_hex"
    )]
    V1(Key),
}

#[derive(uniffi::Object, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RootKey {
    #[serde(flatten)]
    key: VersionedKey,
}

fn serialize_key_as_hex<S>(key: &Key, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = hex::encode(key);
    serializer.serialize_str(&hex_string)
}

fn deserialize_key_from_hex<'de, D>(deserializer: D) -> Result<Key, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    let decoded_key = hex::decode(s).map_err(serde::de::Error::custom)?;

    if decoded_key.len() != KEY_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Key length must be {} bytes",
            KEY_LENGTH
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&decoded_key);

    Ok(key)
}

#[bedrock_error]
pub enum SecureError {
    #[error("Failed to derive subkey from RootKey.")]
    DeriveKeyError,
    #[error("Failed to parse RootKey.")]
    KeyParseError,
}

/// Derives a subkey from the given key and subkey id using KDF.
fn derive_subkey(key: &Key, subkey_id: u64) -> Result<Key, SecureError> {
    let key = Kdf::from_parts(*key, CONTEXT);
    let subkey = key
        .derive_subkey_to_vec(subkey_id)
        .map_err(|_| SecureError::DeriveKeyError)?;
    let mut result_key = [0u8; KEY_LENGTH];
    result_key.copy_from_slice(&subkey);
    Ok(result_key)
}

fn derive_key_v0(encoded_key: String) -> Result<Key, SecureError> {
    let mut hasher = Sha256::new();
    hasher.update(encoded_key);
    let key_bytes = hasher.finalize().to_vec();

    if key_bytes.len() != KEY_LENGTH {
        return Err(SecureError::KeyParseError);
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&key_bytes);

    Ok(key)
}

#[bedrock_export]
impl RootKey {
    /// Generates a new random `RootKey` using the system CSPRNG.
    ///
    /// # Panics
    /// Will panic if there is an error with the CSPRNG. This terminates the app.
    ///
    /// # TODO
    /// Remove the Result and Arc wrapping (API breaking change)
    #[uniffi::constructor]
    pub fn new() -> Result<Self, SecureError> {
        let mut buf = [0u8; KEY_LENGTH];
        OsRng
            .try_fill_bytes(&mut buf)
            .expect("Fatal CSPRNG error: unable to initialize new RootKey");
        Ok(Self {
            key: VersionedKey::V1(buf),
        })
    }

    /// Decodes the key from serialized format.
    #[uniffi::constructor]
    pub fn decode(encoded_key: String) -> Result<Self, SecureError> {
        let key = serde_json::from_str::<Self>(&encoded_key)
            .map_err(|_| SecureError::KeyParseError);

        match key {
            Ok(key) => Ok(key),
            Err(_) => Ok(Self {
                key: VersionedKey::V0(encoded_key),
            }),
        }
    }

    /// Decodes the key from JSON serialized format.
    ///
    /// This function does not allow the key to be in the raw hex format, like regular `decode`.
    /// Even it is a v0 key, it has to be serialized in JSON format (for example, after .encode()).
    ///
    /// This function can be used in cases where `RootKey` is decoded regularly (for v0 or v1) and then
    /// re-encoded to full JSON format. For example, backup service parses the key from HEX/JSON
    /// on enrollment (using regular `decode`) and then re-encodes it to JSON format for storage.
    /// When recovery is happening, we know the key is in JSON format, so we can use this function
    /// to decode it at the recovery time.
    #[uniffi::constructor]
    pub fn decode_from_json_enforced(encoded_key: String) -> Result<Self, SecureError> {
        let key = serde_json::from_str::<Self>(&encoded_key)
            .map_err(|_| SecureError::KeyParseError)?;
        Ok(key)
    }

    /// Encodes the key as JSON.
    pub fn encode(&self) -> Result<String, SecureError> {
        serde_json::to_string(self).map_err(|_| SecureError::Generic {
            message: "unable to encode RootKey as JSON".to_string(),
        })
    }

    /// Returns true if the key is in the legacy format and don't used indexed derivation.
    pub fn is_v0(&self) -> bool {
        matches!(self.key, VersionedKey::V0(_))
    }

    /// Returns the Ethereum key as hex (without leading 0x).
    pub fn ethereum_key(&self) -> Result<String, SecureError> {
        // In the old version, the key was used directly.
        Ok(match &self.key {
            VersionedKey::V0(str) => hex::encode(derive_key_v0(str.clone())?),
            VersionedKey::V1(key) => hex::encode(derive_subkey(key, ETHEREUM_KEY_ID)?),
        })
    }

    pub fn ethereum_key_with_index(&self, index: u64) -> Result<String, SecureError> {
        Ok(match &self.key {
            VersionedKey::V0(str) => {
                if index == 0 {
                    hex::encode(derive_key_v0(str.clone())?)
                } else {
                    // In V0, the base key is used directly for different purposes,
                    // whereas in V1, the main key serves as a seed for deriving subkeys specific to each purpose.
                    // To enable predictable generation of a new Ethereum key from an index,
                    // we must derive a seed key that is distinct from the original one, similar to the "marble" approach.
                    let mut hasher = Sha256::new();
                    hasher.update(ROTATED_ETHEREUM_KEY_SALT);
                    hasher.update(str);
                    let key_bytes = hasher.finalize().to_vec();

                    if key_bytes.len() != KEY_LENGTH {
                        return Err(SecureError::KeyParseError);
                    }

                    let mut result_key = [0u8; KEY_LENGTH];
                    result_key.copy_from_slice(&key_bytes);

                    hex::encode(derive_subkey(&result_key, index)?)
                }
            }
            VersionedKey::V1(key) => {
                if index == 0 {
                    hex::encode(derive_subkey(key, ETHEREUM_KEY_ID)?)
                } else {
                    // Use ROTATED_ETHEREUM_KEY_ID key to create a separate linearly indexed space of ethereum keys.
                    hex::encode(derive_subkey(
                        &derive_subkey(key, ROTATED_ETHEREUM_KEY_ID)?,
                        index,
                    )?)
                }
            }
        })
    }

    /// Returns the World ID key as hex (without leading 0x).
    pub fn worldid_key(&self) -> Result<String, SecureError> {
        // In the old version, the key was used directly.
        // Notes:
        //   (1) The key is used in semaphore-rs, which itself derives a separate key from it through sha256.
        //   (2) The key is 32 bytes and thus larger than BN254 field size, which is not handled in semaphore-rs.
        //       This introduces a modulo bias, but was explicitely not handled to keep equivalence with zk-kit.js.
        Ok(match &self.key {
            VersionedKey::V0(str) => hex::encode(derive_key_v0(str.clone())?),
            VersionedKey::V1(key) => hex::encode(derive_subkey(key, WORLDID_KEY_ID)?),
        })
    }

    // FIXME: Not yet implemented
    // /// Returns the Orb encryption key, used to encrypt the Personal Custody Package.
    // pub fn orb_encryption_key(
    //     &self,
    // ) -> Result<Arc<PersonalCustodyKeypair>, SecureError> {
    //     let key = match &self.key {
    //         VersionedKey::V0(key_str) => derive_key_v0(key_str.clone())?,
    //         VersionedKey::V1(key) => *key,
    //     };

    //     let subkey = derive_subkey(&key, ORB_ENCRYPTION_KEY_ID)?;
    //     Ok(Arc::new(PersonalCustodyKeypair::derive_from_seed(&subkey)))
    // }

    // /// Returns the encryption key for Personal Custody Package for documents, starting with
    // /// the passport.
    // pub fn document_encryption_key(
    //     &self,
    // ) -> Result<Arc<PersonalCustodyKeypair>, SecureError> {
    //     let key = match &self.key {
    //         VersionedKey::V0(key_str) => derive_key_v0(key_str.clone())?,
    //         VersionedKey::V1(key) => *key,
    //     };

    //     let subkey = derive_subkey(&key, DOCUMENT_PCP_KEY_ID)?;
    //     Ok(Arc::new(PersonalCustodyKeypair::derive_from_seed(&subkey)))
    // }

    /// Returns the encryption key for World Chat backup.
    pub fn world_chat_backup_key(&self) -> Result<String, SecureError> {
        let key = match &self.key {
            VersionedKey::V0(key_str) => derive_key_v0(key_str.clone())?,
            VersionedKey::V1(key) => *key,
        };

        let subkey = derive_subkey(&key, WORLDCHAT_BACKUP_KEY_ID)?;
        Ok(hex::encode(subkey))
    }

    pub fn marble_seed(&self) -> Result<String, SecureError> {
        Ok(match &self.key {
            VersionedKey::V0(str) => {
                let mut hasher = Sha256::new();
                hasher.update(MARBLE_SEED_SALT);
                hasher.update(str);

                let bigint = U256::from_be_slice(&hasher.finalize());
                bigint.to_string()
            }
            VersionedKey::V1(key) => {
                let key = derive_subkey(key, MARBLE_SEED_KEY_ID)?;
                U256::from_be_bytes(key).to_string()
            }
        })
    }

    /// Returns world chat push id as hex (without leading 0x)
    ///
    /// Rotation is controlled by a numeric `counter`.
    ///
    /// Steps:
    /// 1. Derive a 32-byte push secret from the root key.
    /// 2. Use BLAKE3 keyed hashing with that secret and the little-endian
    ///    fixed 8-byte encoding of the provided `counter`.
    ///
    /// Using a fixed-length little-endian encoding provides a canonical
    /// representation for the counter input.
    ///
    /// **Note:** The push id itself is not a secret it's used to identify the user across devices for notifications,
    pub fn world_chat_push_id_public(
        &self,
        counter: u64,
    ) -> Result<String, SecureError> {
        let key = match &self.key {
            VersionedKey::V0(key_str) => derive_key_v0(key_str.clone())?,
            VersionedKey::V1(key) => *key,
        };
        let push_secret = derive_subkey(&key, WORLD_CHAT_PUSH_ID_KEY_ID)?;

        let counter_bytes = counter.to_le_bytes();

        let push_id = blake3::keyed_hash(&push_secret, &counter_bytes);

        Ok(push_id.to_hex().to_string())
    }
}

#[cfg(test)]
impl RootKey {
    // A test identity with idComm = 0x305105be6fd1b51e543f8b73744f1b34da9717d38ff17f66a9820c987eb77618
    pub fn test_key() -> Self {
        let key = r#"{"version":"V1","key":"171bb3fa7a43708f077ee4b7c6c0602d95b10f4b7227fe60ec26fdcd964b78c1"}"#;
        RootKey::decode(key.to_owned()).unwrap().clone()
    }
}

#[cfg(test)]
mod test;
