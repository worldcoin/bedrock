mod backup_format;
mod client_events;
mod manifest;
mod service_client;

#[cfg(test)]
mod test;

use bedrock_macros::bedrock_export;
pub use client_events::{
    BaseReport, ClientEventsError, ClientEventsReporter, EncryptionKeyKind, EventKind,
    MainFactor,
};
pub use manifest::ManifestManager;

use crate::backup::backup_format::v0::{
    V0Backup, V0BackupManifest, V0BackupManifestEntry,
};
use crate::backup::backup_format::BackupFormat;
use crate::backup::manifest::BackupManifest;
use crate::primitives::filesystem::{get_filesystem_raw, FileSystemExt};
use crate::root_key::RootKey;
use crypto_box::SecretKey;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// Tools for storing, retrieving, encrypting and decrypting backup data.
///
/// Unsealed backups are raw bytes with the `RootKey` and files.
///
/// Unsealed backups becomes sealed backups when they are encrypted with "a backup keypair".
/// Backup keypair is a keypair that is used to encryp  t the raw backup data and generated
/// during the backup creation.
///
/// Backup keypair itself is encrypted with "a factor secret" to create "encrypted backup keypair".
/// The factor secret is a key that the end user's device / cloud stores or recovers. For example,
/// the factor secret could be a passkey PRF, or a random key that is stored in the iCloud Keychain,
/// or a key that's stored in Turnkey.
///
/// "Encrypted backup keypair" is stored alongside the sealed backup data. Both are needed to
/// decrypt the backup.
///
/// Documentation: <https://docs.toolsforhumanity.com/world-app/backup>
#[derive(uniffi::Object, Clone, Debug, Default)]
pub struct BackupManager {}

#[bedrock_export]
impl BackupManager {
    #[uniffi::constructor]
    #[must_use]
    /// Constructs a new `BackupManager` instance.
    pub fn new() -> Self {
        Self {}
    }

    /// Creates a sealed backup with metadata for a new user with a factor secret. Since it's a new user,
    /// the backup won't contain PCP data yet.
    ///
    /// * `root_secret` - is the root secret seed of the wallet that is used to derive the wallet,
    ///   World ID identity and PCP encryption keys. Hex encoded for V0 and JSON encoded for V1.
    /// * `factor_secret` - is a factor secret that is used to encrypt the backup keypair. Hex encoded.
    ///   It could be coming from the passkey PRF, or a random key that's stored in the iCloud
    ///   keychain or Turnkey.
    /// * `factor_type` - is the type of factor that was used to encrypt the backup keypair. It should mark what
    ///   kind of key `factor_secret` is.
    ///
    /// # Errors
    /// * `BackupError::DecodeFactorSecretError` - if the factor secret is invalid, e.g. not hex encoded.
    /// * `BackupError::InvalidFactorSecretLengthError` - if the factor secret is not 32 bytes.
    /// * `BackupError::EncryptBackupError` - if the backup keypair cannot be created or the backup cannot be
    ///   encrypted.
    pub fn create_sealed_backup_for_new_user(
        &self,
        root_secret: &str,
        factor_secret: String,
        factor_type: FactorType,
    ) -> Result<CreatedBackup, BackupError> {
        log::info!("[BackupManager] creating sealed backup for new user with factor: {factor_type:?}");

        // 1: Decode the root secret from multiple formats
        let root_secret = RootKey::from_json(root_secret)
            .map_err(|_| BackupError::InvalidRootSecretError)?;

        // 2.1: Decode factor secret from hex
        let factor_secret_bytes = hex::decode(factor_secret)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;

        // 2.2: Check that the factor secret is 32 bytes
        if factor_secret_bytes.len() != 32 {
            return Err(BackupError::InvalidFactorSecretLengthError);
        }

        // 2.3: Build a crypto_box SecretKey from factor secret
        // NOTE: SecretKey will get zeroized on drop.
        let factor_secret_key = SecretKey::from_slice(&factor_secret_bytes)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;

        // 3: Build the unsealed backup
        let unsealed_backup = BackupFormat::new_v0(V0Backup::new(root_secret, vec![]));
        let unsealed_backup = unsealed_backup.to_bytes()?;

        // 4.1: Create a backup encryption keypair
        // NOTE: Underlying secret key will get zeroized on drop.
        let backup_secret_key = SecretKey::generate(&mut rand::thread_rng());

        // 4.2: Encrypt the backup with the backup encryption public key to create the sealed backup
        let sealed_backup = Self::seal_backup_with_public_key(
            &unsealed_backup,
            &backup_secret_key.public_key(),
        )?;

        // 5: Encrypt the backup keypair with the factor secret
        // NOTE: We're using `.public_key()`, because `crypto_box` only exposes a keypair primitive,
        // but a symmetric would've sufficed here. However, reducing the amount of crypto primitives
        // reduces the attack surface.
        let encrypted_backup_keypair = factor_secret_key
            .public_key()
            .seal(&mut rand::thread_rng(), &backup_secret_key.to_bytes())
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 5.1: Initialize and persist the initial manifest (empty files set) and compute its hash
        let manifest = BackupManifest::V0(V0BackupManifest {
            previous_manifest_hash: None,
            files: vec![],
        });
        let manifest_hash_hex = hex::encode(manifest.calculate_hash()?);


        let manifest_manager = ManifestManager::new();
        manifest_manager.write_manifest(&manifest)?;

        // 6: Prepare the result
        let result = CreatedBackup {
            sealed_backup_data: sealed_backup,
            encrypted_backup_keypair: hex::encode(encrypted_backup_keypair),
            backup_keypair_public_key: hex::encode(
                backup_secret_key.public_key().as_bytes(),
            ),
            manifest_hash: manifest_hash_hex,
        };

        Ok(result)
    }

    /// Decrypts the sealed backup using the factor secret and the encrypted backup keypair. It then unpacks the backup
    /// directly into the file system.
    ///
    /// * `sealed_backup_data` - is the sealed backup data that was created during sign up. The data is
    ///   encrypted with the backup keypair public key.
    /// * `encrypted_backup_keypair` - is the backup keypair that was encrypted with the factor secret.
    ///   Hex encoded.
    /// * `factor_secret` - is the factor secret that was used to encrypt the backup keypair. Hex encoded.
    /// * `factor_type` - is the type of factor that was used to encrypt the backup keypair.
    ///   It should mark what kind of key `factor_secret` is.
    /// * `current_manifest_hash` - hex-encoded 32-byte blake3 hash of the manifest head at the time
    ///   the fetched backup was created (returned by the remote and provided by the native layer).
    ///
    /// # Errors
    /// * `BackupError::DecodeFactorSecretError` - if the factor secret is invalid, e.g. not hex encoded.
    /// * `BackupError::InvalidFactorSecretLengthError` - if the factor secret is not 32 bytes.
    /// * `BackupError::DecodeBackupKeypairError` - if the encrypted backup keypair is invalid.
    /// * `BackupError::DecryptBackupKeypairError` - if the backup keypair cannot be decrypted.
    /// * `BackupError::DecryptBackupError` - if the sealed backup cannot be decrypted.
    /// * `BackupError::InvalidRootSecretError` - if the root secret in the backup is invalid.
    /// * `BackupError::VersionNotDetectedError` - if the backup version cannot be detected.
    /// * `BackupError::IoError` - if the backup cannot be read.
    ///
    /// Decrypts the sealed backup and unpacks it to the file system.
    ///
    /// # Errors
    /// Propagates decoding/decryption errors when inputs are malformed or do not match.
    pub fn decrypt_and_unpack_sealed_backup(
        &self,
        sealed_backup_data: &[u8],
        encrypted_backup_keypair: String,
        factor_secret: String,
        factor_type: FactorType,
        current_manifest_hash: String,
    ) -> Result<DecryptedBackup, BackupError> {
        log::info!(
            "[BackupManager] decrypting sealed backup with factor: {factor_type:?}"
        );

        if sealed_backup_data.is_empty() {
            return Err(BackupError::InvalidSealedBackupError);
        }

        // Decode factor secret
        let factor_secret_bytes = hex::decode(factor_secret)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;
        if factor_secret_bytes.len() != 32 {
            return Err(BackupError::InvalidFactorSecretLengthError);
        }
        let factor_secret_key = SecretKey::from_slice(&factor_secret_bytes)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;

        // Decrypt `EncryptedBackupKeypair` (from Factor Secret)
        let encrypted_backup_keypair_bytes = hex::decode(encrypted_backup_keypair)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let backup_keypair_bytes = factor_secret_key
            .unseal(&encrypted_backup_keypair_bytes)
            .map_err(|_| BackupError::DecryptBackupKeypairError)?;
        let backup_secret_key = SecretKey::from_slice(&backup_keypair_bytes)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;

        // Decrypt the Sealed Backup
        let unsealed_backup = backup_secret_key
            .unseal(sealed_backup_data)
            .map_err(|_| BackupError::DecryptBackupError)?;

        let unsealed_backup = BackupFormat::from_bytes(&unsealed_backup)?;

        Self::unpack_backup_to_filesystem(&unsealed_backup, current_manifest_hash)?;

        match unsealed_backup {
            BackupFormat::V0(backup) => Ok(DecryptedBackup {
                root_key_json: backup
                    .root_secret
                    .danger_to_json()
                    .map_err(|_| BackupError::InvalidRootSecretError)?,
                backup_keypair_public_key: hex::encode(
                    backup_secret_key.public_key().as_bytes(),
                ),
            }),
        }
    }

    /// Adds new factor by re-encrypting the backup keypair (not the backup itself!)
    /// with a new factor secret.
    ///
    /// * `encrypted_backup_key_with_existing_factor_secret` - is the backup keypair that was
    ///   encrypted with the existing factor secret. Hex encoded.
    /// * `existing_factor_secret` - is an existing factor secret that was used to encrypt the backup keypair. Hex encoded.
    ///   For example, it could be coming from the passkey PRF, or a random key that's
    ///   stored in the iCloud keychain or Turnkey.
    /// * `new_factor_secret` - is the new factor secret that will be used to encrypt the backup keypair. Hex encoded.
    ///   For example, if the main factor is PRF, this could be a random key that's
    ///   stored in the iCloud keychain or Turnkey.
    /// * `existing_factor_type` - is the type of factor that was used to encrypt the backup keypair.
    ///   It should mark what kind of key `existing_factor_secret` is.
    /// * `new_factor_type` - is the type of factor that will be used to encrypt the backup keypair.
    ///   It should mark what kind of key `new_factor_secret` is.
    ///
    /// # Errors
    /// * `BackupError::DecodeFactorSecretError` - if the factor secret is invalid, e.g. not hex encoded.
    /// * `BackupError::InvalidFactorSecretLengthError` - if the factor secret is not 32 bytes.
    /// * `BackupError::DecodeBackupKeypairError` - if the backup keypair is invalid.
    /// * `BackupError::DecryptBackupKeypairError` - if the backup keypair cannot be decrypted.
    /// * `BackupError::EncryptBackupError` - if the backup keypair cannot be encrypted.
    pub fn add_new_factor(
        &self,
        encrypted_backup_key_with_existing_factor_secret: String,
        existing_factor_secret: String,
        new_factor_secret: String,
        existing_factor_type: FactorType,
        new_factor_type: FactorType,
    ) -> Result<AddNewFactorResult, BackupError> {
        log::info!("[BackupManager] creating new encrypted backup key: existing - {existing_factor_type:?}, new - {new_factor_type:?}");

        // 1: Decode the backup keypair that was encrypted with the existing factor secret
        let encrypted_backup_keypair_bytes =
            hex::decode(encrypted_backup_key_with_existing_factor_secret)
                .map_err(|_| BackupError::DecodeBackupKeypairError)?;

        // 2.1: Decode the existing factor secret from hex
        let existing_factor_secret_bytes = hex::decode(existing_factor_secret)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;
        // 2.2: Check that the existing factor secret is 32 bytes
        if existing_factor_secret_bytes.len() != 32 {
            return Err(BackupError::InvalidFactorSecretLengthError);
        }
        // 2.3: Build a crypto_box SecretKey from the existing factor secret
        // NOTE: SecretKey will get zeroized on drop.
        let existing_factor_secret_key =
            SecretKey::from_slice(&existing_factor_secret_bytes)
                .map_err(|_| BackupError::DecodeFactorSecretError)?;

        // 3.1: Decode new factor secret from hex
        let new_factor_secret_bytes = hex::decode(new_factor_secret)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;
        // 3.2: Check that the new factor secret is 32 bytes
        if new_factor_secret_bytes.len() != 32 {
            return Err(BackupError::InvalidFactorSecretLengthError);
        }
        // 3.3: Build a crypto_box SecretKey from new factor secret
        // NOTE: SecretKey will get zeroized on drop.
        let new_factor_secret_key = SecretKey::from_slice(&new_factor_secret_bytes)
            .map_err(|_| BackupError::DecodeFactorSecretError)?;

        // 4: Decrypt the backup keypair with the existing factor secret
        let backup_keypair_bytes = existing_factor_secret_key
            .unseal(&encrypted_backup_keypair_bytes)
            .map_err(|_| BackupError::DecryptBackupKeypairError)?;

        // 5: Re-encrypt the backup keypair with the new factor secret
        let encrypted_backup_keypair_with_new_factor = new_factor_secret_key
            .public_key()
            .seal(&mut rand::thread_rng(), &backup_keypair_bytes)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 6: Prepare the result
        let result = AddNewFactorResult {
            encrypted_backup_keypair_with_new_factor: hex::encode(
                encrypted_backup_keypair_with_new_factor,
            ),
        };

        Ok(result)
    }
}

// Internal helpers (not exported)
impl BackupManager {
    fn unpack_backup_to_filesystem(
        unsealed_backup: &BackupFormat,
        current_manifest_hash_hex: String,
    ) -> Result<(), BackupError> {
        let BackupFormat::V0(backup) = unsealed_backup;

        // NOTE: we don't use the module's prefix (`backup/`) here; as this
        // unpacks files directly into their module-owned locations.
        let fs = get_filesystem_raw()?;
        let mut manifest_entries: Vec<V0BackupManifestEntry> =
            Vec::with_capacity(backup.files.len());

        for file in &backup.files {
            let rel_path = file.path.trim_start_matches('/');

            // If a file already exists, verify checksum and log discrepancies before replacing.
            let path_ref = rel_path.get(..14).unwrap_or(rel_path); // don't log the full path to avoid leaking info
            match fs.file_exists(rel_path.to_string()) {
                Ok(true) => match fs.calculate_checksum(rel_path) {
                    Ok(local_checksum) => {
                        if local_checksum != file.checksum {
                            log::error!(
                                    "[BackupManager] checksum mismatch for existing file at {path_ref} (designator: {}). Replacing with remote content.",
                                    file.designator
                                );
                        }
                    }
                    Err(e) => {
                        log::error!(
                                "[BackupManager] failed to compute checksum for existing file at {path_ref}: {e:?}. Replacing with remote content.",
                            );
                    }
                },
                Ok(false) => {}
                Err(e) => {
                    log::error!(
                        "[BackupManager] failed to check existence for {path_ref}: {e:?}. Proceeding to write.",
                    );
                }
            }

            fs.write_file(rel_path.to_string(), file.data.clone())
                .map_err(|e| {
                    let err = anyhow::Error::from(e)
                        .context(format!("write unpacked file: {path_ref}"));
                    BackupError::from(err)
                })?;

            let designator = file.designator.clone();

            manifest_entries.push(V0BackupManifestEntry {
                designator,
                file_path: rel_path.to_string(),
                checksum_hex: hex::encode(file.checksum),
                file_size_bytes: u64::try_from(file.data.len()).unwrap_or(u64::MAX),
            });
        }

        // If the current manifest hash is the default hash, then there is no previous manifest hash
        // this must be set as `None`, otherwise the remote will appear ahead when it's not.
        // See: `test_decrypt_and_unpack_default_manifest_hash`
        let previous_manifest_hash =
            if current_manifest_hash_hex == BackupManifest::DEFAULT_HASH {
                None
            } else {
                Some(current_manifest_hash_hex)
            };

        let manifest = BackupManifest::V0(V0BackupManifest {
            previous_manifest_hash,
            files: manifest_entries,
        });

        let manifest_manager = ManifestManager::new();
        manifest_manager.write_manifest(&manifest)?;

        Ok(())
    }

    /// Encrypts the provided unsealed backup bytes using the given backup public key.
    /// Returns the sealed (encrypted) backup bytes.
    pub(crate) fn seal_backup_with_public_key(
        unsealed_backup: &[u8],
        public_key: &crypto_box::PublicKey,
    ) -> Result<Vec<u8>, BackupError> {
        public_key
            .seal(&mut rand::thread_rng(), unsealed_backup)
            .map_err(|_| BackupError::EncryptBackupError)
    }
}

/// A global identifier that identifies the type of file.
#[derive(
    strum::Display, strum::EnumString, Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum,
)]
#[strum(serialize_all = "snake_case")]
pub enum BackupFileDesignator {
    /// Orb Personal Custody Package (PCP) or "Orb Credential"
    OrbPkg,
    /// Document (NFC) Personal Custody Package (PCP) or "Document Credential"
    DocumentPkg,
    /// Secure Document (NFC) Personal Custody Package (PCP) or "Secure Document Credential"
    SecureDocumentPkg,
}

impl Serialize for BackupFileDesignator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BackupFileDesignator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(D::Error::custom)
    }
}

/// Errors that can occur when working with backups and manifests.
#[crate::bedrock_error]
pub enum BackupError {
    #[error("Failed to decode factor secret as hex")]
    /// Failed to decode factor secret as hex.
    DecodeFactorSecretError,
    #[error("Invalid factor secret length")]
    /// Factor secret is not the expected length.
    InvalidFactorSecretLengthError,
    #[error("Failed to decode backup keypair")]
    /// Failed to decode backup keypair bytes.
    DecodeBackupKeypairError,
    #[error("Failed to decrypt backup keypair")]
    /// Failed to decrypt backup keypair with factor secret.
    DecryptBackupKeypairError,
    #[error("Failed to decrypt sealed backup")]
    /// Failed to decrypt sealed backup data with backup keypair.
    DecryptBackupError,
    #[error("Invalid sealed backup")]
    /// Provided sealed backup data is empty or malformed.
    InvalidSealedBackupError,
    #[error("Failed to encrypt backup")]
    /// Failed to encrypt data using provided key.
    EncryptBackupError,
    #[error("IO error: {0}")]
    /// IO error while reading/writing backup data.
    IoError(#[from] std::io::Error),
    #[error("Invalid root secret in the backup")]
    /// Root secret inside backup is invalid.
    InvalidRootSecretError,
    #[error("Backup version is not detected")]
    /// Backup version cannot be detected.
    VersionNotDetectedError,
    #[error("Failed to read file name from archive")]
    /// Failed to read file name from archive entry.
    ReadFileNameError,
    #[error("Failed to encode root secret to JSON")]
    /// Failed to encode root secret to JSON.
    EncodeRootSecretError,
    /// The provided file from a manifest to build the unsealed backup is not valid.
    #[error("Invalid file for backup: {0}")]
    /// The provided file from a manifest to build the unsealed backup is not valid.
    InvalidFileForBackup(String),
    #[error("CBOR encoding error: {0}")]
    /// CBOR encoding error while writing a backup file.
    EncodeBackupFileError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("CBOR decoding error {path}: {}", error.as_sanitized_string())]
    /// CBOR decoding error while reading a backup file.
    DecodeBackupFileError {
        /// The underlying decoding error, sanitized for logging.
        error: Box<dyn SanitizeError>,
        /// The path of the file that failed to decode.
        path: String, // the path of the file that failed to decode
    },
    #[error("Manifest not found")]
    /// Manifest file not found.
    ManifestNotFound,
    #[error("[Critical] Checksum for file with designator: {designator} does not match the expected value")]
    /// File checksum does not match the expected value.
    InvalidChecksumError {
        /// The designator associated with the file.
        designator: String,
    },
    /// Remote manifest head is ahead of local.
    /// Native layer should trigger a download/apply of the latest backup before retrying.
    #[error("Remote manifest is ahead of local; fetch and apply latest backup before updating")]
    /// Remote manifest head is ahead of local; fetch and apply latest backup before retrying.
    RemoteAheadStaleError,
    #[error(transparent)]
    /// HTTP error.
    HttpError(#[from] crate::primitives::http_client::HttpError),
    #[error("Backup API not initialized")]
    /// Backup API not initialized.
    BackupApiNotInitialized,
}

/// Trait for errors that can be sanitized for safe logging.
pub trait SanitizeError: std::fmt::Debug + Send + Sync {
    /// Converts the error to a sanitized string safe for logging.
    fn as_sanitized_string(&self) -> String;
}

impl SanitizeError for ciborium::de::Error<std::io::Error> {
    fn as_sanitized_string(&self) -> String {
        match self {
            Self::Io(_) | Self::Syntax(_) => self.to_string(), // error is regular IO and only contains the pos offset
            Self::Semantic(pos, msg) => {
                // generally semantic errors don't contain any payload, but out of an abundance of caution, we only log the first bytes.
                format!(
                    "Semantic error at {pos:?}: {}",
                    msg.replace([' ', '`'], "").get(..14).unwrap_or(msg)
                )
            }
            Self::RecursionLimitExceeded => "recursion limit exceeded".to_string(),
        }
    }
}

/// Result of creating a new sealed backup for a user.
#[derive(Debug, uniffi::Record)]
pub struct CreatedBackup {
    /// The backup data, encrypted with the backup keypair.
    sealed_backup_data: Vec<u8>,
    /// The encrypted backup keypair. This value is encrypted with some factor secret
    /// (e.g. PRF, Turnkey, iCloud Keychain). Hex encoded.
    encrypted_backup_keypair: String,
    /// The public key of backup keypair that can be used to re-encrypt the backup data. Hex encoded.
    backup_keypair_public_key: String,
    /// The manifest hash representing the current backup state. Hex-encoded, 32-byte Blake3 hash.
    manifest_hash: String,
}

/// Result of decrypting a sealed backup.
#[derive(Debug, uniffi::Record)]
pub struct DecryptedBackup {
    /// The JSON-encoded root key. Exposed to foreign code to store securely.
    ///
    /// TODO: Secure memory pointers.
    root_key_json: String,
    /// The public key of the backup keypair that was used to encrypt the backup. Client will need
    /// to save it to re-encrypt future backup updates. Hex encoded.
    backup_keypair_public_key: String,
}

/// Result of re-encrypting the backup keypair with a new factor secret.
#[derive(Debug, uniffi::Record)]
pub struct AddNewFactorResult {
    /// The re-encrypted backup keypair that can be used to decrypt the backup data. The keypair itself
    /// is encrypted with the new factor secret. Hex encoded.
    encrypted_backup_keypair_with_new_factor: String,
}

/// The factor type used to encrypt the backup keypair.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FactorType {
    /// Generated using a passkey PRF.
    Prf,
    /// Generated randomly and stored in the iCloud keychain.
    IcloudKeychain,
    /// Generated randomly and stored in Turnkey.
    Turnkey,
}
