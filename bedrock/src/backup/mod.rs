mod backup_format;
mod manifest;
mod personal_custody_keypair;
mod service_client;
mod signer;
mod utils;

#[cfg(test)]
mod test;

use bedrock_macros::bedrock_export;
pub use manifest::{BackupManifest, GlobalManifestV1, ManifestEntry, ManifestManager};
use personal_custody_keypair::PersonalCustodyKeypair;
use regex::Regex;
pub use signer::SyncSigner;

use crate::backup::backup_format::v0::V0Backup;
use crate::backup::backup_format::BackupFormat;
use crate::secure::RootKey;
use crypto_box::SecretKey;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Tools for storing, retrieving, encrypting and decrypting backup data.
///
/// Unsealed backups are raw bytes with the root secret and files.
///
/// Unsealed backups becomes sealed backups when they are encrypted with "a backup keypair".
/// Backup keypair is a keypair that is used to encrypt the raw backup data and generated
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
/// Why is there a level of indirection, why can't factor secret be used to encrypt the backup directly?
/// Backup keypair can be encrypted multiple times, separately, with different factor secrets.
/// This allows to build 1-of-N recovery flows, where you recover the backup with any of the
/// factor secrets. In this case, Backup Service needs to store one sealed backup and multiple
/// encrypted backup keypairs, one for each factor secret.
///
/// Note that the unsealed backup is encrypted with the backup keypair and not a symmetric key.
/// Users can update the backup content with a new root secret and files, and then re-encrypt the backup
/// with the public key of the backup keypair. This public key can be stored in a location that
/// doesn't have to be secure. This update operation also SHOULD NOT change the encrypted backup
/// keypair(s), making it possible to update the backup content without re-acquiring factor secrets.
///
/// "Sealed backup with metadata" is all the information that needs to be stored on device or
/// in the cloud to enable CRUD operations on the backup and factors (outside of factor secrets
/// themselves). It includes:
/// * Sealed backup data
/// * Encrypted backup keypair(s). Note that all items are encrypting the same backup keypair,
///   but with different factor secrets.
/// * Backup keypair public key
///
/// # Flows
///
/// ## Create
///
/// 1. Acquire a factor secret from user. For example, prompt user for a PRF passkey, or generate a
///    random key and store it in the iCloud Keychain or Turnkey.
/// 2. Prepare an unsealed backup with the root secret and files.
/// 3. Generate a backup keypair randomly (cryptographically secure).
/// 4. Encrypt the unsealed backup with the backup keypair to create a sealed backup.
/// 5. Encrypt the backup keypair with the factor secret to create an encrypted backup keypair.
/// 6. Store the sealed backup and the encrypted backup keypair somewhere, e.g. Backup Service.
///
/// ## Restore (decrypt backup)
///
/// 1. Acquire a factor secret from user. For example, prompt user for a PRF passkey, or generate a
///    random key and store it in the iCloud Keychain or Turnkey.
/// 2. Retrieve the sealed backup and the encrypted backup keypair from the Backup Service.
/// 3. Decrypt the encrypted backup keypair with the factor secret to get the backup keypair.
/// 4. Decrypt the sealed backup with the backup keypair to get the unsealed backup.
/// 5. Use the unsealed backup to restore the wallet.
///
/// ## Add new factor
///
/// 1. Acquire the new factor secret from user. For example, prompt user for a PRF passkey, or generate a
///    random key and store it in the iCloud Keychain or Turnkey.
/// 2. Acquire an existing factor secret from the user.
/// 3. Retrieve the encrypted backup keypair that corresponds to the old factor from the Backup
///    Service or from the device.
/// 4. Decrypt the encrypted backup keypair with the old factor secret to get the backup keypair.
/// 5. Encrypt the backup keypair with the new factor secret to create a new encrypted backup keypair.
/// 6. Store the new encrypted backup keypair and the old encrypted backup keypair alongside the sealed backup.
///
/// Now, the backup can be decrypted with either of the factor secrets.
///
/// ## Remove factor
/// 1. Delete the encrypted backup keypair that corresponds to the factor from the Backup Service.
///
/// ## Update backup
/// 1. Retrieve the public key of the backup keypair from the Backup Service or from the device.
/// 2. Get the new root secret and files, e.g. from the app.
/// 3. Re-generate unsealed backup with the new root secret and files.
/// 4. Encrypt the unsealed backup with the public key of the backup keypair to create a new sealed backup.
/// 5. Store the new sealed backup instead of the old one in the Backup Service. Note that the
///    encrypted backup keypair(s) and the backup keypair has not changed.
///
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
        root_secret: String,
        factor_secret: String,
        factor_type: FactorType,
    ) -> Result<CreatedBackup, BackupError> {
        log::info!("[BackupManager] creating sealed backup for new user with factor: {factor_type:?}");

        // 1: Decode the root secret from multiple formats
        let root_secret = Arc::new(RootKey::decode(root_secret));

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
        let sealed_backup = backup_secret_key
            .public_key()
            .seal(&mut rand::thread_rng(), &unsealed_backup)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 5: Encrypt the backup keypair with the factor secret
        // NOTE: We're using `.public_key()`, because `crypto_box` only exposes a keypair primitive,
        // but a symmetric would've sufficed here. However, reducing the amount of crypto primitives
        // reduces the attack surface.
        let encrypted_backup_keypair = factor_secret_key
            .public_key()
            .seal(&mut rand::thread_rng(), &backup_secret_key.to_bytes())
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 6: Prepare the result
        let result = CreatedBackup {
            sealed_backup_data: sealed_backup,
            encrypted_backup_keypair: hex::encode(encrypted_backup_keypair),
            backup_keypair_public_key: hex::encode(
                backup_secret_key.public_key().as_bytes(),
            ),
            manifest_hash: ManifestManager::compute_manifest_hash(&GlobalManifestV1 {
                version: 1,
                previous_manifest_hash: None,
                files: vec![],
            }),
            // FIXME: check if it's an issue that Oxide doesn't know whether the backup was actually created or not
        };

        Ok(result)
    }

    /// Decrypts the sealed backup using the factor secret and the encrypted backup keypair.
    ///
    /// * `sealed_backup_data` - is the sealed backup data that was created during sign up. The data is
    ///   encrypted with the backup keypair public key.
    /// * `encrypted_backup_keypair` - is the backup keypair that was encrypted with the factor secret.
    ///   Hex encoded.
    /// * `factor_secret` - is the factor secret that was used to encrypt the backup keypair. Hex encoded.
    /// * `factor_type` - is the type of factor that was used to encrypt the backup keypair.
    ///   It should mark what kind of key `factor_secret` is.
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
    /// Decrypts a sealed backup using the factor secret and encrypted backup keypair.
    ///
    /// # Errors
    /// Propagates decoding/decryption errors when inputs are malformed or do not match.
    pub fn decrypt_sealed_backup(
        &self,
        sealed_backup_data: &[u8],
        encrypted_backup_keypair: String,
        factor_secret: String,
        factor_type: FactorType,
    ) -> Result<DecryptedBackup, BackupError> {
        log::info!(
            "[BackupManager] decrypting sealed backup with factor: {factor_type:?}"
        );

        // 1: Check if sealed backup data is valid
        if sealed_backup_data.is_empty() {
            return Err(BackupError::InvalidSealedBackupError);
        }

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

        // 3.1: Decode the backup keypair that was encrypted with the factor secret
        let encrypted_backup_keypair_bytes = hex::decode(encrypted_backup_keypair)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        // 3.2: Decrypt the backup keypair with the factor secret
        let backup_keypair_bytes = factor_secret_key
            .unseal(&encrypted_backup_keypair_bytes)
            .map_err(|_| BackupError::DecryptBackupKeypairError)?;

        // 4.1: Build a PersonalCustodyKeypair from the decrypted backup keypair
        let backup_keypair = Zeroizing::new(
            PersonalCustodyKeypair::from_private_key_bytes(&backup_keypair_bytes),
        );
        // 4.2: Decrypt the sealed backup with the backup keypair
        let unsealed_backup = backup_keypair
            .sk()
            .unseal(sealed_backup_data)
            .map_err(|_| BackupError::DecryptBackupError)?;

        // 5: Deserialize the unsealed backup
        let unsealed_backup = BackupFormat::from_bytes(&unsealed_backup)?;

        Ok(DecryptedBackup {
            backup: unsealed_backup,
            backup_keypair_public_key: hex::encode(backup_keypair.pk().as_bytes()),
        })
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
    ) -> Result<UnpackedBackupResponse, BackupError> {
        log::info!(
            "[BackupManager] decrypting sealed backup with factor: {factor_type:?}"
        );

        // 1: Check if sealed backup data is valid
        if sealed_backup_data.is_empty() {
            return Err(BackupError::InvalidSealedBackupError);
        }

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

        // 3.1: Decode the backup keypair that was encrypted with the factor secret
        let encrypted_backup_keypair_bytes = hex::decode(encrypted_backup_keypair)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        // 3.2: Decrypt the backup keypair with the factor secret
        let backup_keypair_bytes = factor_secret_key
            .unseal(&encrypted_backup_keypair_bytes)
            .map_err(|_| BackupError::DecryptBackupKeypairError)?;

        // 4.1: Build a PersonalCustodyKeypair from the decrypted backup keypair
        let backup_keypair = Zeroizing::new(
            PersonalCustodyKeypair::from_private_key_bytes(&backup_keypair_bytes),
        );
        // 4.2: Decrypt the sealed backup with the backup keypair
        let unsealed_backup = backup_keypair
            .sk()
            .unseal(sealed_backup_data)
            .map_err(|_| BackupError::DecryptBackupError)?;

        // 5: Deserialize the unsealed backup
        let _unsealed_backup = BackupFormat::from_bytes(&unsealed_backup)?;

        Ok(UnpackedBackupResponse {
            backup_keypair_public_key: hex::encode(backup_keypair.pk().as_bytes()),
        })
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

/// The modules which are allowed to create a backup manifest and add a file to the backup.
#[derive(
    strum::Display, strum::EnumString, Debug, Clone, PartialEq, Eq, uniffi::Enum,
)]
#[strum(serialize_all = "snake_case")]
pub enum BackupModule {
    /// Personal Custody Package module.
    PersonalCustody,
    /// Personal Custody for documents module.
    DocumentPersonalCustody,
}

impl Serialize for BackupModule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BackupModule {
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
    #[error("Failed to write file to file system")]
    /// Failed to write file to filesystem.
    WriteFileError,
    /// The provided file from a manifest to build the unsealed backup is not valid.
    #[error("Invalid file for backup: {0}")]
    /// The provided file from a manifest to build the unsealed backup is not valid.
    InvalidFileForBackup(String),
    #[error("Failed to parse backup manifest {manifest_name}: {details}")]
    /// Failed to parse a backup manifest JSON file.
    ParseBackupManifestError {
        /// Additional error details for debugging.
        details: String,
        /// The manifest file name.
        manifest_name: String,
    },
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
    #[error("Invalid module name: {0}")]
    /// Invalid module name provided.
    InvalidModuleName(String),
    #[error("global manifest not found")]
    /// Global manifest file not found.
    GlobalManifestNotFound,
    #[error("local backup checkpoint file does not exist")]
    /// Local backup checkpoint file does not exist.
    InexistentLocalCheckpointFile,
    #[error("local backup checkpoint error: {0}")]
    /// Error while reading/writing local backup checkpoint.
    LocalCheckpointError(String),
    #[error("Invalid checksum for file {module_name}")]
    /// File checksum does not match the expected value.
    InvalidChecksumError {
        /// The module name associated with the file.
        module_name: String,
    },
    /// Remote manifest head is ahead of local.
    /// Native layer should trigger a download/apply of the latest backup before retrying.
    #[error("remote manifest is ahead of local; fetch and apply latest backup before updating")]
    /// Remote manifest head is ahead of local; fetch and apply latest backup before retrying.
    RemoteAheadStaleError,
    #[error("unexpected error: {0}")]
    /// Unexpected error.
    UnexpectedError(String),
}

/// Trait for errors that can be sanitized for safe logging.
pub trait SanitizeError: std::fmt::Debug + Send + Sync {
    /// Converts the error to a sanitized string safe for logging.
    fn as_sanitized_string(&self) -> String;
}

static ERROR_WORD_WHITELIST: &[&str] = &[
    "missing", "field", "checksum", "invalid", "type", "break", "expected", "map",
    "matching", "variant", "not", "found", "bool", "tag", "known", "non",
];

impl SanitizeError for ciborium::de::Error<std::io::Error> {
    fn as_sanitized_string(&self) -> String {
        match self {
            Self::Io(_) | Self::Syntax(_) => self.to_string(), // error is regular IO and only contains the pos offset
            Self::Semantic(pos, msg) => {
                // generally semantic errors don't contain any payload, but out of an abundance of caution, we sanitize to only
                // specific whitelisted words.
                let re = Regex::new(r"[A-Za-z0-9\-]+");
                re.map_or_else(
                    |_| format!("Semantic error at {pos:?}. Unable to sanitize error message, skipping."),
                    |re| {
                        let sanitized_msg = re
                            .find_iter(msg)
                            .map(|m| m.as_str())
                            .filter(|token| ERROR_WORD_WHITELIST.iter().any(|&w| w.eq_ignore_ascii_case(token)))
                            .collect::<Vec<_>>()
                            .join(" ");
                        format!("Semantic error at {pos:?}: {sanitized_msg}")
                    },
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
    /// The unsealed backup data with all the files.
    backup: BackupFormat,
    /// The public key of the backup keypair that was used to encrypt the backup. Client will need
    /// to save it to re-encrypt future backup updates. Hex encoded.
    backup_keypair_public_key: String,
}

/// Result of decrypting and unpacking a sealed backup.
#[derive(Debug, uniffi::Record)]
pub struct UnpackedBackupResponse {
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
