mod backup_format;

#[cfg(test)]
mod test;

use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::BackupFormat;
use crate::primitives::filesystem::create_middleware;
use crate::primitives::personal_custody_keypair::PersonalCustodyKeypair;
use crate::{bedrock_export, info, warn};
use chrono::{DateTime, Utc};
use crypto_box::SecretKey;
use serde::{Deserialize, Serialize};

use thiserror::Error;
use zeroize::Zeroizing;

const BACKUP_MANIFEST_DIRECTORY: &str = "/backup_manifests";

/// This struct represents metadata for files that should be backed up to external storage.
/// It's compatible with the oxide implementation
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Absolute path to the file on the device that should be backed up
    pub file_absolute_path: String,
    /// Name to save the file as in the backup storage
    pub save_as: String,
    /// When this manifest was last updated
    pub manifest_last_updated_at: DateTime<Utc>,
    /// Version of the manifest format
    pub manifest_version: u32,
    /// Maximum allowed file size in KB
    pub max_file_size_kb: u64,
}

impl BackupManifest {
    /// Create a new backup manifest
    ///
    /// # Arguments
    /// * `file_absolute_path` - Absolute path to the file that should be backed up
    /// * `save_as` - Name to save the file as in backup storage
    /// * `manifest_last_updated_at` - When this manifest was created/updated
    /// * `max_file_size_kb` - Maximum allowed file size in KB
    #[allow(clippy::missing_const_for_fn)] // DateTime<Utc> cannot be constructed in const context
    #[must_use]
    pub fn new(
        file_absolute_path: String,
        save_as: String,
        manifest_last_updated_at: DateTime<Utc>,
        max_file_size_kb: u64,
    ) -> Self {
        Self {
            file_absolute_path,
            save_as,
            manifest_last_updated_at,
            manifest_version: 1,
            max_file_size_kb,
        }
    }
}

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
/// keypair.
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
/// 3. Retrieve the encrypted backup keypair from the Backup Service or from the device.
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
#[derive(uniffi::Object, Clone, Debug, Default)]
pub struct BackupManager {}

#[bedrock_export]
impl BackupManager {
    /// Create a new backup manager
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Creates a sealed backup with metadata for a new user with a factor secret. Since it's a new user,
    /// the backup won't contain PCP data yet.
    ///
    /// * `root_secret` - is the root secret seed of the wallet that is used to derive the wallet,
    ///   World ID identity and PCP encryption keys. This is a placeholder string for now.
    /// * `factor_secret` - is the factor secret that will be used to encrypt the backup keypair. Hex encoded.
    ///   For example, it could be coming from the passkey PRF, or a random key that's
    ///   stored in the iCloud keychain or Turnkey.
    /// * `factor_type` - is the type of factor that will be used to encrypt the backup keypair.
    ///   It should mark what kind of key `factor_secret` is.
    ///
    /// Returns sealed backup data that can be stored somewhere and a backup keypair that was
    ///   encrypted.
    ///
    /// # Errors
    /// * `BackupError::DecodeFactorSecretError` - if the factor secret is invalid, e.g. not hex encoded.
    /// * `BackupError::InvalidFactorSecretLengthError` - if the factor secret is not 32 bytes.
    /// * `BackupError::EncryptBackupError` - if the backup cannot be encrypted.
    pub fn create_sealed_backup_for_new_user(
        &self,
        root_secret: String,
        factor_secret: &str,
        factor_type: FactorType,
    ) -> Result<CreatedBackup, BackupError> {
        info!("[BackupManager] creating sealed backup for new user with factor: {factor_type:?}");

        // 1: Decode the root secret from multiple formats (placeholder for now)
        // Using root_secret parameter directly

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
        let backup_encryption_keypair = PersonalCustodyKeypair::new()?;

        // 4.2: Encrypt the backup with the backup encryption public key to create the sealed backup
        let sealed_backup = backup_encryption_keypair
            .pk()
            .seal(&mut rand::thread_rng(), &unsealed_backup)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 5: Encrypt the backup keypair with the factor secret
        // NOTE: We're using `.public_key()`, because `crypto_box` only exposes a keypair primitive,
        // but a symmetric would've sufficed here. However, reducing the amount of crypto primitives
        // reduces the attack surface.
        let encrypted_backup_keypair = factor_secret_key
            .public_key()
            .seal(
                &mut rand::thread_rng(),
                &backup_encryption_keypair.sk_as_bytes(),
            )
            .map_err(|_| BackupError::EncryptBackupError)?;

        Ok(CreatedBackup {
            sealed_backup_data: sealed_backup,
            encrypted_backup_keypair: hex::encode(encrypted_backup_keypair),
            backup_keypair_public_key: hex::encode(
                backup_encryption_keypair.pk_as_bytes(),
            ),
        })
    }

    /// Decrypts a sealed backup using the provided factor secret.
    ///
    /// * `sealed_backup_data` - is the sealed backup data that was encrypted with the backup keypair.
    /// * `encrypted_backup_keypair` - is the encrypted backup keypair. Hex encoded.
    /// * `factor_secret` - is the factor secret that was used to encrypt the backup keypair. Hex encoded.
    ///   For example, it could be coming from the passkey PRF, or a random key that's
    ///   stored in the iCloud keychain or Turnkey.
    /// * `factor_type` - is the type of factor that was used to encrypt the backup keypair.
    ///   It should mark what kind of key `factor_secret` is.
    ///
    /// # Errors
    /// * `BackupError::InvalidSealedBackupError` - if the sealed backup data is empty.
    /// * `BackupError::DecodeFactorSecretError` - if the factor secret is invalid, e.g. not hex encoded.
    /// * `BackupError::InvalidFactorSecretLengthError` - if the factor secret is not 32 bytes.
    /// * `BackupError::DecodeBackupKeypairError` - if the backup keypair is invalid.
    /// * `BackupError::DecryptBackupKeypairError` - if the backup keypair cannot be decrypted.
    /// * `BackupError::DecryptBackupError` - if the backup cannot be decrypted.
    /// * `BackupError::IoError` - if the backup cannot be read.
    pub fn decrypt_sealed_backup(
        &self,
        sealed_backup_data: &[u8],
        encrypted_backup_keypair: String,
        factor_secret: &str,
        factor_type: FactorType,
    ) -> Result<DecryptedBackup, BackupError> {
        info!("[BackupManager] decrypting sealed backup with factor: {factor_type:?}");

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
            backup_keypair_public_key: hex::encode(backup_keypair.pk_as_bytes()),
        })
    }

    /// Adds new factor by re-encrypting the backup keypair (not the backup itself!)
    /// with a new factor secret.
    ///
    /// * `encrypted_backup_keypair` - is the backup keypair that was
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
        encrypted_backup_keypair: String,
        existing_factor_secret: &str,
        new_factor_secret: &str,
        existing_factor_type: FactorType,
        new_factor_type: FactorType,
    ) -> Result<AddNewFactorResult, BackupError> {
        info!("[BackupManager] creating new encrypted backup key: existing - {existing_factor_type:?}, new - {new_factor_type:?}");

        // 1: Decode the backup keypair that was encrypted with the existing factor secret
        let encrypted_backup_keypair_bytes = hex::decode(encrypted_backup_keypair)
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

    /// Updates the backup with the new root secret and files. The update DOES NOT change any
    /// encrypted backup keypair(s) nor the backup keypair (stored in metadata). It only updates the
    /// sealed backup data by re-encrypting it with the backup keypair public key.
    ///
    /// Note that this function OVERWRITES the existing sealed backup data with the new one. If
    /// some of the existing files are not present in the `files` list, they will be
    /// removed from the backup.
    ///
    /// New sealed backup data should be sent to backup-service for storage.
    ///
    /// * `root_secret` - is the root secret seed of the wallet that is used to derive the wallet,
    ///   World ID identity and PCP encryption keys. This is a placeholder string for now.
    /// * `files` - is the list of files that will be included in the new backup.
    /// * `backup_keypair_public_key` - is the public key of the backup keypair that was used to
    ///    encrypt the backup. Hex encoded.
    ///
    /// # Errors
    /// * `BackupError::DecodeBackupKeypairError` - if the backup keypair public key is invalid.
    /// * `BackupError::EncryptBackupError` - if new backup cannot be encrypted.
    /// * `BackupError::IoError` - if unsealed backup creation fails.
    /// * `BackupError::InvalidRootSecretError` - if the backup root secret is invalid.
    pub fn update_sealed_backup(
        &self,
        root_secret: String,
        files: Vec<V0BackupFile>,
        backup_keypair_public_key: String,
    ) -> Result<UpdatedSealedBackup, BackupError> {
        info!("[BackupManager] updating sealed backup, public key: {backup_keypair_public_key}");

        // 1: Decode the root secret from multiple formats (placeholder for now)
        // Using root_secret parameter directly

        // 2: Build the unsealed backup
        let unsealed_backup = BackupFormat::new_v0(V0Backup::new(root_secret, files));
        let unsealed_backup = unsealed_backup.to_bytes()?;

        // 3: Build a crypto_box PublicKey from the backup keypair public key
        let backup_keypair_public_key_bytes = hex::decode(backup_keypair_public_key)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let backup_keypair_public_key =
            crypto_box::PublicKey::from_slice(&backup_keypair_public_key_bytes)
                .map_err(|_| BackupError::DecodeBackupKeypairError)?;

        // 4: Encrypt the unsealed backup with the backup keypair public key to create the new sealed backup
        let sealed_backup = backup_keypair_public_key
            .seal(&mut rand::thread_rng(), &unsealed_backup)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 5: Prepare the result
        let result = UpdatedSealedBackup {
            sealed_backup_data: sealed_backup,
        };

        Ok(result)
    }

    /// Unpacks the unsealed backup to the file system. Unsealed backup should come from
    /// `decrypt_sealed_backup` method.
    ///
    /// # Errors
    /// * `BackupError::WriteFileError` - if the file cannot be written to the file system.
    pub fn unpack_unsealed_backup_to_file_system(
        &self,
        backup: &BackupFormat,
    ) -> Result<(), BackupError> {
        info!("Unpacking backup to filesystem");

        // Use raw filesystem access to bypass prefixing for oxide compatibility
        let fs_middleware = create_middleware("BackupManager");

        match backup {
            BackupFormat::V0(v0_backup) => {
                let user_data_dir = fs_middleware
                    .raw_get_user_data_directory()
                    .map_err(|_| BackupError::WriteFileError)?;

                for file in &v0_backup.files {
                    let file_path = format!(
                        "{}/{}",
                        user_data_dir.trim_end_matches('/'),
                        file.name
                    );

                    // Don't overwrite existing files
                    if fs_middleware
                        .raw_file_exists(&file_path)
                        .map_err(|_| BackupError::WriteFileError)?
                    {
                        warn!("File already exists, skipping: {}", file_path);
                    } else {
                        if !fs_middleware
                            .raw_write_file(&file_path, file.data.clone())
                            .map_err(|_| BackupError::WriteFileError)?
                        {
                            return Err(BackupError::WriteFileError);
                        }
                        info!("Wrote file: {}", file_path);
                    }
                }
            }
        }

        Ok(())
    }

    /// Syncs the backup manifest for a specific file to ensure it's backed up.
    ///
    /// This method creates or updates a backup manifest file that instructs the native app
    /// to backup the specified file. The method is idempotent - if the backup manifest
    /// already exists and matches the provided file path, it won't be updated.
    /// # Arguments
    /// * `module_name` - Name of the module requesting the backup (used as manifest filename)
    /// * `file_absolute_path` - Absolute path to the file that should be backed up
    /// * `save_as` - Name to save the file as in backup storage
    /// * `max_file_size_kb` - Maximum allowed file size in KB
    ///
    /// # Errors
    /// * `BackupError::WriteFileError` - if the manifest cannot be written
    /// * `BackupError::EncodeManifestError` - if the manifest cannot be serialized
    pub fn sync_backup_manifest(
        &self,
        module_name: &str,
        file_absolute_path: String,
        save_as: String,
        max_file_size_kb: u64,
    ) -> Result<(), BackupError> {
        info!("[BackupManager] syncing backup manifest for module: {module_name}");

        // Use raw filesystem access to maintain compatibility with oxide usage patterns
        let fs_middleware = create_middleware("BackupManager");

        // Check if file exists before creating manifest
        if !fs_middleware
            .raw_file_exists(&file_absolute_path)
            .map_err(|_| BackupError::WriteFileError)?
        {
            warn!(
                "File does not exist, cannot create backup manifest: {}",
                file_absolute_path
            );
            return Err(BackupError::WriteFileError);
        }

        let backup_manifest_path = format!("{BACKUP_MANIFEST_DIRECTORY}/{module_name}");

        // Check if backup manifest already exists and matches the file path
        // If it does, skip the update to avoid triggering unnecessary backup sync
        if let Ok(existing_manifest_data) =
            fs_middleware.raw_read_file(&backup_manifest_path)
        {
            if let Ok(existing_manifest) =
                serde_json::from_slice::<BackupManifest>(&existing_manifest_data)
            {
                if existing_manifest.file_absolute_path == file_absolute_path {
                    info!(
                        "Backup manifest already matches current file, skipping update"
                    );
                    return Ok(());
                }
            }
        }

        // Create new manifest
        let manifest = BackupManifest::new(
            file_absolute_path,
            save_as,
            Utc::now(),
            max_file_size_kb,
        );

        // Serialize manifest to JSON
        let manifest_json = serde_json::to_vec(&manifest)
            .map_err(|_| BackupError::EncodeManifestError)?;

        // Write manifest file (this will trigger backup sync in the native app)
        if !fs_middleware
            .raw_write_file(&backup_manifest_path, manifest_json)
            .map_err(|_| BackupError::WriteFileError)?
        {
            warn!("Failed to write backup manifest for module: {module_name}");
            return Err(BackupError::WriteFileError);
        }

        info!("Successfully wrote backup manifest for module: {module_name}");
        Ok(())
    }

    /// Removes the backup manifest for a specific module.
    ///
    /// This method deletes the backup manifest file, which will stop the native app
    /// from backing up the associated file.
    ///
    /// # Arguments
    /// * `module_name` - Name of the module whose backup manifest should be removed
    ///
    /// # Errors
    /// * `BackupError::WriteFileError` - if the manifest cannot be deleted
    pub fn remove_backup_manifest(&self, module_name: &str) -> Result<(), BackupError> {
        info!("[BackupManager] removing backup manifest for module: {module_name}");

        // Use raw filesystem access to maintain compatibility with oxide usage patterns
        let fs_middleware = create_middleware("BackupManager");
        let backup_manifest_path = format!("{BACKUP_MANIFEST_DIRECTORY}/{module_name}");

        if !fs_middleware
            .raw_delete_file(&backup_manifest_path)
            .map_err(|_| BackupError::WriteFileError)?
        {
            warn!("Failed to delete backup manifest for module: {module_name}");
            return Err(BackupError::WriteFileError);
        }

        info!("Successfully removed backup manifest for module: {module_name}");
        Ok(())
    }
}

/// Errors that can occur during backup operations
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum BackupError {
    /// Failed to decode factor secret as hex
    #[error("Failed to decode factor secret as hex")]
    DecodeFactorSecretError,
    /// Invalid factor secret length
    #[error("Invalid factor secret length")]
    InvalidFactorSecretLengthError,
    /// Failed to decode backup keypair
    #[error("Failed to decode backup keypair")]
    DecodeBackupKeypairError,
    /// Failed to decrypt backup keypair
    #[error("Failed to decrypt backup keypair")]
    DecryptBackupKeypairError,
    /// Failed to decrypt sealed backup
    #[error("Failed to decrypt sealed backup")]
    DecryptBackupError,
    /// Invalid sealed backup
    #[error("Invalid sealed backup")]
    InvalidSealedBackupError,
    /// Failed to encrypt backup
    #[error("Failed to encrypt backup")]
    EncryptBackupError,
    /// IO error
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    /// Invalid root secret in the backup
    #[error("Invalid root secret in the backup")]
    InvalidRootSecretError,
    /// Backup version is not detected
    #[error("Backup version is not detected")]
    VersionNotDetectedError,
    /// Failed to read file name from archive
    #[error("Failed to read file name from archive")]
    ReadFileNameError,
    /// Failed to encode root secret to JSON
    #[error("Failed to encode root secret to JSON")]
    EncodeRootSecretError,
    /// Failed to write recovered file to file system
    #[error("Failed to write recovered file to file system")]
    WriteFileError,
    /// Failed to encode backup manifest to JSON
    #[error("Failed to encode backup manifest to JSON")]
    EncodeManifestError,
}

impl From<crate::primitives::personal_custody_keypair::PersonalCustodyKeypairError>
    for BackupError
{
    fn from(
        _: crate::primitives::personal_custody_keypair::PersonalCustodyKeypairError,
    ) -> Self {
        Self::EncryptBackupError
    }
}

impl From<hex::FromHexError> for BackupError {
    fn from(_: hex::FromHexError) -> Self {
        Self::DecodeFactorSecretError
    }
}

impl From<crypto_box::aead::Error> for BackupError {
    fn from(_: crypto_box::aead::Error) -> Self {
        Self::DecryptBackupKeypairError
    }
}

impl From<std::array::TryFromSliceError> for BackupError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::DecodeBackupKeypairError
    }
}

/// Result of creating a backup
#[derive(Debug, uniffi::Record)]
pub struct CreatedBackup {
    /// The backup data, encrypted with the backup keypair.
    pub sealed_backup_data: Vec<u8>,
    /// The encrypted backup keypair. This value is encrypted with some factor secret
    /// (e.g. PRF, Turnkey, iCloud Keychain). Hex encoded.
    pub encrypted_backup_keypair: String,
    /// The public key of backup keypair that can be used to re-encrypt the backup data. Hex encoded.
    pub backup_keypair_public_key: String,
}

/// Result of decrypting a backup
#[derive(Debug, uniffi::Record)]
pub struct DecryptedBackup {
    /// The unsealed backup data with all the files.
    pub backup: BackupFormat,
    /// The public key of the backup keypair that was used to encrypt the backup. Client will need
    /// to save it to re-encrypt future backup updates. Hex encoded.
    pub backup_keypair_public_key: String,
}

/// Result of updating a sealed backup
#[derive(Debug, uniffi::Record)]
pub struct UpdatedSealedBackup {
    /// The new sealed backup data
    pub sealed_backup_data: Vec<u8>,
}

/// Result of adding a new factor
#[derive(Debug, uniffi::Record)]
pub struct AddNewFactorResult {
    /// The backup keypair encrypted with the new factor secret. Hex encoded.
    pub encrypted_backup_keypair_with_new_factor: String,
}

/// Types of factors that can be used for backup encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FactorType {
    /// Passkey PRF (Pseudo-Random Function)
    Prf,
    /// iCloud Keychain storage
    IcloudKeychain,
    /// Turnkey service
    Turnkey,
}
