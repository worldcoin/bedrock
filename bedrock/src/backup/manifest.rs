//! This module contains the logic for managing the backup manifests.
//!
//! The backup manifest is a local file-based system that any module can set to describe which files should
//! be included in the backup.

use std::sync::Arc;

use crypto_box::PublicKey;
use serde::{Deserialize, Serialize};

use crate::backup::backup_format::v0::{V0BackupManifest, V0BackupManifestEntry};
use crate::backup::BackupFileDesignator;
use crate::primitives::filesystem::{
    create_middleware, FileSystemError, FileSystemExt, FileSystemMiddleware,
};
use crate::root_key::RootKey;
use crate::{
    backup::{
        backup_format::v0::{V0Backup, V0BackupFile},
        service_client::BackupServiceClient,
        BackupError,
    },
    primitives::filesystem::get_filesystem_raw,
};

/// A single, global manifest that describes the backup content.
///
/// All operations on the backup use this as a source.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "version", content = "manifest")]
pub enum BackupManifest {
    V0(V0BackupManifest),
}

/// Abstraction for signing backup-service challenges with the sync factor keypair.
///
/// Implementations are expected to:
/// - return the sync factor public key in uncompressed SEC1 form, base64 (standard) encoded
/// - sign the raw ASCII challenge string with ECDSA P-256, DER-encode the signature, base64 (standard) encode it
#[uniffi::export(with_foreign)]
pub trait SyncSigner: Send + Sync {
    /// Returns the sync factor public key in standard base64 encoding.
    fn public_key_base64(&self) -> String;
    /// Signs the provided raw ASCII challenge with ECDSA P-256; returns DER signature, base64 encoded.
    fn sign_challenge_base64(&self, challenge: String) -> String;
}

/// Manager responsible for reading and writing backup manifests and coordinating sync.
#[derive(uniffi::Object)]
pub struct ManifestManager {
    file_system: FileSystemMiddleware,
    signer: Arc<dyn SyncSigner>,
}

impl ManifestManager {
    #[uniffi::constructor]
    /// Constructs a new `ManifestManager` instance with a file system middleware scoped to backups.
    #[must_use]
    pub fn new(signer: Arc<dyn SyncSigner>) -> Self {
        Self {
            file_system: create_middleware("backup"),
            signer,
        }
    }

    /// Returns files recorded in the global manifest after verifying local is not stale vs remote.
    ///
    /// The caller must supply an HTTP client and signer to perform the gate. This method does not mutate state.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or if network/IO errors occur.
    pub async fn list_files(
        &self,
        designator: BackupFileDesignator,
    ) -> Result<Vec<String>, BackupError> {
        let client = BackupServiceClient::new().map_err(|e| BackupError::Generic {
            message: e.to_string(),
        })?;
        let remote_hash = client
            .get_remote_manifest_hash(&*self.signer)
            .await
            .map_err(|e| BackupError::Generic {
                message: e.to_string(),
            })?;

        let (manifest, local_hash) = self.read_manifest()?;
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }

        let BackupManifest::V0(manifest) = manifest;

        let files = manifest
            .files
            .iter()
            .filter(|e| e.designator == designator)
            .map(|e| e.file_path.clone())
            .collect();

        Ok(files)
    }

    /// Adds a file entry for a given designator. Will trigger a backup sync.
    ///
    /// # Errors
    /// - Returns an error if remote hash does not match local (remote is ahead).
    /// - Returns an error if serialization fails.
    pub async fn store_file(
        &self,
        designator: BackupFileDesignator,
        file_path: String,
        root_secret: &str,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        // Step 0: Verify inputs
        let root = RootKey::from_json(root_secret)
            .map_err(|_| BackupError::InvalidRootSecretError)?;
        let pk_bytes = hex::decode(backup_keypair_public_key)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;

        // Step 1: Fetch the remote hash
        let client = BackupServiceClient::new().map_err(|e| BackupError::Generic {
            message: e.to_string(),
        })?;
        let remote_hash = client
            .get_remote_manifest_hash(&*self.signer)
            .await
            .map_err(|e| BackupError::Generic {
                message: e.to_string(),
            })?;

        // Step 2: Fetch the local hash and compare against the remote hash
        let (manifest, local_hash) = self.read_manifest()?;
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }
        let BackupManifest::V0(mut manifest) = manifest;

        // Step 3: Check the file does not exist in the manifest
        if manifest.files.iter().any(|e| e.file_path == file_path) {
            log::warn!("File already exists in the manifest: {file_path}");
            return Ok(());
        }

        // Step 4: Compute checksum for provided file
        let file_path = file_path.trim_start_matches('/').to_string();
        let fs = get_filesystem_raw()?;
        let checksum_hex = fs.calculate_checksum_hex(&file_path).map_err(|e| {
            let msg = format!("Failed to load file: {e}");
            log::error!("{msg}");
            BackupError::InvalidFileForBackup(msg)
        })?;

        // Step 5: Build candidate manifest M'
        manifest.files.push(V0BackupManifestEntry {
            designator,
            file_path,
            checksum_hex: checksum_hex.clone(),
        });

        // Step 6: Construct new unsealed backup
        manifest.previous_manifest_hash = Some(hex::encode(local_hash));
        let files = self.build_unsealed_backup_files_from_manifest(&manifest)?;

        let unsealed_backup = V0Backup::new(root, files).to_bytes()?;

        // Step 7: Seal the backup
        let sealed_backup = pk
            .seal(&mut rand::thread_rng(), &unsealed_backup)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // Step 8: Sync the backup with the remote
        let challenge = client.get_sync_challenge_keypair().await.map_err(|e| {
            BackupError::Generic {
                message: e.to_string(),
            }
        })?;
        let _resp = client
            .post_sync_with_keypair(
                &*self.signer,
                &challenge,
                hex::encode(local_hash),
                "fixme!".to_string(),
                sealed_backup,
            )
            .await
            .map_err(|e| BackupError::Generic {
                message: e.to_string(),
            })?;

        // Step 9: Commit the manifest
        self.write_manifest(&BackupManifest::V0(manifest))?;
        Ok(())
    }

    /// Replaces all the file entries for a given designator by removing all existing entries for a given designator
    /// and adding a new file.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or downstream operations fail.
    pub fn replace_all_files_for_designator(
        &self,
        _designator: BackupFileDesignator,
        _new_file_path: String,
        _root_secret: &str,
        _backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        todo!("implement");
    }

    /// Removes a specific file entry. Triggers a backup sync.
    ///
    /// # Errors
    /// - Returns an error if the file does not exist in the backup.
    /// - Returns an error if the remote hash does not match local (remote is ahead).
    /// - Returns an error if serialization fails.
    pub fn remove_file(
        &self,
        _file_path: String,
        _root_secret: &str,
        _backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        // most of the code can be re-used from store_file, abstract as appropriate
        todo!("implement");
    }
}

/// Internal methods for the `ManifestManager` (not exposed to foreign code).
impl ManifestManager {
    /// Thepath to the global manifest file
    const GLOBAL_MANIFEST_FILE: &str = "manifest.json";

    /// Reads the global manifest from disk.
    ///
    /// # Errors
    /// Returns an error if the manifest file is missing or cannot be parsed.
    fn read_manifest(&self) -> Result<(BackupManifest, [u8; 32]), BackupError> {
        let result = self.file_system.read_file(Self::GLOBAL_MANIFEST_FILE);
        match result {
            Ok(bytes) => {
                let checksum = blake3::hash(&bytes).into();
                let manifest: BackupManifest =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        BackupError::Generic {
                            message: (format!(
                                "Unexpectedly unable to parse BackupManifest: {e}"
                            )),
                        }
                    })?;
                Ok((manifest, checksum))
            }
            Err(e) => match e {
                FileSystemError::FileDoesNotExist => Err(BackupError::ManifestNotFound),
                _ => Err(BackupError::Generic {
                    message: e.to_string(),
                }),
            },
        }
    }

    /// Writes the updated manifest to disk.
    ///
    /// # Errors
    /// Returns an error if the manifest cannot be serialized or written.
    pub fn write_manifest(&self, manifest: &BackupManifest) -> Result<(), BackupError> {
        let serialized =
            serde_json::to_vec(manifest).map_err(|e| BackupError::Generic {
                message: (format!(
                    "Unexpectedly unable to serialize BackupManifest: {e}"
                )),
            })?;
        let result = self
            .file_system
            .write_file(Self::GLOBAL_MANIFEST_FILE, serialized);
        if result.is_err() {
            return Err(BackupError::Generic {
                message: "Unable to save the BackupManifest to the filesystem"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Builds unsealed backup files from the global manifest by reading and checksumming the files.
    /// Validates presence and recomputes checksum to ensure manifest correctness.
    ///
    /// # Errors
    /// Returns an error if the files cannot be read or checksums do not match.
    pub fn build_unsealed_backup_files_from_manifest(
        &self,
        manifest: &V0BackupManifest,
    ) -> Result<Vec<V0BackupFile>, BackupError> {
        let mut files = Vec::with_capacity(manifest.files.len());
        // Use the global filesystem (no prefixing) to read file contents.
        let fs = get_filesystem_raw()?;
        for entry in &manifest.files {
            let rel = entry.file_path.trim_start_matches('/');
            let data = fs.read_file(rel.to_string()).map_err(|e| {
                let msg =
                    format!("Failed to load file from {:?}: {e}", entry.designator);
                log::error!("{msg}");
                BackupError::InvalidFileForBackup(msg)
            })?;

            // Validate checksum matches manifest
            let computed_checksum = blake3::hash(&data);
            let expected_checksum: [u8; 32] = hex::decode(&entry.checksum_hex).map_err(|_| {
                log::error!(
                    "[Critical] Unable to decode checksum for file with designator: {}. Triggering a fresh fetch.",
                    entry.designator
                );
                BackupError::RemoteAheadStaleError
            })?.try_into().map_err(|_| {
                log::error!(
                    "[Critical] Unable to decode checksum for file with designator: {}. Triggering a fresh fetch.",
                    entry.designator
                );
                BackupError::RemoteAheadStaleError
            } )?;

            if computed_checksum != expected_checksum {
                return Err(BackupError::InvalidChecksumError {
                    designator: entry.designator.to_string(),
                });
            }

            files.push(V0BackupFile {
                data,
                checksum: computed_checksum.into(),
                path: format!(
                    "{}/{}",
                    entry.designator,
                    rel.rsplit('/').next().unwrap_or(rel)
                ),
            });
        }
        Ok(files)
    }
}
