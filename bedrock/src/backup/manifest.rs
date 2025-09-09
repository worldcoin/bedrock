//! This module contains the logic for managing the backup manifests.
//!
//! The backup manifest is a local file-based system that any module can set to describe which files should
//! be included in the backup.

use anyhow::Context;
use bedrock_macros::bedrock_export;
use chrono::Utc;
use crypto_box::PublicKey;
use serde::{Deserialize, Serialize};

use crate::backup::backup_format::v0::{V0BackupManifest, V0BackupManifestEntry};
use crate::backup::service_client::BackupServiceClient;
use crate::backup::{
    BackupFileDesignator, BackupManager, ClientEventsReporter, EventKind,
};
use crate::primitives::filesystem::{
    create_middleware, FileSystemError, FileSystemMiddleware,
};
use crate::root_key::RootKey;
use crate::{
    backup::{
        backup_format::v0::{V0Backup, V0BackupFile},
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

impl BackupManifest {
    /// Computes the BLAKE3 hash of the manifest, ignoring non-semantic/cache fields.
    ///
    /// Currently, this ignores `file_size_bytes` in each file entry so telemetry can
    /// cache sizes locally without affecting the manifest head.
    pub fn calculate_hash(&self) -> Result<[u8; 32], BackupError> {
        #[derive(serde::Serialize)]
        struct HashableV0Entry {
            designator: BackupFileDesignator,
            file_path: String,
            checksum_hex: String,
        }

        #[derive(serde::Serialize)]
        struct HashableV0Manifest {
            previous_manifest_hash: Option<String>,
            files: Vec<HashableV0Entry>,
        }

        let value = match self {
            Self::V0(v0) => {
                let hashable = HashableV0Manifest {
                    previous_manifest_hash: v0.previous_manifest_hash.clone(),
                    files: v0
                        .files
                        .iter()
                        .map(|e| HashableV0Entry {
                            designator: e.designator.clone(),
                            file_path: e.file_path.clone(),
                            checksum_hex: e.checksum_hex.clone(),
                        })
                        .collect(),
                };
                serde_json::json!({
                    "version": "V0",
                    "manifest": hashable,
                })
            }
        };

        let serialized =
            serde_json::to_vec(&value).context("serialize hashable BackupManifest")?;
        Ok(blake3::hash(&serialized).into())
    }
}

/// Manager responsible for reading and writing backup manifests and coordinating sync.
///
/// Documentation: <https://docs.toolsforhumanity.com/world-app/backup/structure-and-sync>
#[derive(uniffi::Object)]
pub struct ManifestManager {
    file_system: FileSystemMiddleware,
}

#[bedrock_export]
impl ManifestManager {
    #[uniffi::constructor]
    /// Constructs a new `ManifestManager` instance with a file system middleware scoped to backups.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // The prefix must follow the `BackupManager` struct name.
            file_system: create_middleware("backup_manager"),
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
        let (manifest, _local_hash) = self.load_manifest_gated().await?;

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
        let normalized_path = file_path.trim_start_matches('/').to_string();
        let result = self
            .mutate_manifest_and_sync(
                root_secret,
                backup_keypair_public_key,
                |manifest| {
                    if manifest
                        .files
                        .iter()
                        .any(|e| e.file_path == normalized_path)
                    {
                        log::warn!(
                            "File already exists in the manifest: {}",
                            normalized_path.get(..14).unwrap_or(&normalized_path)
                        );
                        return Ok(ManifestMutation::NoChange);
                    }
                    let (checksum_hex, file_size_bytes) =
                        Self::checksum_and_size_for_file(&normalized_path)?;
                    manifest.files.push(V0BackupManifestEntry {
                        designator,
                        file_path: normalized_path,
                        checksum_hex,
                        file_size_bytes,
                    });
                    Ok(ManifestMutation::Changed)
                },
            )
            .await;

        if let Err(e) = ClientEventsReporter::new()
            .send_event(
                EventKind::Sync,
                result.is_ok(),
                result.as_ref().err().map(std::string::ToString::to_string),
                Utc::now().to_rfc3339(),
            )
            .await
        {
            log::warn!("[ClientEvents] failed to send Sync event (store): {e:?}");
        }

        result
    }

    /// Replaces all the file entries for a given designator by removing all existing entries for a given designator
    /// and adding a new file.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or downstream operations fail.
    pub async fn replace_all_files_for_designator(
        &self,
        designator: BackupFileDesignator,
        new_file_path: String,
        root_secret: &str,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        let normalized_path = new_file_path.trim_start_matches('/').to_string();
        let result = self
            .mutate_manifest_and_sync(
                root_secret,
                backup_keypair_public_key,
                |manifest| {
                    let (checksum_hex, file_size_bytes) =
                        Self::checksum_and_size_for_file(&normalized_path)?;
                    manifest.files.retain(|e| e.designator != designator);
                    manifest.files.push(V0BackupManifestEntry {
                        designator,
                        file_path: normalized_path,
                        checksum_hex,
                        file_size_bytes,
                    });
                    Ok(ManifestMutation::Changed)
                },
            )
            .await;

        if let Err(e) = ClientEventsReporter::new()
            .send_event(
                EventKind::Sync,
                result.is_ok(),
                result.as_ref().err().map(std::string::ToString::to_string),
                Utc::now().to_rfc3339(),
            )
            .await
        {
            log::warn!("[ClientEvents] failed to send Sync event (replace): {e:?}");
        }

        result
    }

    /// Removes a specific file entry. Triggers a backup sync.
    ///
    /// # Errors
    /// - Returns an error if the file does not exist in the backup.
    /// - Returns an error if the remote hash does not match local (remote is ahead).
    /// - Returns an error if serialization fails.
    pub async fn remove_file(
        &self,
        file_path: String,
        root_secret: &str,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        let normalized_path = file_path.trim_start_matches('/').to_string();
        let result = self
            .mutate_manifest_and_sync(
                root_secret,
                backup_keypair_public_key,
                |manifest| {
                    let before_len = manifest.files.len();
                    manifest.files.retain(|e| e.file_path != normalized_path);
                    if manifest.files.len() == before_len {
                        return Err(BackupError::InvalidFileForBackup(format!(
                            "File not found in manifest: {}",
                            // only log the first 14 characters of the path to avoid leaking info
                            normalized_path.get(..14).unwrap_or(&normalized_path)
                        )));
                    }
                    Ok(ManifestMutation::Changed)
                },
            )
            .await;

        if let Err(e) = ClientEventsReporter::new()
            .send_event(
                EventKind::Sync,
                result.is_ok(),
                result.as_ref().err().map(std::string::ToString::to_string),
                Utc::now().to_rfc3339(),
            )
            .await
        {
            log::warn!("[ClientEvents] failed to send Sync event (remove): {e:?}");
        }

        result
    }
}

/// Internal methods for the `ManifestManager` (not exposed to foreign code).
impl ManifestManager {
    /// Thepath to the global manifest file
    const GLOBAL_MANIFEST_FILE: &str = "manifest.json";

    /// Test-only constructor allowing a custom filesystem prefix to isolate tests.
    #[cfg(test)]
    #[must_use]
    pub fn new_with_prefix(prefix: &str) -> Self {
        Self {
            file_system: FileSystemMiddleware::new(prefix),
        }
    }

    /// Gated manifest read that ensures local is not stale vs remote.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or if network/IO errors occur.
    pub async fn load_manifest_gated(
        &self,
    ) -> Result<(V0BackupManifest, [u8; 32]), BackupError> {
        let remote_hash = BackupServiceClient::get_remote_manifest_hash().await?;
        let (manifest, local_hash) = self.read_manifest()?;
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }
        let BackupManifest::V0(manifest) = manifest;
        Ok((manifest, local_hash))
    }

    /// Reads the manifest from disk without checking against the remote hash.
    ///
    /// This is intended for local computations (e.g., size telemetry) that must not fail
    /// due to remote staleness and that don't mutate state.
    ///
    /// # Errors
    /// Returns an error if the manifest file is missing or cannot be parsed.
    pub(crate) fn load_manifest_unchecked(
        &self,
    ) -> Result<V0BackupManifest, BackupError> {
        let (manifest, _checksum) = self.read_manifest()?;
        let BackupManifest::V0(manifest) = manifest;
        Ok(manifest)
    }

    /// Writes the updated manifest to disk.
    ///
    /// # Errors
    /// Returns an error if the manifest cannot be serialized or written.
    pub fn write_manifest(&self, manifest: &BackupManifest) -> Result<(), BackupError> {
        let serialized =
            serde_json::to_vec(manifest).context("serialize BackupManifest")?;
        self.file_system
            .write_file(Self::GLOBAL_MANIFEST_FILE, serialized)
            .context("write manifest.json")?;
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
            let expected_checksum: [u8; 32] = hex::decode(&entry.checksum_hex)
                .map_err(|_| {
                    log::error!(
                        "[Critical] Unable to decode checksum hex for file with designator: {}. Manifest entry is invalid.",
                        entry.designator
                    );
                    BackupError::InvalidFileForBackup(format!(
                        "Invalid checksum encoding for designator: {}",
                        entry.designator
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    log::error!(
                        "[Critical] Decoded checksum has invalid length for file with designator: {}. Manifest entry is invalid.",
                        entry.designator
                    );
                    BackupError::InvalidFileForBackup(format!(
                        "Invalid checksum length for designator: {}",
                        entry.designator
                    ))
                })?;

            if computed_checksum != expected_checksum {
                return Err(BackupError::InvalidChecksumError {
                    designator: entry.designator.to_string(),
                });
            }

            files.push(V0BackupFile {
                data,
                checksum: computed_checksum.into(),
                path: rel.to_string(),
                designator: entry.designator.clone(),
            });
        }
        Ok(files)
    }

    /// Reads the global manifest from disk.
    ///
    /// # Errors
    /// Returns an error if the manifest file is missing or cannot be parsed.
    fn read_manifest(&self) -> Result<(BackupManifest, [u8; 32]), BackupError> {
        let result = self.file_system.read_file(Self::GLOBAL_MANIFEST_FILE);
        match result {
            Ok(bytes) => {
                let manifest: BackupManifest =
                    serde_json::from_slice(&bytes).context("parse BackupManifest")?;
                let checksum = manifest.calculate_hash()?;
                Ok((manifest, checksum))
            }
            Err(FileSystemError::FileDoesNotExist) => {
                Err(BackupError::ManifestNotFound)
            }
            Err(e) => {
                let err = anyhow::Error::from(e).context("read manifest.json");
                Err(BackupError::from(err))
            }
        }
    }

    /// Computes both checksum hex and size (bytes) for a given file path using the raw filesystem.
    fn checksum_and_size_for_file(
        file_path: &str,
    ) -> Result<(String, u64), BackupError> {
        let fs = get_filesystem_raw()?;
        let mut hasher = blake3::Hasher::new();
        let mut offset: u64 = 0;
        let chunk_size: u64 = 65_536; // 64 KiB
        loop {
            let chunk = fs
                .read_file_range(file_path.to_string(), offset, chunk_size)
                .map_err(|e| {
                    let msg = format!("Failed to load file: {e}");
                    log::error!("{msg}");
                    BackupError::InvalidFileForBackup(msg)
                })?;
            if chunk.is_empty() {
                break;
            }
            hasher.update(&chunk);
            offset = offset.saturating_add(chunk.len() as u64);
        }
        Ok((hex::encode(hasher.finalize().as_bytes()), offset))
    }

    /// Applies a manifest mutation and, if changed, rebuilds, syncs, and commits the update.
    async fn mutate_manifest_and_sync<F>(
        &self,
        root_secret: &str,
        backup_keypair_public_key: String,
        mutator: F,
    ) -> Result<(), BackupError>
    where
        F: FnOnce(&mut V0BackupManifest) -> Result<ManifestMutation, BackupError>,
    {
        let root = RootKey::from_json(root_secret)
            .map_err(|_| BackupError::InvalidRootSecretError)?;
        let pk_bytes = hex::decode(backup_keypair_public_key)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;

        let (mut manifest, local_hash) = self.load_manifest_gated().await?;

        match mutator(&mut manifest)? {
            ManifestMutation::NoChange => return Ok(()),
            ManifestMutation::Changed => (),
        }

        manifest.previous_manifest_hash = Some(hex::encode(local_hash));

        let files = self.build_unsealed_backup_files_from_manifest(&manifest)?;
        let unsealed_backup = V0Backup::new(root, files).to_bytes()?;
        let sealed_backup =
            BackupManager::seal_backup_with_public_key(&unsealed_backup, &pk)?;

        let updated_manifest = BackupManifest::V0(manifest);
        let new_manifest_hash = updated_manifest.calculate_hash()?;

        let result = BackupServiceClient::sync(
            hex::encode(local_hash),
            hex::encode(new_manifest_hash),
            sealed_backup,
        )
        .await;

        if let Err(e) = ClientEventsReporter::new()
            .send_event(
                EventKind::Sync,
                result.is_ok(),
                result.as_ref().err().map(std::string::ToString::to_string),
                Utc::now().to_rfc3339(),
            )
            .await
        {
            log::warn!("[ClientEvents] failed to send Sync event: {e:?}");
        }

        result?;

        // commit the updated manifest once the remote sync has been successful
        self.write_manifest(&updated_manifest)?;

        // Refresh backup report from manifest; ignore errors
        if let Err(e) = ClientEventsReporter::new().recalculate_backup_size() {
            log::warn!(
                "[ClientEvents] failed to refresh backup report after manifest update: {e:?}"
            );
        }

        Ok(())
    }
}

impl Default for ManifestManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal signal indicating whether a manifest mutation produced a change.
enum ManifestMutation {
    NoChange,
    Changed,
}
