//! This module contains the logic for managing the backup manifests.
//!
//! The backup manifest is a local file-based system that any module can set to describe which files should
//! be included in the backup.

use std::{collections::HashSet, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use crypto_box::PublicKey;
use serde::{Deserialize, Serialize};

use crate::primitives::filesystem::{create_middleware, FileSystemMiddleware};
use crate::secure::RootKey;
use crate::{
    backup::{
        backup_format::v0::{V0Backup, V0BackupFile, V0BackupManifest},
        service_client::BackupServiceClient,
        BackupError, BackupModule, SyncSigner,
    },
    primitives::filesystem::get_filesystem_raw,
};

const BACKUP_MANIFEST_DIRECTORY: &str = "backup_manifests";
const GLOBAL_MANIFEST_FILE: &str = "manifest.json";

/// A single, global manifest (v1) that describes the entire backup content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GlobalManifestV1 {
    /// Manifest version. Must be 1.
    pub version: u32, // must be 1
    /// Hash of the immediately previous manifest state (hex, 32-byte blake3), if any.
    ///
    /// Used to provide a lightweight chain of states for conflict detection and auditing.
    pub previous_manifest_hash: Option<String>,
    /// Entries describing each file to be backed up.
    pub files: Vec<ManifestEntry>,
}

/// One entry in the global manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Logical module/designator for the file.
    pub designator: BackupModule,
    /// Relative path under the user data directory where the file resides.
    pub file_path: String,
    /// Lowercase hex-encoded BLAKE3 checksum of the file's raw bytes (32 bytes → 64 chars).
    pub checksum_hex: String,
}

/// A manifest file that describes a file that should be included in the backup.
///
/// The manifest file is stored in the backup manifest directory and is used to determine which files should be included in the backup.
///
/// Each module which adds a file to the backup creates a `BackupManifest`
#[derive(Debug, Serialize, Deserialize)]
pub enum BackupManifest {
    /// Version 0 backup manifest.
    V0(V0BackupManifest),
}

impl BackupManifest {
    /// Initializes a new `BackupManifest`.
    ///
    /// # Errors
    /// - Will error if the module name is invalid  (i.e. is not an allowed `BackupModule`).
    #[allow(clippy::missing_const_for_fn)] // even though it appears const, constructing a DateTime<Utc> cannot be achieved in a const context
    pub fn new(
        file_path: &str,
        manifest_last_updated_at: DateTime<Utc>,
        max_file_size_kb: u64,
        unparsed_module_name: String,
    ) -> Result<Self, BackupError> {
        let module_name: BackupModule =
            BackupModule::from_str(&unparsed_module_name)
                .map_err(|_| BackupError::InvalidModuleName(unparsed_module_name))?;

        Ok(Self::V0(V0BackupManifest::new(
            file_path,
            manifest_last_updated_at,
            max_file_size_kb,
            module_name,
        )?))
    }

    /// Returns the path to the file that should be included in the backup (relative to the user data directory).
    #[must_use]
    pub fn file_path(&self) -> &str {
        match self {
            Self::V0(manifest) => manifest.file_path(),
        }
    }

    /// Returns the module name that the file belongs to.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // even though it appears const, constructing a DateTime<Utc> cannot be achieved in a const context
    pub fn module_name(&self) -> &BackupModule {
        match self {
            Self::V0(manifest) => &manifest.module_name,
        }
    }
}

/// Manager responsible for reading and writing backup manifests and coordinating sync.
#[derive(uniffi::Object)]
pub struct ManifestManager {
    file_system: FileSystemMiddleware,
}

impl ManifestManager {
    #[uniffi::constructor]
    /// Constructs a new `ManifestManager` instance with a file system middleware scoped to backups.
    #[must_use]
    pub fn new() -> Self {
        Self {
            file_system: create_middleware("backup"),
        }
    }

    /// Returns the absolute path to the global manifest file on disk.
    #[allow(clippy::missing_const_for_fn)]
    fn global_manifest_path() -> &'static str {
        GLOBAL_MANIFEST_FILE
    }

    /// Reads the global manifest from disk.
    ///
    /// # Errors
    /// Returns an error if the manifest file is missing or cannot be parsed.
    pub fn read_global_manifest(&self) -> Result<GlobalManifestV1, BackupError> {
        let result = self.file_system.read_file(Self::global_manifest_path());
        match result {
            Ok(bytes) => {
                let manifest: GlobalManifestV1 = serde_json::from_slice(&bytes)
                    .map_err(|e| BackupError::ParseBackupManifestError {
                        details: e.to_string(),
                        manifest_name: "global_manifest".to_string(),
                    })?;
                Ok(manifest)
            }
            Err(_) => Err(BackupError::GlobalManifestNotFound),
        }
    }

    /// Writes the provided global manifest to disk.
    /// Writes the provided global manifest to disk.
    ///
    /// # Errors
    /// Returns an error if the manifest cannot be serialized or written.
    pub fn write_global_manifest(
        &self,
        manifest: &GlobalManifestV1,
    ) -> Result<(), BackupError> {
        let serialized = serde_json::to_vec(manifest).map_err(|e| {
            BackupError::ParseBackupManifestError {
                details: e.to_string(),
                manifest_name: "global_manifest".to_string(),
            }
        })?;
        let result = self
            .file_system
            .write_file(Self::global_manifest_path(), serialized);
        if result.is_err() {
            return Err(BackupError::WriteFileError);
        }
        Ok(())
    }

    /// Computes a deterministic BLAKE3 hash over the entire manifest bytes.
    ///
    /// We serialize the full `GlobalManifestV1` to JSON and hash the raw bytes.
    /// Returns lowercase hex string (64 chars).
    #[must_use]
    pub fn compute_manifest_hash(manifest: &GlobalManifestV1) -> String {
        let serialized = serde_json::to_vec(manifest).unwrap_or_default();
        let hash = blake3::hash(&serialized);
        hex::encode(hash.as_bytes())
    }

    /// Builds unsealed backup files from the global manifest by reading and checksumming the files.
    /// Validates presence and recomputes checksum to ensure manifest correctness.
    /// TODO: verify paths prefixing is correct here.
    ///
    /// # Errors
    /// Returns an error if the files cannot be read or checksums do not match.
    pub fn build_unsealed_backup_files_from_manifest(
        &self,
        manifest: &GlobalManifestV1,
    ) -> Result<Vec<V0BackupFile>, BackupError> {
        let mut files = Vec::with_capacity(manifest.files.len());
        // Use the global filesystem (no prefixing) to read file contents.
        let fs = get_filesystem_raw()?;
        for entry in &manifest.files {
            let rel = entry.file_path.trim_start_matches('/');
            let data = fs.read_file(rel.to_string()).map_err(|e| {
                let msg = format!(
                    "High Impact. Failed to load file from {:?}: {e}",
                    entry.designator
                );
                log::error!("{msg}");
                BackupError::InvalidFileForBackup(msg)
            })?;

            // Validate checksum matches manifest
            let computed = blake3::hash(&data);
            let expected_bytes = hex::decode(&entry.checksum_hex).map_err(|_| {
                BackupError::InvalidChecksumError {
                    module_name: entry.designator.to_string(),
                }
            })?;
            if computed.as_bytes() != expected_bytes.as_slice() {
                return Err(BackupError::InvalidChecksumError {
                    module_name: entry.designator.to_string(),
                });
            }

            files.push(V0BackupFile {
                data,
                checksum: expected_bytes,
                path: format!(
                    "{}/{}",
                    entry.designator,
                    rel.rsplit('/').next().unwrap_or(rel)
                ),
            });
        }
        Ok(files)
    }

    /// Returns files recorded in the global manifest after verifying local is not stale vs remote.
    ///
    /// The caller must supply an HTTP client and signer to perform the gate. This method does not mutate state.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or if network/IO errors occur.
    pub async fn list_files(
        &self,
        signer: &dyn SyncSigner,
    ) -> Result<Vec<ManifestEntry>, BackupError> {
        let client = BackupServiceClient::new()
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;
        let remote_hash = client
            .get_remote_manifest_hash(signer)
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;

        let manifest = self.read_global_manifest()?;
        let local_hash = Self::compute_manifest_hash(&manifest);
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }
        Ok(manifest.files)
    }

    /// Adds or replaces the file entry for a given designator and performs a remote-gated update inline.
    ///
    /// TODO: Integrate size validation policies per module when available.
    ///
    /// # Errors
    /// Returns an error if remote hash does not match local or if serialization/IO fails.
    pub async fn store_file(
        &self,
        signer: &dyn SyncSigner,
        designator: BackupModule,
        file_path: String,
        root_secret: String,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        // 1) Remote hash
        let client = BackupServiceClient::new()
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;
        let remote_hash = client
            .get_remote_manifest_hash(signer)
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;

        // 2) Local hash
        let mut manifest = self.read_global_manifest()?;
        let local_hash = Self::compute_manifest_hash(&manifest);
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }

        // 3) Compute checksum for provided file
        let rel_path = file_path.trim_start_matches('/').to_string();
        let data = self.file_system.read_file(&rel_path).map_err(|e| {
            let msg = format!("Failed to load file from {designator:?}: {e}");
            log::error!("{msg}");
            BackupError::InvalidFileForBackup(msg)
        })?;
        let checksum_hex = hex::encode(blake3::hash(&data).as_bytes());

        // 4) Build candidate manifest M'
        if let Some(entry) = manifest
            .files
            .iter_mut()
            .find(|e| e.designator == designator)
        {
            // Persist full global path (prefixed) in the manifest
            entry.file_path = self.file_system.get_full_path_from_file_path(&rel_path);
            entry.checksum_hex.clone_from(&checksum_hex);
        } else {
            manifest.files.push(ManifestEntry {
                designator,
                // Persist full global path (prefixed) in the manifest
                file_path: self.file_system.get_full_path_from_file_path(&rel_path),
                checksum_hex: checksum_hex.clone(),
            });
        }

        // 6) Build files from M', generate sealed backup, compute Hnew
        //    Set previous_manifest_hash to the current local hash
        manifest.previous_manifest_hash = Some(local_hash.clone());
        let new_manifest_hash = Self::compute_manifest_hash(&manifest);

        // Materialize files from manifest and build a sealed backup container
        let files = self.build_unsealed_backup_files_from_manifest(&manifest)?;
        let root = Arc::new(RootKey::decode(root_secret));
        let unsealed = V0Backup::new(root, files);
        let unsealed_bytes = unsealed.to_bytes()?;
        // Encrypt with backup keypair public key
        let pk_bytes = hex::decode(backup_keypair_public_key)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let sealed_backup = pk
            .seal(&mut rand::thread_rng(), &unsealed_bytes)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 7) Challenge/sign for sync and POST /v1/sync multipart
        let challenge = client
            .get_sync_challenge_keypair()
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;
        let _resp = client
            .post_sync_with_keypair(
                signer,
                &challenge,
                local_hash,
                new_manifest_hash,
                sealed_backup,
            )
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;

        // 8) Commit manifest
        self.write_global_manifest(&manifest)?;
        Ok(())
    }

    /// Replaces the file entry for a given designator with a new file path and performs a remote-gated update inline.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or downstream operations fail.
    pub async fn replace_file(
        &self,
        signer: &dyn SyncSigner,
        designator: BackupModule,
        file_path: String,
        root_secret: String,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        // Delegate to store_file, as replace semantics equal to upsert for this designator.
        self.store_file(
            signer,
            designator,
            file_path,
            root_secret,
            backup_keypair_public_key,
        )
        .await
    }

    /// Removes the file entry for the given designator, if present, and performs a remote-gated update inline.
    ///
    /// # Errors
    /// Returns an error if the remote hash does not match local or downstream operations fail.
    pub async fn remove_file(
        &self,
        signer: &dyn SyncSigner,
        designator: BackupModule,
        root_secret: String,
        backup_keypair_public_key: String,
    ) -> Result<(), BackupError> {
        // 1) Remote gate
        let client = BackupServiceClient::new()
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;
        let remote_hash = client
            .get_remote_manifest_hash(signer)
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;

        // 2) Local manifest
        let mut manifest = self.read_global_manifest()?;
        let local_hash = Self::compute_manifest_hash(&manifest);
        if remote_hash != local_hash {
            return Err(BackupError::RemoteAheadStaleError);
        }

        // 3) Remove entry if present
        manifest.files.retain(|e| e.designator != designator);

        // 4) Compute new manifest hash and reseal
        manifest.previous_manifest_hash = Some(local_hash.clone());
        let new_manifest_hash = Self::compute_manifest_hash(&manifest);

        let files = self.build_unsealed_backup_files_from_manifest(&manifest)?;
        let root = Arc::new(RootKey::decode(root_secret));
        let unsealed = V0Backup::new(root, files);
        let unsealed_bytes = unsealed.to_bytes()?;
        let pk_bytes = hex::decode(backup_keypair_public_key)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| BackupError::DecodeBackupKeypairError)?;
        let sealed_backup = pk
            .seal(&mut rand::thread_rng(), &unsealed_bytes)
            .map_err(|_| BackupError::EncryptBackupError)?;

        // 5) Sync
        let challenge = client
            .get_sync_challenge_keypair()
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;
        let _resp = client
            .post_sync_with_keypair(
                signer,
                &challenge,
                local_hash,
                new_manifest_hash,
                sealed_backup,
            )
            .await
            .map_err(|e| BackupError::UnexpectedError(e.to_string()))?;

        // 6) Commit
        self.write_global_manifest(&manifest)?;
        Ok(())
    }

    /// Retrieves a manifest from the file system.
    ///
    /// # Errors
    /// - This method will error loudly if it fails to read or parse any manifest file, as this is not standard behavior.
    pub fn get_manifest(
        &self,
        unparsed_module_name: String,
    ) -> Result<BackupManifest, BackupError> {
        let module_name: BackupModule =
            BackupModule::from_str(&unparsed_module_name)
                .map_err(|_| BackupError::InvalidModuleName(unparsed_module_name))?;

        let backup_manifest_path = format!("{BACKUP_MANIFEST_DIRECTORY}/{module_name}");

        let manifest = self.file_system.read_file(&backup_manifest_path);
        match manifest {
            Ok(manifest) => {
                let manifest: BackupManifest = serde_json::from_slice(&manifest)
                    .map_err(|e| BackupError::ParseBackupManifestError {
                        details: e.to_string(),
                        manifest_name: module_name.to_string(),
                    })?;
                Ok(manifest)
            }
            Err(e) => {
                log::error!("High Impact. Failed to read backup manifest for {module_name}: {e}");
                Err(BackupError::ParseBackupManifestError {
                    details: e.to_string(),
                    manifest_name: module_name.to_string(),
                })
            }
        }
    }

    /// Saves a manifest to the file system.
    ///
    /// # Errors
    /// - Will error if the manifest cannot be serialized to JSON.
    /// - Will error if the manifest cannot be written to the file system.
    pub fn save_manifest(
        &self,
        backup_manifest: &BackupManifest,
    ) -> Result<(), BackupError> {
        let module_name = backup_manifest.module_name();
        let manifest_path = format!("{BACKUP_MANIFEST_DIRECTORY}/{module_name}");
        let manifest = serde_json::to_vec(&backup_manifest).map_err(|e| {
            BackupError::ParseBackupManifestError {
                details: e.to_string(),
                manifest_name: module_name.to_string(),
            }
        })?;
        let result = self.file_system.write_file(&manifest_path, manifest);
        if result.is_err() {
            log::error!("Failed to write backup manifest for {module_name}");
            return Err(BackupError::WriteFileError);
        }
        Ok(())
    }

    /// Deletes a manifest from the file system.
    ///
    /// This is useful when the file to be backed up is no longer needed. If a manifest does not exist, it will be safely ignored.
    ///
    /// # Errors
    /// - Will error if the module name is invalid (i.e. is not an allowed `BackupModule`).
    /// - Will error if the manifest cannot be deleted from the file system (unexpected).
    pub fn delete_manifest(
        &self,
        unparsed_module_name: String,
    ) -> Result<(), BackupError> {
        let module_name: BackupModule =
            BackupModule::from_str(&unparsed_module_name)
                .map_err(|_| BackupError::InvalidModuleName(unparsed_module_name))?;

        let manifest_path = format!("{BACKUP_MANIFEST_DIRECTORY}/{module_name}");

        let file_exists = self.file_system.file_exists(&manifest_path)?;
        if !file_exists {
            log::debug!("Skipping deletion of backup manifest for {module_name}: file does not exist");
            return Ok(());
        }

        let result = self.file_system.delete_file(&manifest_path);
        if result.is_err() {
            log::error!("Failed to delete backup manifest for {module_name}");
            return Err(BackupError::WriteFileError);
        }
        Ok(())
    }

    /// Collects all manifests from the file system.
    ///
    /// # Errors
    /// - This method will error loudly if it fails to read or parse any manifest file, as this is not standard behavior.
    pub fn collect_manifests(&self) -> Result<Vec<BackupManifest>, BackupError> {
        let mut file_path_list = HashSet::new();
        let mut manifests = vec![];
        let manifest_paths = self.file_system.list_files(BACKUP_MANIFEST_DIRECTORY)?;

        for manifest_path in manifest_paths {
            if BackupModule::try_from(manifest_path.as_str()).is_err() {
                // The file name is not as important, this is just a sanity check and to continue processing,
                // the parsing below to a `BackupManifest` will fail in the case of a non-whitelisted module.
                log::warn!("Skipping backup manifest for non-whitelisted module: {manifest_path}");
                continue;
            }

            let backup_manifest = self
                .file_system
                .read_file(&format!(
                    "{BACKUP_MANIFEST_DIRECTORY}/{manifest_path}"
                ))
                .map_err(|e| {
                    log::error!("High Impact. Failed to read backup manifest for /{manifest_path}: {e}");
                    BackupError::ParseBackupManifestError {
                        details: e.to_string(),
                        manifest_name: format!("/{manifest_path}"),
                    }
                })?;

            let backup_manifest: BackupManifest = serde_json::from_slice(&backup_manifest).map_err(|e| {
                // We terminate here because this is not standard behavior, and updating the backup may result in adverse data loss.
                // Generally this should never occur, unless there's a critical bug or maliciously tampering with the file system.
                // Note we never log the file name as it may contain user information (e.g. signup attempt ID).
                log::error!("High Impact. Failed to parse backup manifest for /{manifest_path}: {e}");
                BackupError::ParseBackupManifestError {
                    details: e.to_string(),
                    manifest_name: format!("/{manifest_path}"),
                }
            })?;

            // Temporary check to ensure no duplicate file paths are added to the backup.
            // TODO: Remove this once each module is constrained to their own directory.
            if file_path_list.contains(backup_manifest.file_path()) {
                log::error!(
                    "High Impact. Duplicate save_as found in backup manifest for {}",
                    backup_manifest.module_name()
                );
                return Err(BackupError::ParseBackupManifestError {
                    details: "Duplicate save_as found in backup manifest.".to_string(),
                    manifest_name: backup_manifest.module_name().to_string(),
                });
            }

            file_path_list.insert(backup_manifest.file_path().to_string());

            manifests.push(backup_manifest);
        }

        Ok(manifests)
    }

    /// Fetches all files from the file system that should be included in the backup.
    ///
    /// Currently this returns a `V0BackupFile` array, as this is the file format currently in use.
    ///
    /// # Errors
    /// - Will error if there is any issue reading or parsing any of the files (see `build_unsealed_backup_file` for more details)
    pub fn build_unsealed_backup_files(
        &self,
        manifests: Vec<BackupManifest>,
    ) -> Result<Vec<V0BackupFile>, BackupError> {
        let mut files = Vec::with_capacity(manifests.len());
        for manifest in manifests {
            let file = self.build_unsealed_backup_file(&manifest)?;
            files.push(file);
        }
        Ok(files)
    }

    /// Attempts to retrieve a file that should be included in the backup.
    ///
    /// It will validate the file conforms to the definitions in the manifest (e.g. max file size, file exists, etc.)
    ///
    /// Currently, this builds a `V0BackupFile` as it's the one supported for new backups.
    ///
    /// # Errors
    /// - Will error if there is any issue reading the file to be backed up.
    /// - Will error if the file does not conform to the manifest (e.g. max file size, file exists, etc.)
    fn build_unsealed_backup_file(
        &self,
        backup_manifest: &BackupManifest,
    ) -> Result<V0BackupFile, BackupError> {
        #[allow(clippy::infallible_destructuring_match)]
        // using a match statement to future proof for new versions
        let backup_manifest = match backup_manifest {
            BackupManifest::V0(manifest) => manifest,
        };

        let rel_path = backup_manifest.file_path().trim_start_matches('/');
        let candidate_file = self.file_system.read_file(rel_path);

        match candidate_file {
            Ok(file) => {
                let file_size_kb = u64::try_from(file.len())
                    .map_err(|_| BackupError::ParseBackupManifestError {
                        details: "failed to convert file size to u64".to_string(),
                        manifest_name: backup_manifest.module_name.to_string(),
                    })?
                    .div_ceil(1024);

                if file_size_kb > backup_manifest.max_file_size_kb {
                    let msg = format!(
                        "File for {} exceeds the maximum defined file size of {} KB. File size: {} KB.",
                        backup_manifest.module_name, backup_manifest.max_file_size_kb, file_size_kb
                    );
                    log::error!("{msg}");
                    return Err(BackupError::InvalidFileForBackup(msg));
                }

                let checksum = blake3::hash(&file);
                Ok(V0BackupFile {
                    data: file,
                    checksum: checksum.as_bytes().to_vec(),
                    path: format!(
                        "{}/{}",
                        backup_manifest.module_name,
                        rel_path.rsplit('/').next().unwrap_or(rel_path)
                    ),
                })
            }
            Err(e) => {
                let msg = format!(
                    "High Impact. Failed to load file from {}: {e}",
                    backup_manifest.module_name
                );
                log::error!("{msg}");
                Err(BackupError::InvalidFileForBackup(msg))
            }
        }
    }
}

impl Default for ManifestManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cannot_create_backup_manifest_with_parent_directory() {
        let result =
            BackupManifest::new("../../test.txt", Utc::now(), 1024, "test".to_string());
        assert!(result.is_err());

        let result = BackupManifest::new(
            "folder/../test.txt",
            Utc::now(),
            1024,
            "test".to_string(),
        );
        assert!(result.is_err());
    }
}
