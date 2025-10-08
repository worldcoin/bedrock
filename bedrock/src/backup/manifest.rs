//! This module contains the logic for managing the backup manifests.
//!
//! The backup manifest is a local file-based system that any module can set to describe which files should
//! be included in the backup.

use anyhow::Context;
use bedrock_macros::bedrock_export;
use chrono::Utc;
use crypto_box::PublicKey;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::backup::backup_format::v0::{V0BackupManifest, V0BackupManifestEntry};
use crate::backup::service_client::BackupServiceClient;
use crate::backup::{
    BackupFileDesignator, BackupManager, BackupReportEventKind, ClientEventsReporter,
};
use crate::primitives::filesystem::{
    create_middleware, FileSystemError, FileSystemExt, FileSystemMiddleware,
};
use crate::root_key::RootKey;
use crate::{
    backup::{
        backup_format::v0::{V0Backup, V0BackupFile},
        BackupError,
    },
    primitives::filesystem::get_filesystem_raw,
};

static DEFAULT_DIGEST_HEX: OnceCell<String> = OnceCell::new();

/// A single, global manifest that describes the backup content.
///
/// All operations on the backup use this as a source.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "version", content = "manifest")]
pub enum BackupManifest {
    V0(V0BackupManifest),
}

impl BackupManifest {
    fn to_digest(&self) -> Result<Vec<u8>, BackupError> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"BEDROCK_MANIFEST");
        match self {
            Self::V0(m) => {
                // Version tag for V0
                out.push(0x00);

                // Reject duplicate file paths (case-insensitive) to prevent ambiguous manifests
                {
                    let mut seen_paths_lower =
                        std::collections::HashSet::with_capacity(m.files.len());
                    for entry in &m.files {
                        let key = entry.file_path.to_lowercase();
                        if !seen_paths_lower.insert(key) {
                            return Err(BackupError::InvalidFileForBackup(
                                "Duplicate file path in manifest".to_string(),
                            ));
                        }
                    }
                }

                // Files length (u32 BE)
                #[allow(clippy::cast_possible_truncation)]
                let count = m.files.len() as u32;
                out.extend_from_slice(&count.to_be_bytes());

                let mut sorted_files: Vec<&V0BackupManifestEntry> =
                    m.files.iter().collect();
                sorted_files.sort_by(|a, b| {
                    a.file_path.to_lowercase().cmp(&b.file_path.to_lowercase())
                });

                // Files in-order
                for entry in sorted_files {
                    // Designator (snake_case) + 0x00 separator
                    out.extend_from_slice(entry.designator.to_string().as_bytes());
                    out.push(0x00);

                    // File path (UTF-8) + 0x00 separator
                    out.extend_from_slice(entry.file_path.as_bytes());
                    out.push(0x00);

                    // Checksum: 32 raw bytes from hex
                    let ck_bytes = hex::decode(&entry.checksum_hex).map_err(|_| {
                        log::error!(
                            "[Critical] Unable to decode checksum hex for file with designator: {}. Manifest entry is invalid.",
                            entry.designator
                        );
                        BackupError::InvalidFileForBackup(format!(
                            "Invalid checksum encoding for designator: {}",
                            entry.designator
                        ))
                    })?;
                    let ck_arr: [u8; 32] = ck_bytes.try_into().map_err(|_| {
                        log::error!(
                            "[Critical] Decoded checksum has invalid length for file with designator: {}. Manifest entry is invalid.",
                            entry.designator
                        );
                        BackupError::InvalidFileForBackup(format!(
                            "Invalid checksum length for designator: {}",
                            entry.designator
                        ))
                    })?;
                    out.extend_from_slice(&ck_arr);
                }
            }
        }
        Ok(out)
    }

    /// Computes the BLAKE3 hash of the canonical manifest bytes.
    pub fn to_hash(&self) -> Result<[u8; 32], BackupError> {
        let pre_image = self.to_digest()?;
        Ok(blake3::hash(&pre_image).into())
    }

    /// Returns the hex-encoded hash of the default (empty) manifest.
    #[must_use]
    pub fn default_hash_hex() -> &'static str {
        DEFAULT_DIGEST_HEX.get_or_init(|| {
            // This cannot fail: empty files to decode.
            hex::encode(
                Self::default()
                    .to_hash()
                    .expect("default manifest hash is infallible"),
            )
        })
    }

    /// The number of file entries in the manifest.
    pub const fn entries_length(&self) -> usize {
        match self {
            Self::V0(m) => m.files.len(),
        }
    }
}

impl Default for BackupManifest {
    fn default() -> Self {
        Self::V0(V0BackupManifest { files: vec![] })
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
        let normalized_path = Self::normalize_input_path(&file_path).to_string();
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
                    let (checksum_hex, _file_size_bytes) =
                        Self::checksum_and_size_for_file(&normalized_path)?;
                    manifest.files.push(V0BackupManifestEntry {
                        designator,
                        file_path: normalized_path,
                        checksum_hex,
                    });
                    Ok(ManifestMutation::Changed)
                },
            )
            .await;

        Self::send_sync_event(&result).await;

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
        let normalized_path = Self::normalize_input_path(&new_file_path).to_string();
        let result = self
            .mutate_manifest_and_sync(
                root_secret,
                backup_keypair_public_key,
                |manifest| {
                    let (checksum_hex, _file_size_bytes) =
                        Self::checksum_and_size_for_file(&normalized_path)?;
                    manifest.files.retain(|e| e.designator != designator);
                    manifest.files.push(V0BackupManifestEntry {
                        designator,
                        file_path: normalized_path,
                        checksum_hex,
                    });
                    Ok(ManifestMutation::Changed)
                },
            )
            .await;

        Self::send_sync_event(&result).await;

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
        let normalized_path = Self::normalize_input_path(&file_path).to_string();
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

        Self::send_sync_event(&result).await;

        result
    }
}

/// Internal methods for the `ManifestManager` (not exposed to foreign code).
impl ManifestManager {
    /// Normalizes an input path by stripping any leading "./" or "/" segments.
    /// This is tolerant to multiple occurrences (e.g., "././path" or "///path").
    fn normalize_input_path(path: &str) -> &str {
        let mut p = path;
        loop {
            if let Some(rest) = p.strip_prefix("./") {
                p = rest;
                continue;
            }
            if let Some(rest) = p.strip_prefix('/') {
                p = rest;
                continue;
            }
            break;
        }
        p
    }
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

    /// Writes the updated manifest to disk.
    ///
    /// # Errors
    /// Returns an error if the manifest cannot be serialized or written.
    pub fn write_manifest(&self, manifest: &BackupManifest) -> Result<(), BackupError> {
        let serialized =
            serde_json::to_vec(manifest).context("serialize BackupManifest")?;
        let BackupManifest::V0(manifest) = manifest;

        crate::info!(
            "Writing manifest file with files: {}",
            manifest
                .files
                .iter()
                .map(|f| f.designator.to_string())
                .collect::<Vec<String>>()
                .join(", "),
        );

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
            let rel = Self::normalize_input_path(&entry.file_path);
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

    /// Deletes the global manifest file. This is useful when the backup is deleted.
    ///
    /// # Errors
    /// Returns an error if the manifest file cannot be deleted.
    pub fn danger_delete_manifest(&self) -> Result<(), BackupError> {
        self.file_system.delete_file(Self::GLOBAL_MANIFEST_FILE)?;
        Ok(())
    }

    /// Reads the global manifest from disk.
    ///
    /// # Errors
    /// Returns an error if the manifest file is missing or cannot be parsed.
    pub(crate) fn read_manifest(
        &self,
    ) -> Result<(BackupManifest, [u8; 32]), BackupError> {
        let result = self.file_system.read_file(Self::GLOBAL_MANIFEST_FILE);
        match result {
            Ok(bytes) => {
                let manifest: BackupManifest =
                    serde_json::from_slice(&bytes).context("parse BackupManifest")?;
                let checksum = manifest.to_hash()?;
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
        let normalized = Self::normalize_input_path(file_path);
        fs.calculate_checksum_and_size(normalized)
            .map(|(checksum, size)| (hex::encode(checksum), size))
            .map_err(|e| {
                let msg = format!("Failed to load file: {e}");
                log::error!("{msg}");
                BackupError::InvalidFileForBackup(msg)
            })
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

        let files = self.build_unsealed_backup_files_from_manifest(&manifest)?;
        let unsealed_backup = V0Backup::new(root, files).to_bytes()?;
        let sealed_backup =
            BackupManager::seal_backup_with_public_key(&unsealed_backup, &pk)?;

        let updated_manifest = BackupManifest::V0(manifest);
        let new_manifest_hash = updated_manifest.to_hash()?;

        BackupServiceClient::sync(
            hex::encode(local_hash),
            hex::encode(new_manifest_hash),
            sealed_backup,
        )
        .await?;

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

    async fn send_sync_event(result: &Result<(), BackupError>) {
        if let Err(e) = ClientEventsReporter::new()
            .send_event(
                BackupReportEventKind::Sync,
                result.is_ok(),
                result.as_ref().err().map(std::string::ToString::to_string),
                Utc::now().to_rfc3339(),
            )
            .await
        {
            log::warn!("[ClientEvents] failed to send Sync event (remove): {e:?}");
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_entry(
        designator: crate::backup::BackupFileDesignator,
        path: &str,
        data: &[u8],
    ) -> V0BackupManifestEntry {
        V0BackupManifestEntry {
            designator,
            file_path: path.to_string(),
            checksum_hex: hex::encode(blake3::hash(data).as_bytes()),
        }
    }

    #[test]
    fn test_digest_default_and_known_hash() {
        let manifest = BackupManifest::default();
        let digest = manifest.to_digest().unwrap();
        assert_eq!(digest, b"BEDROCK_MANIFEST\x00\x00\x00\x00\x00");
        let hash = manifest.to_hash().unwrap();
        assert_eq!(
            hex::encode(hash),
            "85c9d3437fbd13e892674f14603650fff5cb32db314d375722f39f84f501036f"
        );
        assert_eq!(
            BackupManifest::default_hash_hex(),
            "85c9d3437fbd13e892674f14603650fff5cb32db314d375722f39f84f501036f"
        );
    }

    #[test]
    fn test_order_independent_hashing() {
        use crate::backup::BackupFileDesignator as D;
        let e1 = mk_entry(D::OrbPkg, "a/file1.bin", b"DATA1");
        let e2 = mk_entry(D::DocumentPkg, "b/file2.bin", b"DATA2");
        let m1 = BackupManifest::V0(V0BackupManifest {
            files: vec![
                V0BackupManifestEntry {
                    designator: e1.designator.clone(),
                    file_path: e1.file_path.clone(),
                    checksum_hex: e1.checksum_hex.clone(),
                },
                V0BackupManifestEntry {
                    designator: e2.designator.clone(),
                    file_path: e2.file_path.clone(),
                    checksum_hex: e2.checksum_hex.clone(),
                },
            ],
        });
        let m2 = BackupManifest::V0(V0BackupManifest {
            files: vec![e2, e1],
        });
        assert_eq!(m1.to_hash().unwrap(), m2.to_hash().unwrap());
    }

    #[test]
    fn test_duplicate_paths_rejected_case_insensitive() {
        use crate::backup::BackupFileDesignator as D;
        let e1 = mk_entry(D::OrbPkg, "PCP/FILE.bin", b"DATA");
        let e2 = mk_entry(D::DocumentPkg, "pcp/file.BIN", b"DATA");
        let m = BackupManifest::V0(V0BackupManifest {
            files: vec![e1, e2],
        });
        let err = m.to_hash().expect_err("expected duplicate path error");
        assert!(err.to_string().to_lowercase().contains("duplicate"));
    }

    #[test]
    fn test_checksum_hex_must_be_valid_and_32_bytes() {
        use crate::backup::BackupFileDesignator as D;
        // invalid hex
        let e1 = V0BackupManifestEntry {
            designator: D::OrbPkg,
            file_path: "p.bin".into(),
            checksum_hex: "zz".into(),
        };
        let m = BackupManifest::V0(V0BackupManifest { files: vec![e1] });
        let err = m.to_hash().expect_err("expected invalid hex");
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid checksum encoding"));

        // wrong length (not 32 bytes)
        let e2 = V0BackupManifestEntry {
            designator: D::OrbPkg,
            file_path: "p.bin".into(),
            checksum_hex: hex::encode([0u8; 31]),
        };
        let m = BackupManifest::V0(V0BackupManifest { files: vec![e2] });
        let err = m.to_hash().expect_err("expected invalid length");
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid checksum length"));
    }

    #[test]
    fn test_hash_changes_when_entry_changes() {
        use crate::backup::BackupFileDesignator as D;
        let e1 = mk_entry(D::OrbPkg, "same.bin", b"A");
        let e2 = mk_entry(D::OrbPkg, "same.bin", b"B");
        // Different checksums but can't have dup paths; instead compare single-entry manifests
        let m1 = BackupManifest::V0(V0BackupManifest { files: vec![e1] });
        let m2 = BackupManifest::V0(V0BackupManifest { files: vec![e2] });
        assert_ne!(m1.to_hash().unwrap(), m2.to_hash().unwrap());
    }

    #[test]
    fn test_hash_stable_across_serialization_variations() {
        use crate::backup::BackupFileDesignator as D;
        // Manifest with two files; serialize and deserialize shouldn't affect hash
        let orig = BackupManifest::V0(V0BackupManifest {
            files: vec![
                mk_entry(D::OrbPkg, "x.bin", b"X"),
                mk_entry(D::DocumentPkg, "y.bin", b"Y"),
            ],
        });
        let h0 = orig.to_hash().unwrap();
        let json = serde_json::to_string_pretty(&orig).unwrap();
        let round: BackupManifest = serde_json::from_str(&json).unwrap();
        let h1 = round.to_hash().unwrap();
        assert_eq!(h0, h1);
    }
}
