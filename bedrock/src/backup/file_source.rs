//! Host-owned backup contents, registered process-wide alongside their restore sink.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use super::{BackupError, BackupFileDesignator, ManifestManager};
use crate::primitives::filesystem::{unscoped_filesystem, FileSystemError};

/// Bounded failure classes for host callbacks. Never include paths or file contents.
#[derive(Debug, Clone, Copy, thiserror::Error, uniffi::Error)]
pub enum BackupFileSourceError {
    /// The requested logical entry is missing.
    #[error("not_found")]
    NotFound,
    /// The host store is temporarily unavailable, for example while locked.
    #[error("unavailable")]
    Unavailable,
    /// The host could not complete the operation.
    #[error("failure")]
    Failure,
    /// The foreign callback raised an unexpected exception.
    #[error("unexpected_callback")]
    UnexpectedCallback,
}

impl From<uniffi::UnexpectedUniFFICallbackError> for BackupFileSourceError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        // Foreign exception text can contain paths or contents.
        Self::UnexpectedCallback
    }
}

/// Supplies the exact bytes of entries belonging to registered designators.
///
/// Paths are normalized logical IDs, with leading `./` and `/` removed. Reads
/// must be repeatable until the backup operation returns. Missing entries must
/// return an error; Bedrock never falls back to disk for an owned designator.
#[uniffi::export(with_foreign)]
pub trait BackupFileSource: Send + Sync {
    /// Reads one entry, without transforming its stored bytes.
    ///
    /// # Errors
    /// Return a bounded failure class if the entry cannot be read.
    fn read(
        &self,
        designator: BackupFileDesignator,
        path: String,
    ) -> Result<Vec<u8>, BackupFileSourceError>;
}

/// One restored entry for a host-owned designator.
#[derive(Clone, uniffi::Record)]
pub struct RestoredBackupFile {
    /// File category registered with the source and sink.
    pub designator: BackupFileDesignator,
    /// Normalized logical ID, identical to the manifest and backup entry path.
    pub path: String,
    /// Exact bytes recovered from the backup.
    pub data: Vec<u8>,
}

/// Receives all host-owned files in one call after restore path validation.
///
/// Restore can be retried after a partial failure or process interruption. Upsert
/// entries by their logical path so replaying the same batch is safe. Bedrock
/// writes the manifest only after this call and all disk writes succeed; it
/// cannot roll back changes already made by the host or to disk.
#[uniffi::export(with_foreign)]
pub trait BackupFileSink: Send + Sync {
    /// Persists all supplied entries before returning success.
    ///
    /// # Errors
    /// Return a bounded failure class if the batch cannot be restored.
    fn restore(
        &self,
        files: Vec<RestoredBackupFile>,
    ) -> Result<(), BackupFileSourceError>;
}

pub(super) struct BackupFileHandlers {
    designators: HashSet<BackupFileDesignator>,
    source: Arc<dyn BackupFileSource>,
    sink: Arc<dyn BackupFileSink>,
}

static HANDLERS: RwLock<Option<Arc<BackupFileHandlers>>> = RwLock::new(None);

/// Registers a source and its matching restore sink for the supplied designators.
///
/// Call once at startup, before any backup operation. Registration is process-wide
/// because sync, restore, and reporting create managers internally. Unregistered
/// designators keep using disk. The callbacks must resolve the active account and
/// serialize account changes with backup operations. Ownership cannot change
/// during the process lifetime, and no callback runs under the registration lock.
///
/// # Errors
/// Returns an error if handlers have already been registered.
///
/// # Panics
/// Panics if the registration lock is poisoned.
#[uniffi::export]
pub fn set_backup_file_handlers(
    designators: Vec<BackupFileDesignator>,
    source: Arc<dyn BackupFileSource>,
    sink: Arc<dyn BackupFileSink>,
) -> Result<(), BackupError> {
    let handlers = Arc::new(BackupFileHandlers {
        designators: designators.into_iter().collect(),
        source,
        sink,
    });
    let mut registered = HANDLERS.write().expect("backup handler lock poisoned");
    if registered.is_some() {
        return Err(BackupError::BackupFileHandlersAlreadyRegistered);
    }
    *registered = Some(handlers);
    drop(registered);
    Ok(())
}

pub(super) fn backup_file_handlers() -> Option<Arc<BackupFileHandlers>> {
    HANDLERS
        .read()
        .expect("backup handler lock poisoned")
        .clone()
}

impl BackupFileHandlers {
    pub(super) fn owns(&self, designator: &BackupFileDesignator) -> bool {
        self.designators.contains(designator)
    }

    pub(super) fn restore(
        &self,
        files: Vec<RestoredBackupFile>,
    ) -> Result<(), BackupError> {
        if files.is_empty() {
            return Ok(());
        }
        let mut designators: Vec<_> = files
            .iter()
            .map(|file| file.designator.to_string())
            .collect();
        designators.sort();
        designators.dedup();
        let designators = designators.join(",");
        self.sink.restore(files).map_err(|failure| {
            crate::error!(
                designators = designators,
                failure_class = failure,
                "Failed to restore host-owned backup files"
            );
            BackupError::InvalidFileForBackup(format!(
                "restore for designators {designators}: {failure}"
            ))
        })
    }
}

pub(super) fn read_backup_file(
    designator: &BackupFileDesignator,
    path: &str,
) -> Result<Vec<u8>, BackupError> {
    let path = ManifestManager::normalize_input_path(path);
    let fs = unscoped_filesystem();
    if let Some(handlers) = backup_file_handlers().filter(|h| h.owns(designator)) {
        fs.resolved_file_path(path)
            .map_err(|e| disk_file_error(designator, &e))?;
        return handlers
            .source
            .read(designator.clone(), path.to_string())
            .map_err(|failure| {
                crate::error!(
                    designator = designator,
                    failure_class = failure,
                    "Failed to read host-owned backup file"
                );
                BackupError::InvalidFileForBackup(format!(
                    "read for designator {designator}: {failure}"
                ))
            });
    }
    fs.read_file(path)
        .map_err(|e| disk_file_error(designator, &e))
}

pub(super) fn checksum_and_size_for_file(
    designator: &BackupFileDesignator,
    path: &str,
) -> Result<([u8; 32], u64), BackupError> {
    if backup_file_handlers().is_some_and(|h| h.owns(designator)) {
        let data = read_backup_file(designator, path)?;
        return Ok((blake3::hash(&data).into(), data.len() as u64));
    }
    unscoped_filesystem()
        .calculate_checksum_and_size(ManifestManager::normalize_input_path(path))
        .map_err(|e| disk_file_error(designator, &e))
}

pub(super) fn disk_file_error(
    designator: &BackupFileDesignator,
    failure: &FileSystemError,
) -> BackupError {
    let failure_class = match failure {
        FileSystemError::FileDoesNotExist => "not_found",
        FileSystemError::IoFailure(_) => "io_failure",
        FileSystemError::NotInitialized => "not_initialized",
        FileSystemError::InvalidPath(_) => "invalid_path",
    };
    crate::error!(
        designator = designator,
        failure_class = failure_class,
        "Backup file disk operation failed"
    );
    BackupError::InvalidFileForBackup(format!(
        "disk operation for designator {designator}: {failure_class}"
    ))
}

#[cfg(test)]
pub(super) struct TestHandlersGuard;

#[cfg(test)]
impl Drop for TestHandlersGuard {
    fn drop(&mut self) {
        *HANDLERS.write().unwrap() = None;
    }
}
