use crate::backup::backup_format::v0::V0Backup;
use crate::backup::BackupError;

pub mod v0;

/// Enum representing different versions of backup formats
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupFormat {
    /// Version 0 backup format
    V0(V0Backup),
}

impl BackupFormat {
    /// Create a new V0 backup format
    #[must_use]
    pub const fn new_v0(backup: V0Backup) -> Self {
        Self::V0(backup)
    }

    /// Deserialize backup format from bytes
    ///
    /// # Errors
    /// Returns `BackupError` if deserialization fails or version is not detected
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if V0Backup::peek_version(bytes) {
            let backup = V0Backup::from_bytes(bytes)?;
            Ok(Self::V0(backup))
        } else {
            Err(BackupError::VersionNotDetectedError)
        }
    }

    /// Serialize backup format to bytes
    ///
    /// # Errors
    /// Returns `BackupError` if serialization fails
    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        match self {
            Self::V0(backup) => backup.to_bytes(),
        }
    }
}
