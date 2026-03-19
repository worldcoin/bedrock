use crate::backup::backup_format::v0::V0Backup;
use crate::backup::BackupError;

pub mod v0;

#[derive(Debug)]
pub enum BackupFormat {
    V0(V0Backup),
}

impl BackupFormat {
    pub const fn new_v0(backup: V0Backup) -> Self {
        Self::V0(backup)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        if V0Backup::peek_version(bytes)? {
            let backup = V0Backup::from_bytes(bytes)?;
            Ok(Self::V0(backup))
        } else {
            Err(BackupError::VersionNotDetectedError)
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        match self {
            Self::V0(backup) => backup.to_bytes(),
        }
    }
}
