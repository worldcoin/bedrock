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
        V0Backup::from_bytes(bytes).map(Self::V0)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        match self {
            Self::V0(backup) => backup.to_bytes(),
        }
    }
}
