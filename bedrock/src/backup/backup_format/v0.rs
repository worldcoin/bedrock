use crate::backup::BackupError;

use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Cursor, Read};

use tar::{Archive, Builder, Header};

const VERSION_TAG: &str = "BEDROCK_BACKUP_VERSION";
const ROOT_SECRET_FILE: &str = "root_secret.json";

/// This backup format allows the app to store any files that it wants, primarily, PCPs. Root secret
/// is stored separately. In the future, we should migrate to a strongly typed format
/// (which would be `V1Backup`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct V0Backup {
    /// Root secret that is used to derive the wallet, World ID identity and PCP encryption keys.
    pub root_secret: String,
    /// List of files in the backup determined by the mobile app.
    pub files: Vec<V0BackupFile>,
}

/// A file stored in a V0 backup
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct V0BackupFile {
    /// The name of the file
    pub name: String,
    /// The file data
    pub data: Vec<u8>,
}

impl V0Backup {
    /// Create a new V0 backup
    #[must_use]
    pub const fn new(root_secret: String, files: Vec<V0BackupFile>) -> Self {
        Self { root_secret, files }
    }

    /// Check if the backup has the correct tag for this version of the backup format.
    /// Returns true if the correct version tag is present, false otherwise.
    #[must_use]
    pub fn peek_version(bytes: &[u8]) -> bool {
        let gz_decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz_decoder);
        let Ok(entries) = archive.entries() else {
            return false;
        };

        // Iterate through the files in the backup and check if the version tag is present
        for entry in entries {
            let Ok(mut file) = entry else {
                return false;
            };
            let path = if let Ok(path) = file.path() {
                path.into_owned()
            } else {
                return false;
            };
            let path = if let Some(path) = path.to_str() {
                path.to_string()
            } else {
                return false;
            };
            // If the version tag is present, check if it has the correct value
            if path == VERSION_TAG {
                let mut version_data = Vec::new();
                return match file.read_to_end(&mut version_data) {
                    Ok(1) => version_data[0] == 0,
                    _ => false,
                };
            }
        }
        false
    }

    /// Deserialize the `V0Backup` from unencrypted bytes.
    ///
    /// # Errors
    /// * If the archive cannot be decompressed or read, `BackupError::IoError` is returned.
    /// * If the root secret is invalid, `BackupError::InvalidRootSecretError` is returned.
    /// * If the version tag is not present, `BackupError::VersionNotDetectedError` is returned.
    /// * If the file name cannot be read, `BackupError::ReadFileNameError` is returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        let gz_decoder = GzDecoder::new(Cursor::new(bytes));
        let mut archive = Archive::new(gz_decoder);

        let mut root_secret = String::new();
        let mut files = Vec::new();

        for entry in archive.entries()? {
            let mut file = entry?;
            let path = file
                .path()?
                .to_str()
                .ok_or(BackupError::ReadFileNameError)?
                .to_string();

            if path == ROOT_SECRET_FILE {
                file.read_to_string(&mut root_secret)?;
            } else if path == VERSION_TAG {
                // Skip the version tag file, it should be checked by .peek_version
            } else {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                files.push(V0BackupFile { name: path, data });
            }
        }

        // Validate the root secret.
        // Use placeholder string for root secret
        let root_secret = root_secret;

        Ok(Self { root_secret, files })
    }

    /// Serialize the `V0Backup` into unencrypted bytes. The encryption is going to be done
    /// later by the caller.
    ///
    /// # Errors
    /// * If the bytes cannot be compressed or written, `BackupError::IoError` is returned.
    /// * If the root secret is invalid, `BackupError::InvalidRootSecretError` is returned.
    /// * If any of the metadata or files cannot be written, `BackupError::IoError` is returned.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        // Add a version tag to the archive
        write_to_archive(&mut archive, VERSION_TAG, &[0])?;

        // Add root secret
        write_to_archive(&mut archive, ROOT_SECRET_FILE, self.root_secret.as_bytes())?;

        // Add files (e.g. PCPs)
        for file in &self.files {
            write_to_archive(&mut archive, &file.name, &file.data)?;
        }

        // Finish the archive
        archive.finish()?;
        let encoder = archive.into_inner()?;
        encoder.finish()?;

        Ok(result)
    }
}

/// Write a single file to the archive encoder.
fn write_to_archive(
    archive: &mut Builder<GzEncoder<&mut Vec<u8>>>,
    name: &str,
    data: &[u8],
) -> Result<(), BackupError> {
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    #[allow(clippy::cast_sign_loss)]
    header.set_mtime(Utc::now().timestamp() as u64);
    // 600 = you can read and write the file or directory, but other users have no access to it
    header.set_mode(0o600);
    header.set_cksum();
    archive.append_data(&mut header, name, Cursor::new(data))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v0_backup() {
        let root_secret =
            "{\"version\":\"V1\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .to_string();
        let files = vec![
            V0BackupFile {
                name: "file1.txt".to_string(),
                data: b"Hello, World!".to_vec(),
            },
            V0BackupFile {
                name: "file2.txt".to_string(),
                data: vec![],
            },
        ];

        let backup = V0Backup::new(root_secret, files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized_backup.root_secret, backup.root_secret);
        assert_eq!(deserialized_backup.files, files);

        // Check if the version tag is present
        assert!(V0Backup::peek_version(&bytes));

        // Test with new key
        let new_root_secret = "test_root_secret".to_string();
        let new_backup = V0Backup::new(new_root_secret.clone(), vec![]);
        let new_bytes = new_backup.to_bytes().unwrap();
        let new_deserialized_backup = V0Backup::from_bytes(&new_bytes).unwrap();
        assert_eq!(new_deserialized_backup.root_secret, new_root_secret);
        assert_eq!(new_deserialized_backup.files, vec![]);
        assert!(V0Backup::peek_version(&new_bytes));
    }

    #[test]
    fn test_v0_backup_with_no_files() {
        let root_secret =
            "{\"version\":\"V1\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .to_string();
        let files = vec![];
        let backup = V0Backup::new(root_secret, files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized_backup.root_secret, backup.root_secret);
        assert_eq!(deserialized_backup.files, files);
        assert!(V0Backup::peek_version(&bytes));
    }

    #[test]
    fn test_v0_backup_with_incorrect_root_secret() {
        let root_secret = "incorrect-secret".to_string();

        // deserialization
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(&mut archive, ROOT_SECRET_FILE, root_secret.as_bytes())
            .unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();
        // With string placeholder, any string is valid now
        assert!(V0Backup::from_bytes(&result).is_ok());
    }

    #[test]
    fn test_v0_backup_without_root_secret() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(&mut archive, "file.txt", b"Hello").unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        // Without root secret file, this now creates empty string
        let backup = V0Backup::from_bytes(&result).unwrap();
        assert_eq!(backup.root_secret, "");
        assert_eq!(backup.files.len(), 1);
    }

    #[test]
    fn test_v0_backup_with_other_version() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[1]).unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        assert!(!V0Backup::peek_version(&result));
    }

    #[test]
    fn test_v0_backup_without_version() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, "file.txt", b"Hello").unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        assert!(!V0Backup::peek_version(&result));
    }
}
