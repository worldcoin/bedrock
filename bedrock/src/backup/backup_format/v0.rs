use crate::backup::{BackupError, BackupModule};
use crate::secure::RootKey;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};
use std::path::{Component, Path};
use std::sync::Arc;
use tar::{Archive, Builder, Header};

const VERSION_TAG: &str = "OXIDE_BACKUP_VERSION";
const ROOT_SECRET_FILE: &str = "root_secret.json";

/// V0 version of the backup manifest. See `BackupManifest` for more details.
#[derive(Debug, Serialize, Deserialize)]
pub struct V0BackupManifest {
    /// The path to the file on the file system (relative to the user data directory). It is where the file will be retrieved from to add to the backup, and
    /// where the file will be extracted to when restoring the backup.
    /// TODO: This needs to be standardized and constrained to relevant relative paths (i.e. personal_custody can only backup files relative to personal_custody)
    file_path: String,
    /// The last time the manifest was updated.
    pub manifest_last_updated_at: DateTime<Utc>,
    /// The maximum file size allowed in kilobytes.
    pub max_file_size_kb: u64,
    /// The module that the file belongs to.
    pub module_name: BackupModule,
}

impl V0BackupManifest {
    pub fn new(
        file_path: String,
        manifest_last_updated_at: DateTime<Utc>,
        max_file_size_kb: u64,
        module_name: BackupModule,
    ) -> Result<Self, BackupError> {
        let unsanitized_path = Path::new(&file_path);

        for component in unsanitized_path.components() {
            match component {
                Component::Normal(_) | Component::CurDir | Component::RootDir => {}
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(BackupError::ParseBackupManifestError {
                        // Important we don't log the actual file path as it may contain some user info
                        details: "Invalid file path for manifest.".to_string(),
                        manifest_name: module_name.to_string(),
                    });
                }
            }
        }

        Ok(Self {
            file_path: file_path.trim_start_matches('/').to_string(),
            manifest_last_updated_at,
            max_file_size_kb,
            module_name,
        })
    }

    pub fn file_path(&self) -> &str {
        &self.file_path
    }
}

/// This backup format allows the app to store any files that it wants, primarily, PCPs. Root secret
/// is stored separately and specially handled.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct V0Backup {
    /// Root secret that is used to derive the wallet, World ID identity and PCP encryption keys.
    pub root_secret: Arc<RootKey>,
    /// List of files in the backup determined by the mobile app.
    pub files: Vec<V0BackupFile>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record, Serialize, Deserialize)]
pub struct V0BackupFile {
    /// The actual file data (usually binary).
    pub data: Vec<u8>,
    /// The blake3 hash of the file. A vector is used to be able to pass to foreign code.
    pub checksum: Vec<u8>,
    /// Relative path under the user data directory; also used as archive entry name.
    pub path: String,
}

impl V0BackupFile {
    /// Validates the checksum of the file.
    ///
    /// # Errors
    /// * If the checksum is invalid, `BackupError::InvalidChecksumError` is returned.
    pub fn validate_checksum(&self) -> Result<(), BackupError> {
        let computed_checksum = blake3::hash(&self.data);
        if self.checksum != computed_checksum.as_bytes().to_vec() {
            return Err(BackupError::InvalidChecksumError {
                module_name: self.path.clone(),
            });
        }
        Ok(())
    }
}

impl V0Backup {
    pub const fn new(root_secret: Arc<RootKey>, files: Vec<V0BackupFile>) -> Self {
        Self { root_secret, files }
    }

    /// Check if the backup has the correct tag for this version of the backup format.
    /// Returns true if the correct version tag is present, false otherwise.
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

    /// Deserialize the `BackupFormat` from unencrypted bytes.
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

                let file: V0BackupFile = ciborium::from_reader(Cursor::new(&data))
                    .map_err(|e| {
                        log::error!("Failed to deserialize backup file {path}: {e}");
                        BackupError::DecodeBackupFileError {
                            error: Box::new(e),
                            path,
                        }
                    })?;

                file.validate_checksum()?;

                files.push(file);
            }
        }

        // Validate the root secret.
        let root_secret = RootKey::decode_from_json_enforced(&root_secret)
            .map_err(|_| BackupError::InvalidRootSecretError)?;

        Ok(Self {
            root_secret: Arc::new(root_secret),
            files,
        })
    }

    /// Serialize the `BackupFormat` into unencrypted bytes. The encryption is going to be done
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
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            self.root_secret
                .encode()
                .map_err(|_| BackupError::EncodeRootSecretError)?
                .as_bytes(),
        )?;

        // Add files (e.g. PCPs)
        for file in &self.files {
            // The entire BackupFile is encoded to preserve the metadata (checksum, path, etc.)
            // We use CBOR as it's more performant than JSON for the binary data (more compact).
            let mut encoded_file: Vec<u8> = Vec::new();
            ciborium::into_writer(file, &mut encoded_file)?;
            write_to_archive(&mut archive, &file.path, &encoded_file)?;
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
    archive.append_data(&mut header, name, Cursor::new(&data))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v0_backup() {
        let root_secret =
            "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b"
                .to_string();
        let files = vec![
            V0BackupFile {
                data: b"Hello, World!".to_vec(),
                checksum: blake3::hash(b"Hello, World!").as_bytes().to_vec(),
                path: "personal_custody/file1.txt".to_string(),
            },
            V0BackupFile {
                data: vec![],
                checksum: blake3::hash(&vec![]).as_bytes().to_vec(),
                path: "document_personal_custody/file2.txt".to_string(),
            },
        ];

        let backup =
            V0Backup::new(Arc::new(RootKey::decode(root_secret)), files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();

        assert_eq!(
            deserialized_backup.root_secret.encode().unwrap(),
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
        );
        assert_eq!(deserialized_backup.files, files);

        // Check if the version tag is present
        assert!(V0Backup::peek_version(&bytes));

        // Test with v1 key
        let v1_root_secret = RootKey::new_random();
        let v1_backup = V0Backup::new(Arc::new(v1_root_secret.clone()), vec![]);
        let v1_bytes = v1_backup.to_bytes().unwrap();
        let v1_deserialized_backup = V0Backup::from_bytes(&v1_bytes).unwrap();
        assert_eq!(
            v1_deserialized_backup.root_secret.encode().unwrap(),
            v1_root_secret.encode().unwrap()
        );
        assert_eq!(v1_deserialized_backup.files, vec![]);
        assert!(V0Backup::peek_version(&v1_bytes));
    }

    #[test]
    fn test_v0_backup_with_no_files() {
        let root_secret =
            "1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b"
                .to_string();
        let files = vec![];
        let backup =
            V0Backup::new(Arc::new(RootKey::decode(root_secret)), files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();
        assert_eq!(
            deserialized_backup.root_secret.encode().unwrap(),
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
        );
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
        assert_eq!(
            V0Backup::from_bytes(&result).unwrap_err().to_string(),
            BackupError::InvalidRootSecretError.to_string()
        );
    }

    #[test]
    fn test_v0_backup_without_root_secret() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        let test_file = V0BackupFile {
            data: b"Hello".to_vec(),
            checksum: blake3::hash(b"Hello").as_bytes().to_vec(),
            path: "personal_custody/file.txt".to_string(),
        };
        let mut encoded_file = Vec::new();
        ciborium::into_writer(&test_file, &mut encoded_file).unwrap();

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(&mut archive, &test_file.path, &encoded_file).unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        assert_eq!(
            V0Backup::from_bytes(&result).unwrap_err().to_string(),
            BackupError::InvalidRootSecretError.to_string()
        );
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

    /// Creates a file that is not actually valid CBOR.
    #[test]
    fn test_invalidly_encoded_file() {
        // Create a backup archive with a file that contains invalid CBOR data
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .as_bytes(),
        )
        .unwrap();

        // Add a file with invalid CBOR data (just random bytes that aren't valid CBOR)
        write_to_archive(&mut archive, "invalid_file.txt", &[0xFF, 0xFE, 0xFD, 0xFC])
            .unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        // Should fail with CBOR decoding error
        let error = V0Backup::from_bytes(&result).unwrap_err();
        assert_eq!(
            error.to_string(),
            "CBOR decoding error invalid_file.txt: Semantic error at None: invalid type break expected map"
        );
    }

    #[test]
    fn test_encoded_file_with_missing_attributes() {
        #[derive(serde::Serialize)]
        struct MockBackupFile {
            name: String,
            data: Vec<u8>,
            // no checksum
            module_name: BackupModule,
            file_path: String,
        }

        let mock_file = MockBackupFile {
            name: "test_file.txt".to_string(),
            data: vec![],
            module_name: BackupModule::PersonalCustody,
            file_path: "/documents/file.txt".to_string(),
        };

        let mut invalid_cbor = Vec::new();
        ciborium::into_writer(&mock_file, &mut invalid_cbor).unwrap();

        // Create a backup archive
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .as_bytes(),
        )
        .unwrap();

        write_to_archive(&mut archive, "invalid_module_file.txt", &invalid_cbor)
            .unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        let error = V0Backup::from_bytes(&result).unwrap_err();
        assert_eq!(
            error.to_string(),
            "CBOR decoding error invalid_module_file.txt: Semantic error at None: missing field checksum"
        );
    }

    #[test]
    fn test_invalidly_encoded_file_with_wrong_module_name() {
        #[derive(serde::Serialize)]
        struct MockBackupFile {
            name: String,
            data: Vec<u8>,
            checksum: Vec<u8>,
            module_name: String, // where this can be a String, not a typed BackupModule
            file_path: String,
        }

        let mock_file = MockBackupFile {
            name: "test_file.txt".to_string(),
            data: vec![],
            checksum: vec![1, 2, 3, 4],
            module_name: "invalid_module_name".to_string(),
            file_path: "/documents/file.txt".to_string(),
        };

        let mut invalid_cbor = Vec::new();
        ciborium::into_writer(&mock_file, &mut invalid_cbor).unwrap();

        // Create a backup archive
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .as_bytes(),
        )
        .unwrap();

        write_to_archive(&mut archive, "invalid_module_file.txt", &invalid_cbor)
            .unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        let error = V0Backup::from_bytes(&result).unwrap_err();
        assert_eq!(
            error.to_string(),
            "CBOR decoding error invalid_module_file.txt: Semantic error at None: Matching variant not found"
        );
    }

    #[test]
    fn test_invalid_checksum() {
        let file_with_incorrect_checksum = V0BackupFile {
            data: b"Hello, World!".to_vec(),
            checksum: blake3::hash(b"Goodbye, World!").as_bytes().to_vec(),
            path: "personal_custody/file.txt".to_string(),
        };

        let mut encoded_file = Vec::new();
        ciborium::into_writer(&file_with_incorrect_checksum, &mut encoded_file)
            .unwrap();

        // Create a backup archive with this file
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            "{\"version\":\"V0\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
                .as_bytes(),
        )
        .unwrap();

        write_to_archive(&mut archive, "test_file.txt", &encoded_file).unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        // Should fail with checksum validation error
        let error = V0Backup::from_bytes(&result).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid checksum for file personal_custody"
        );
    }
}
