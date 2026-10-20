use crate::backup::{BackupError, BackupFileDesignator};
use crate::root_key::RootKey;
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use tar::{Archive, Builder, Header};

const VERSION_TAG: &str = "OXIDE_BACKUP_VERSION";
const ROOT_SECRET_FILE: &str = "root_secret.json";

/// Maximum number of bytes a backup archive may decompress to.
///
/// Defense-in-depth in case an attacker is able to provide a malicious backup.
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// V0 version of the backup manifest. See `BackupManifest` for more details.
///
/// NOTE: Important not to incorporate types with undefined iteration order into this struct (e.g. `HashMap`)
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct V0BackupManifest {
    /// Entries describing each file to be backed up.
    pub files: Vec<V0BackupManifestEntry>,
}

/// One entry in the global manifest.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct V0BackupManifestEntry {
    /// Logical designator for the file.
    pub designator: BackupFileDesignator,
    /// Full path under the user data directory where the file resides.
    pub file_path: String,
    /// Lowercase hex-encoded checksum of the file's raw bytes (32 bytes → 64 chars).
    pub checksum_hex: String,
}

/// This backup format allows the app to store any files that it wants, primarily, PCPs. Root secret
/// is stored separately and specially handled.
#[derive(Debug)]
pub struct V0Backup {
    /// Root secret that is used to derive the wallet, World ID identity and PCP encryption keys.
    pub root_secret: RootKey,
    /// List of files in the backup determined by the mobile app.
    pub files: Vec<V0BackupFile>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(Clone))]
pub struct V0BackupFile {
    /// The actual file data (usually binary).
    pub data: Vec<u8>,
    /// The blake3 hash of the file.
    pub checksum: [u8; 32],
    /// Relative path under the user data directory; also used as archive entry name.
    pub path: String,
    /// Logical designator for this file. Required to reconstruct the manifest when unpacking a backup from the remote.
    pub designator: BackupFileDesignator,
}

impl V0BackupFile {
    /// Validates the checksum of the file.
    ///
    /// # Errors
    /// * If the checksum is invalid, `BackupError::InvalidChecksumError` is returned.
    pub fn validate_checksum(&self) -> Result<(), BackupError> {
        let computed_checksum = blake3::hash(&self.data);
        if &self.checksum != computed_checksum.as_bytes() {
            crate::critical!(
                designator = self.designator,
                "Checksum for file in backup does not match the expected value"
            );
            return Err(BackupError::InvalidChecksumError {
                designator: self.designator.to_string(),
            });
        }
        Ok(())
    }
}

impl V0Backup {
    pub const fn new(root_secret: RootKey, files: Vec<V0BackupFile>) -> Self {
        Self { root_secret, files }
    }

    /// Deserialize the `BackupFormat` from unencrypted bytes.
    ///
    /// # Errors
    /// * If the archive cannot be decompressed or read, `BackupError::IoError` is returned.
    /// * If the version tag is absent or belongs to another format,
    ///   `BackupError::VersionNotDetectedError` is returned.
    /// * If the file name cannot be read, `BackupError::ReadFileNameError` is returned.
    /// * If a file cannot be decoded from CBOR, `BackupError::DecodeBackupFileError` is returned.
    /// * If a file checksum does not match, `BackupError::InvalidChecksumError` is returned.
    /// * If the root secret is invalid, `BackupError::InvalidRootSecretError` is returned.
    /// * If the archive decompresses to more than [`MAX_DECOMPRESSED_BYTES`],
    ///   `BackupError::BackupTooLargeError` is returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BackupError> {
        let mut archive = bounded_archive(bytes);
        let result = read_entries(&mut archive);
        let (root_secret, files) = archive.into_inner().map_limit_error(result)?;

        // Validate the root secret.
        let root_secret = RootKey::from_json(&root_secret).map_err(|_| {
            // Shape only, never the secret itself: whether it looks like JSON at all,
            // and how long it is.
            let looks_like_json =
                root_secret.chars().next().unwrap_or_default() == '{';
            crate::critical!(
                looks_like_json = looks_like_json,
                length = root_secret.len(),
                "Invalid root secret in decrypted backup"
            );
            BackupError::InvalidRootSecretError(format!(
                "Invalid root secret in decrypted backup: {looks_like_json} with length {}.",
                root_secret.len()
            ))
        })?;

        Ok(Self { root_secret, files })
    }

    /// Serialize the `BackupFormat` into unencrypted bytes. The encryption is going to be done
    /// later by the caller.
    ///
    /// # Errors
    /// * If the bytes cannot be compressed or written, `BackupError::IoError` is returned.
    /// * If the root secret cannot be encoded to JSON, `BackupError::EncodeRootSecretError` is returned.
    /// * If a backup file cannot be CBOR-encoded, `BackupError::EncodeBackupFileError` is returned.
    /// * If any of the metadata or files cannot be written, `BackupError::IoError` is returned.
    /// * If the archive would decompress to more than [`MAX_DECOMPRESSED_BYTES`],
    ///   `BackupError::BackupTooLargeError` is returned.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BackupError> {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(CountingWriter::new(gz_builder));

        // Add a version tag to the archive
        write_to_archive(&mut archive, VERSION_TAG, &[0])?;

        // Add root secret
        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            self.root_secret
                // ok to export the secret as this is included in the secure encrypted backup
                .danger_to_json()
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
        let counting_writer = archive.into_inner()?;

        // Never produce a backup that `from_bytes` would then refuse to restore.
        if counting_writer.written > MAX_DECOMPRESSED_BYTES {
            crate::critical!(
                uncompressed_size = counting_writer.written,
                file_count = self.files.len(),
                "Backup exceeds the maximum size and could not be restored"
            );
            return Err(BackupError::BackupTooLargeError);
        }

        counting_writer.into_inner().finish()?;

        Ok(result)
    }
}

/// Opens the archive through a decoder that cannot expand past [`MAX_DECOMPRESSED_BYTES`].
fn bounded_archive(bytes: &[u8]) -> Archive<BoundedReader<GzDecoder<Cursor<&[u8]>>>> {
    Archive::new(BoundedReader::new(GzDecoder::new(Cursor::new(bytes))))
}

/// Reads the version tag, the root secret JSON and every backup file out of the archive in a
/// single pass.
fn read_entries<R: Read>(
    archive: &mut Archive<R>,
) -> Result<(String, Vec<V0BackupFile>), BackupError> {
    let mut version_tagged = false;
    let mut root_secret = String::new();
    let mut files = Vec::new();
    let mut budget = EntryBudget::new();

    for entry in archive.entries()? {
        let mut file = entry?;
        let path = file
            .path()?
            .to_str()
            .ok_or(BackupError::ReadFileNameError)?
            .to_string();
        let declared_size = file.size();

        if path == VERSION_TAG {
            if budget.read_entry(&mut file, declared_size)? != [0] {
                return Err(BackupError::VersionNotDetectedError);
            }
            version_tagged = true;
        } else if path == ROOT_SECRET_FILE {
            let bytes = budget.read_entry(&mut file, declared_size)?;
            root_secret = String::from_utf8(bytes).map_err(|_| {
                BackupError::IoError(
                    "root secret in backup is not valid UTF-8".to_string(),
                )
            })?;
        } else {
            let data = budget.read_entry(&mut file, declared_size)?;

            let file: V0BackupFile = ciborium::from_reader(Cursor::new(&data))
                .inspect_err(|e| {
                    crate::error!(
                        path = path,
                        error_message = e,
                        "Failed to deserialize backup file"
                    );
                })?;

            file.validate_checksum()?;

            files.push(file);
        }
    }

    if !version_tagged {
        return Err(BackupError::VersionNotDetectedError);
    }

    Ok((root_secret, files))
}

/// Cumulative cap on the bytes materialized from archive entries.
///
/// This bound has to be enforced above `tar`, not on the gzip stream: a GNU sparse entry
/// synthesizes its holes from `io::repeat`, so its logical size can be arbitrarily larger
/// than anything [`BoundedReader`] observes.
struct EntryBudget {
    remaining: u64,
}

impl EntryBudget {
    const fn new() -> Self {
        Self {
            remaining: MAX_DECOMPRESSED_BYTES,
        }
    }

    /// Reads one entry into memory, charging its bytes against the budget.
    ///
    /// The declared size is checked first so an oversized entry costs no allocation at all;
    /// the read itself is bounded too, rather than trusting that declared size.
    fn read_entry<R: Read>(
        &mut self,
        entry: &mut R,
        declared_size: u64,
    ) -> Result<Vec<u8>, BackupError> {
        if declared_size > self.remaining {
            return Err(entry_too_large(declared_size));
        }

        let mut data = Vec::new();
        entry.take(self.remaining + 1).read_to_end(&mut data)?;

        let read = data.len() as u64;
        if read > self.remaining {
            return Err(entry_too_large(read));
        }
        self.remaining -= read;

        Ok(data)
    }
}

/// Logs and builds the failure for an entry that would exceed [`MAX_DECOMPRESSED_BYTES`].
fn entry_too_large(entry_bytes: u64) -> BackupError {
    crate::critical!(
        entry_bytes = entry_bytes,
        max_decompressed_bytes = MAX_DECOMPRESSED_BYTES,
        "Backup archive entry exceeds the maximum decompressed size"
    );
    BackupError::BackupTooLargeError
}

/// Reader that fails once the inner reader has produced more than [`MAX_DECOMPRESSED_BYTES`].
///
/// Bounds the decompression work itself, including the entries that are skipped rather than
/// read. `Read::take` is not usable here: reaching the cap would look like a clean end of
/// archive to the tar reader and silently truncate the backup.
struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> BoundedReader<R> {
    const fn new(inner: R) -> Self {
        // One byte of slack, so an archive of exactly the maximum size still reads cleanly.
        Self {
            inner,
            remaining: MAX_DECOMPRESSED_BYTES + 1,
        }
    }

    /// Reports a read that hit the cap as `BackupTooLargeError` instead of the opaque I/O
    /// error the tar reader surfaced.
    fn map_limit_error<T>(
        self,
        result: Result<T, BackupError>,
    ) -> Result<T, BackupError> {
        if result.is_err() && self.remaining == 0 {
            crate::critical!(
                max_decompressed_bytes = MAX_DECOMPRESSED_BYTES,
                "Backup archive exceeds the maximum decompressed size"
            );
            return Err(BackupError::BackupTooLargeError);
        }
        result
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "backup archive exceeds the maximum decompressed size",
            ));
        }

        let allowed = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let read = self.inner.read(&mut buf[..allowed])?;
        self.remaining -= read as u64;
        Ok(read)
    }
}

/// Writer that tracks how many uncompressed bytes the archive builder has produced, so a
/// backup that could not be restored is rejected at creation instead of at restore.
struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> CountingWriter<W> {
    const fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Write a single file to the archive encoder.
fn write_to_archive<W: Write>(
    archive: &mut Builder<W>,
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
        // not an actual secure secret
        let root_secret =
            "{\"version\":\"V1\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();

        let files = vec![
            V0BackupFile {
                data: b"Hello, World!".to_vec(),
                checksum: blake3::hash(b"Hello, World!").as_bytes().to_owned(),
                path: "personal_custody/file1.txt".to_string(),
                designator: BackupFileDesignator::OrbPkg,
            },
            V0BackupFile {
                data: vec![],
                checksum: blake3::hash(&[]).as_bytes().to_owned(),
                path: "document_personal_custody/file2.txt".to_string(),
                designator: BackupFileDesignator::DocumentPkg,
            },
        ];

        let backup =
            V0Backup::new(RootKey::from_json(&root_secret).unwrap(), files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();

        assert_eq!(
            deserialized_backup.root_secret.danger_to_json().unwrap(),
            "{\"version\":\"V1\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
        );
        assert_eq!(deserialized_backup.files, files);

        // Test with v1 key
        let v1_root_secret = RootKey::new_random();
        let v1_root_secret_json = v1_root_secret.danger_to_json().unwrap();
        let v1_backup = V0Backup::new(v1_root_secret, vec![]);
        let v1_bytes = v1_backup.to_bytes().unwrap();
        let v1_deserialized_backup = V0Backup::from_bytes(&v1_bytes).unwrap();
        assert_eq!(
            v1_deserialized_backup.root_secret.danger_to_json().unwrap(),
            v1_root_secret_json
        );
        assert_eq!(v1_deserialized_backup.files, vec![]);
    }

    #[test]
    fn test_v0_backup_with_no_files() {
        let root_secret =
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();

        let files = vec![];
        let backup =
            V0Backup::new(RootKey::from_json(&root_secret).unwrap(), files.clone());
        let bytes = backup.to_bytes().unwrap();
        let deserialized_backup = V0Backup::from_bytes(&bytes).unwrap();
        assert_eq!(
            deserialized_backup.root_secret.danger_to_json().unwrap(),
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
        );
        assert_eq!(deserialized_backup.files, files);
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
            "Invalid root secret provided: Invalid root secret in decrypted backup: false with length 16."
        );
    }

    #[test]
    fn test_v0_backup_without_root_secret() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        let test_file = V0BackupFile {
            data: b"Hello".to_vec(),
            checksum: blake3::hash(b"Hello").as_bytes().to_owned(),
            path: "personal_custody/file.txt".to_string(),
            designator: BackupFileDesignator::OrbPkg,
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
            "Invalid root secret provided: Invalid root secret in decrypted backup: false with length 0."
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

        assert_eq!(
            V0Backup::from_bytes(&result).unwrap_err().to_string(),
            "Backup version is not detected"
        );
    }

    #[test]
    fn test_v0_backup_without_version() {
        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        write_to_archive(
            &mut archive,
            ROOT_SECRET_FILE,
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
                .as_bytes(),
        )
        .unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        assert_eq!(
            V0Backup::from_bytes(&result).unwrap_err().to_string(),
            "Backup version is not detected"
        );
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
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
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
            "CBOR decoding error: Semantic error at None: invalidtype:br"
        );
    }

    #[test]
    fn test_encoded_file_with_missing_attributes() {
        #[derive(serde::Serialize)]
        struct MockBackupFile {
            data: Vec<u8>,
            // no checksum
            file_path: String,
        }

        let mock_file = MockBackupFile {
            data: vec![],
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
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
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
            "CBOR decoding error: Semantic error at None: missingfieldch"
        );
    }

    #[test]
    fn test_invalid_checksum() {
        let file_with_incorrect_checksum = V0BackupFile {
            data: b"Hello, World!".to_vec(),
            checksum: blake3::hash(b"Goodbye, World!").as_bytes().to_owned(),
            path: "personal_custody/file.txt".to_string(),
            designator: BackupFileDesignator::OrbPkg,
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
            "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}"
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
            "Checksum for file with designator: orb_pkg does not match the expected value"
        );
    }

    /// Builds an archive whose entries expand past the decompression cap.
    fn decompression_bomb(version_tagged: bool) -> Vec<u8> {
        let oversized = vec![0u8; usize::try_from(MAX_DECOMPRESSED_BYTES).unwrap() + 1];

        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);

        if version_tagged {
            write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        }
        write_to_archive(&mut archive, "bomb.bin", &oversized).unwrap();

        archive.finish().unwrap();
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap();

        result
    }

    #[test]
    fn test_from_bytes_rejects_decompression_bomb() {
        let bomb = decompression_bomb(true);
        // The archive itself has to stay small, or it is not a bomb.
        assert!(bomb.len() < 1024 * 1024);

        assert_eq!(
            V0Backup::from_bytes(&bomb).unwrap_err().to_string(),
            "Backup archive exceeds the maximum size"
        );
    }

    /// The cap cannot depend on the version tag: the archive controls it, so an unmarked
    /// archive has to hit the ceiling rather than the version check.
    #[test]
    fn test_from_bytes_rejects_unmarked_decompression_bomb() {
        assert_eq!(
            V0Backup::from_bytes(&decompression_bomb(false))
                .unwrap_err()
                .to_string(),
            "Backup archive exceeds the maximum size"
        );
    }

    #[test]
    fn test_to_bytes_rejects_oversized_backup() {
        let data = vec![0u8; usize::try_from(MAX_DECOMPRESSED_BYTES).unwrap() + 1];
        let files = vec![V0BackupFile {
            checksum: blake3::hash(&data).as_bytes().to_owned(),
            data,
            path: "personal_custody/huge.bin".to_string(),
            designator: BackupFileDesignator::OrbPkg,
        }];

        let backup = V0Backup::new(RootKey::new_random(), files);
        assert_eq!(
            backup.to_bytes().unwrap_err().to_string(),
            "Backup archive exceeds the maximum size"
        );
    }

    /// Builds an archive holding one GNU sparse entry: ~1 KiB of physical data declaring a
    /// 1 GiB logical size. `tar` synthesizes the hole from `io::repeat`, so the expansion
    /// never passes through the gzip stream.
    fn sparse_bomb(name: &str) -> Vec<u8> {
        const HOLE: u64 = 1024 * 1024 * 1024;
        const DATA_BLOCK: u64 = 512;

        let mut header = Header::new_gnu();
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(DATA_BLOCK * 2);
        {
            let gnu = header.as_gnu_mut().unwrap();
            gnu.sparse[0].set_offset(0);
            gnu.sparse[0].set_length(DATA_BLOCK);
            gnu.sparse[1].set_offset(HOLE);
            gnu.sparse[1].set_length(DATA_BLOCK);
            gnu.set_real_size(HOLE + DATA_BLOCK);
        }
        header.set_path(name).unwrap();
        header.set_cksum();

        let mut result = Vec::new();
        let gz_builder = GzEncoder::new(&mut result, flate2::Compression::default());
        let mut archive = Builder::new(gz_builder);
        archive
            .append(
                &header,
                Cursor::new(vec![0u8; usize::try_from(DATA_BLOCK * 2).unwrap()]),
            )
            .unwrap();
        write_to_archive(&mut archive, VERSION_TAG, &[0]).unwrap();
        archive.finish().unwrap();
        archive.into_inner().unwrap().finish().unwrap();

        result
    }

    #[test]
    fn test_from_bytes_rejects_sparse_bomb() {
        let bomb = sparse_bomb("personal_custody/bomb.bin");
        assert!(bomb.len() < 1024 * 1024);

        assert_eq!(
            V0Backup::from_bytes(&bomb).unwrap_err().to_string(),
            "Backup archive exceeds the maximum size"
        );
    }

    #[test]
    fn test_from_bytes_rejects_sparse_version_tag() {
        assert_eq!(
            V0Backup::from_bytes(&sparse_bomb(VERSION_TAG))
                .unwrap_err()
                .to_string(),
            "Backup archive exceeds the maximum size"
        );
    }
}
