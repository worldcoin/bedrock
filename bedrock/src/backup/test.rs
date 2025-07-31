use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::BackupFormat;
use crate::backup::{BackupError, BackupManager, FactorType};
use crate::primitives::filesystem::{
    create_middleware, set_filesystem, FileSystem, FileSystemError,
};

use crate::primitives::personal_custody_keypair::PersonalCustodyKeypair;
use crypto_box::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Mock filesystem for testing
struct MockFileSystem {
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl MockFileSystem {
    fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl FileSystem for MockFileSystem {
    fn get_user_data_directory(&self) -> String {
        "/mock/user/data".to_string()
    }

    fn file_exists(&self, file_path: String) -> bool {
        self.files.lock().unwrap().contains_key(&file_path)
    }

    fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError> {
        self.files
            .lock()
            .unwrap()
            .get(&file_path)
            .cloned()
            .ok_or(FileSystemError::FileDoesNotExist)
    }

    fn list_files(&self, _folder_path: String) -> Vec<String> {
        self.files.lock().unwrap().keys().cloned().collect()
    }

    fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> bool {
        self.files.lock().unwrap().insert(file_path, file_buffer);
        true
    }

    fn delete_file(&self, file_path: String) -> bool {
        self.files.lock().unwrap().remove(&file_path).is_some()
    }
}

#[test]
fn test_create_sealed_backup_with_prf_for_new_user() {
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret = "{\"version\":\"V1\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            &prf_result,
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Try to decrypt sealed_backup_data using encrypted_backup_keypair and
    // original PRF result
    let prf_factor_secret =
        SecretKey::from_slice(&hex::decode(&prf_result).unwrap()).unwrap();
    let decrypted_backup_keypair_bytes = prf_factor_secret
        .unseal(&hex::decode(&result.encrypted_backup_keypair).unwrap())
        .unwrap();
    let decrypted_backup_keypair =
        PersonalCustodyKeypair::from_private_key_bytes(&decrypted_backup_keypair_bytes);
    let decrypted_backup = decrypted_backup_keypair
        .sk()
        .unseal(&result.sealed_backup_data)
        .unwrap();
    assert_eq!(
        BackupFormat::from_bytes(&decrypted_backup).unwrap(),
        BackupFormat::V0(V0Backup {
            root_secret: root_secret.clone(),
            files: vec![]
        })
    );

    // The backup shouldn't decrypt using incorrect factor secret
    let original_factor_secret = hex::decode(&prf_result).unwrap();
    let mut bitflipped_factor_secret = original_factor_secret;
    bitflipped_factor_secret[3] ^= 1;
    let bitflipped_factor_secret =
        SecretKey::from_slice(&bitflipped_factor_secret).unwrap();
    let decryption_error = bitflipped_factor_secret
        .unseal(&hex::decode(&result.encrypted_backup_keypair).unwrap())
        .expect_err("Expected decryption to fail with bitflipped factor secret");
    assert_eq!(decryption_error.to_string(), "aead::Error");

    // Try to re-encrypt the backup using just the public key
    let new_backup = BackupFormat::V0(V0Backup {
        root_secret,
        files: vec![V0BackupFile {
            name: "file1.txt".to_string(),
            data: b"Hello, World!".to_vec(),
        }],
    });
    let re_encrypted_backup =
        PublicKey::from_slice(&hex::decode(result.backup_keypair_public_key).unwrap())
            .unwrap()
            .seal(&mut rand::thread_rng(), &new_backup.to_bytes().unwrap())
            .unwrap();

    // Decrypt the re-encrypted backup using the backup keypair
    let re_decrypted_backup = decrypted_backup_keypair
        .sk()
        .unseal(&re_encrypted_backup)
        .unwrap();
    assert_eq!(
        BackupFormat::from_bytes(&re_decrypted_backup).unwrap(),
        new_backup
    );
}

#[test]
fn test_decrypt_sealed_backup_with_prf() {
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret = "{\"version\":\"V1\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            root_secret.clone(),
            &prf_result,
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Decrypt it
    let decrypted = manager
        .decrypt_sealed_backup(
            &create_result.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            &prf_result,
            FactorType::Prf,
        )
        .unwrap();

    assert_eq!(
        decrypted.backup_keypair_public_key,
        create_result.backup_keypair_public_key
    );
    assert_eq!(
        decrypted.backup,
        BackupFormat::V0(V0Backup {
            root_secret,
            files: vec![]
        })
    );

    // Test with incorrect factor secret
    let mut incorrect_factor_secret = hex::decode(&prf_result).unwrap();
    incorrect_factor_secret[15] ^= 1;
    let incorrect_factor_secret = hex::encode(incorrect_factor_secret);

    let decryption_error = manager
        .decrypt_sealed_backup(
            &create_result.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            &incorrect_factor_secret,
            FactorType::Prf,
        )
        .expect_err("Expected decryption to fail with incorrect factor secret");
    assert_eq!(
        decryption_error.to_string(),
        "Failed to decrypt backup keypair"
    );
}

#[test]
fn test_unpack_unsealed_backup_to_file_system() {
    // Set up mock filesystem
    set_filesystem(Arc::new(MockFileSystem::new()));

    let manager = BackupManager::new();

    // Create test files to include in backup
    let test_files = vec![
        V0BackupFile {
            name: "test1.txt".to_string(),
            data: b"test file 1 content".to_vec(),
        },
        V0BackupFile {
            name: "test2.txt".to_string(),
            data: b"test file 2 content".to_vec(),
        },
    ];

    // Create a mock backup
    let root_secret = "test_root_secret".to_string();
    let backup = BackupFormat::new_v0(V0Backup::new(root_secret, test_files));

    let result = manager.unpack_unsealed_backup_to_file_system(&backup);
    assert!(result.is_ok());

    // Check that files were written to the file system using raw access
    let fs_middleware = create_middleware("BackupManager");
    let user_data_dir = fs_middleware.raw_get_user_data_directory().unwrap();

    // Verify file1 was written
    let file1_path = format!("{user_data_dir}/test1.txt");
    let file1_content = fs_middleware.raw_read_file(&file1_path).unwrap();
    assert_eq!(file1_content, b"test file 1 content".to_vec());

    // Verify file2 was written
    let file2_path = format!("{user_data_dir}/test2.txt");
    let file2_content = fs_middleware.raw_read_file(&file2_path).unwrap();
    assert_eq!(file2_content, b"test file 2 content".to_vec());
}

#[test]
fn test_create_sealed_backup_with_invalid_factor_secret() {
    let manager = BackupManager::new();
    let root_secret = "{\"version\":\"V1\",\"key\":\"1810f739487f5447c01df40e57d38885caad51912851f1cbdd69117fe3641d1b\"}"
        .to_string();

    // Test with non-hex factor secret
    let invalid_hex_result = manager.create_sealed_backup_for_new_user(
        root_secret.clone(),
        "not_hex_data",
        FactorType::Prf,
    );
    assert!(invalid_hex_result.is_err());
    assert!(matches!(
        invalid_hex_result.unwrap_err(),
        BackupError::DecodeFactorSecretError
    ));

    // Test with wrong length factor secret (16 bytes instead of 32)
    let short_factor_secret = "67a9b25d7cd2e11cba781af1d4be91c7"; // 31 chars = 15.5 bytes
    let invalid_length_result = manager.create_sealed_backup_for_new_user(
        root_secret.clone(),
        short_factor_secret,
        FactorType::Prf,
    );
    assert!(invalid_length_result.is_err());
    assert!(matches!(
        invalid_length_result.unwrap_err(),
        BackupError::InvalidFactorSecretLengthError
    ));

    // Test with too long factor secret (64 bytes instead of 32)
    let long_factor_secret = "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae3767a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37";
    let invalid_length_result2 = manager.create_sealed_backup_for_new_user(
        root_secret,
        long_factor_secret,
        FactorType::Prf,
    );
    assert!(invalid_length_result2.is_err());
    assert!(matches!(
        invalid_length_result2.unwrap_err(),
        BackupError::InvalidFactorSecretLengthError
    ));
}

// Backup manifest tests
#[test]
fn test_sync_backup_manifest_creates_new_manifest() {
    let mock_fs = MockFileSystem::new();
    set_filesystem(Arc::new(mock_fs));

    let backup_manager = BackupManager::new();
    let test_file_path = "/mock/user/data/test_file.dat".to_string();
    let fs_middleware = create_middleware("BackupManager");

    // Create the test file first
    fs_middleware
        .raw_write_file(&test_file_path, b"test content".to_vec())
        .unwrap();

    // Sync backup manifest
    let result = backup_manager.sync_backup_manifest(
        "test_module",
        test_file_path.clone(),
        "test_backup.dat".to_string(),
        1024,
    );

    assert!(result.is_ok());

    // Check that manifest was created
    let manifest_path = "/backup_manifests/test_module";
    let manifest_data = fs_middleware.raw_read_file(manifest_path).unwrap();
    let manifest: crate::backup::BackupManifest =
        serde_json::from_slice(&manifest_data).unwrap();

    assert_eq!(manifest.file_absolute_path, test_file_path);
    assert_eq!(manifest.save_as, "test_backup.dat");
    assert_eq!(manifest.manifest_version, 1);
    assert_eq!(manifest.max_file_size_kb, 1024);
}

#[test]
fn test_sync_backup_manifest_skips_update_if_same_file() {
    // Create a fresh filesystem instance for this test to avoid state leakage
    use crate::primitives::filesystem::{FileSystem, FileSystemError};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    struct IsolatedMockFileSystem {
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl IsolatedMockFileSystem {
        fn new() -> Self {
            Self {
                files: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl FileSystem for IsolatedMockFileSystem {
        fn get_user_data_directory(&self) -> String {
            "/isolated/mock/user/data".to_string()
        }

        fn file_exists(&self, file_path: String) -> bool {
            self.files.lock().unwrap().contains_key(&file_path)
        }

        fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError> {
            self.files
                .lock()
                .unwrap()
                .get(&file_path)
                .cloned()
                .ok_or(FileSystemError::FileDoesNotExist)
        }

        fn list_files(&self, _folder_path: String) -> Vec<String> {
            self.files.lock().unwrap().keys().cloned().collect()
        }

        fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> bool {
            self.files.lock().unwrap().insert(file_path, file_buffer);
            true
        }

        fn delete_file(&self, file_path: String) -> bool {
            self.files.lock().unwrap().remove(&file_path).is_some()
        }
    }

    // Reset global filesystem for this test
    static RESET_FS: OnceLock<()> = OnceLock::new();
    RESET_FS.get_or_init(|| {
        let isolated_fs = IsolatedMockFileSystem::new();
        // Force reset by setting new filesystem
        crate::primitives::filesystem::set_filesystem(Arc::new(isolated_fs));
    });

    let backup_manager = BackupManager::new();
    let test_file_path = "/isolated/mock/user/data/isolated_test_file.dat".to_string();
    let fs_middleware = create_middleware("BackupManager");

    // Create the test file first
    fs_middleware
        .raw_write_file(&test_file_path, b"test content".to_vec())
        .unwrap();

    // First sync - this should create the manifest
    backup_manager
        .sync_backup_manifest(
            "isolated_test_module",
            test_file_path.clone(),
            "test_backup.dat".to_string(),
            1024,
        )
        .unwrap();

    // Get original manifest content as bytes for exact comparison
    let manifest_path = "/backup_manifests/isolated_test_module";
    let original_manifest_bytes = fs_middleware.raw_read_file(manifest_path).unwrap();

    // Add delay to ensure timestamp would be different if update occurs
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Second sync with same file path - should skip update
    backup_manager
        .sync_backup_manifest(
            "isolated_test_module",
            test_file_path,
            "test_backup.dat".to_string(),
            1024,
        )
        .unwrap();

    // Get current manifest content as bytes
    let current_manifest_bytes = fs_middleware.raw_read_file(manifest_path).unwrap();

    // The bytes should be identical if no update occurred
    assert_eq!(
        original_manifest_bytes, current_manifest_bytes,
        "Manifest should not have been updated when file path is the same"
    );
}

#[test]
fn test_sync_backup_manifest_updates_if_different_file() {
    let mock_fs = MockFileSystem::new();
    set_filesystem(Arc::new(mock_fs));

    let backup_manager = BackupManager::new();
    let test_file_path1 = "/mock/user/data/test_file1.dat".to_string();
    let test_file_path2 = "/mock/user/data/test_file2.dat".to_string();
    let fs_middleware = create_middleware("BackupManager");

    // Create both test files
    fs_middleware
        .raw_write_file(&test_file_path1, b"test content 1".to_vec())
        .unwrap();
    fs_middleware
        .raw_write_file(&test_file_path2, b"test content 2".to_vec())
        .unwrap();

    // First sync with file1
    backup_manager
        .sync_backup_manifest(
            "test_module",
            test_file_path1,
            "test_backup.dat".to_string(),
            1024,
        )
        .unwrap();

    // Second sync with file2 - should update
    backup_manager
        .sync_backup_manifest(
            "test_module",
            test_file_path2.clone(),
            "test_backup.dat".to_string(),
            1024,
        )
        .unwrap();

    // Check that manifest was updated to point to file2
    let manifest_path = "/backup_manifests/test_module";
    let manifest_data = fs_middleware.raw_read_file(manifest_path).unwrap();
    let manifest: crate::backup::BackupManifest =
        serde_json::from_slice(&manifest_data).unwrap();

    assert_eq!(manifest.file_absolute_path, test_file_path2);
}

#[test]
fn test_sync_backup_manifest_fails_if_file_does_not_exist() {
    let mock_fs = MockFileSystem::new();
    set_filesystem(Arc::new(mock_fs));

    let backup_manager = BackupManager::new();
    let test_file_path = "/mock/user/data/nonexistent_file.dat".to_string();

    // Try to sync manifest for nonexistent file
    let result = backup_manager.sync_backup_manifest(
        "test_module",
        test_file_path,
        "test_backup.dat".to_string(),
        1024,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), BackupError::WriteFileError));
}

#[test]
fn test_remove_backup_manifest() {
    let mock_fs = MockFileSystem::new();
    set_filesystem(Arc::new(mock_fs));

    let backup_manager = BackupManager::new();
    let test_file_path = "/mock/user/data/test_file.dat".to_string();
    let fs_middleware = create_middleware("BackupManager");

    // Create the test file and manifest
    fs_middleware
        .raw_write_file(&test_file_path, b"test content".to_vec())
        .unwrap();

    backup_manager
        .sync_backup_manifest(
            "test_module",
            test_file_path,
            "test_backup.dat".to_string(),
            1024,
        )
        .unwrap();

    // Verify manifest exists
    let manifest_path = "/backup_manifests/test_module";
    assert!(fs_middleware.raw_file_exists(manifest_path).unwrap());

    // Remove manifest
    let result = backup_manager.remove_backup_manifest("test_module");
    assert!(result.is_ok());

    // Verify manifest was deleted
    assert!(!fs_middleware.raw_file_exists(manifest_path).unwrap());
}

#[test]
fn test_backup_manifest_new() {
    use chrono::Utc;

    let file_path = "/test/path/file.dat".to_string();
    let save_as = "backup_file.dat".to_string();
    let timestamp = Utc::now();
    let max_size = 2048;

    let manifest = crate::backup::BackupManifest::new(
        file_path.clone(),
        save_as.clone(),
        timestamp,
        max_size,
    );

    assert_eq!(manifest.file_absolute_path, file_path);
    assert_eq!(manifest.save_as, save_as);
    assert_eq!(manifest.manifest_last_updated_at, timestamp);
    assert_eq!(manifest.manifest_version, 1);
    assert_eq!(manifest.max_file_size_kb, max_size);
}

#[test]
fn test_backup_manifest_serialization() {
    use chrono::Utc;

    let manifest = crate::backup::BackupManifest::new(
        "/test/path/file.dat".to_string(),
        "backup_file.dat".to_string(),
        Utc::now(),
        1024,
    );

    // Test serialization
    let serialized = serde_json::to_vec(&manifest).unwrap();
    assert!(!serialized.is_empty());

    // Test deserialization
    let deserialized: crate::backup::BackupManifest =
        serde_json::from_slice(&serialized).unwrap();

    assert_eq!(manifest.file_absolute_path, deserialized.file_absolute_path);
    assert_eq!(manifest.save_as, deserialized.save_as);
    assert_eq!(
        manifest.manifest_last_updated_at,
        deserialized.manifest_last_updated_at
    );
    assert_eq!(manifest.manifest_version, deserialized.manifest_version);
    assert_eq!(manifest.max_file_size_kb, deserialized.max_file_size_kb);
}
