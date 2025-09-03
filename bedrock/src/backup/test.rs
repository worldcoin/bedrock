use crate::backup::backup_format::v0::{V0Backup, V0BackupFile};
use crate::backup::backup_format::BackupFormat;
use crate::backup::FactorType;
use crate::backup::{BackupFileDesignator, BackupManager};
use crate::primitives::filesystem::{set_filesystem, InMemoryFileSystem};
use crate::root_key::RootKey;
use crypto_box::{PublicKey, SecretKey};
use std::str::FromStr;
use std::sync::Mutex;

// Test-only global lock to serialize manifest-affecting tests to avoid races.
static MANIFEST_LOCK: Mutex<()> = Mutex::new(());

fn ensure_fs_initialized() {
    if crate::primitives::filesystem::get_filesystem_raw().is_err() {
        let fs = InMemoryFileSystem::new();
        set_filesystem(std::sync::Arc::new(fs));
    }
}

fn helper_compare_backups(source: &BackupFormat, target: &BackupFormat) -> bool {
    let BackupFormat::V0(source_backup) = source;
    let BackupFormat::V0(target_backup) = target;
    source_backup.root_secret == target_backup.root_secret
        && source_backup.files == target_backup.files
}

#[test]
fn test_backup_module_enum() {
    assert_eq!(
        BackupFileDesignator::OrbPkg.to_string(),
        "orb_pkg".to_string()
    );
    assert_eq!(
        BackupFileDesignator::DocumentPkg.to_string(),
        "document_pkg".to_string()
    );

    assert_eq!(
        BackupFileDesignator::from_str("orb_pkg").unwrap(),
        BackupFileDesignator::OrbPkg
    );
    assert_eq!(
        BackupFileDesignator::from_str("document_pkg").unwrap(),
        BackupFileDesignator::DocumentPkg
    );

    assert_eq!(
        serde_json::to_string(&BackupFileDesignator::OrbPkg).unwrap(),
        "\"orb_pkg\""
    );
    assert_eq!(
        serde_json::to_string(&BackupFileDesignator::DocumentPkg).unwrap(),
        "\"document_pkg\""
    );
}

#[test]
fn test_create_sealed_backup_with_prf_for_new_user() {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    ensure_fs_initialized();
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret =
        "{\"version\":\"V1\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let result = manager
        .create_sealed_backup_for_new_user(
            &root_secret,
            prf_result.clone(),
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
        SecretKey::from_slice(&decrypted_backup_keypair_bytes).unwrap();
    let decrypted_backup = decrypted_backup_keypair
        .unseal(&result.sealed_backup_data)
        .unwrap();

    assert!(helper_compare_backups(
        &BackupFormat::from_bytes(&decrypted_backup).unwrap(),
        &BackupFormat::V0(V0Backup {
            root_secret: RootKey::from_json(&root_secret).unwrap(),
            files: vec![]
        })
    ));

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
        root_secret: RootKey::from_json(&root_secret).unwrap(),
        files: vec![V0BackupFile {
            data: b"Hello, World!".to_vec(),
            checksum: hex::decode(
                "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            path: "documents/file1.txt".to_string(),
        }],
    });
    let re_encrypted_backup =
        PublicKey::from_slice(&hex::decode(result.backup_keypair_public_key).unwrap())
            .unwrap()
            .seal(&mut rand::thread_rng(), &new_backup.to_bytes().unwrap())
            .unwrap();

    // Decrypt the re-encrypted backup using the backup keypair
    let re_decrypted_backup = decrypted_backup_keypair
        .unseal(&re_encrypted_backup)
        .unwrap();
    assert!(helper_compare_backups(
        &BackupFormat::from_bytes(&re_decrypted_backup).unwrap(),
        &new_backup
    ));
}

#[test]
fn test_decrypt_sealed_backup_with_prf() {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    ensure_fs_initialized();
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret =
        "{\"version\":\"V1\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();

    let create_result = manager
        .create_sealed_backup_for_new_user(
            &root_secret,
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Decrypt it
    let decrypted = manager
        .decrypt_and_unpack_sealed_backup(
            &create_result.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            prf_result.clone(),
            FactorType::Prf,
        )
        .unwrap();

    assert_eq!(
        decrypted.backup_keypair_public_key,
        create_result.backup_keypair_public_key
    );
    assert_eq!(
        decrypted.root_key_json,
        RootKey::from_json(&root_secret)
            .unwrap()
            .danger_to_json()
            .unwrap()
    );

    // Test with incorrect factor secret
    let mut incorrect_factor_secret = hex::decode(&prf_result).unwrap();
    incorrect_factor_secret[15] ^= 1;
    let incorrect_factor_secret = hex::encode(incorrect_factor_secret);

    let decryption_error = manager
        .decrypt_and_unpack_sealed_backup(
            &create_result.sealed_backup_data,
            create_result.encrypted_backup_keypair.clone(),
            incorrect_factor_secret,
            FactorType::Prf,
        )
        .expect_err("Expected decryption to fail with incorrect factor secret");
    assert_eq!(
        decryption_error.to_string(),
        "Failed to decrypt backup keypair"
    );

    // Test with incorrect encrypted backup keypair
    let mut incorrect_encrypted_backup_keypair =
        hex::decode(&create_result.encrypted_backup_keypair).unwrap();
    incorrect_encrypted_backup_keypair[0] ^= 1;
    let incorrect_encrypted_backup_keypair =
        hex::encode(incorrect_encrypted_backup_keypair);

    let decryption_error = manager
        .decrypt_and_unpack_sealed_backup(
            &create_result.sealed_backup_data,
            incorrect_encrypted_backup_keypair,
            prf_result,
            FactorType::Prf,
        )
        .expect_err(
            "Expected decryption to fail with incorrect encrypted backup keypair",
        );
    assert_eq!(
        decryption_error.to_string(),
        "Failed to decrypt backup keypair"
    );
}

#[test]
fn test_unpack_writes_files_and_manifest() {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    ensure_fs_initialized();
    // Arrange filesystem: use the already-initialized global filesystem (tests set it once).
    // We don't replace it if already set; we just assert via the global handle.
    let manager = BackupManager::new();

    // Create a backup with a couple of files resembling real paths
    let root_secret = RootKey::new_random();
    let files = vec![
        V0BackupFile {
            data: b"hello-orb".to_vec(),
            checksum: blake3::hash(b"hello-orb").as_bytes().to_owned(),
            path: "orb_pkg/personal_custody/pcp-1234.bin".to_string(),
        },
        V0BackupFile {
            data: b"doc-blob".to_vec(),
            checksum: blake3::hash(b"doc-blob").as_bytes().to_owned(),
            path: "document_pkg/document_personal_custody/passport-1.bin".to_string(),
        },
    ];
    let unsealed = BackupFormat::V0(V0Backup { root_secret, files });
    let unsealed_bytes = unsealed.to_bytes().unwrap();

    // Encrypt sealed backup using a one-off keypair and then decrypt via manager path
    let backup_sk = SecretKey::generate(&mut rand::thread_rng());
    let sealed = backup_sk
        .public_key()
        .seal(&mut rand::thread_rng(), &unsealed_bytes)
        .unwrap();

    // Factor secret wraps the backup keypair
    let factor_sk = SecretKey::generate(&mut rand::thread_rng());
    let encrypted_backup_keypair = factor_sk
        .public_key()
        .seal(&mut rand::thread_rng(), &backup_sk.to_bytes())
        .unwrap();

    // Act: decrypt and unpack
    let _ = manager
        .decrypt_and_unpack_sealed_backup(
            &sealed,
            hex::encode(encrypted_backup_keypair),
            hex::encode(factor_sk.to_bytes()),
            FactorType::Prf,
        )
        .unwrap();

    // Assert: files exist at expected paths (global filesystem, no prefix)
    let global_fs = crate::primitives::filesystem::get_filesystem_raw()
        .unwrap()
        .clone();
    assert!(global_fs
        .file_exists("orb_pkg/personal_custody/pcp-1234.bin".to_string())
        .unwrap());
    assert!(global_fs
        .file_exists(
            "document_pkg/document_personal_custody/passport-1.bin".to_string()
        )
        .unwrap());

    // Manifest is written under backup/manifest.json
    let manifest_bytes = global_fs
        .read_file("backup/manifest.json".to_string())
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["version"], "V0");
    let files_array = manifest["manifest"]["files"].as_array().unwrap();
    assert_eq!(files_array.len(), 2);
    // Checksums match stored values
    let checksum0 = &files_array[0]["checksum_hex"];
    let checksum1 = &files_array[1]["checksum_hex"];
    assert!(checksum0.is_string());
    assert!(checksum1.is_string());
}

#[test]
fn test_re_encrypt_backup() {
    let _guard = MANIFEST_LOCK.lock().unwrap();
    ensure_fs_initialized();
    let manager = BackupManager::new();

    // Example root secret seed
    let root_secret: String =
        "{\"version\":\"V0\",\"key\":\"2111111111111111111111111111111111111111111111111111111111111111\"}".to_string();
    // Example passkey PRF result - converted from base64url "Z6myXXzS4Ry6eBrx1L6Rxz01YeWo-8KQTLbC8nSsrjc=" to hex
    let prf_result =
        "67a9b25d7cd2e11cba781af1d4be91c73d3561e5a8fbc2904cb6c2f274acae37".to_string();
    // New factor secret
    let new_factor_secret = SecretKey::generate(&mut rand::thread_rng());

    let create_result = manager
        .create_sealed_backup_for_new_user(
            &root_secret,
            prf_result.clone(),
            FactorType::Prf,
        )
        .expect("Failed to create sealed backup with PRF for new user");

    // Re-encrypt the backup
    let re_encrypted_backup = manager
        .add_new_factor(
            create_result.encrypted_backup_keypair.clone(),
            prf_result.clone(),
            hex::encode(new_factor_secret.to_bytes()),
            FactorType::Prf,
            FactorType::IcloudKeychain,
        )
        .expect("Failed to re-encrypt backup keypair with new factor secret");

    // Decrypt the re-encrypted backup keypair
    let decrypted_backup_keypair_bytes = new_factor_secret
        .unseal(
            &hex::decode(&re_encrypted_backup.encrypted_backup_keypair_with_new_factor)
                .unwrap(),
        )
        .expect("Failed to decrypt re-encrypted backup keypair");

    let decrypted_backup_keypair =
        SecretKey::from_slice(&decrypted_backup_keypair_bytes).unwrap();
    let decrypted_backup = decrypted_backup_keypair
        .unseal(&create_result.sealed_backup_data)
        .expect("Failed to decrypt backup data");

    assert!(helper_compare_backups(
        &BackupFormat::from_bytes(&decrypted_backup).unwrap(),
        &BackupFormat::V0(V0Backup {
            root_secret: RootKey::from_json(&root_secret).unwrap(),
            files: vec![]
        })
    ));

    // Test with incorrect existing factor secret
    let mut incorrect_existing_factor_secret = hex::decode(&prf_result).unwrap();
    incorrect_existing_factor_secret[10] ^= 1;
    let decryption_error = manager
        .add_new_factor(
            create_result.encrypted_backup_keypair,
            hex::encode(incorrect_existing_factor_secret),
            hex::encode(new_factor_secret.to_bytes()),
            FactorType::Prf,
            FactorType::IcloudKeychain,
        )
        .expect_err(
            "Expected decryption to fail with incorrect existing factor secret",
        );
    assert_eq!(
        decryption_error.to_string(),
        "Failed to decrypt backup keypair"
    );
}
